// cage-approve —— Cage 宿主机审批代理
//
// 运行在宿主机用户会话里，本身**不提权**。它的职责只有三件事：
//   1. 接收客机（Cage 内 Claude）发来的命令请求；
//   2. 把**完整命令原文**弹窗给你，由你决定批不批准；
//   3. 批准后走 Windows 的 runas 提权执行——每次执行都会出现 UAC 确认，
//      因此即使本进程被攻破，攻击者也拿不到管理员权限，只能替你弹框。
//
// 安全边界：
//   - 监听地址由防火墙限定为客机 tailnet IP；
//   - 必须携带 token（首次运行生成，写入 %ProgramData%\CageBroker\token）；
//   - 批准与否只由人决定，代理不做任何自动放行；
//   - 所有请求（含被拒）都会写审计日志。
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	messageBoxW     = user32.NewProc("MessageBoxW")
	shellExecuteExW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteExW")
)

const (
	mbOK        = 0x00000000
	mbOKCancel  = 0x00000001
	mbIconWarn  = 0x00000030
	mbIconQuest = 0x00000020
	mbTopmost   = 0x00001000
	mbSetFg     = 0x00010000
)

func messageBox(title, text string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString(title)
	r, _, _ := messageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
	return int(r)
}

type broker struct {
	root  string
	token string
	mu    sync.Mutex // 一次只处理一个请求，避免弹窗排队失控
	uid   int
}

func (b *broker) logf(format string, args ...any) {
	line := fmt.Sprintf("%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	f, err := os.OpenFile(filepath.Join(b.root, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		f.WriteString(line)
		f.Close()
	}
}

func (b *broker) authorized(r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(b.token)) == 1
}

type runRequest struct {
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type runResponse struct {
	Approved bool   `json:"approved"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

// escapePowerShell 把任意文本变成单引号字面量，避免拼接注入
func escapePowerShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (b *broker) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !b.authorized(r) {
		b.logf("DENY unauthorized %s", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req runRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	req.Command = strings.TrimSpace(req.Command)
	if req.Command == "" {
		http.Error(w, "empty command", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// 弹窗展示的就是将要执行的全部内容：没有隐式包装、不做字符串改写
	text := req.Command
	if req.Reason != "" {
		text = req.Reason + "\n\n── 将要执行 ──\n" + req.Command
	}
	text += "\n\n批准后将以管理员权限执行（随后出现 UAC 确认）。"
	choice := messageBox("Cage 请求管理员操作", text, mbOKCancel|mbIconWarn|mbTopmost|mbSetFg)
	if choice != 1 { // IDOK
		b.logf("DENIED  %q", req.Command)
		json.NewEncoder(w).Encode(runResponse{Approved: false})
		return
	}

	b.uid++
	id := b.uid
	script := filepath.Join(b.root, fmt.Sprintf("run-%d.ps1", id))
	outFile := filepath.Join(b.root, fmt.Sprintf("run-%d.out", id))
	body := fmt.Sprintf("$ErrorActionPreference='Continue'\n& {\n%s\n} *>&1 | Tee-Object -FilePath %s\n",
		req.Command, escapePowerShell(outFile))
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		http.Error(w, "write script", http.StatusInternalServerError)
		return
	}

	// Start-Process -Verb RunAs 触发 UAC；-Wait 让我们能回收结果
	arg := fmt.Sprintf(
		"Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',%s",
		escapePowerShell(script))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()

	output, _ := os.ReadFile(outFile)
	code := 0
	if err != nil {
		code = 1
	}
	b.logf("APPROVED exit=%d  %q", code, req.Command)
	json.NewEncoder(w).Encode(runResponse{Approved: true, ExitCode: code, Output: string(output)})
}

func (b *broker) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "pid": os.Getpid()})
}

func loadOrCreateToken(root string) (string, error) {
	path := filepath.Join(root, "token")
	if data, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(data)); len(t) >= 32 {
			return t, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func main() {
	addr := flag.String("addr", ":8642", "监听地址")
	flag.Parse()

	root := filepath.Join(os.Getenv("ProgramData"), "CageBroker")
	if os.Getenv("ProgramData") == "" {
		root = filepath.Join(os.TempDir(), "CageBroker")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}
	token, err := loadOrCreateToken(root)
	if err != nil {
		log.Fatalf("初始化 token 失败: %v", err)
	}

	b := &broker{root: root, token: token}
	mux := http.NewServeMux()
	mux.HandleFunc("/run", b.handleRun)
	mux.HandleFunc("/health", b.handleHealth)

	b.logf("START listen=%s root=%s", *addr, root)
	fmt.Printf("cage-approve 已启动\n  监听: %s\n  数据: %s\n  token: %s\n", *addr, root, token)
	fmt.Println("把上面的 token 写入客机 /etc/cage-broker-token 即可使用。")
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}