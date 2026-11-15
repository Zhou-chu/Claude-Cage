//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	user32                       = syscall.NewLazyDLL("user32.dll")
	shell32                      = syscall.NewLazyDLL("shell32.dll")
	advapi32                     = syscall.NewLazyDLL("advapi32.dll")
	ole32                        = syscall.NewLazyDLL("ole32.dll")
	messageBoxW                  = user32.NewProc("MessageBoxW")
	shellExecuteExW              = shell32.NewProc("ShellExecuteExW")
	shGetKnownFolderPath         = shell32.NewProc("SHGetKnownFolderPath")
	coTaskMemFree                = ole32.NewProc("CoTaskMemFree")
	getSystemDirectoryW          = kernel32.NewProc("GetSystemDirectoryW")
	getNamedSecurityInfoW        = advapi32.NewProc("GetNamedSecurityInfoW")
	getSecurityDescriptorControl = advapi32.NewProc("GetSecurityDescriptorControl")
	isValidACL                   = advapi32.NewProc("IsValidAcl")
	getACE                       = advapi32.NewProc("GetAce")
	isValidSID                   = advapi32.NewProc("IsValidSid")
)

const (
	mbOKCancel                = 0x00000001
	mbIconWarn                = 0x00000030
	mbDefaultCancel           = 0x00000100
	mbTopmost                 = 0x00040000
	mbSetForeground           = 0x00010000
	fileAttributeDirectory    = 0x10
	fileAttributeReparsePoint = 0x400
	inheritOnlyACE            = 0x08
	seDACLProtected           = 0x1000
	// Includes generic write/all, delete/child deletion, write ACL/owner,
	// write data/append/EA/attributes and MAXIMUM_ALLOWED (fail closed).
	writeAccessMask uint32 = 0x10000000 | 0x40000000 | 0x02000000 | 0x000D0156
	// Creating a sibling in ProgramData does not authorize changing the
	// preinstalled protected root. Inherited-only parent grants do not apply.
	ancestorMutationMask uint32 = 0x10000000 | 0x40000000 | 0x02000000 | 0x000D0040
	trustedInstallerSID         = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

func promptApproval(a approval) (bool, error) {
	// Bounded review pages avoid silently clipping a 4 KiB command in a single
	// oversized MessageBox. Any cancelled/failed page means no execution.
	pages := reviewPages(a)
	for i, text := range pages {
		t, err := syscall.UTF16PtrFromString(text)
		if err != nil {
			return false, err
		}
		c, _ := syscall.UTF16PtrFromString(fmt.Sprintf("Cage: human review %d/%d (Cancel is default)", i+1, len(pages)))
		result, _, callErr := messageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), mbOKCancel|mbIconWarn|mbDefaultCancel|mbTopmost|mbSetForeground)
		if result == 0 {
			return false, fmt.Errorf("MessageBoxW: %v", callErr)
		}
		if result != 1 {
			return false, nil
		}
	}
	return true, nil // Only IDOK on EVERY page, including final approval.
}

func brokerRoot() (string, error) {
	// FOLDERID_ProgramData, from the OS, never an attacker-controlled environment
	// variable or a writable temporary-directory fallback.
	folderID := syscall.GUID{Data1: 0x62AB5D82, Data2: 0xFDC1, Data3: 0x4DC3, Data4: [8]byte{0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97}}
	var path *uint16
	hr, _, _ := shGetKnownFolderPath.Call(uintptr(unsafe.Pointer(&folderID)), 0, 0, uintptr(unsafe.Pointer(&path)))
	if int32(hr) < 0 || path == nil {
		return "", fmt.Errorf("SHGetKnownFolderPath failed: HRESULT 0x%08x", uint32(hr))
	}
	defer coTaskMemFree.Call(uintptr(unsafe.Pointer(path)))
	var units []uint16
	for i := 0; ; i++ {
		if i >= 32767 {
			return "", errors.New("ProgramData path too long")
		}
		u := *(*uint16)(unsafe.Add(unsafe.Pointer(path), 2*i))
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	root := filepath.Join(syscall.UTF16ToString(units), "CageBroker")
	if !filepath.IsAbs(root) {
		return "", errors.New("ProgramData path is not absolute")
	}
	return root, nil
}

func validateOperatorIdentity(account string, elevated bool) error {
	if strings.EqualFold(account, "cageops") {
		return errors.New("broker must run as the trusted host operator, not cageops")
	}
	if elevated {
		return errors.New("broker must run unelevated; do not use Run as administrator or RunHighest")
	}
	return nil
}

func operatorPrincipals() (map[string]bool, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	var elevation, returned uint32
	ok, _, callErr := advapi32.NewProc("GetTokenInformation").Call(uintptr(token), 20, uintptr(unsafe.Pointer(&elevation)), unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&returned)))
	if ok == 0 || returned != uint32(unsafe.Sizeof(elevation)) {
		return nil, fmt.Errorf("query broker token elevation: %v", callErr)
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	name, _, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("resolve trusted operator identity: %w", err)
	}
	if err := validateOperatorIdentity(name, elevation != 0); err != nil {
		return nil, err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return nil, err
	}
	return map[string]bool{sid: true, "S-1-5-18": true, "S-1-5-32-544": true}, nil
}

type aclHeader struct {
	Revision  byte
	Reserved  byte
	Size      uint16
	Count     uint16
	Reserved2 uint16
}

type aceHeader struct {
	Type  byte
	Flags byte
	Size  uint16
}

// validateACE is deliberately conservative: do not try to cancel broad allow
// entries against deny/conditional ACEs or infer membership of arbitrary groups.
func validateACE(kind, flags byte, mask uint32, sid string, trusted map[string]bool, ancestor, strict bool) error {
	if kind == 1 { // ACCESS_DENIED_ACE: never grants a right
		return nil
	}
	if kind != 0 { // refuse object/callback/unknown DACL forms, rather than guess
		return fmt.Errorf("unsupported DACL ACE type %d", kind)
	}
	if ancestor && flags&inheritOnlyACE != 0 {
		return nil
	}
	if trusted[sid] {
		return nil
	}
	if strict && mask != 0 {
		return fmt.Errorf("untrusted DACL principal %s has access 0x%08x", sid, mask)
	}
	risky := writeAccessMask
	if ancestor {
		risky = ancestorMutationMask
	}
	if mask&risky != 0 {
		return fmt.Errorf("untrusted DACL principal %s can mutate protected path (0x%08x)", sid, mask)
	}
	return nil
}

func checkSecurity(path string, trusted map[string]bool, protected, ancestor, strict bool) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var owner *syscall.SID
	var acl *aclHeader
	var sd uintptr
	// SE_FILE_OBJECT = 1; OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION.
	code, _, _ := getNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(name)), 1, 0x5,
		uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&sd)))
	if code != 0 {
		return fmt.Errorf("read Windows owner/DACL for %s: %w", path, syscall.Errno(code))
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if owner == nil || acl == nil {
		return errors.New("missing owner or NULL DACL grants unrestricted access")
	}
	ownerSID, err := owner.String()
	if err != nil || !trusted[ownerSID] {
		return fmt.Errorf("untrusted owner on %s", path)
	}
	var control uint16
	var revision uint32
	ok, _, _ := getSecurityDescriptorControl.Call(sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || (protected && control&seDACLProtected == 0) {
		return fmt.Errorf("%s must have a protected (inheritance-disabled) DACL", path)
	}
	ok, _, _ = isValidACL.Call(uintptr(unsafe.Pointer(acl)))
	if ok == 0 || acl.Size < uint16(unsafe.Sizeof(aclHeader{})) {
		return fmt.Errorf("invalid DACL on %s", path)
	}
	for i := uint16(0); i < acl.Count; i++ {
		var ptr unsafe.Pointer
		ok, _, _ = getACE.Call(uintptr(unsafe.Pointer(acl)), uintptr(i), uintptr(unsafe.Pointer(&ptr)))
		if ok == 0 || ptr == nil {
			return fmt.Errorf("cannot read DACL ACE on %s", path)
		}
		base := uintptr(unsafe.Pointer(acl))
		if uintptr(ptr) < base || uintptr(ptr)-base+unsafe.Sizeof(aceHeader{}) > uintptr(acl.Size) {
			return errors.New("invalid DACL ACE header bounds")
		}
		header := (*aceHeader)(ptr)
		if header.Size < 16 || uintptr(ptr)-base+uintptr(header.Size) > uintptr(acl.Size) {
			return errors.New("invalid DACL ACE bounds")
		}
		// Ordinary ACCESS_ALLOWED/ACCESS_DENIED ACEs store SID at byte 8.
		if header.Type != 0 && header.Type != 1 {
			return fmt.Errorf("unsupported DACL ACE type %d on %s", header.Type, path)
		}
		mask := *(*uint32)(unsafe.Add(ptr, 4))
		sidData := unsafe.Slice((*byte)(unsafe.Add(ptr, 8)), int(header.Size)-8)
		if 8+4*int(sidData[1]) > len(sidData) {
			return errors.New("DACL SID exceeds its ACE")
		}
		sid := (*syscall.SID)(unsafe.Add(ptr, 8))
		ok, _, _ = isValidSID.Call(uintptr(unsafe.Pointer(sid)))
		if ok == 0 || sid.Len() > len(sidData) {
			return errors.New("invalid DACL SID")
		}
		sidText, err := sid.String()
		if err != nil {
			return err
		}
		if err := validateACE(header.Type, header.Flags, mask, sidText, trusted, ancestor, strict); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

func checkPlainPath(path string, directory bool, allowOSHardLinks ...bool) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attrs&fileAttributeReparsePoint != 0 || (attrs&fileAttributeDirectory != 0) != directory {
		return fmt.Errorf("not a plain %s (reparse points forbidden): %s", map[bool]string{true: "directory", false: "file"}[directory], path)
	}
	// Refuse hard-linked broker data. Only a verified OS executable may opt
	// out, because Windows servicing normally hard-links binaries into WinSxS.
	if !directory && !(len(allowOSHardLinks) == 1 && allowOSHardLinks[0]) {
		h, err := syscall.CreateFile(name, 0x80, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
		if err != nil {
			return err
		}
		defer syscall.CloseHandle(h)
		var info syscall.ByHandleFileInformation
		if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
			return err
		}
		if info.NumberOfLinks != 1 {
			return fmt.Errorf("hard-linked protected file forbidden: %s", path)
		}
	}
	return nil
}

func verifyProtectedRoot(root string) error {
	trusted, err := operatorPrincipals()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(root) {
		return errors.New("broker root must be absolute")
	}
	if err := checkPlainPath(root, true); err != nil {
		return fmt.Errorf("preinstalled broker directory required: %w", err)
	}
	// Root and sensitive files allow ONLY operator, SYSTEM and Administrators,
	// including inheritable grants. This also forbids other principals reading
	// the token or the captured command output.
	if err := checkSecurity(root, trusted, true, false, true); err != nil {
		return err
	}
	parents := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, trustedInstallerSID: true}
	for sid := range trusted {
		parents[sid] = true
	}
	for parent := filepath.Dir(root); ; parent = filepath.Dir(parent) {
		if err := checkPlainPath(parent, true); err != nil {
			return err
		}
		if err := checkSecurity(parent, parents, false, true, false); err != nil {
			return err
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	for _, base := range []string{"token", "audit.log"} {
		path := filepath.Join(root, base)
		if err := checkPlainPath(path, false); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := checkSecurity(path, trusted, false, false, true); err != nil {
			return err
		}
	}
	return nil
}

func trustedPowerShellPath() (string, error) {
	buf := make([]uint16, 32768)
	n, _, callErr := getSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return "", fmt.Errorf("GetSystemDirectoryW: %v", callErr)
	}
	path := filepath.Join(syscall.UTF16ToString(buf[:n]), "WindowsPowerShell", "v1.0", "powershell.exe")
	if !filepath.IsAbs(path) {
		return "", errors.New("Windows PowerShell path is not absolute")
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, trustedInstallerSID: true}
	if err := checkPlainPath(path, false, true); err != nil {
		return "", err
	}
	if err := checkSecurity(path, trusted, false, false, false); err != nil {
		return "", err
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if err := checkPlainPath(parent, true); err != nil {
			return "", err
		}
		if err := checkSecurity(parent, trusted, false, true, false); err != nil {
			return "", err
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	return path, nil
}

// Layout matches SHELLEXECUTEINFOW on both Windows 32- and 64-bit targets.
type shellExecuteInfo struct {
	Size       uint32
	Mask       uint32
	Window     syscall.Handle
	Verb       *uint16
	File       *uint16
	Parameters *uint16
	Directory  *uint16
	Show       int32
	Instance   syscall.Handle
	IDList     unsafe.Pointer
	Class      *uint16
	ClassKey   syscall.Handle
	HotKey     uint32
	Icon       syscall.Handle
	Process    syscall.Handle
}

func launchElevated(path, root, encoded string) (process syscall.Handle, started bool, err error) {
	file, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false, err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	args := "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	if len(args)+len(path)+2 >= 32767 {
		return 0, false, errors.New("encoded command exceeds the Windows command-line limit; nothing executed")
	}
	parameters, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		return 0, false, err
	}
	directory, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return 0, false, err
	}
	info := shellExecuteInfo{Mask: 0x40 | 0x100 | 0x400, Verb: verb, File: file, Parameters: parameters, Directory: directory, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, callErr := shellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		if errors.Is(callErr, syscall.Errno(1223)) {
			return 0, false, errors.New("Windows UAC consent cancelled (1223); nothing executed")
		}
		return 0, false, fmt.Errorf("elevated process not started: %v", callErr)
	}
	if info.Process == 0 {
		return 0, true, errors.New("Windows returned no elevated child handle; outcome unknown, do not automatically retry")
	}
	return info.Process, true, nil
}

func runElevated(root string, a approval) runResult {
	result := runResult{ExitCode: notExecuted}
	if err := verifyProtectedRoot(root); err != nil {
		result.Error = "protected storage validation failed; nothing executed"
		return result
	}
	powershell, err := trustedPowerShellPath()
	if err != nil {
		result.Error = "trusted Windows PowerShell validation failed; nothing executed"
		return result
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		result.Error = "secure output name generation failed; nothing executed"
		return result
	}
	outputPath := filepath.Join(root, "output-"+hex.EncodeToString(nonce[:])+".txt")
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		result.Error = "create exclusive output capture failed; nothing executed"
		return result
	}
	if err := f.Close(); err != nil {
		result.Error = "close output capture failed; nothing executed"
		return result
	}
	// Keep protected capture files for operator audit/retention. Do not leave a
	// predictable executable script or silently delete an audit artifact.
	trusted, err := operatorPrincipals()
	if err != nil {
		result.Error = "operator identity unavailable; nothing executed"
		return result
	}
	if err := checkSecurity(outputPath, trusted, false, false, true); err != nil {
		result.Error = "output DACL validation failed; nothing executed"
		return result
	}
	script, err := executionScript(a, outputPath)
	if err != nil {
		result.Error = "approved command validation failed; nothing executed"
		return result
	}
	process, started, err := launchElevated(powershell, root, encodedCommand(script))
	result.Executed = started
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer syscall.CloseHandle(process)
	state, err := syscall.WaitForSingleObject(process, syscall.INFINITE)
	if err != nil || state != syscall.WAIT_OBJECT_0 {
		result.Error = "elevated child wait failed; outcome unknown, do not automatically retry"
		return result
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(process, &code); err != nil {
		result.Error = "elevated child exit code unavailable; do not automatically retry"
		return result
	}
	result.ExitCode = int(code) // preserve the real Windows child DWORD, not a launcher's exit
	if err := verifyProtectedRoot(root); err != nil {
		result.Error = "storage protection changed during execution; output withheld"
		return result
	}
	if err := checkPlainPath(outputPath, false); err != nil {
		result.Error = "output capture is no longer a plain file; output withheld"
		return result
	}
	if err := checkSecurity(outputPath, trusted, false, false, true); err != nil {
		result.Error = "output capture DACL changed; output withheld"
		return result
	}
	capture, err := os.Open(outputPath)
	if err != nil {
		result.Error = "read output capture failed"
		return result
	}
	defer capture.Close()
	output, err := io.ReadAll(io.LimitReader(capture, maxOutputBytes+1))
	if err != nil {
		result.Error = "read output capture failed"
		return result
	}
	if len(output) > maxOutputBytes {
		output = output[:maxOutputBytes]
		result.Error = "output truncated at 1 MiB; full capture remains in protected broker storage"
	}
	result.Output = strings.TrimPrefix(string(output), "\ufeff")
	return result
}
