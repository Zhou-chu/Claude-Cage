package cage

import (
	"strings"
	"testing"

	"github.com/sylvinus/agent-vm/internal/guestprofile"
)

func TestForkDisplayDefaultsPreserveUpstreamService(t *testing.T) {
	profile, err := guestprofile.New(guestprofile.Options{DisplayWidth: 2560, DisplayHeight: 1440})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, geometry string
		profile        *guestprofile.Profile
	}{
		{"legacy", "1920x1080", nil},
		{"configured", "2560x1440", profile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.GuestProfile = tc.profile
			for name, script := range map[string]string{"setup": cfg.SetupScript(), "start": cfg.StartScript()} {
				var display string
				for _, line := range strings.Split(script, "\n") {
					if strings.HasPrefix(line, "ExecStart=/usr/local/bin/cage-log-run /usr/bin/Xtigervnc :77 ") {
						display = line
						break
					}
				}
				for _, want := range []string{"-geometry " + tc.geometry + " ", "-depth 16 ", "-rfbport 15900 ", "-localhost ", "-nolisten tcp ", "-SecurityTypes VncAuth ", "-PasswordFile ", "-AlwaysShared"} {
					if !strings.Contains(display, want) {
						t.Fatalf("%s display lacks %q: %s", name, want, display)
					}
				}
				if strings.Contains(display, "-rfbport -1") || strings.Contains(display, "-rfbunixpath") {
					t.Fatalf("%s restored obsolete socket-only display", name)
				}
			}
		})
	}
}
