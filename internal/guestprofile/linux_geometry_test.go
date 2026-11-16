package guestprofile

import "testing"

func TestLinuxDisplayGeometryTemplateDefaults(t *testing.T) {
	p, err := New(Options{DisplayWidth: 2560, DisplayHeight: 1440})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, input, want string }{
		{"upstream", "Xtigervnc :77 -geometry 2880x1800 -depth 24", "Xtigervnc :77 -geometry 2560x1440 -depth 24"},
		{"fork", "Xtigervnc :77 -geometry 1920x1080 -depth 16", "Xtigervnc :77 -geometry 2560x1440 -depth 16"},
		{"unrelated", "xrandr --fb 1920x1080", "xrandr --fb 1920x1080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Linux(tc.input); got != tc.want {
				t.Fatalf("rendered %q, want %q", got, tc.want)
			}
			if got := p.Linux(tc.want); got != tc.want {
				t.Fatalf("second render changed geometry: %q", got)
			}
			var legacy *Profile
			if got := legacy.Linux(tc.input); got != tc.input {
				t.Fatalf("nil profile changed legacy template: %q", got)
			}
		})
	}
}
