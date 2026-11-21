package middleware

import "testing"

func TestSSORole(t *testing.T) {
	cases := []struct {
		in    string
		admin bool
		ok    bool
	}{{"admin", true, true}, {"user", false, true}, {"", false, false}, {"Admin", false, false}, {"root", false, false}}
	for _, c := range cases {
		a, ok := ssoRole(c.in)
		if a != c.admin || ok != c.ok {
			t.Errorf("ssoRole(%q) = %v,%v want %v,%v", c.in, a, ok, c.admin, c.ok)
		}
	}
}

func TestSSODisplayName(t *testing.T) {
	if got := ssoDisplayName("ana.silva@example.com"); got != "ana.silva" {
		t.Errorf("got %q", got)
	}
	if got := ssoDisplayName("admin"); got != "admin" {
		t.Errorf("got %q", got)
	}
	if got := ssoDisplayName("@x"); got != "@x" {
		t.Errorf("got %q", got)
	}
}
