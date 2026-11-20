/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package support

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var injection = []string{
	"1.1.1.1; reboot", "$(id)", "`id`", "a b", "a\nb", "a\x00b", "-oProxyCommand=id", "--help", "-1",
	"host|cat /etc/passwd", "host&&id", "host>/tmp/x", "../../etc/passwd", "é.example.com", "a'b", "a\"b",
	"*", "?", "{a,b}", "[a]", "a\\b", "http://x", "1.2.3.4/24x", "fe80::1%eth0", "0.0.0.0", "224.0.0.1", "::",
}

func TestParamValidate_RejectsInjection(t *testing.T) {
	kinds := []Param{
		{Name: "v", Kind: KindIPv4}, {Name: "v", Kind: KindIPv6}, {Name: "v", Kind: KindIP}, {Name: "v", Kind: KindCIDR},
		{Name: "v", Kind: KindFQDN}, {Name: "v", Kind: KindHost}, {Name: "v", Kind: KindPort},
		{Name: "v", Kind: KindInteger, Min: 1, Max: 10}, {Name: "v", Kind: KindEnum, Enum: []string{"tcp", "udp"}},
	}
	for _, p := range kinds {
		for _, bad := range injection {
			_, err := p.Validate(bad)
			assert.ErrorIs(t, err, ErrInvalidParam, "kind %s accepted %q", p.Kind, bad)
		}
	}
}

func TestParamValidate_Accepts(t *testing.T) {
	cases := []struct {
		p    Param
		in   string
		want string
	}{
		{Param{Name: "a", Kind: KindIPv4}, "192.168.1.10", "192.168.1.10"},
		{Param{Name: "a", Kind: KindIPv6}, "2001:db8::1", "2001:db8::1"},
		{Param{Name: "a", Kind: KindIP}, "::ffff:10.0.0.1", "10.0.0.1"},
		{Param{Name: "a", Kind: KindCIDR}, "10.1.2.3/24", "10.1.2.0/24"},
		{Param{Name: "a", Kind: KindFQDN}, "Nexwall.com.BR.", "nexwall.com.br"},
		{Param{Name: "a", Kind: KindHost}, "8.8.8.8", "8.8.8.8"},
		{Param{Name: "a", Kind: KindHost}, "dns.google", "dns.google"},
		{Param{Name: "a", Kind: KindPort}, "443", "443"},
		{Param{Name: "a", Kind: KindInteger, Min: 5, Max: 60}, "20", "20"},
		{Param{Name: "a", Kind: KindEnum, Enum: []string{"tcp", "udp"}}, "udp", "udp"},
		{Param{Name: "a", Kind: KindInteger, Min: 1, Max: 9, Default: "3"}, "", "3"},
		{Param{Name: "a", Kind: KindIP}, "", ""},
	}
	for _, c := range cases {
		got, err := c.p.Validate(c.in)
		require.NoError(t, err, "%s %q", c.p.Kind, c.in)
		assert.Equal(t, c.want, got)
	}
}

func TestParamValidate_Bounds(t *testing.T) {
	p := Param{Name: "n", Kind: KindInteger, Min: 5, Max: 60}
	for _, bad := range []string{"4", "61", "05", "+5", "5.0", "abc", "-5", "99999999999999999999"} {
		_, err := p.Validate(bad)
		assert.ErrorIs(t, err, ErrInvalidParam, bad)
	}
	for _, bad := range []string{"0", "65536", "080", "-1"} {
		_, err := (Param{Name: "p", Kind: KindPort}).Validate(bad)
		assert.ErrorIs(t, err, ErrInvalidParam, bad)
	}
	_, err := (Param{Name: "h", Kind: KindHost, Required: true}).Validate("")
	assert.ErrorIs(t, err, ErrInvalidParam)
	_, err = (Param{Name: "h", Kind: KindFQDN}).Validate(strings.Repeat("a", 64) + ".com")
	assert.ErrorIs(t, err, ErrInvalidParam)
}

func FuzzParamValidate(f *testing.F) {
	for _, s := range injection {
		f.Add(s)
	}
	f.Add("8.8.8.8")
	f.Add("example.com")
	safe := regexp.MustCompile(`^[A-Za-z0-9:][A-Za-z0-9.:/-]*$`)
	kinds := []Param{
		{Name: "v", Kind: KindIP}, {Name: "v", Kind: KindCIDR}, {Name: "v", Kind: KindHost}, {Name: "v", Kind: KindPort},
		{Name: "v", Kind: KindInteger, Min: 1, Max: 100},
	}
	f.Fuzz(func(t *testing.T, in string) {
		for _, p := range kinds {
			out, err := p.Validate(in)
			if err != nil || out == "" {
				continue
			}
			if !safe.MatchString(out) {
				t.Fatalf("kind %s: %q produced unsafe value %q", p.Kind, in, out)
			}
		}
	})
}

func TestDefaultCatalog(t *testing.T) {
	c, err := Default()
	require.NoError(t, err)
	list := c.List()
	require.NotEmpty(t, list)
	ids := map[string]bool{}
	for _, e := range list {
		assert.False(t, ids[e.ID], "duplicate %s", e.ID)
		ids[e.ID] = true
		_, err := c.Get(e.ID)
		assert.NoError(t, err)
	}
	for _, want := range []string{"health-check", "ping", "port-test", "packet-1", "packet-2", "packet-3", "support-package", "dpi-unknown"} {
		assert.True(t, ids[want], want)
	}
	_, err = c.Get("rm-rf")
	assert.ErrorIs(t, err, ErrUnknownEntry)
}

var mutating = regexp.MustCompile(`(?m)(^|[;&|(]\s*)(reboot|poweroff|halt|opkg|sysupgrade|passwd|kill|killall|iptables|ip6tables|ifup|ifdown|logger)\b|uci\s+(set|add|delete|rename|revert|commit|import)|nft\s+(add|delete|flush|insert|replace)|/etc/init\.d/\S+\s+(start|stop|restart|reload|enable|disable)\b|ubus\s+call\s+\S+\s+(set|restart|reload|stop|start|reboot|delete|add|remove)\b|\bwget\b|\bscp\b|\bssh\b`)

func TestCatalogScriptsAreReadOnly(t *testing.T) {
	c, err := Default()
	require.NoError(t, err)
	quoted := regexp.MustCompile(`'[^']*'`)
	for _, e := range c.List() {
		assert.False(t, mutating.MatchString(quoted.ReplaceAllString(e.Script, "''")), "%s contains a mutating command", e.ID)
		if e.Class == R0 {
			assert.False(t, strings.Contains(e.Script, "rm "), "%s: R0 must not remove files", e.ID)
			assert.False(t, strings.Contains(e.Script, "mkdir"), "%s: R0 must not create files", e.ID)
			for _, line := range strings.Split(e.Script, "\n") {
				stripped := strings.NewReplacer("2>/dev/null", "", "2>&1", "", "&>/dev/null", "").Replace(line)
				assert.NotContains(t, stripped, ">", "%s: R0 must not redirect output to files: %s", e.ID, line)
			}
		}
	}
}

func TestCatalogScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	c, err := Default()
	require.NoError(t, err)
	for _, e := range c.List() {
		out, err := exec.Command(sh, "-n", "-c", e.Script).CombinedOutput()
		assert.NoError(t, err, "%s: %s", e.ID, out)
	}
}

func TestResolve(t *testing.T) {
	c, err := Default()
	require.NoError(t, err)

	e, cmd, err := c.Resolve("ping", map[string]string{"host": "Dns.Google"})
	require.NoError(t, err)
	assert.Equal(t, "ping", e.ID)
	assert.Equal(t, "/bin/sh", cmd.Program)
	assert.Equal(t, []string{"-c", e.Script, "nexwall-support-ping", "dns.google", "3"}, cmd.Args)

	_, _, err = c.Resolve("ping", map[string]string{})
	assert.ErrorIs(t, err, ErrInvalidParam)
	_, _, err = c.Resolve("ping", map[string]string{"host": "8.8.8.8", "extra": "x"})
	assert.ErrorIs(t, err, ErrInvalidParam)
	_, _, err = c.Resolve("ping", map[string]string{"host": "8.8.8.8; id"})
	assert.ErrorIs(t, err, ErrInvalidParam)
	_, _, err = c.Resolve("nope", nil)
	assert.ErrorIs(t, err, ErrUnknownEntry)
}

func TestParseRejectsBadCatalogs(t *testing.T) {
	good := `[{"id":"x","group":"g","class":"R0","kba":[1],"title":{"en":"a","es":"a","pt-BR":"a"},"description":{"en":"a","es":"a","pt-BR":"a"},"params":[],"script":"true","timeout_sec":5,"max_output":2048}]`
	_, err := Parse([]byte(good))
	require.NoError(t, err)
	bad := map[string]string{
		"class":    strings.Replace(good, `"R0"`, `"R2"`, 1),
		"timeout":  strings.Replace(good, `"timeout_sec":5`, `"timeout_sec":0`, 1),
		"output":   strings.Replace(good, `"max_output":2048`, `"max_output":1`, 1),
		"language": strings.Replace(good, `"pt-BR":"a"},"description"`, `"pt-BR":""},"description"`, 1),
		"kba":      strings.Replace(good, `"kba":[1]`, `"kba":[]`, 1),
		"script":   strings.Replace(good, `"script":"true"`, `"script":""`, 1),
		"json":     `[`,
		"dup":      "[" + good[1:len(good)-1] + "," + good[1:len(good)-1] + "]",
	}
	for name, doc := range bad {
		_, err := Parse([]byte(doc))
		assert.Error(t, err, name)
	}
}

// The packet scripts build a filter with validated tokens only. Run them for
// real with stub tools to check the argument vector.
func TestPacketScriptsBuildFilter(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	for _, tool := range []string{"drppkt", "fwtrace"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, tool), []byte("#!/bin/sh\necho \"$0 $*\"\n"), 0o755))
	}
	c, err := Default()
	require.NoError(t, err)
	run := func(id string, params map[string]string) string {
		_, cmd, err := c.Resolve(id, params)
		require.NoError(t, err)
		cm := exec.Command(sh, cmd.Args...)
		cm.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
		out, _ := cm.CombinedOutput()
		return string(out)
	}
	out := run("packet-1", map[string]string{"src": "192.168.1.102", "dst": "8.8.8.8", "port": "443", "proto": "tcp", "seconds": "30"})
	assert.Contains(t, out, "drppkt -i 30 src host 192.168.1.102 and dst host 8.8.8.8 and dst port 443 and proto tcp")
	out = run("packet-2", map[string]string{"dst": "10.0.0.5"})
	assert.Contains(t, out, "fwtrace -i 20 dst host 10.0.0.5")
	out = run("packet-3", map[string]string{"src": "10.0.0.7", "seconds": "5"})
	assert.Contains(t, out, "fwtrace --both -i 5 src host 10.0.0.7")
	out = run("packet-1", map[string]string{})
	assert.Contains(t, out, "Enter at least a source or a destination.")
	assert.NotContains(t, out, "drppkt -i")
}

func TestRedact(t *testing.T) {
	sentinels := []string{
		"S3NT1NEL-PASS", "S3NT1NEL-PSK", "S3NT1NEL-TOKEN", "S3NT1NEL-APIKEY", "S3NT1NEL-LIC", "S3NT1NEL-URL", "S3NT1NEL-BEARER",
		"S3NT1NEL-PEM", "S3NT1NEL-UCI", "S3NT1NEL-JSON",
	}
	input := strings.Join([]string{
		"password: S3NT1NEL-PASS",
		"option psk 'S3NT1NEL-PSK'",
		"token=S3NT1NEL-TOKEN",
		"api_key = S3NT1NEL-APIKEY",
		"license_key: S3NT1NEL-LIC",
		"fetch https://admin:S3NT1NEL-URL@example.com/path",
		"Authorization: Bearer S3NT1NEL-BEARERxxxxxxxx",
		"-----BEGIN PRIVATE KEY-----\nS3NT1NEL-PEM\n-----END PRIVATE KEY-----",
		"config wireguard\n\toption private_key 'S3NT1NEL-UCI'",
		`{"secret": "S3NT1NEL-JSON"}`,
		"PrivateKey = " + strings.Repeat("A", 43) + "=",
		"healthy line: eth0 UP 192.168.1.1/24",
	}, "\n")
	out, n := Redact(input)
	for _, s := range sentinels {
		assert.NotContains(t, out, s)
	}
	assert.NotContains(t, out, strings.Repeat("A", 43))
	assert.GreaterOrEqual(t, n, len(sentinels))
	assert.Contains(t, out, "healthy line: eth0 UP 192.168.1.1/24")
}

func TestRedactLeavesNormalOutput(t *testing.T) {
	in := "== DISK\nFilesystem Size Used\n/dev/sda1 20G 6G\n== CONTROLLER\n \"status\": \"connected\"\n"
	out, n := Redact(in)
	assert.Equal(t, in, out)
	assert.Zero(t, n)
}

type fakeExec struct {
	calls   []Command
	results map[string]ExecResult
	err     error
}

func (f *fakeExec) Exec(_ context.Context, _ string, cmd Command, _ time.Duration) (ExecResult, error) {
	f.calls = append(f.calls, cmd)
	if f.err != nil {
		return ExecResult{}, f.err
	}
	if len(cmd.Args) >= 3 {
		if r, ok := f.results[cmd.Args[2]]; ok {
			return r, nil
		}
	}
	return ExecResult{Stdout: "ok\n"}, nil
}

type sink struct{ recs []AuditRecord }

func (s *sink) Record(r AuditRecord) { s.recs = append(s.recs, r) }

func newService(t *testing.T, fx *fakeExec) (*Service, *sink) {
	c, err := Default()
	require.NoError(t, err)
	s := &sink{}
	return &Service{Catalog: c, Exec: fx, Audit: s, Now: func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) }}, s
}

func TestRunRedactsAndAudits(t *testing.T) {
	fx := &fakeExec{results: map[string]ExecResult{"nexwall-support-health-check": {Stdout: "disk ok\npassword: S3NT1NEL-RUN\n", Stderr: "warn\n"}}}
	svc, aud := newService(t, fx)
	res, err := svc.Run(context.Background(), Request{Actor: "u1", TicketID: "T-1", UnitID: "unit-9", EntryID: "health-check"})
	require.NoError(t, err)
	assert.NotContains(t, res.Output, "S3NT1NEL-RUN")
	assert.Contains(t, res.Output, "disk ok")
	assert.Contains(t, res.Output, "warn")
	assert.Equal(t, 1, res.Redacted)
	sum := sha256.Sum256([]byte(res.Output))
	assert.Equal(t, hex.EncodeToString(sum[:]), res.SHA256)
	require.Len(t, aud.recs, 1)
	assert.Equal(t, "ok", aud.recs[0].Outcome)
	assert.Equal(t, "T-1", aud.recs[0].TicketID)
	assert.Equal(t, "u1", aud.recs[0].Actor)
}

func TestRunRejectsAndAudits(t *testing.T) {
	fx := &fakeExec{}
	svc, aud := newService(t, fx)
	_, err := svc.Run(context.Background(), Request{UnitID: "u", EntryID: "ping", Params: map[string]string{"host": "1.1.1.1; reboot"}})
	assert.ErrorIs(t, err, ErrInvalidParam)
	_, err = svc.Run(context.Background(), Request{UnitID: "u", EntryID: "reboot"})
	assert.ErrorIs(t, err, ErrUnknownEntry)
	_, err = svc.Run(context.Background(), Request{EntryID: "health-check"})
	assert.ErrorIs(t, err, ErrNoUnit)
	assert.Empty(t, fx.calls, "nothing reaches the unit when the request is rejected")
	require.Len(t, aud.recs, 3)
	for _, r := range aud.recs {
		assert.Equal(t, "rejected", r.Outcome)
	}
}

func TestRunTruncates(t *testing.T) {
	big := strings.Repeat("x", 200000)
	fx := &fakeExec{results: map[string]ExecResult{"nexwall-support-links-routes": {Stdout: big}}}
	svc, _ := newService(t, fx)
	res, err := svc.Run(context.Background(), Request{UnitID: "u", EntryID: "links-routes"})
	require.NoError(t, err)
	assert.True(t, res.Truncated)
	assert.LessOrEqual(t, len(res.Output), 65536+64)
	assert.True(t, strings.HasSuffix(res.Output, "[output truncated]\n"))
}

func TestRunCleanupRunsEvenOnError(t *testing.T) {
	fx := &fakeExec{err: errors.New("unit unreachable")}
	svc, aud := newService(t, fx)
	_, err := svc.Run(context.Background(), Request{UnitID: "u", EntryID: "packet-2", Params: map[string]string{"dst": "10.0.0.1"}})
	require.Error(t, err)
	require.Len(t, fx.calls, 2)
	assert.Equal(t, []string{"-c", "fwtrace --cleanup"}, fx.calls[1].Args)
	require.Len(t, aud.recs, 1)
	assert.Equal(t, "error", aud.recs[0].Outcome)
}

func TestWriteBundle(t *testing.T) {
	at := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	results := []*Result{
		{EntryID: "health-check", Output: "disk ok\n", Redacted: 1, SHA256: "x"},
		{EntryID: "ping", Params: map[string]string{"host": "8.8.8.8"}, Output: "3 packets\n", ExitCode: 0},
	}
	var buf bytes.Buffer
	require.NoError(t, WriteBundle(&buf, "T-1", "unit-9", "u1", at, results))
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		require.NoError(t, err)
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = b
	}
	require.Contains(t, files, "manifest.json")
	var m Manifest
	require.NoError(t, json.Unmarshal(files["manifest.json"], &m))
	assert.Equal(t, "T-1", m.TicketID)
	assert.Equal(t, "unit-9", m.UnitID)
	assert.Equal(t, 1, m.Redacted)
	require.Len(t, m.Files, 2)
	for _, mf := range m.Files {
		body, ok := files[mf.Name]
		require.True(t, ok, mf.Name)
		sum := sha256.Sum256(body)
		assert.Equal(t, hex.EncodeToString(sum[:]), mf.SHA256, mf.Name)
		assert.Equal(t, len(body), mf.Bytes)
	}
}

func TestWordParam(t *testing.T) {
	p := Param{Name: "word", Kind: KindWord, Required: true}
	for _, ok := range []string{"dnsmasq", "nexwall-fastpath", "eth0.10", "a:b"} {
		if _, err := p.Validate(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-e", "a b", "a;b", "$(id)", "a'b", "a\nb", strings.Repeat("a", 65)} {
		if _, err := p.Validate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLintDistinguishesEnabledQuery(t *testing.T) {
	assert.False(t, mutating.MatchString(`/etc/init.d/"$1" enabled`))
	assert.True(t, mutating.MatchString(`/etc/init.d/"$1" enable`))
	assert.True(t, mutating.MatchString(`/etc/init.d/dropbear restart`))
}

func TestUbusExecutor(t *testing.T) {
	var got struct {
		path, auth string
		call       map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path, got.auth = r.URL.Path, r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got.call)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"code":200,"data":{"code":3,"stdout":"out","stderr":"err"},"message":"ok"}`))
	}))
	defer srv.Close()
	u := &UbusExecutor{BaseURL: srv.URL, Token: func(context.Context, string) (string, error) { return "tok", nil }}
	res, err := u.Exec(context.Background(), "unit-1", Command{Program: "/bin/ping", Args: []string{"-c", "1", "10.0.0.1"}}, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, ExecResult{Code: 3, Stdout: "out", Stderr: "err"}, res)
	assert.Equal(t, "/unit-1/api/ubus/call", got.path)
	assert.Equal(t, "Bearer tok", got.auth)
	assert.Equal(t, "file", got.call["path"])
	assert.Equal(t, "exec", got.call["method"])
	p := got.call["payload"].(map[string]any)
	assert.Equal(t, "/bin/ping", p["command"])
	assert.Equal(t, []any{"-c", "1", "10.0.0.1"}, p["params"])
}

func TestUbusExecutorRejectsAndFails(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/slow/api/ubus/call":
			time.Sleep(300 * time.Millisecond)
		case "/err/api/ubus/call":
			w.WriteHeader(500)
		case "/junk/api/ubus/call":
			w.Write([]byte("nope"))
		case "/big/api/ubus/call":
			w.Write(bytes.Repeat([]byte("a"), maxUbusReply+10))
		}
	}))
	defer srv.Close()
	u := &UbusExecutor{BaseURL: srv.URL, Token: func(context.Context, string) (string, error) { return "tok", nil }}
	cmd := Command{Program: "/bin/true"}
	for _, bad := range []string{"", "../x", "a/b", "a b", "a?x=1", "a#b", "..", strings.Repeat("a", 65)} {
		_, err := u.Exec(context.Background(), bad, cmd, time.Second)
		assert.ErrorIs(t, err, ErrBadUnit, bad)
	}
	assert.Equal(t, int32(0), calls.Load(), "a bad unit id must never reach the proxy")
	_, err := u.Exec(context.Background(), "slow", cmd, 50*time.Millisecond)
	assert.ErrorContains(t, err, "timed out")
	for _, id := range []string{"err", "junk", "big"} {
		_, err := u.Exec(context.Background(), id, cmd, time.Second)
		assert.Error(t, err, id)
	}
	_, err = u.Exec(context.Background(), "x", Command{}, time.Second)
	assert.Error(t, err)
	noTok := &UbusExecutor{BaseURL: srv.URL, Token: func(context.Context, string) (string, error) { return "", errors.New("secret detail") }}
	_, err = noTok.Exec(context.Background(), "x", cmd, time.Second)
	assert.EqualError(t, err, "cannot get a session on the unit")
}

func TestIsRequestError(t *testing.T) {
	cat, err := Default()
	require.NoError(t, err)
	svc := &Service{Catalog: cat, Exec: nil}
	_, err = svc.Run(context.Background(), Request{UnitID: "u", EntryID: "nope"})
	assert.True(t, IsRequestError(err))
	_, err = svc.Run(context.Background(), Request{EntryID: "ping"})
	assert.True(t, IsRequestError(err))
	_, err = svc.Run(context.Background(), Request{UnitID: "u", EntryID: "ping", Params: map[string]string{"host": "1.1.1.1; reboot"}})
	assert.True(t, IsRequestError(err))
	assert.False(t, IsRequestError(errors.New("unit is not reachable")))
}
