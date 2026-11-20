/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package methods

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const supportCtlSecret = "0123456789abcdef0123456789abcdef-ctl"

type supportSeen struct {
	method, path, query, host string
	hdr                       http.Header
	body                      string
}

func supportTicketsRig(t *testing.T) (*gin.Engine, *supportSeen) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	got := &supportSeen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = supportSeen{r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Clone(), string(b)}
		http.SetCookie(w, &http.Cookie{Name: "leak", Value: "1"})
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	old := configuration.Config
	t.Cleanup(func() { configuration.Config = old })
	configuration.Config.SupportServiceURL = srv.URL
	configuration.Config.SupportServiceHost = "support-internal.nexwall.lan"
	configuration.Config.SupportControllerToken = supportCtlSecret
	configuration.Config.SupportOrgID = "orgP"
	configuration.Config.FQDN = "acme.painel.example"

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "admin"}) })
	r.Any("/support/tickets", SupportTicketsProxy("/api/v1/tickets"))
	r.Any("/support/tickets/:id/messages", SupportTicketsProxy("/api/v1/tickets/:id/messages"))
	return r, got
}

func supportCall(r http.Handler, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestSupportTicketsProxyIdentity(t *testing.T) {
	r, got := supportTicketsRig(t)
	rec := supportCall(r, "POST", "/support/tickets?org=other&foo=bar&page=2&open=true", `{"subject":"s","body":"b"}`, map[string]string{
		"Content-Type":           "application/json",
		"Authorization":          "Bearer browser-token",
		"Cookie":                 "session=abc",
		"X-Portal-Org":           "attacker-org",
		"X-Portal-User":          "attacker",
		"X-Portal-Staff":         "1",
		"X-Support-Portal-Token": "forged",
	})
	require.Equal(t, 201, rec.Code)
	assert.Equal(t, "/api/v1/tickets", got.path)
	assert.Equal(t, "support-internal.nexwall.lan", got.host)
	assert.Equal(t, "open=true&page=2", got.query)
	assert.Equal(t, supportCtlSecret, got.hdr.Get("X-Support-Portal-Token"))
	assert.Equal(t, "orgP", got.hdr.Get("X-Portal-Org"))
	assert.Equal(t, "admin@acme.painel.example", got.hdr.Get("X-Portal-User"))
	for _, k := range []string{"Authorization", "Cookie", "X-Portal-Staff"} {
		assert.Empty(t, got.hdr.Get(k), k)
	}
	assert.Empty(t, rec.Header().Get("Set-Cookie"))
}

func TestSupportTicketsProxyGuards(t *testing.T) {
	r, _ := supportTicketsRig(t)
	for _, bad := range []string{"abc", "1;2", "1%2F2", "99999999999999999999"} {
		assert.Equal(t, 404, supportCall(r, "GET", "/support/tickets/"+bad+"/messages", "", nil).Code, bad)
	}
	// each missing setting closes the route
	for name, set := range map[string]func(){
		"no url":   func() { configuration.Config.SupportServiceURL = "" },
		"no token": func() { configuration.Config.SupportControllerToken = "" },
		"short":    func() { configuration.Config.SupportControllerToken = "short" },
		"no org":   func() { configuration.Config.SupportOrgID = "" },
	} {
		r, _ := supportTicketsRig(t)
		set()
		assert.Equal(t, 503, supportCall(r, "GET", "/support/tickets", "", nil).Code, name)
	}
}

func TestSupportTicketsProxyUnreachable(t *testing.T) {
	r, _ := supportTicketsRig(t)
	configuration.Config.SupportServiceURL = "http://127.0.0.1:1"
	rec := supportCall(r, "GET", "/support/tickets", "", nil)
	assert.Equal(t, 502, rec.Code)
	assert.NotContains(t, rec.Body.String(), "127.0.0.1")
}
