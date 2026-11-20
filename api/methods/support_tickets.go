/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package methods

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// Tickets of the Support screen. They live in the Nexwall support service; the
// controller only vouches for the signed-in user and for the organization this
// controller belongs to (SUPPORT_ORG_ID, set when the tenant is provisioned).
// Nothing the browser sends can choose another organization: its own headers,
// cookies and unknown query parameters never reach the service.

const (
	supportMaxBody   = 11 << 20 // largest attachment plus multipart framing
	supportMinSecret = 32
)

// supportQueryKeys are the only query parameters forwarded to the service.
var supportQueryKeys = []string{"open", "status", "page", "per_page"}

var supportTransport = &http.Transport{
	Proxy:                 nil, // the support service is on the internal network
	MaxIdleConns:          10,
	IdleConnTimeout:       60 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
}

func allDigits(s string) bool {
	if s == "" || len(s) > 18 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func supportQuery(in url.Values) string {
	out := url.Values{}
	for _, k := range supportQueryKeys {
		if v := in.Get(k); v != "" && len(v) <= 32 {
			out.Set(k, v)
		}
	}
	return out.Encode()
}

// plainWriter hides gin's CloseNotify, which httputil.ReverseProxy would call
// although the request context already reports a closed client.
type plainWriter struct{ w gin.ResponseWriter }

func (p plainWriter) Header() http.Header         { return p.w.Header() }
func (p plainWriter) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p plainWriter) WriteHeader(code int)        { p.w.WriteHeader(code) }
func (p plainWriter) Flush()                      { p.w.Flush() }

// SupportTicketsProxy forwards one controller route to the support service. upstream is the
// service path; ":id" is replaced by the validated numeric route parameter.
func SupportTicketsProxy(upstream string) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := configuration.Config
		base, err := url.Parse(cfg.SupportServiceURL)
		if cfg.SupportServiceURL == "" || err != nil || base.Host == "" || len(cfg.SupportControllerToken) < supportMinSecret || cfg.SupportOrgID == "" {
			supportFail(c, http.StatusServiceUnavailable, "support is not available")
			return
		}
		org := strings.TrimSpace(cfg.SupportOrgID)
		path := upstream
		if strings.Contains(path, ":id") {
			id := c.Param("id")
			if !allDigits(id) {
				supportFail(c, http.StatusNotFound, "not found")
				return
			}
			path = strings.Replace(path, ":id", id, 1)
		}
		who, _ := jwt.ExtractClaims(c)["id"].(string)
		if who == "" {
			who = "controller-user"
		}
		who += "@" + cfg.FQDN
		query := supportQuery(c.Request.URL.Query())
		host := cfg.SupportServiceHost
		if host == "" {
			host = base.Host
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, supportMaxBody)

		rp := &httputil.ReverseProxy{
			Transport: supportTransport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				ct := pr.In.Header.Get("Content-Type")
				pr.Out.URL.Scheme, pr.Out.URL.Host = base.Scheme, base.Host
				pr.Out.URL.Path, pr.Out.URL.RawPath, pr.Out.URL.RawQuery = path, "", query
				pr.Out.Host = host
				pr.Out.Header = http.Header{}
				if ct != "" {
					pr.Out.Header.Set("Content-Type", ct)
				}
				pr.Out.Header.Set("X-Support-Portal-Token", cfg.SupportControllerToken)
				pr.Out.Header.Set("X-Portal-Org", org)
				pr.Out.Header.Set("X-Portal-User", who)
			},
			ModifyResponse: func(r *http.Response) error {
				r.Header.Del("Set-Cookie")
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte(`{"code":502,"message":"support service unreachable","data":null}`))
			},
		}
		rp.ServeHTTP(plainWriter{c.Writer}, c.Request)
	}
}
