/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package support

import (
	"regexp"
	"strings"
)

// Redacted replaces every removed secret.
const Redacted = "[redacted]"

var (
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	// key: value, key = value, key='value', option key 'value', "key": "value"
	secretKV = regexp.MustCompile(`(?i)(["']?[A-Za-z0-9_.-]*(?:pass(?:word|wd|phrase)?|secret|psk|pre[_-]?shared[_-]?key|private[_-]?key|token|api[_-]?key|apikey|license[_-]?key|credential|authorization)[A-Za-z0-9_.-]*["']?\s*(?:[:=]|\s)\s*)(?:"[^"\n]*"|'[^'\n]*'|Bearer\s+\S+|[^\s,;]+)`)
	bearer   = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	urlCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)
	// WireGuard keys are 44 base64 characters ending in "=".
	wgKey = regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`)
)

// Redact removes secrets from text and reports how many replacements it made.
// It is applied to everything that leaves the firewall: command output and
// bundle contents.
func Redact(text string) (string, int) {
	count := 0
	text = pemBlock.ReplaceAllStringFunc(text, func(string) string { count++; return Redacted })
	text = urlCreds.ReplaceAllStringFunc(text, func(m string) string {
		count++
		i := strings.Index(m, "://")
		return m[:i+3] + Redacted + "@"
	})
	text = bearer.ReplaceAllStringFunc(text, func(m string) string {
		count++
		return strings.Fields(m)[0] + " " + Redacted
	})
	text = secretKV.ReplaceAllStringFunc(text, func(m string) string {
		sub := secretKV.FindStringSubmatch(m)
		count++
		return sub[1] + Redacted
	})
	text = wgKey.ReplaceAllStringFunc(text, func(string) string { count++; return Redacted })
	return text, count
}
