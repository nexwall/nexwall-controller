/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

// Package support implements the tier-2 troubleshooting catalog: a fixed list
// of read-only diagnostic scripts taken from the knowledge-base articles, the
// validation of their parameters, the redaction of secrets from their output
// and the packaging of the results.
package support

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// ParamKind is the type of a catalog parameter.
type ParamKind string

const (
	KindIPv4    ParamKind = "ipv4"
	KindIPv6    ParamKind = "ipv6"
	KindIP      ParamKind = "ip"
	KindCIDR    ParamKind = "cidr"
	KindFQDN    ParamKind = "fqdn"
	KindHost    ParamKind = "host"
	KindPort    ParamKind = "port"
	KindEnum    ParamKind = "enum"
	KindInteger ParamKind = "int"
)

// Param describes one argument of a catalog entry.
type Param struct {
	Name     string            `json:"name"`
	Kind     ParamKind         `json:"kind"`
	Required bool              `json:"required"`
	Min      int               `json:"min,omitempty"`
	Max      int               `json:"max,omitempty"`
	Enum     []string          `json:"enum,omitempty"`
	Default  string            `json:"default,omitempty"`
	Label    map[string]string `json:"label"`
}

// ErrInvalidParam is returned, wrapped, for every rejected parameter value.
var ErrInvalidParam = errors.New("invalid parameter")

var fqdnLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func invalid(name, why string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidParam, name, why)
}

// Validate checks value against the parameter definition and returns the
// canonical form to pass to the script. An empty value yields the default
// (or the empty string for an optional parameter) and an error for a
// required one.
func (p Param) Validate(value string) (string, error) {
	if value == "" {
		value = p.Default
	}
	if value == "" {
		if p.Required {
			return "", invalid(p.Name, "required")
		}
		return "", nil
	}
	if len(value) > 253 {
		return "", invalid(p.Name, "too long")
	}
	for _, r := range value {
		if r <= 0x20 || r >= 0x7f {
			return "", invalid(p.Name, "unsupported character")
		}
	}
	switch p.Kind {
	case KindIPv4:
		return validateAddr(p.Name, value, true, false)
	case KindIPv6:
		return validateAddr(p.Name, value, false, true)
	case KindIP:
		return validateAddr(p.Name, value, true, true)
	case KindCIDR:
		pf, err := netip.ParsePrefix(value)
		if err != nil || pf.Addr().Zone() != "" {
			return "", invalid(p.Name, "not a network in CIDR notation")
		}
		return pf.Masked().String(), nil
	case KindFQDN:
		return validateFQDN(p.Name, value)
	case KindHost:
		if a, err := validateAddr(p.Name, value, true, true); err == nil {
			return a, nil
		}
		return validateFQDN(p.Name, value)
	case KindPort:
		return validateInt(p.Name, value, 1, 65535)
	case KindInteger:
		lo, hi := p.Min, p.Max
		if hi == 0 {
			hi = lo
		}
		return validateInt(p.Name, value, lo, hi)
	case KindEnum:
		for _, e := range p.Enum {
			if value == e {
				return value, nil
			}
		}
		return "", invalid(p.Name, "not one of the allowed values")
	}
	return "", invalid(p.Name, "unknown kind")
}

func validateAddr(name, value string, v4, v6 bool) (string, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || a.Zone() != "" {
		return "", invalid(name, "not an IP address")
	}
	a = a.Unmap()
	if a.Is4() && !v4 || a.Is6() && !v6 {
		return "", invalid(name, "wrong address family")
	}
	if a.IsUnspecified() || a.IsMulticast() {
		return "", invalid(name, "address not allowed")
	}
	return a.String(), nil
}

func validateFQDN(name, value string) (string, error) {
	v := strings.TrimSuffix(strings.ToLower(value), ".")
	if v == "" || len(v) > 253 {
		return "", invalid(name, "not a host name")
	}
	labels := strings.Split(v, ".")
	for _, l := range labels {
		if !fqdnLabel.MatchString(l) {
			return "", invalid(name, "not a host name")
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", invalid(name, "not a host name")
	}
	return v, nil
}

func validateInt(name, value string, lo, hi int) (string, error) {
	n, err := strconv.Atoi(value)
	if err != nil || strconv.Itoa(n) != value {
		return "", invalid(name, "not a number")
	}
	if n < lo || n > hi {
		return "", invalid(name, fmt.Sprintf("must be between %d and %d", lo, hi))
	}
	return value, nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
