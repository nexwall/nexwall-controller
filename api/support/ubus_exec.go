/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// maxUbusReply caps what the executor reads back from a unit; the catalog entry
// trims the text further.
const maxUbusReply = 4 << 20

// unitIDRe matches the identifiers the controller gives to units. It keeps a
// unit id from changing the path of the proxied request.
var unitIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// ErrBadUnit is returned for a unit id that is not a plain identifier.
var ErrBadUnit = errors.New("invalid unit id")

// UbusExecutor runs commands on a unit with the ubus call file.exec, through the
// controller's reverse proxy (the same path the web interface uses). It never
// builds a shell line itself: the program and its arguments go as separate JSON
// values, and the catalog has already validated every parameter.
type UbusExecutor struct {
	// BaseURL is the proxy address, for example "http://proxy:8080". The unit id is
	// added as the first path segment.
	BaseURL string
	// Token returns a session token of the unit.
	Token func(ctx context.Context, unitID string) (string, error)
	// Client is optional; the default has no timeout, the call context decides.
	Client *http.Client
}

type ubusCall struct {
	Path    string         `json:"path"`
	Method  string         `json:"method"`
	Payload map[string]any `json:"payload"`
}

type ubusExecReply struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	} `json:"data"`
}

// Exec implements Executor.
func (u *UbusExecutor) Exec(ctx context.Context, unitID string, cmd Command, timeout time.Duration) (ExecResult, error) {
	if !unitIDRe.MatchString(unitID) {
		return ExecResult{}, ErrBadUnit
	}
	if cmd.Program == "" {
		return ExecResult{}, errors.New("empty command")
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	token, err := u.Token(ctx, unitID)
	if err != nil || token == "" {
		return ExecResult{}, errors.New("cannot get a session on the unit")
	}
	args := cmd.Args
	if args == nil {
		args = []string{}
	}
	body, err := json.Marshal(ubusCall{Path: "file", Method: "exec", Payload: map[string]any{
		"command": cmd.Program, "params": args,
	}})
	if err != nil {
		return ExecResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.BaseURL+"/"+unitID+"/api/ubus/call", bytes.NewReader(body))
	if err != nil {
		return ExecResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := u.Client
	if client == nil {
		client = &http.Client{}
	}
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ExecResult{}, fmt.Errorf("command timed out after %s", timeout)
		}
		return ExecResult{}, errors.New("unit is not reachable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxUbusReply+1))
	if err != nil {
		return ExecResult{}, errors.New("reading the unit answer failed")
	}
	if len(raw) > maxUbusReply {
		return ExecResult{}, errors.New("unit answer is too large")
	}
	if res.StatusCode != http.StatusOK {
		return ExecResult{}, fmt.Errorf("unit answered HTTP %d", res.StatusCode)
	}
	var out ubusExecReply
	if err := json.Unmarshal(raw, &out); err != nil {
		return ExecResult{}, errors.New("unit answer is not valid")
	}
	return ExecResult{Code: out.Data.Code, Stdout: out.Data.Stdout, Stderr: out.Data.Stderr}, nil
}
