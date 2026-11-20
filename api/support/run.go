/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package support

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ExecResult is what a unit returns for one command.
type ExecResult struct {
	Code   int
	Stdout string
	Stderr string
}

// Executor runs a command on a unit. The implementation talks to the unit
// through the controller; tests use a fake.
type Executor interface {
	Exec(ctx context.Context, unitID string, cmd Command, timeout time.Duration) (ExecResult, error)
}

// AuditRecord is written for every attempt, accepted or not.
type AuditRecord struct {
	Time     time.Time
	Actor    string
	TicketID string
	UnitID   string
	EntryID  string
	Params   map[string]string
	Outcome  string // "ok", "rejected", "error"
	ExitCode int
	Bytes    int
	Redacted int
	Detail   string
}

// AuditSink receives audit records.
type AuditSink interface {
	Record(AuditRecord)
}

// Request asks for one catalog entry to run on one unit.
type Request struct {
	Actor    string
	TicketID string
	UnitID   string
	EntryID  string
	Params   map[string]string
}

// Result is the redacted outcome of a run.
type Result struct {
	EntryID   string            `json:"entry_id"`
	Params    map[string]string `json:"params"`
	StartedAt time.Time         `json:"started_at"`
	Duration  time.Duration     `json:"duration_ns"`
	ExitCode  int               `json:"exit_code"`
	Output    string            `json:"output"`
	Truncated bool              `json:"truncated"`
	Redacted  int               `json:"redacted"`
	SHA256    string            `json:"sha256"`
}

// Service runs catalog entries.
type Service struct {
	Catalog *Catalog
	Exec    Executor
	Audit   AuditSink
	Now     func() time.Time
}

// ErrNoUnit is returned when a request does not name a unit.
var ErrNoUnit = errors.New("unit is required")

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) audit(r AuditRecord) {
	if s.Audit != nil {
		s.Audit.Record(r)
	}
}

// Run validates the request, executes the entry and returns the redacted
// result. The cleanup command of the entry runs even when the run failed.
func (s *Service) Run(ctx context.Context, req Request) (*Result, error) {
	rec := AuditRecord{Time: s.now(), Actor: req.Actor, TicketID: req.TicketID, UnitID: req.UnitID, EntryID: req.EntryID, Params: req.Params}
	if req.UnitID == "" {
		rec.Outcome, rec.Detail = "rejected", ErrNoUnit.Error()
		s.audit(rec)
		return nil, ErrNoUnit
	}
	entry, cmd, err := s.Catalog.Resolve(req.EntryID, req.Params)
	if err != nil {
		rec.Outcome, rec.Detail = "rejected", err.Error()
		s.audit(rec)
		return nil, err
	}
	timeout := time.Duration(entry.TimeoutSec) * time.Second
	started := s.now()
	res, execErr := s.Exec.Exec(ctx, req.UnitID, cmd, timeout)
	if entry.Cleanup != "" {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		_, _ = s.Exec.Exec(cctx, req.UnitID, Command{Program: "/bin/sh", Args: []string{"-c", entry.Cleanup}}, 15*time.Second)
		cancel()
	}
	if execErr != nil {
		rec.Outcome, rec.Detail = "error", execErr.Error()
		s.audit(rec)
		return nil, fmt.Errorf("run %s: %w", entry.ID, execErr)
	}
	text := res.Stdout
	if strings.TrimSpace(res.Stderr) != "" {
		text += res.Stderr
	}
	text = strings.ToValidUTF8(text, "?")
	truncated := false
	if len(text) > entry.MaxOutput {
		text = text[:entry.MaxOutput]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
		text += "\n[output truncated]\n"
		truncated = true
	}
	text, n := Redact(text)
	sum := sha256.Sum256([]byte(text))
	out := &Result{
		EntryID: entry.ID, Params: req.Params, StartedAt: started,
		Duration: s.now().Sub(started), ExitCode: res.Code, Output: text,
		Truncated: truncated, Redacted: n, SHA256: hex.EncodeToString(sum[:]),
	}
	rec.Outcome, rec.ExitCode, rec.Bytes, rec.Redacted = "ok", res.Code, len(text), n
	s.audit(rec)
	return out, nil
}

// IsRequestError reports whether err comes from the request itself (unknown
// entry, rejected parameter, missing unit) and not from the firewall.
func IsRequestError(err error) bool {
	return errors.Is(err, ErrInvalidParam) || errors.Is(err, ErrUnknownEntry) || errors.Is(err, ErrNoUnit)
}
