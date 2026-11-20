/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package support

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

//go:embed catalog.json
var catalogJSON []byte

// Class is the risk class of a catalog entry.
//
//	R0: reads state only.
//	R1: reads state and creates temporary diagnostic artefacts that the entry
//	    removes before it ends (probe rules, files in /tmp).
type Class string

const (
	R0 Class = "R0"
	R1 Class = "R1"
)

// Entry is one diagnostic script of the catalog. The script text is fixed;
// the only variable parts are its validated positional arguments.
type Entry struct {
	ID          string            `json:"id"`
	Group       string            `json:"group"`
	Class       Class             `json:"class"`
	KBA         []int             `json:"kba"`
	Title       map[string]string `json:"title"`
	Description map[string]string `json:"description"`
	Params      []Param           `json:"params"`
	Script      string            `json:"script"`
	TimeoutSec  int               `json:"timeout_sec"`
	MaxOutput   int               `json:"max_output"`
	// Cleanup runs after the script even when it timed out or failed.
	Cleanup string `json:"cleanup,omitempty"`
	// Artifact is a file the entry leaves in /tmp for download.
	Artifact string `json:"artifact,omitempty"`
}

// Catalog is the set of entries known to the controller.
type Catalog struct {
	entries map[string]Entry
	order   []string
}

// ErrUnknownEntry is returned for an identifier that is not in the catalog.
var ErrUnknownEntry = errors.New("unknown catalog entry")

// Default parses the embedded catalog and validates it.
func Default() (*Catalog, error) {
	return Parse(catalogJSON)
}

// Parse builds a catalog from JSON and rejects any structural problem.
func Parse(data []byte) (*Catalog, error) {
	var list []Entry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	c := &Catalog{entries: make(map[string]Entry, len(list))}
	for _, e := range list {
		if err := e.check(); err != nil {
			return nil, fmt.Errorf("catalog: entry %q: %w", e.ID, err)
		}
		if _, dup := c.entries[e.ID]; dup {
			return nil, fmt.Errorf("catalog: duplicate entry %q", e.ID)
		}
		c.entries[e.ID] = e
		c.order = append(c.order, e.ID)
	}
	return c, nil
}

func (e Entry) check() error {
	if e.ID == "" || e.Script == "" {
		return errors.New("id and script are required")
	}
	if e.Class != R0 && e.Class != R1 {
		return errors.New("class must be R0 or R1")
	}
	if e.TimeoutSec < 1 || e.TimeoutSec > 180 {
		return errors.New("timeout_sec must be between 1 and 180")
	}
	if e.MaxOutput < 1024 || e.MaxOutput > 4<<20 {
		return errors.New("max_output must be between 1 KiB and 4 MiB")
	}
	for _, lang := range []string{"en", "es", "pt-BR"} {
		if e.Title[lang] == "" || e.Description[lang] == "" {
			return fmt.Errorf("title and description are required in %s", lang)
		}
	}
	if len(e.KBA) == 0 {
		return errors.New("at least one KBA reference is required")
	}
	seen := map[string]bool{}
	for _, p := range e.Params {
		if p.Name == "" || seen[p.Name] {
			return errors.New("parameter names must be unique and not empty")
		}
		seen[p.Name] = true
		if p.Kind == KindEnum && len(p.Enum) == 0 {
			return fmt.Errorf("parameter %s: enum without values", p.Name)
		}
		for _, lang := range []string{"en", "es", "pt-BR"} {
			if p.Label[lang] == "" {
				return fmt.Errorf("parameter %s: label missing in %s", p.Name, lang)
			}
		}
	}
	return nil
}

// Get returns an entry by identifier.
func (c *Catalog) Get(id string) (Entry, error) {
	e, ok := c.entries[id]
	if !ok {
		return Entry{}, ErrUnknownEntry
	}
	return e, nil
}

// List returns the entries in catalog order.
func (c *Catalog) List() []Entry {
	out := make([]Entry, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.entries[id])
	}
	return out
}

// Groups returns the distinct group names, sorted.
func (c *Catalog) Groups() []string {
	set := map[string]bool{}
	for _, e := range c.entries {
		set[e.Group] = true
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// Command is what the controller sends to the unit: the program and its
// arguments, never a shell line assembled from user input.
type Command struct {
	Program string
	Args    []string
	// PacketID and PacketArgs name the Support Packet installed on the unit (ns.support run).
	// When PacketID is set the unit runs its own copy of the packet; Program and Args are only
	// used by the shell-based test executors.
	PacketID   string
	PacketArgs []string
}

// Resolve validates the supplied parameters and builds the command for an
// entry. Unknown parameter names are rejected.
func (c *Catalog) Resolve(id string, values map[string]string) (Entry, Command, error) {
	e, err := c.Get(id)
	if err != nil {
		return Entry{}, Command{}, err
	}
	known := map[string]bool{}
	args := []string{"-c", e.Script, "nexwall-support-" + e.ID}
	packetArgs := []string{}
	for _, p := range e.Params {
		known[p.Name] = true
		v, err := p.Validate(values[p.Name])
		if err != nil {
			return Entry{}, Command{}, err
		}
		args = append(args, v)
		packetArgs = append(packetArgs, v)
	}
	for name := range values {
		if !known[name] {
			return Entry{}, Command{}, fmt.Errorf("%w: %s: not accepted by this entry", ErrInvalidParam, name)
		}
	}
	return e, Command{Program: "/bin/sh", Args: args, PacketID: e.ID, PacketArgs: packetArgs}, nil
}
