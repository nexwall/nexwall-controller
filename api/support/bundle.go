/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package support

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Manifest describes a bundle: where it came from and what it contains.
type Manifest struct {
	Version   int            `json:"version"`
	TicketID  string         `json:"ticket_id"`
	UnitID    string         `json:"unit_id"`
	CreatedAt time.Time      `json:"created_at"`
	CreatedBy string         `json:"created_by"`
	Files     []ManifestFile `json:"files"`
	Redacted  int            `json:"redacted"`
}

// ManifestFile is one output inside a bundle.
type ManifestFile struct {
	Name     string            `json:"name"`
	EntryID  string            `json:"entry_id"`
	Params   map[string]string `json:"params"`
	ExitCode int               `json:"exit_code"`
	Bytes    int               `json:"bytes"`
	SHA256   string            `json:"sha256"`
}

// WriteBundle writes a zip with manifest.json and one text file per result.
// Every output is already redacted by Service.Run; the manifest records the
// total number of replacements so a reader can see that the filter ran.
func WriteBundle(w io.Writer, ticketID, unitID, actor string, at time.Time, results []*Result) error {
	zw := zip.NewWriter(w)
	m := Manifest{Version: 1, TicketID: ticketID, UnitID: unitID, CreatedAt: at.UTC(), CreatedBy: actor}
	for i, r := range results {
		name := fmt.Sprintf("outputs/%02d-%s.txt", i+1, r.EntryID)
		f, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: at})
		if err != nil {
			return err
		}
		if _, err := io.WriteString(f, r.Output); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(r.Output))
		m.Files = append(m.Files, ManifestFile{Name: name, EntryID: r.EntryID, Params: r.Params, ExitCode: r.ExitCode, Bytes: len(r.Output), SHA256: hex.EncodeToString(sum[:])})
		m.Redacted += r.Redacted
	}
	f, err := zw.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Deflate, Modified: at})
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return err
	}
	return zw.Close()
}
