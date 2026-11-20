/*
 * Copyright (C) 2026 Nexwall
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

package methods

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/NethServer/nethsecurity-controller/api/support"
	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// Tier 2 of the support system: read-only diagnostics, run on one firewall from
// a fixed catalog. The catalog validates every parameter and builds the command;
// nothing the browser sends is ever a command line.

var (
	supportOnce sync.Once
	supportSvc  *support.Service
	supportErr  error

	// one diagnostic at a time per firewall, and a cap on the whole controller
	supportBusy  = map[string]bool{}
	supportBusyM sync.Mutex
	supportSlots = make(chan struct{}, 8)
)

type supportAudit struct{}

func (supportAudit) Record(r support.AuditRecord) {
	params, _ := json.Marshal(r.Params)
	logs.Logs.Println("[INFO][support] actor=" + r.Actor + " ticket=" + r.TicketID + " unit=" + r.UnitID +
		" entry=" + r.EntryID + " outcome=" + r.Outcome + " params=" + string(params) + " detail=" + r.Detail)
}

func supportService() (*support.Service, error) {
	supportOnce.Do(func() {
		cat, err := support.Default()
		if err != nil {
			supportErr = err
			return
		}
		supportSvc = &support.Service{
			Catalog: cat,
			Audit:   supportAudit{},
			Exec: &support.UbusExecutor{
				BaseURL: configuration.Config.ProxyProtocol + configuration.Config.ProxyHost + ":" + configuration.Config.ProxyPort,
				Token: func(_ context.Context, unitID string) (string, error) {
					t, _, err := getUnitToken(unitID)
					return t, err
				},
			},
		}
	})
	return supportSvc, supportErr
}

// GetSupportCatalog lists what can be run: titles, descriptions and parameters,
// never the scripts.
func GetSupportCatalog(c *gin.Context) {
	svc, err := supportService()
	if err != nil {
		supportFail(c, http.StatusInternalServerError, "support catalog unavailable")
		return
	}
	type item struct {
		ID          string            `json:"id"`
		Group       string            `json:"group"`
		Class       support.Class     `json:"class"`
		KBA         []int             `json:"kba"`
		Title       map[string]string `json:"title"`
		Description map[string]string `json:"description"`
		Params      []support.Param   `json:"params"`
		TimeoutSec  int               `json:"timeout_sec"`
		// Script is what the entry runs on the firewall; the screen shows it before the user authorizes the run.
		Script    string `json:"script"`
		MaxOutput int    `json:"max_output"`
	}
	entries := svc.Catalog.List()
	out := make([]item, 0, len(entries))
	for _, e := range entries {
		out = append(out, item{e.ID, e.Group, e.Class, e.KBA, e.Title, e.Description, e.Params, e.TimeoutSec, e.Script, e.MaxOutput})
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "message": "success", "data": gin.H{"entries": out, "groups": svc.Catalog.Groups()}})
}

type supportRunRequest struct {
	UnitID   string            `json:"unit_id" binding:"required"`
	Entry    string            `json:"entry" binding:"required"`
	Params   map[string]string `json:"params"`
	TicketID string            `json:"ticket_id"`
}

// RunSupportEntry runs one catalog entry on one firewall and returns the
// redacted output.
func RunSupportEntry(c *gin.Context) {
	var in supportRunRequest
	if err := c.ShouldBindJSON(&in); err != nil || len(in.TicketID) > 40 {
		supportFail(c, http.StatusBadRequest, "invalid request")
		return
	}
	if _, err := storage.GetUnit(in.UnitID); err != nil {
		supportFail(c, http.StatusNotFound, "firewall not found")
		return
	}
	svc, err := supportService()
	if err != nil {
		supportFail(c, http.StatusInternalServerError, "support catalog unavailable")
		return
	}
	actor, _ := jwt.ExtractClaims(c)["id"].(string)

	supportBusyM.Lock()
	if supportBusy[in.UnitID] {
		supportBusyM.Unlock()
		supportFail(c, http.StatusConflict, "another diagnostic is running on this firewall")
		return
	}
	select {
	case supportSlots <- struct{}{}:
	default:
		supportBusyM.Unlock()
		supportFail(c, http.StatusTooManyRequests, "too many diagnostics running")
		return
	}
	supportBusy[in.UnitID] = true
	supportBusyM.Unlock()
	defer func() {
		supportBusyM.Lock()
		delete(supportBusy, in.UnitID)
		supportBusyM.Unlock()
		<-supportSlots
	}()

	ctx, cancel := context.WithTimeout(c.Request.Context(), 150*time.Second)
	defer cancel()
	res, err := svc.Run(ctx, support.Request{Actor: actor, TicketID: in.TicketID, UnitID: in.UnitID, EntryID: in.Entry, Params: in.Params})
	if err != nil {
		// Parameter and catalog errors are the caller's; everything else is the firewall's.
		if support.IsRequestError(err) {
			supportFail(c, http.StatusBadRequest, err.Error())
			return
		}
		supportFail(c, http.StatusBadGateway, "the firewall could not run the diagnostic")
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "message": "success", "data": res})
}

func supportFail(c *gin.Context, code int, msg string) {
	c.JSON(code, gin.H{"code": code, "message": msg, "data": nil})
}
