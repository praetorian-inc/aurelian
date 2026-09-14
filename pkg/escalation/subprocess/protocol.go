// Package subprocess implements the escalation-solver subprocess evaluator
// protocol. It reads newline-delimited JSON queries from stdin, evaluates
// them against loaded IAM data using Aurelian's PolicyEvaluator, and writes
// JSON responses to stdout.
package subprocess

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Protocol version advertised by this evaluator.
const ProtocolVersion = "1.0"

// Query types.
const (
	TypeHandshake           = "handshake"
	TypeCheckSpecific       = "check_specific"
	TypeCheckAnyTarget      = "check_any_target"
	TypeCheckCounterfactual = "check_counterfactual"
	TypeWhoCanBulk          = "who_can_bulk"
	TypeWhoCan              = "who_can"
	TypeListGrants          = "list_grants"
	TypeShutdown            = "shutdown"
)

// Request is a query from the solver (stdin).
type Request struct {
	Type      string `json:"type"`
	Version   string `json:"version,omitempty"`
	Principal string `json:"principal,omitempty"`
	Action    string `json:"action,omitempty"`
	Target    string `json:"target,omitempty"`

	// check_counterfactual
	RemovedStatements []RemovedStatement `json:"removed_statements,omitempty"`

	// who_can_bulk
	Targets    []string `json:"targets,omitempty"`
	Principals []string `json:"principals,omitempty"`
}

// RemovedStatement is a deny statement to exclude in counterfactual evaluation.
type RemovedStatement struct {
	Effect   string `json:"effect"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// HandshakeResponse is sent in reply to a handshake.
type HandshakeResponse struct {
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// CheckResponse is the response to check_specific, check_any_target, or
// check_counterfactual.
type CheckResponse struct {
	Result             string      `json:"result"`
	Conditions         []Condition `json:"conditions,omitempty"`
	ResourceConstraint *string     `json:"resource_constraint"`
}

// Condition is an IAM condition on an allowed grant.
type Condition struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// WhoCanBulkResponse is the response to who_can_bulk and who_can. Only
// allowed grants are included; denied pairs are omitted. Grants is never
// null: an empty result is [].
type WhoCanBulkResponse struct {
	Grants []Grant `json:"grants"`
}

// Grant is a single allowed permission in a who_can_bulk response.
type Grant struct {
	Principal  string      `json:"principal"`
	Target     string      `json:"target"`
	Result     string      `json:"result"`
	Conditions []Condition `json:"conditions"`
}

// ListGrantsEntry is a principal's effective statements in a list_grants response.
type ListGrantsEntry struct {
	Principal           string                `json:"principal"`
	EffectiveStatements []ListGrantsStatement `json:"effective_statements"`
}

// ListGrantsStatement is a single effective statement in a list_grants response.
type ListGrantsStatement struct {
	Effect   string `json:"effect"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// ListGrantsResponse is the response to list_grants.
type ListGrantsResponse struct {
	Entries []ListGrantsEntry `json:"entries"`
}

// ErrorResponse is sent when a query fails.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Handler processes individual query types. Implementations are provided by
// the evaluator (see evaluator.go).
type Handler interface {
	CheckSpecific(principal, action, target string) (*CheckResponse, error)
	CheckAnyTarget(principal, action string) (*CheckResponse, error)
	CheckCounterfactual(principal, action, target string, removed []RemovedStatement) (*CheckResponse, error)
	WhoCanBulk(action string, principals, targets []string) ([]Grant, error)
	WhoCan(action string, principals []string) ([]Grant, error)
	ListGrants() (*ListGrantsResponse, error)
}

// Serve runs the subprocess protocol loop, reading from r and writing to w.
// It blocks until a shutdown message is received or r is closed.
func Serve(r io.Reader, w io.Writer, h Handler) error {
	scanner := bufio.NewScanner(r)
	// Increase buffer for large who_can_bulk requests.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	capabilities := []string{"check_specific", "check_any_target", "check_counterfactual", "who_can_bulk", "who_can", "list_grants"}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			writeJSON(w, ErrorResponse{Error: fmt.Sprintf("invalid JSON: %v", err)})
			continue
		}

		switch req.Type {
		case TypeHandshake:
			writeJSON(w, HandshakeResponse{
				Version:      ProtocolVersion,
				Capabilities: capabilities,
			})

		case TypeCheckSpecific:
			resp, err := h.CheckSpecific(req.Principal, req.Action, req.Target)
			if err != nil {
				slog.Error("check_specific failed", "error", err)
				writeJSON(w, ErrorResponse{Error: err.Error()})
			} else {
				writeJSON(w, resp)
			}

		case TypeCheckAnyTarget:
			resp, err := h.CheckAnyTarget(req.Principal, req.Action)
			if err != nil {
				slog.Error("check_any_target failed", "error", err)
				writeJSON(w, ErrorResponse{Error: err.Error()})
			} else {
				writeJSON(w, resp)
			}

		case TypeCheckCounterfactual:
			resp, err := h.CheckCounterfactual(req.Principal, req.Action, req.Target, req.RemovedStatements)
			if err != nil {
				slog.Error("check_counterfactual failed", "error", err)
				writeJSON(w, ErrorResponse{Error: err.Error()})
			} else {
				writeJSON(w, resp)
			}

		case TypeWhoCanBulk:
			grants, err := h.WhoCanBulk(req.Action, req.Principals, req.Targets)
			if err != nil {
				slog.Error("who_can_bulk failed", "error", err)
				writeJSON(w, ErrorResponse{Error: err.Error()})
			} else {
				writeJSON(w, WhoCanBulkResponse{Grants: grants})
			}

		case TypeWhoCan:
			grants, err := h.WhoCan(req.Action, req.Principals)
			if err != nil {
				slog.Error("who_can failed", "error", err)
				writeJSON(w, ErrorResponse{Error: err.Error()})
			} else {
				if grants == nil {
					grants = []Grant{}
				}
				writeJSON(w, WhoCanBulkResponse{Grants: grants})
			}

		case TypeListGrants:
			resp, err := h.ListGrants()
			if err != nil {
				slog.Error("list_grants failed", "error", err)
				writeJSON(w, ErrorResponse{Error: err.Error()})
			} else {
				writeJSON(w, resp)
			}

		case TypeShutdown:
			return nil

		default:
			writeJSON(w, ErrorResponse{Error: fmt.Sprintf("unknown query type: %q", req.Type)})
		}
	}

	return scanner.Err()
}

// writeJSON writes a single JSON object followed by a newline.
func writeJSON(w io.Writer, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		slog.Error("failed to marshal response", "error", err)
		return
	}
	data = append(data, '\n')
	_, _ = w.Write(data)
}
