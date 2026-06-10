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
	TypeHandshake          = "handshake"
	TypeCheckSpecific      = "check_specific"
	TypeCheckAnyTarget     = "check_any_target"
	TypeCheckCounterfactual = "check_counterfactual"
	TypeWhoCanBulk         = "who_can_bulk"
	TypeShutdown           = "shutdown"
)

// Request is a query from the solver (stdin).
type Request struct {
	Type      string          `json:"type"`
	Version   string          `json:"version,omitempty"`
	Principal string          `json:"principal,omitempty"`
	Action    string          `json:"action,omitempty"`
	Target    string          `json:"target,omitempty"`

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
}

// Serve runs the subprocess protocol loop, reading from r and writing to w.
// It blocks until a shutdown message is received or r is closed.
func Serve(r io.Reader, w io.Writer, h Handler) error {
	scanner := bufio.NewScanner(r)
	// Increase buffer for large who_can_bulk requests.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	capabilities := []string{"check_specific", "check_any_target", "check_counterfactual"}

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
			// Not implemented in v1 — respond with error per spec.
			writeJSON(w, ErrorResponse{Error: "who_can_bulk not implemented"})

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
