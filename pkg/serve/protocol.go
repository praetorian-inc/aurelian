// Package serve implements the subprocess evaluator protocol for Aurelian's
// --serve mode. The solver communicates with Aurelian over newline-delimited
// JSON (NDJSON) on stdin/stdout, sending requests and receiving responses.
//
// Supported methods:
//   - capabilities: returns the list of supported methods
//   - check_specific: evaluates a single (actor, action, resource) triple
//   - verify_pairs: batch-evaluates multiple (actor, action, resource) triples
package serve

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Request is the envelope for all incoming NDJSON messages.
type Request struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id,omitempty"` // echoed back in response
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the envelope for all outgoing NDJSON messages.
type Response struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Result any             `json:"result,omitempty"`
	Error  *ErrorDetail    `json:"error,omitempty"`
}

// ErrorDetail carries structured error information in a response.
type ErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CapabilitiesResult is returned by the "capabilities" method.
type CapabilitiesResult struct {
	Methods []string `json:"methods"`
}

// CheckSpecificParams are the parameters for "check_specific".
type CheckSpecificParams struct {
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// CheckSpecificResult is the result of a "check_specific" call.
type CheckSpecificResult struct {
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Allowed  bool   `json:"allowed"`
}

// VerifyPair is a single (actor, action, resource) triple within a verify_pairs batch.
type VerifyPair struct {
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// VerifyPairsParams are the parameters for "verify_pairs".
type VerifyPairsParams struct {
	Pairs []VerifyPair `json:"pairs"`
}

// VerifyPairsResultEntry is a single result in the verify_pairs batch response.
type VerifyPairsResultEntry struct {
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Allowed  bool   `json:"allowed"`
}

// VerifyPairsResult is the result of a "verify_pairs" call.
type VerifyPairsResult struct {
	Results []VerifyPairsResultEntry `json:"results"`
}

// Handler processes subprocess protocol requests using the provided IAM
// PolicyEvaluator and state. It reads NDJSON from reader, writes NDJSON
// responses to writer, and returns when reader reaches EOF.
type Handler struct {
	evaluator  *iam.PolicyEvaluator
	state      EvaluatorState
	encoder    *json.Encoder
}

// EvaluatorState provides the lookup methods the handler needs to build
// evaluation requests. This interface decouples the handler from the full
// AnalyzerState, making it testable with stubs.
type EvaluatorState interface {
	// LookupPrincipalStatements returns the identity and boundary policy
	// statements for the given principal ARN. Returns nil slices if not found.
	LookupPrincipalStatements(principalArn string) (identity, boundary *types.PolicyStatementList)

	// GetResourceAccount returns the account ID that owns the given resource ARN.
	GetResourceAccount(resourceArn string) string
}

// NewHandler creates a handler with the given evaluator and state.
func NewHandler(evaluator *iam.PolicyEvaluator, state EvaluatorState) *Handler {
	return &Handler{
		evaluator: evaluator,
		state:     state,
	}
}

// Serve reads NDJSON requests from r and writes NDJSON responses to w.
// It returns nil on clean EOF and an error on I/O or protocol failures.
func (h *Handler) Serve(r io.Reader, w io.Writer) error {
	h.encoder = json.NewEncoder(w)
	scanner := bufio.NewScanner(r)

	// Allow up to 10MB per line to handle large verify_pairs batches.
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			if writeErr := h.writeError(nil, -32700, fmt.Sprintf("parse error: %v", err)); writeErr != nil {
				return writeErr
			}
			continue
		}

		if err := h.dispatch(&req); err != nil {
			return err // I/O error writing response — abort
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	return nil
}

func (h *Handler) dispatch(req *Request) error {
	switch req.Method {
	case "capabilities":
		return h.handleCapabilities(req)
	case "check_specific":
		return h.handleCheckSpecific(req)
	case "verify_pairs":
		return h.handleVerifyPairs(req)
	default:
		return h.writeError(req.ID, -32601, fmt.Sprintf("unknown method: %s", req.Method))
	}
}

func (h *Handler) handleCapabilities(req *Request) error {
	return h.writeResult(req.ID, CapabilitiesResult{
		Methods: []string{"capabilities", "check_specific", "verify_pairs"},
	})
}

func (h *Handler) handleCheckSpecific(req *Request) error {
	var params CheckSpecificParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return h.writeError(req.ID, -32602, fmt.Sprintf("invalid params: %v", err))
	}

	allowed := h.evaluateTriple(params.Actor, params.Action, params.Resource)

	return h.writeResult(req.ID, CheckSpecificResult{
		Actor:    params.Actor,
		Action:   params.Action,
		Resource: params.Resource,
		Allowed:  allowed,
	})
}

func (h *Handler) handleVerifyPairs(req *Request) error {
	var params VerifyPairsParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return h.writeError(req.ID, -32602, fmt.Sprintf("invalid params: %v", err))
	}

	results := make([]VerifyPairsResultEntry, len(params.Pairs))
	for i, pair := range params.Pairs {
		results[i] = VerifyPairsResultEntry{
			Actor:    pair.Actor,
			Action:   pair.Action,
			Resource: pair.Resource,
			Allowed:  h.evaluateTriple(pair.Actor, pair.Action, pair.Resource),
		}
	}

	return h.writeResult(req.ID, VerifyPairsResult{Results: results})
}

// evaluateTriple checks whether the given (actor, action, resource) triple is
// allowed by IAM policy.
func (h *Handler) evaluateTriple(actor, action, resource string) bool {
	identity, boundary := h.state.LookupPrincipalStatements(actor)
	resourceAccount := h.state.GetResourceAccount(resource)

	ctx := &iam.RequestContext{
		PrincipalArn:    actor,
		ResourceAccount: resourceAccount,
	}

	req := &iam.EvaluationRequest{
		Action:             action,
		Resource:           resource,
		Context:            ctx,
		IdentityStatements: identity,
		BoundaryStatements: boundary,
	}

	result, err := h.evaluator.Evaluate(req)
	if err != nil {
		slog.Error("evaluation error", "actor", actor, "action", action, "resource", resource, "error", err)
		return false
	}
	return result.Allowed
}

func (h *Handler) writeResult(id json.RawMessage, result any) error {
	return h.encoder.Encode(Response{ID: id, Result: result})
}

func (h *Handler) writeError(id json.RawMessage, code int, message string) error {
	return h.encoder.Encode(Response{ID: id, Error: &ErrorDetail{Code: code, Message: message}})
}
