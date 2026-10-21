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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
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
	Error    string `json:"error,omitempty"`
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

	// LookupServicePrincipalStatements returns identity statements for a
	// service principal (e.g. "lambda.amazonaws.com") derived from trust
	// policies that grant that service sts:AssumeRole. Returns nil if none.
	LookupServicePrincipalStatements(servicePrincipal string) *types.PolicyStatementList

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

	allowed, evalErr := h.evaluateTriple(params.Actor, params.Action, params.Resource)
	if evalErr != nil {
		return h.writeError(req.ID, -32000, fmt.Sprintf("evaluation error: %v", evalErr))
	}

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
		allowed, evalErr := h.evaluateTriple(pair.Actor, pair.Action, pair.Resource)
		entry := VerifyPairsResultEntry{
			Actor:    pair.Actor,
			Action:   pair.Action,
			Resource: pair.Resource,
			Allowed:  allowed,
		}
		if evalErr != nil {
			entry.Error = evalErr.Error()
		}
		results[i] = entry
	}

	return h.writeResult(req.ID, VerifyPairsResult{Results: results})
}

// evaluateTriple checks whether the given (actor, action, resource) triple is
// allowed by IAM policy. It returns the allow/deny decision and any evaluation
// error so callers can distinguish IAM denies from evaluator failures.
func (h *Handler) evaluateTriple(actor, action, resource string) (bool, error) {
	identity, boundary := h.state.LookupPrincipalStatements(actor)
	resourceAccount := h.state.GetResourceAccount(resource)

	// For service principals (e.g. "lambda.amazonaws.com"), LookupPrincipalStatements
	// returns nil because they're not indexed as users/roles. Match the established
	// code path in processAssumeRolePolicies: use the trust-policy statements the
	// state provides as identity statements.
	if identity == nil && isServicePrincipal(actor) {
		identity = h.state.LookupServicePrincipalStatements(actor)
	}

	// Derive the principal's account from the ARN when it parses.
	var principalAccount string
	if parsed, err := arn.Parse(actor); err == nil {
		principalAccount = parsed.AccountID
	}

	ctx := &iam.RequestContext{
		PrincipalArn:     actor,
		PrincipalAccount: principalAccount,
		ResourceAccount:  resourceAccount,
		CurrentTime:      time.Now(),
	}

	// Populate derivable condition keys (aws:PrincipalAccount, aws:PrincipalType,
	// etc.) so policies that reference them evaluate correctly.
	if err := ctx.PopulateDefaultRequestConditionKeys(resource); err != nil {
		return false, fmt.Errorf("populating request context for actor=%s resource=%s: %w", actor, resource, err)
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
		return false, fmt.Errorf("evaluating actor=%s action=%s resource=%s: %w", actor, action, resource, err)
	}
	return result.Allowed, nil
}

// isServicePrincipal reports whether a string is a service principal rather
// than an ARN (e.g. "lambda.amazonaws.com").
func isServicePrincipal(s string) bool {
	return strings.HasSuffix(s, ".amazonaws.com")
}

func (h *Handler) writeResult(id json.RawMessage, result any) error {
	return h.encoder.Encode(Response{ID: id, Result: result})
}

func (h *Handler) writeError(id json.RawMessage, code int, message string) error {
	return h.encoder.Encode(Response{ID: id, Error: &ErrorDetail{Code: code, Message: message}})
}
