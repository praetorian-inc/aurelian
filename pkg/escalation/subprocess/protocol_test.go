package subprocess

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHandler implements Handler with configurable responses.
type mockHandler struct {
	checkSpecificFn      func(principal, action, target string) (*CheckResponse, error)
	checkAnyTargetFn     func(principal, action string) (*CheckResponse, error)
	checkCounterfactualFn func(principal, action, target string, removed []RemovedStatement) (*CheckResponse, error)
}

func (m *mockHandler) CheckSpecific(principal, action, target string) (*CheckResponse, error) {
	return m.checkSpecificFn(principal, action, target)
}

func (m *mockHandler) CheckAnyTarget(principal, action string) (*CheckResponse, error) {
	return m.checkAnyTargetFn(principal, action)
}

func (m *mockHandler) CheckCounterfactual(principal, action, target string, removed []RemovedStatement) (*CheckResponse, error) {
	return m.checkCounterfactualFn(principal, action, target, removed)
}

func newAllowHandler() *mockHandler {
	return &mockHandler{
		checkSpecificFn: func(_, _, _ string) (*CheckResponse, error) {
			return &CheckResponse{Result: "allowed", Conditions: []Condition{}, ResourceConstraint: nil}, nil
		},
		checkAnyTargetFn: func(_, _ string) (*CheckResponse, error) {
			constraint := "arn:aws:iam::111111111111:role/*"
			return &CheckResponse{Result: "allowed", Conditions: []Condition{}, ResourceConstraint: &constraint}, nil
		},
		checkCounterfactualFn: func(_, _, _ string, _ []RemovedStatement) (*CheckResponse, error) {
			return &CheckResponse{Result: "allowed", Conditions: []Condition{}, ResourceConstraint: nil}, nil
		},
	}
}

func newDenyHandler() *mockHandler {
	return &mockHandler{
		checkSpecificFn: func(_, _, _ string) (*CheckResponse, error) {
			return &CheckResponse{Result: "denied", ResourceConstraint: nil}, nil
		},
		checkAnyTargetFn: func(_, _ string) (*CheckResponse, error) {
			return &CheckResponse{Result: "denied", ResourceConstraint: nil}, nil
		},
		checkCounterfactualFn: func(_, _, _ string, _ []RemovedStatement) (*CheckResponse, error) {
			return &CheckResponse{Result: "denied", ResourceConstraint: nil}, nil
		},
	}
}

func runProtocol(t *testing.T, input string, h Handler) []string {
	t.Helper()
	in := strings.NewReader(input)
	var out bytes.Buffer
	err := Serve(in, &out, h)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func TestHandshake(t *testing.T) {
	lines := runProtocol(t, `{"type":"handshake","version":"1.0"}`+"\n"+`{"type":"shutdown"}`+"\n", newAllowHandler())
	require.Len(t, lines, 1)

	var resp HandshakeResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Equal(t, "1.0", resp.Version)
	assert.Contains(t, resp.Capabilities, "check_specific")
	assert.Contains(t, resp.Capabilities, "check_any_target")
	assert.Contains(t, resp.Capabilities, "check_counterfactual")
}

func TestCheckSpecific_Allowed(t *testing.T) {
	input := `{"type":"check_specific","principal":"arn:aws:iam::111:role/A","action":"sts:AssumeRole","target":"arn:aws:iam::111:role/B"}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 1)

	var resp CheckResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Equal(t, "allowed", resp.Result)
}

func TestCheckSpecific_Denied(t *testing.T) {
	input := `{"type":"check_specific","principal":"arn:aws:iam::111:role/A","action":"s3:GetObject","target":"arn:aws:s3:::bucket"}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newDenyHandler())
	require.Len(t, lines, 1)

	var resp CheckResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Equal(t, "denied", resp.Result)
}

func TestCheckAnyTarget(t *testing.T) {
	input := `{"type":"check_any_target","principal":"arn:aws:iam::111:role/D","action":"iam:CreateRole"}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 1)

	var resp CheckResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Equal(t, "allowed", resp.Result)
	require.NotNil(t, resp.ResourceConstraint)
	assert.Equal(t, "arn:aws:iam::111111111111:role/*", *resp.ResourceConstraint)
}

func TestCheckCounterfactual(t *testing.T) {
	input := `{"type":"check_counterfactual","principal":"arn:aws:iam::111:role/A","action":"iam:CreateRole","target":"*","removed_statements":[{"effect":"Deny","action":"iam:*","resource":"*"}]}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 1)

	var resp CheckResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Equal(t, "allowed", resp.Result)
}

func TestWhoCanBulk_AllAllowed(t *testing.T) {
	input := `{"type":"who_can_bulk","action":"sts:AssumeRole","targets":["t1","t2"],"principals":["p1","p2"]}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 1)

	var resp WhoCanBulkResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	// 2 principals × 2 targets = 4 grants (all allowed by mock)
	assert.Len(t, resp.Grants, 4)
	for _, g := range resp.Grants {
		assert.Equal(t, "allowed", g.Result)
	}
}

func TestWhoCanBulk_AllDenied(t *testing.T) {
	input := `{"type":"who_can_bulk","action":"iam:DeleteRole","targets":["t1"],"principals":["p1"]}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newDenyHandler())
	require.Len(t, lines, 1)

	var resp WhoCanBulkResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	// All denied — grants should be empty array, not null
	assert.Len(t, resp.Grants, 0)
	assert.Contains(t, lines[0], `"grants":[]`)
}

func TestWhoCanBulk_Advertised(t *testing.T) {
	lines := runProtocol(t, `{"type":"handshake","version":"1.0"}`+"\n"+`{"type":"shutdown"}`+"\n", newAllowHandler())
	require.Len(t, lines, 1)

	var resp HandshakeResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Contains(t, resp.Capabilities, "who_can_bulk")
}

func TestShutdown(t *testing.T) {
	input := `{"type":"shutdown"}` + "\n"
	in := strings.NewReader(input)
	var out bytes.Buffer
	err := Serve(in, &out, newAllowHandler())
	require.NoError(t, err)
	assert.Empty(t, out.String(), "shutdown should produce no output")
}

func TestUnknownType(t *testing.T) {
	input := `{"type":"foobar"}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 1)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Contains(t, resp.Error, "unknown query type")
}

func TestInvalidJSON(t *testing.T) {
	input := `not json at all` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 1)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Contains(t, resp.Error, "invalid JSON")
}

func TestNewlineDelimited(t *testing.T) {
	// Multiple queries in sequence.
	input := `{"type":"handshake","version":"1.0"}` + "\n" +
		`{"type":"check_specific","principal":"p","action":"a","target":"t"}` + "\n" +
		`{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 2, "should get handshake + check_specific responses")
}

func TestEmptyLines(t *testing.T) {
	input := "\n\n" + `{"type":"handshake","version":"1.0"}` + "\n\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, newAllowHandler())
	require.Len(t, lines, 1, "empty lines should be skipped")
}

func TestHandlerError(t *testing.T) {
	h := &mockHandler{
		checkSpecificFn: func(_, _, _ string) (*CheckResponse, error) {
			return nil, fmt.Errorf("internal evaluator error")
		},
		checkAnyTargetFn:      newAllowHandler().checkAnyTargetFn,
		checkCounterfactualFn: newAllowHandler().checkCounterfactualFn,
	}

	input := `{"type":"check_specific","principal":"p","action":"a","target":"t"}` + "\n" + `{"type":"shutdown"}` + "\n"
	lines := runProtocol(t, input, h)
	require.Len(t, lines, 1)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))
	assert.Contains(t, resp.Error, "internal evaluator error")
}
