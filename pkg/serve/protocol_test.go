package serve

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubState implements EvaluatorState for testing.
type stubState struct {
	principals map[string]struct {
		identity *types.PolicyStatementList
		boundary *types.PolicyStatementList
	}
	resourceAccounts map[string]string
}

func newStubState() *stubState {
	return &stubState{
		principals: make(map[string]struct {
			identity *types.PolicyStatementList
			boundary *types.PolicyStatementList
		}),
		resourceAccounts: make(map[string]string),
	}
}

func (s *stubState) LookupPrincipalStatements(principalArn string) (identity, boundary *types.PolicyStatementList) {
	p, ok := s.principals[principalArn]
	if !ok {
		return nil, nil
	}
	return p.identity, p.boundary
}

func (s *stubState) LookupServicePrincipalStatements(servicePrincipal string) *types.PolicyStatementList {
	return nil
}

func (s *stubState) GetResourceAccount(resourceArn string) string {
	return s.resourceAccounts[resourceArn]
}

func (s *stubState) addPrincipal(arn string, identity *types.PolicyStatementList, boundary *types.PolicyStatementList) {
	s.principals[arn] = struct {
		identity *types.PolicyStatementList
		boundary *types.PolicyStatementList
	}{identity, boundary}
}

// buildHandler creates a handler with a real PolicyEvaluator and a stubState
// pre-loaded with one principal that has Allow *.
func buildTestHandler() (*Handler, *stubState) {
	state := newStubState()

	// Principal with full admin access (Allow * on *)
	adminStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}
	state.addPrincipal("arn:aws:iam::111111111111:user/admin", adminStatements, nil)

	// Principal with limited access (only s3:GetObject on specific bucket)
	limitedStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"s3:GetObject"}),
			Resource: types.NewDynaString([]string{"arn:aws:s3::111111111111:my-bucket/*"}),
		},
	}
	state.addPrincipal("arn:aws:iam::111111111111:user/readonly", limitedStatements, nil)

	// Set resource accounts
	state.resourceAccounts["arn:aws:s3::111111111111:my-bucket/file.txt"] = "111111111111"
	state.resourceAccounts["arn:aws:ec2:us-east-1:111111111111:instance/i-1234"] = "111111111111"

	pd := iam.NewPolicyData(nil, nil, nil, nil)
	evaluator := iam.NewPolicyEvaluator(pd)

	handler := NewHandler(evaluator, state)
	return handler, state
}

// sendRequest serializes a request to NDJSON, feeds it to Serve, and returns
// the parsed response.
func sendRequest(t *testing.T, h *Handler, req Request) Response {
	t.Helper()
	input, err := json.Marshal(req)
	require.NoError(t, err)
	input = append(input, '\n')

	var out bytes.Buffer
	err = h.Serve(bytes.NewReader(input), &out)
	require.NoError(t, err)

	var resp Response
	err = json.Unmarshal(out.Bytes(), &resp)
	require.NoError(t, err, "response: %s", out.String())
	return resp
}

// --- capabilities ---

func TestCapabilities(t *testing.T) {
	h, _ := buildTestHandler()
	resp := sendRequest(t, h, Request{
		Method: "capabilities",
		ID:     json.RawMessage(`1`),
	})

	assert.Nil(t, resp.Error)
	assert.JSONEq(t, `1`, string(resp.ID))

	resultBytes, err := json.Marshal(resp.Result)
	require.NoError(t, err)

	var caps CapabilitiesResult
	require.NoError(t, json.Unmarshal(resultBytes, &caps))

	assert.Contains(t, caps.Methods, "capabilities")
	assert.Contains(t, caps.Methods, "check_specific")
	assert.Contains(t, caps.Methods, "verify_pairs")
}

// --- check_specific ---

func TestCheckSpecific_Allowed(t *testing.T) {
	h, _ := buildTestHandler()
	params, _ := json.Marshal(CheckSpecificParams{
		Actor:    "arn:aws:iam::111111111111:user/admin",
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3::111111111111:my-bucket/file.txt",
	})
	resp := sendRequest(t, h, Request{
		Method: "check_specific",
		ID:     json.RawMessage(`2`),
		Params: params,
	})

	assert.Nil(t, resp.Error)

	resultBytes, _ := json.Marshal(resp.Result)
	var result CheckSpecificResult
	require.NoError(t, json.Unmarshal(resultBytes, &result))

	assert.True(t, result.Allowed)
	assert.Equal(t, "arn:aws:iam::111111111111:user/admin", result.Actor)
	assert.Equal(t, "s3:GetObject", result.Action)
	assert.Equal(t, "arn:aws:s3::111111111111:my-bucket/file.txt", result.Resource)
}

func TestCheckSpecific_Denied(t *testing.T) {
	h, _ := buildTestHandler()
	params, _ := json.Marshal(CheckSpecificParams{
		Actor:    "arn:aws:iam::111111111111:user/readonly",
		Action:   "s3:DeleteObject",
		Resource: "arn:aws:s3::111111111111:my-bucket/file.txt",
	})
	resp := sendRequest(t, h, Request{
		Method: "check_specific",
		ID:     json.RawMessage(`3`),
		Params: params,
	})

	assert.Nil(t, resp.Error)

	resultBytes, _ := json.Marshal(resp.Result)
	var result CheckSpecificResult
	require.NoError(t, json.Unmarshal(resultBytes, &result))

	assert.False(t, result.Allowed)
}

func TestCheckSpecific_UnknownPrincipal(t *testing.T) {
	h, _ := buildTestHandler()
	params, _ := json.Marshal(CheckSpecificParams{
		Actor:    "arn:aws:iam::111111111111:user/nonexistent",
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3::111111111111:my-bucket/file.txt",
	})
	resp := sendRequest(t, h, Request{
		Method: "check_specific",
		ID:     json.RawMessage(`4`),
		Params: params,
	})

	assert.Nil(t, resp.Error)

	resultBytes, _ := json.Marshal(resp.Result)
	var result CheckSpecificResult
	require.NoError(t, json.Unmarshal(resultBytes, &result))

	// Unknown principal has no statements → implicit deny
	assert.False(t, result.Allowed)
}

// --- verify_pairs ---

func TestVerifyPairs_Batch(t *testing.T) {
	h, _ := buildTestHandler()
	params, _ := json.Marshal(VerifyPairsParams{
		Pairs: []VerifyPair{
			{
				Actor:    "arn:aws:iam::111111111111:user/admin",
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3::111111111111:my-bucket/file.txt",
			},
			{
				Actor:    "arn:aws:iam::111111111111:user/readonly",
				Action:   "s3:DeleteObject",
				Resource: "arn:aws:s3::111111111111:my-bucket/file.txt",
			},
			{
				Actor:    "arn:aws:iam::111111111111:user/readonly",
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3::111111111111:my-bucket/file.txt",
			},
		},
	})
	resp := sendRequest(t, h, Request{
		Method: "verify_pairs",
		ID:     json.RawMessage(`5`),
		Params: params,
	})

	assert.Nil(t, resp.Error)

	resultBytes, _ := json.Marshal(resp.Result)
	var result VerifyPairsResult
	require.NoError(t, json.Unmarshal(resultBytes, &result))

	require.Len(t, result.Results, 3)
	assert.True(t, result.Results[0].Allowed, "admin should be allowed s3:GetObject")
	assert.False(t, result.Results[1].Allowed, "readonly should be denied s3:DeleteObject")
	assert.True(t, result.Results[2].Allowed, "readonly should be allowed s3:GetObject")
}

func TestVerifyPairs_EmptyBatch(t *testing.T) {
	h, _ := buildTestHandler()
	params, _ := json.Marshal(VerifyPairsParams{Pairs: []VerifyPair{}})
	resp := sendRequest(t, h, Request{
		Method: "verify_pairs",
		ID:     json.RawMessage(`6`),
		Params: params,
	})

	assert.Nil(t, resp.Error)

	resultBytes, _ := json.Marshal(resp.Result)
	var result VerifyPairsResult
	require.NoError(t, json.Unmarshal(resultBytes, &result))

	assert.Len(t, result.Results, 0)
}

// --- error handling ---

func TestUnknownMethod(t *testing.T) {
	h, _ := buildTestHandler()
	resp := sendRequest(t, h, Request{
		Method: "unknown_method",
		ID:     json.RawMessage(`7`),
	})

	require.NotNil(t, resp.Error)
	assert.Equal(t, -32601, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "unknown method")
}

func TestMalformedJSON(t *testing.T) {
	h, _ := buildTestHandler()
	input := []byte("this is not json\n")

	var out bytes.Buffer
	err := h.Serve(bytes.NewReader(input), &out)
	require.NoError(t, err) // should not abort

	var resp Response
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32700, resp.Error.Code)
}

func TestInvalidParams(t *testing.T) {
	h, _ := buildTestHandler()
	resp := sendRequest(t, h, Request{
		Method: "check_specific",
		ID:     json.RawMessage(`8`),
		Params: json.RawMessage(`"not an object"`),
	})

	require.NotNil(t, resp.Error)
	assert.Equal(t, -32602, resp.Error.Code)
}

// --- multi-request stream ---

func TestMultipleRequests(t *testing.T) {
	h, _ := buildTestHandler()

	// Build two requests on separate lines
	req1, _ := json.Marshal(Request{
		Method: "capabilities",
		ID:     json.RawMessage(`1`),
	})
	params2, _ := json.Marshal(CheckSpecificParams{
		Actor:    "arn:aws:iam::111111111111:user/admin",
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3::111111111111:my-bucket/file.txt",
	})
	req2, _ := json.Marshal(Request{
		Method: "check_specific",
		ID:     json.RawMessage(`2`),
		Params: params2,
	})

	input := string(req1) + "\n" + string(req2) + "\n"

	var out bytes.Buffer
	err := h.Serve(strings.NewReader(input), &out)
	require.NoError(t, err)

	// Should get two NDJSON responses
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)

	var resp1, resp2 Response
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp1))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &resp2))

	assert.Nil(t, resp1.Error)
	assert.Nil(t, resp2.Error)
}

// --- ID echo ---

func TestIDEchoed(t *testing.T) {
	h, _ := buildTestHandler()

	// String ID
	resp := sendRequest(t, h, Request{
		Method: "capabilities",
		ID:     json.RawMessage(`"abc-123"`),
	})
	assert.JSONEq(t, `"abc-123"`, string(resp.ID))

	// Numeric ID
	resp = sendRequest(t, h, Request{
		Method: "capabilities",
		ID:     json.RawMessage(`42`),
	})
	assert.JSONEq(t, `42`, string(resp.ID))

	// No ID (omitted)
	resp = sendRequest(t, h, Request{
		Method: "capabilities",
	})
	assert.Nil(t, resp.ID)
}

// --- verify_pairs is advertised in capabilities ---

func TestCapabilities_AdvertisesVerifyPairs(t *testing.T) {
	h, _ := buildTestHandler()
	resp := sendRequest(t, h, Request{
		Method: "capabilities",
		ID:     json.RawMessage(`99`),
	})

	resultBytes, _ := json.Marshal(resp.Result)
	var caps CapabilitiesResult
	require.NoError(t, json.Unmarshal(resultBytes, &caps))

	// The solver checks for this exact capability name
	assert.Contains(t, caps.Methods, "verify_pairs",
		"verify_pairs must be advertised so the solver uses batch mode")
}
