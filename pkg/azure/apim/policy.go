package apim

import (
	"encoding/xml"
	"strings"
)

// AuthPosture records which authentication-related elements appear inside an
// APIM policy's <inbound> section.
//
// A check-header element counts only when the header it asserts is one of the
// common authentication headers (Authorization, X-API-Key, etc.). Subscription
// keys are tracked separately on the API contract and are not an authentication
// control on their own.
//
// IncludeFragment is true when an <include-fragment> element is present and
// the referenced fragment itself contains an auth primitive. Fragments whose
// bodies aren't resolvable are treated as authenticating (conservative: do not
// flag the API as unauthenticated when we can't see the fragment).
type AuthPosture struct {
	ValidateJWT          bool
	ValidateAzureADToken bool
	CheckHeader          bool
	IPFilter             bool
	IncludeFragment      bool
}

// HasAuth reports whether any auth element was detected.
func (p AuthPosture) HasAuth() bool {
	return p.ValidateJWT || p.ValidateAzureADToken || p.CheckHeader || p.IPFilter || p.IncludeFragment
}

// authHeaders is the set of header names (lower-cased) whose presence in a
// <check-header> directive we treat as authentication.
var authHeaders = map[string]bool{
	"authorization":   true,
	"x-api-key":       true,
	"x-auth-token":    true,
	"api-key":         true,
	"x-access-token":  true,
	"x-client-secret": true,
}

// ParseInboundAuth scans an APIM policy XML document and reports which
// authentication-related elements exist inside <inbound>. Any content outside
// <inbound> (e.g., in <backend>, <outbound>, <on-error>) is ignored.
//
// fragmentAuth maps fragment IDs to whether that fragment contains an auth
// primitive. Fragments absent from the map are conservatively treated as
// authenticating — if we can't see the fragment body, we cannot prove the
// policy is unauthenticated.
//
// Malformed XML and empty input are returned as a zero AuthPosture.
func ParseInboundAuth(policyXML string, fragmentAuth map[string]bool) AuthPosture {
	if strings.TrimSpace(policyXML) == "" {
		return AuthPosture{}
	}

	decoder := xml.NewDecoder(strings.NewReader(policyXML))
	var posture AuthPosture
	inInbound := 0 // depth counter: >0 means we are inside <inbound>

	for {
		tok, err := decoder.Token()
		if err != nil {
			// io.EOF or malformed input — stop gracefully.
			return posture
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "inbound" && inInbound == 0 {
				inInbound = 1
				continue
			}
			if inInbound > 0 {
				inInbound++
				inspectElement(t, &posture, fragmentAuth)
			}
		case xml.EndElement:
			if inInbound > 0 {
				inInbound--
			}
		}
	}
}

func inspectElement(t xml.StartElement, posture *AuthPosture, fragmentAuth map[string]bool) {
	switch t.Name.Local {
	case "validate-jwt":
		posture.ValidateJWT = true
	case "validate-azure-ad-token":
		posture.ValidateAzureADToken = true
	case "ip-filter":
		posture.IPFilter = true
	case "check-header":
		if headerAttr := attrValue(t, "name"); authHeaders[strings.ToLower(headerAttr)] {
			posture.CheckHeader = true
		}
	case "include-fragment":
		id := attrValue(t, "fragment-id")
		if id == "" {
			return
		}
		hasAuth, known := fragmentAuth[id]
		if !known || hasAuth {
			posture.IncludeFragment = true
		}
	}
}

func attrValue(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// FragmentHasAuth reports whether a policy fragment body contains any
// authentication-related element. It is used to pre-index policy fragments
// referenced via <include-fragment>.
func FragmentHasAuth(fragmentXML string) bool {
	if strings.TrimSpace(fragmentXML) == "" {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(fragmentXML))
	for {
		tok, err := decoder.Token()
		if err != nil {
			return false
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "validate-jwt", "validate-azure-ad-token", "ip-filter":
			return true
		case "check-header":
			if authHeaders[strings.ToLower(attrValue(start, "name"))] {
				return true
			}
		}
	}
}
