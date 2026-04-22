package apim

import "testing"

func TestParseAPIListPage(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantItems    []APIInventoryItem
		wantNextLink string
	}{
		{
			name: "empty value array",
			body: `{"value":[],"count":0}`,
			wantItems: nil,
		},
		{
			name: "native MCP API sets IsMCPServer from properties.type",
			body: `{
				"value": [
					{
						"name": "f5-mcp",
						"type": "Microsoft.ApiManagement/service/apis",
						"properties": {
							"displayName": "f5 MCP",
							"path": "f5",
							"protocols": ["https"],
							"subscriptionRequired": false,
							"type": "mcp"
						}
					}
				]
			}`,
			wantItems: []APIInventoryItem{
				{
					APIID:                "f5-mcp",
					DisplayName:          "f5 MCP",
					Path:                 "f5",
					Protocols:            []string{"https"},
					SubscriptionRequired: false,
					IsMCPServer:          true,
				},
			},
		},
		{
			name: "regular REST API has empty properties.type, IsMCPServer=false",
			body: `{
				"value": [
					{
						"name": "echo-api",
						"type": "Microsoft.ApiManagement/service/apis",
						"properties": {
							"displayName": "Echo API",
							"path": "echo",
							"protocols": ["https"],
							"subscriptionRequired": true
						}
					}
				]
			}`,
			wantItems: []APIInventoryItem{
				{
					APIID:                "echo-api",
					DisplayName:          "Echo API",
					Path:                 "echo",
					Protocols:            []string{"https"},
					SubscriptionRequired: true,
					IsMCPServer:          false,
				},
			},
		},
		{
			name: "case-insensitive type matching",
			body: `{
				"value": [
					{"name": "x", "properties": {"type": "MCP", "path": "x"}}
				]
			}`,
			wantItems: []APIInventoryItem{
				{APIID: "x", Path: "x", IsMCPServer: true},
			},
		},
		{
			name: "nextLink propagated when present",
			body: `{
				"value": [],
				"nextLink": "https://management.azure.com/foo?api-version=2024-06-01-preview&$skiptoken=abc"
			}`,
			wantNextLink: "https://management.azure.com/foo?api-version=2024-06-01-preview&$skiptoken=abc",
		},
		{
			name:      "malformed JSON returns error",
			body:      `{"value":[`,
			wantItems: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items, nextLink, err := parseAPIListPage([]byte(tc.body))
			if tc.name == "malformed JSON returns error" {
				if err == nil {
					t.Fatal("expected error for malformed JSON, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if nextLink != tc.wantNextLink {
				t.Errorf("nextLink = %q, want %q", nextLink, tc.wantNextLink)
			}
			if len(items) != len(tc.wantItems) {
				t.Fatalf("got %d items, want %d", len(items), len(tc.wantItems))
			}
			for i, want := range tc.wantItems {
				got := items[i]
				if got.APIID != want.APIID || got.DisplayName != want.DisplayName ||
					got.Path != want.Path || got.SubscriptionRequired != want.SubscriptionRequired ||
					got.IsMCPServer != want.IsMCPServer {
					t.Errorf("item[%d] = %+v, want %+v", i, got, want)
				}
				if len(got.Protocols) != len(want.Protocols) {
					t.Errorf("item[%d] protocols = %v, want %v", i, got.Protocols, want.Protocols)
				}
			}
		})
	}
}
