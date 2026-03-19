package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func TestParseResourceGroup(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		want       string
	}{
		{
			name:       "standard resource ID",
			resourceID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myRG/providers/Microsoft.Web/sites/myApp",
			want:       "myRG",
		},
		{
			name:       "empty string",
			resourceID: "",
			want:       "",
		},
		{
			name:       "no resource group segment",
			resourceID: "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Web/sites/myApp",
			want:       "",
		},
		{
			name:       "case insensitive resourcegroups",
			resourceID: "/subscriptions/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/myRG/providers/Microsoft.Web/sites/myApp",
			want:       "myRG",
		},
		{
			name:       "mixed case resourceGroups",
			resourceID: "/subscriptions/sub-id/ResourceGroups/TestRG/providers/Microsoft.Sql/servers/myServer",
			want:       "TestRG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseResourceGroup(tt.resourceID)
			if got != tt.want {
				t.Errorf("ParseResourceGroup(%q) = %q, want %q", tt.resourceID, got, tt.want)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{
			name:   "short string unchanged",
			s:      "hello",
			maxLen: 10,
			want:   "hello",
		},
		{
			name:   "exact length unchanged",
			s:      "hello",
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "long string truncated",
			s:      "hello world this is a long string",
			maxLen: 11,
			want:   "hello world...",
		},
		{
			name:   "empty string",
			s:      "",
			maxLen: 5,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateString(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("TruncateString(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestExtractHTMLTitle(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "standard title",
			body: "<html><head><title>My Page</title></head><body></body></html>",
			want: "My Page",
		},
		{
			name: "title with attributes",
			body: `<html><head><title lang="en">Attributed Title</title></head></html>`,
			want: "Attributed Title",
		},
		{
			name: "no title tag",
			body: "<html><head></head><body>No title here</body></html>",
			want: "",
		},
		{
			name: "empty title",
			body: "<html><title></title></html>",
			want: "",
		},
		{
			name: "mixed case title tags",
			body: "<HTML><HEAD><TITLE>Upper Case</TITLE></HEAD></HTML>",
			want: "Upper Case",
		},
		{
			name: "title with whitespace",
			body: "<title>  Spaced Title  </title>",
			want: "Spaced Title",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractHTMLTitle(tt.body)
			if got != tt.want {
				t.Errorf("ExtractHTMLTitle(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestDerefString(t *testing.T) {
	t.Run("nil returns empty string", func(t *testing.T) {
		if got := derefString(nil); got != "" {
			t.Errorf("derefString(nil) = %q, want %q", got, "")
		}
	})
	t.Run("non-nil returns value", func(t *testing.T) {
		s := "hello"
		if got := derefString(&s); got != "hello" {
			t.Errorf("derefString(&%q) = %q, want %q", s, got, "hello")
		}
	})
}

func TestDerefInt32(t *testing.T) {
	t.Run("nil returns zero", func(t *testing.T) {
		if got := derefInt32(nil); got != 0 {
			t.Errorf("derefInt32(nil) = %d, want 0", got)
		}
	})
	t.Run("non-nil returns value", func(t *testing.T) {
		v := int32(42)
		if got := derefInt32(&v); got != 42 {
			t.Errorf("derefInt32(&42) = %d, want 42", got)
		}
	})
}

func TestHTTPProbe(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "OK")
		}))
		defer srv.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		cmd := HTTPProbe(client, srv.URL, "curl "+srv.URL, "test probe", "should return 200")

		if cmd.ExitCode != 0 {
			t.Errorf("expected ExitCode 0, got %d (error: %s)", cmd.ExitCode, cmd.Error)
		}
		if !strings.Contains(cmd.ActualOutput, "HTTP 200") {
			t.Errorf("expected ActualOutput to contain 'HTTP 200', got %q", cmd.ActualOutput)
		}
	})

	t.Run("connection error", func(t *testing.T) {
		client := &http.Client{Timeout: 1 * time.Second}
		cmd := HTTPProbe(client, "http://127.0.0.1:1", "curl fail", "test", "")

		if cmd.ExitCode != 1 {
			t.Errorf("expected ExitCode 1, got %d", cmd.ExitCode)
		}
		if cmd.Error == "" {
			t.Error("expected non-empty Error")
		}
	})
}

func TestTCPProbe(t *testing.T) {
	t.Run("success with open port", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		port := ln.Addr().(*net.TCPAddr).Port
		cmd := TCPProbe("127.0.0.1", port, 2*time.Second)

		if cmd.ExitCode != 0 {
			t.Errorf("expected ExitCode 0, got %d (error: %s)", cmd.ExitCode, cmd.Error)
		}
		if !strings.Contains(cmd.ActualOutput, "succeeded") {
			t.Errorf("expected 'succeeded' in output, got %q", cmd.ActualOutput)
		}
	})

	t.Run("failure with closed port", func(t *testing.T) {
		// Listen and immediately close to get a port that is not in use.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()

		cmd := TCPProbe("127.0.0.1", port, 1*time.Second)

		if cmd.ExitCode != 1 {
			t.Errorf("expected ExitCode 1, got %d", cmd.ExitCode)
		}
		if !strings.Contains(cmd.ActualOutput, "failed") {
			t.Errorf("expected 'failed' in output, got %q", cmd.ActualOutput)
		}
	})
}

func TestBuildFirewallRulesCommand(t *testing.T) {
	t.Run("successful callback with rules", func(t *testing.T) {
		rules := []firewallRuleOutput{
			{Name: "AllowAll", StartIPAddress: "0.0.0.0", EndIPAddress: "255.255.255.255"},
		}
		cmd := buildFirewallRulesCommand("az sql server firewall-rule list", "List firewall rules", func() ([]firewallRuleOutput, error) {
			return rules, nil
		})

		if cmd.ExitCode != 0 {
			t.Errorf("expected ExitCode 0, got %d", cmd.ExitCode)
		}
		if !strings.Contains(cmd.ActualOutput, "AllowAll") {
			t.Errorf("expected output to contain rule name, got %q", cmd.ActualOutput)
		}
		// Verify it's valid JSON.
		var parsed []firewallRuleOutput
		if err := json.Unmarshal([]byte(cmd.ActualOutput), &parsed); err != nil {
			t.Errorf("output is not valid JSON: %v", err)
		}
	})

	t.Run("callback returns error", func(t *testing.T) {
		cmd := buildFirewallRulesCommand("az sql server firewall-rule list", "List firewall rules", func() ([]firewallRuleOutput, error) {
			return nil, fmt.Errorf("sdk error")
		})

		if cmd.ExitCode != 1 {
			t.Errorf("expected ExitCode 1, got %d", cmd.ExitCode)
		}
		if !strings.Contains(cmd.Error, "sdk error") {
			t.Errorf("expected error to contain 'sdk error', got %q", cmd.Error)
		}
	})
}

func TestBuildNetworkRulesCommand(t *testing.T) {
	t.Run("empty input returns error command", func(t *testing.T) {
		cfg := plugin.AzureEnricherConfig{Context: context.Background()}
		cmd := buildNetworkRulesCommand(cfg, "az cmd", "desc", "expected", "missing input", []string{"valid", ""}, func(ctx context.Context) (string, error) {
			return "", nil
		})

		if cmd.ExitCode != 1 {
			t.Errorf("expected ExitCode 1, got %d", cmd.ExitCode)
		}
		if cmd.ActualOutput != "missing input" {
			t.Errorf("expected ActualOutput %q, got %q", "missing input", cmd.ActualOutput)
		}
	})

	t.Run("successful callback", func(t *testing.T) {
		cfg := plugin.AzureEnricherConfig{Context: context.Background()}
		cmd := buildNetworkRulesCommand(cfg, "az cmd", "desc", "expected", "missing", []string{"a", "b"}, func(ctx context.Context) (string, error) {
			return "network rules output", nil
		})

		if cmd.ExitCode != 0 {
			t.Errorf("expected ExitCode 0, got %d", cmd.ExitCode)
		}
		if cmd.ActualOutput != "network rules output" {
			t.Errorf("expected ActualOutput %q, got %q", "network rules output", cmd.ActualOutput)
		}
	})
}

func TestFormatNetworkRuleSet(t *testing.T) {
	t.Run("nil input returns null", func(t *testing.T) {
		if got := formatNetworkRuleSet(nil, "SomeType", ""); got != "null" {
			t.Errorf("expected %q, got %q", "null", got)
		}
	})

	t.Run("populated input", func(t *testing.T) {
		id := "/subscriptions/sub/resourceGroups/myRG/providers/Microsoft.EventHub/namespaces/ns/networkRuleSets/default"
		name := "default"
		loc := "eastus"
		defaultAction := "Deny"
		trusted := true
		ipMask := "10.0.0.0/24"
		ipAction := "Allow"
		subnetID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"
		ignoreMissing := true

		input := &networkRuleSetInput{
			ID:                          &id,
			Name:                        &name,
			Location:                    &loc,
			DefaultAction:               &defaultAction,
			TrustedServiceAccessEnabled: &trusted,
			IPRules: []networkRuleSetIPRule{
				{IPMask: &ipMask, Action: &ipAction},
			},
			VirtualNetworkRules: []networkRuleSetVNetRule{
				{SubnetID: &subnetID, IgnoreMissingVnetServiceEndpoint: &ignoreMissing},
			},
		}

		result := formatNetworkRuleSet(input, "Microsoft.EventHub/namespaces/networkRuleSets", "")

		// Verify it's valid JSON with expected fields.
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(result), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v\n%s", err, result)
		}
		if parsed["defaultAction"] != "Deny" {
			t.Errorf("expected defaultAction=Deny, got %v", parsed["defaultAction"])
		}
		if parsed["resourceGroup"] != "myRG" {
			t.Errorf("expected resourceGroup=myRG, got %v", parsed["resourceGroup"])
		}
		if parsed["trustedServiceAccessEnabled"] != true {
			t.Errorf("expected trustedServiceAccessEnabled=true, got %v", parsed["trustedServiceAccessEnabled"])
		}
	})
}

func TestEnrichEventGridPOSTEndpoint(t *testing.T) {
	t.Run("basic command construction with explicit endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		// Use the test server URL as the endpoint.
		cmds, err := enrichEventGridPOSTEndpoint(context.Background(), "myTopic", "eastus", srv.URL+"/api/events", "POST test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cmds) != 1 {
			t.Fatalf("expected 1 command, got %d", len(cmds))
		}
		if cmds[0].ExitCode != 0 {
			t.Errorf("expected ExitCode 0, got %d (error: %s)", cmds[0].ExitCode, cmds[0].Error)
		}
		if !strings.Contains(cmds[0].ActualOutput, "HTTP 401") {
			t.Errorf("expected 'HTTP 401' in output, got %q", cmds[0].ActualOutput)
		}
	})

	t.Run("nil returned for empty location and name", func(t *testing.T) {
		cmds, err := enrichEventGridPOSTEndpoint(context.Background(), "", "", "", "POST test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cmds != nil {
			t.Errorf("expected nil commands for empty inputs, got %d", len(cmds))
		}
	})
}
