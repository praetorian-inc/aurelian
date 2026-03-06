package enrichers

import (
	"testing"
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
