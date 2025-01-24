package test

import (
	"testing"

	"github.com/praetorian-inc/nebula/pkg/stages"
)

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		rawURL  string
		want    string
		wantErr bool
	}{
		{"https://example.com/repo/image:tag", "example.com", false},
		{"http://example.com/repo/image:tag", "example.com", false},
		{"example.com/repo/image:tag", "example.com", false},
		{"example.com:5000/repo/image:tag", "example.com:5000", false},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			got, err := stages.DockerExtractDomain(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestExtractContainer(t *testing.T) {
	tests := []struct {
		rawURL  string
		want    string
		wantErr bool
	}{
		{"https://example.com/repo/image:tag", "image:tag", false},
		{"http://example.com/repo/image:tag", "image:tag", false},
		{"example.com/repo/image:tag", "image:tag", false},
		{"example.com:5000/repo/image:tag", "image:tag", false},
		{"invalid-url", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			got, err := stages.DockerExtractContainer(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractContainer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestExtractRegion(t *testing.T) {
	tests := []struct {
		rawURL  string
		want    string
		wantErr bool
	}{
		{"https://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo/image:tag", "us-west-2", false},
		{"https://123456789012.dkr.ecr.eu-central-1.amazonaws.com/repo/image:tag", "eu-central-1", false},
		{"https://ecr.us-east-1.amazonaws.com/repo/image:tag", "us-east-1", false},
		{"https://example.com/repo/image:tag", "", true},
		{"invalid-url", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			got, err := stages.DockerExtractRegion(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractRegion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractRegion() = %v, want %v", got, tt.want)
			}
		})
	}
}
