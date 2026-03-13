package recon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- mfaDeviceARN tests ---

func TestGetConsole_MFADeviceARN(t *testing.T) {
	tests := []struct {
		name        string
		callerARN   string
		expectedARN string
		wantErr     bool
	}{
		{
			name:        "valid IAM user ARN",
			callerARN:   "arn:aws:iam::123456789012:user/alice",
			expectedARN: "arn:aws:iam::123456789012:mfa/alice",
		},
		{
			name:        "ARN with path - uses everything after first slash",
			callerARN:   "arn:aws:iam::123456789012:user/path/to/username",
			expectedARN: "arn:aws:iam::123456789012:mfa/path/to/username",
		},
		{
			name:      "short malformed ARN fewer than 6 parts",
			callerARN: "arn:aws:iam::123456789012",
			wantErr:   true,
		},
		{
			name:      "ARN resource part without slash",
			callerARN: "arn:aws:iam::123456789012:root",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mfaDeviceARN(tt.callerARN)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedARN, got)
		})
	}
}

// --- extractCreds tests ---

func TestGetConsole_ExtractCreds(t *testing.T) {
	t.Run("valid credentials", func(t *testing.T) {
		expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		keyID := "AKIAIOSFODNN7EXAMPLE"
		secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		token := "session-token-value"

		creds := &ststypes.Credentials{
			AccessKeyId:     &keyID,
			SecretAccessKey: &secretKey,
			SessionToken:    &token,
			Expiration:      &expiry,
		}

		gotID, gotSecret, gotToken, gotExpiry := extractCreds(creds)

		assert.Equal(t, keyID, gotID)
		assert.Equal(t, secretKey, gotSecret)
		assert.Equal(t, token, gotToken)
		assert.Equal(t, expiry, gotExpiry)
	})

	t.Run("nil credentials returns zero values", func(t *testing.T) {
		gotID, gotSecret, gotToken, gotExpiry := extractCreds(nil)

		assert.Empty(t, gotID)
		assert.Empty(t, gotSecret)
		assert.Empty(t, gotToken)
		assert.True(t, gotExpiry.IsZero())
	})

	t.Run("credentials with nil Expiration", func(t *testing.T) {
		keyID := "AKIAIOSFODNN7EXAMPLE"
		secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		token := "session-token-value"

		creds := &ststypes.Credentials{
			AccessKeyId:     &keyID,
			SecretAccessKey: &secretKey,
			SessionToken:    &token,
			Expiration:      nil,
		}

		gotID, gotSecret, gotToken, gotExpiry := extractCreds(creds)

		assert.Equal(t, keyID, gotID)
		assert.Equal(t, secretKey, gotSecret)
		assert.Equal(t, token, gotToken)
		assert.True(t, gotExpiry.IsZero())
	})
}

// --- buildConsoleURL tests ---

func TestGetConsole_BuildConsoleURL(t *testing.T) {
	t.Run("successful federation token flow - includes SessionDuration", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "getSigninToken", r.URL.Query().Get("Action"))
			assert.Equal(t, "3600", r.URL.Query().Get("SessionDuration"), "federation-token must include SessionDuration")
			assert.NotEmpty(t, r.URL.Query().Get("Session"))

			resp := signinTokenResponse{SigninToken: "test-signin-token"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
		}))
		defer srv.Close()

		consoleURL, err := buildConsoleURL(srv.URL, "AKID", "SECRET", "TOKEN", "federation-token", 3600)
		require.NoError(t, err)
		assert.Contains(t, consoleURL, "Action=login")
		assert.Contains(t, consoleURL, "SigninToken=test-signin-token")
	})

	t.Run("successful assume-role flow - no SessionDuration", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "getSigninToken", r.URL.Query().Get("Action"))
			assert.Empty(t, r.URL.Query().Get("SessionDuration"), "assume-role must not include SessionDuration")
			assert.NotEmpty(t, r.URL.Query().Get("Session"))

			resp := signinTokenResponse{SigninToken: "assume-role-token"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
		}))
		defer srv.Close()

		consoleURL, err := buildConsoleURL(srv.URL, "AKID", "SECRET", "TOKEN", "assume-role", 3600)
		require.NoError(t, err)
		assert.Contains(t, consoleURL, "Action=login")
		assert.Contains(t, consoleURL, "SigninToken=assume-role-token")
	})

	t.Run("federation endpoint returns non-200 status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		defer srv.Close()

		_, err := buildConsoleURL(srv.URL, "AKID", "SECRET", "TOKEN", "federation-token", 3600)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403")
	})

	t.Run("federation endpoint returns empty SigninToken", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := signinTokenResponse{SigninToken: ""}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
		}))
		defer srv.Close()

		_, err := buildConsoleURL(srv.URL, "AKID", "SECRET", "TOKEN", "federation-token", 3600)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty signin token")
	})

	t.Run("federation endpoint returns invalid JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not-valid-json{{{")) //nolint:errcheck
		}))
		defer srv.Close()

		_, err := buildConsoleURL(srv.URL, "AKID", "SECRET", "TOKEN", "federation-token", 3600)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding signin token response")
	})
}

// --- Duration validation tests (via Run) ---

func TestGetConsole_DurationValidation(t *testing.T) {
	tests := []struct {
		name     string
		duration int
	}{
		{
			name:     "duration below minimum (899)",
			duration: 899,
		},
		{
			name:     "duration above maximum (129601)",
			duration: 129601,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &GetConsoleModule{}
			m.Duration = tt.duration

			out := pipeline.New[model.AurelianModel]()
			out.Close()

			err := m.Run(plugin.Config{}, out)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "out of range")
		})
	}
}
