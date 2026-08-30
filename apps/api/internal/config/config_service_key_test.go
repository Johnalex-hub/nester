package config

import (
	"strings"
	"testing"
)

// NESTER_SERVICE_API_KEY authenticates service-to-service callers and is
// shared between them, so a weak value is a weak value for every caller at
// once. Startup must refuse it rather than serve with it (nester#1149).
func TestLoadRejectsWeakServiceAPIKey(t *testing.T) {
	const strongJWTSecret = "3f9a7c21b8e45d06af17c9b2e83d5416"

	tests := []struct {
		name       string
		serviceKey string
		wantErr    string
	}{
		{
			name:       "too short",
			serviceKey: "short-service-key",
			wantErr:    "at least 32 characters",
		},
		{
			// Long enough to pass the length check, too few distinct bytes
			// to be a real secret.
			name:       "low entropy",
			serviceKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantErr:    "entropy",
		},
		{
			// Reuse would let any holder of the service key mint arbitrary
			// user JWTs, making every other control on it pointless.
			name:       "reuses the JWT secret",
			serviceKey: strongJWTSecret,
			wantErr:    "must not reuse AUTH_JWT_SECRET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseEnv(t)
			requiredEnv(t)
			t.Setenv("APP_ENV", "development")
			t.Setenv("AUTH_JWT_SECRET", strongJWTSecret)
			t.Setenv("NESTER_SERVICE_API_KEY", tt.serviceKey)

			chdir(t, t.TempDir())

			_, err := Load()
			if err == nil {
				t.Fatalf("expected Load() to fail for a %s service key", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// A strong key must still boot, and an absent key must still boot: an empty
// value disables service auth entirely, which is the safe configuration
// rather than a weak one.
func TestLoadAcceptsStrongOrAbsentServiceAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		serviceKey string
	}{
		{name: "strong key", serviceKey: "b47f2e9c15a83d60472ecb18f95a3d2e"},
		{name: "absent key disables service auth", serviceKey: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseEnv(t)
			requiredEnv(t)
			t.Setenv("APP_ENV", "development")
			t.Setenv("AUTH_JWT_SECRET", "3f9a7c21b8e45d06af17c9b2e83d5416")
			t.Setenv("NESTER_SERVICE_API_KEY", tt.serviceKey)

			chdir(t, t.TempDir())

			if _, err := Load(); err != nil {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}
