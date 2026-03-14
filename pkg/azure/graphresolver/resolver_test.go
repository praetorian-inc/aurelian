package graphresolver

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterValidUUIDs_RemovesNonUUIDValues(t *testing.T) {
	input := []string{
		"All",
		"None",
		"GuestsOrExternalUsers",
		"",
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"not-a-uuid",
		"12345678-1234-1234-1234-123456789012",
	}

	result := filterValidUUIDs(input)

	assert.Equal(t, []string{
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"12345678-1234-1234-1234-123456789012",
	}, result)
}

func TestFilterValidUUIDs_EmptyInput(t *testing.T) {
	result := filterValidUUIDs(nil)
	assert.Empty(t, result)
}

func TestFilterValidUUIDs_AllSpecialValues(t *testing.T) {
	result := filterValidUUIDs([]string{"All", "None", "GuestsOrExternalUsers"})
	assert.Empty(t, result)
}

func TestFilterValidUUIDs_DeduplicatesUUIDs(t *testing.T) {
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	result := filterValidUUIDs([]string{uuid, uuid, uuid})
	require.Len(t, result, 1)
	assert.Equal(t, uuid, result[0])
}

func TestFilterValidUUIDs_CaseInsensitiveUUID(t *testing.T) {
	upper := "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
	lower := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	result := filterValidUUIDs([]string{upper, lower})
	// Both are valid UUIDs with different case, so both should be included
	assert.Len(t, result, 2)
}

func TestFilterValidUUIDs_InvalidFormats(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"too short", "a1b2c3d4"},
		{"missing dashes", "a1b2c3d4e5f67890abcdef1234567890"},
		{"wrong dash positions", "a1b2c3d4e5f6-7890-abcd-ef12-34567890"},
		{"contains non-hex", "g1b2c3d4-e5f6-7890-abcd-ef1234567890"},
		{"spaces", "a1b2c3d4 -e5f6-7890-abcd-ef1234567890"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterValidUUIDs([]string{tt.input})
			assert.Empty(t, result)
		})
	}
}

func TestFallbackEntity(t *testing.T) {
	t.Run("user fallback", func(t *testing.T) {
		entity := fallbackEntity("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "user")
		assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", entity.ID)
		assert.Equal(t, "user", entity.Type)
		assert.Equal(t, "Unknown user (a1b2c3d4)", entity.DisplayName)
	})

	t.Run("group fallback", func(t *testing.T) {
		entity := fallbackEntity("12345678-1234-1234-1234-123456789012", "group")
		assert.Equal(t, "group", entity.Type)
		assert.Equal(t, "Unknown group (12345678)", entity.DisplayName)
	})

	t.Run("application fallback", func(t *testing.T) {
		entity := fallbackEntity("abcdef12-3456-7890-abcd-ef1234567890", "application")
		assert.Equal(t, "application", entity.Type)
		assert.Equal(t, "Unknown application (abcdef12)", entity.DisplayName)
	})

	t.Run("role fallback", func(t *testing.T) {
		entity := fallbackEntity("deadbeef-dead-beef-dead-beefdeadbeef", "role")
		assert.Equal(t, "role", entity.Type)
		assert.Equal(t, "Unknown role (deadbeef)", entity.DisplayName)
	})

	t.Run("short uuid truncation", func(t *testing.T) {
		entity := fallbackEntity("abc", "user")
		assert.Equal(t, "Unknown user (abc)", entity.DisplayName)
	})
}

func TestBuildAppEntity(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		name := "My Application"
		desc := "A test application"
		appID := "app-id-123"

		entity := buildAppEntity("uuid-123", &name, &desc, &appID)

		assert.Equal(t, "uuid-123", entity.ID)
		assert.Equal(t, "application", entity.Type)
		assert.Equal(t, "My Application", entity.DisplayName)
		assert.Equal(t, "A test application", entity.Description)
		assert.Equal(t, "app-id-123", entity.ExtraInfo["appId"])
	})

	t.Run("nil fields", func(t *testing.T) {
		entity := buildAppEntity("uuid-123", nil, nil, nil)
		assert.Equal(t, "uuid-123", entity.ID)
		assert.Equal(t, "application", entity.Type)
		assert.Empty(t, entity.DisplayName)
		assert.Empty(t, entity.Description)
		assert.Nil(t, entity.ExtraInfo)
	})

	t.Run("only display name", func(t *testing.T) {
		name := "App Name"
		entity := buildAppEntity("uuid-456", &name, nil, nil)
		assert.Equal(t, "App Name", entity.DisplayName)
		assert.Empty(t, entity.Description)
		assert.Nil(t, entity.ExtraInfo)
	})
}

func TestResolverCaching(t *testing.T) {
	r := &Resolver{
		cache: make(map[string]output.ResolvedEntity),
	}

	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	cachedEntity := output.ResolvedEntity{
		ID:          uuid,
		Type:        "user",
		DisplayName: "Cached User",
	}

	// Pre-populate cache
	r.cache[uuid] = cachedEntity

	callCount := 0
	result := r.cachedResolve(context.Background(), uuid, "user", func(_ context.Context, _ string) output.ResolvedEntity {
		callCount++
		return output.ResolvedEntity{DisplayName: "Fresh User"}
	})

	assert.Equal(t, "Cached User", result.DisplayName)
	assert.Equal(t, 0, callCount, "should not call resolver when cached")
}
