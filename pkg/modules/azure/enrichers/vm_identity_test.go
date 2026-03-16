package enrichers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUUIDPattern(t *testing.T) {
	assert.True(t, uuidPattern.MatchString("8e3af657-a8ff-443c-a75c-2fe8c4bcb635"))
	assert.True(t, uuidPattern.MatchString("B24988AC-6180-42A0-AB88-20F7382DD24C"))
	assert.False(t, uuidPattern.MatchString("not-a-uuid"))
	assert.False(t, uuidPattern.MatchString(""))
	assert.False(t, uuidPattern.MatchString("' OR 1=1 --"))
}

func TestPrivilegedRoleIDs_ExactSet(t *testing.T) {
	assert.Len(t, privilegedRoleIDs, 3)
	assert.True(t, privilegedRoleIDs["8e3af657-a8ff-443c-a75c-2fe8c4bcb635"], "Owner missing")
	assert.True(t, privilegedRoleIDs["b24988ac-6180-42a0-ab88-20f7382dd24c"], "Contributor missing")
	assert.True(t, privilegedRoleIDs["18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"], "User Access Admin missing")
}
