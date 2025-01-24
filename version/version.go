package version

import "fmt"

var (
	// Version is the current version of Nebula, set via build flags
	Version = "dev"

	// Commit is the git commit hash, set via build flags
	Commit = "none"

	// BuildTime is the build timestamp, set via build flags
	BuildTime = "unknown"
)

// FullVersion returns the full version string
func FullVersion() string {
	return fmt.Sprintf("Nebula %s, build %s, built at %s", Version, Commit, BuildTime)
}

func AbbreviatedVersion() string {
	return fmt.Sprintf("%s-%s", Version, Commit)
}
