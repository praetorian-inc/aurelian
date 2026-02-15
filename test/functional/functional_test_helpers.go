package functional

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// Default timeout for nebula commands
	DefaultTestTimeout = 5 * time.Minute
	// Nebula binary execution command
	NebulaCommand = "go"
	NebulaArgs    = "run main.go"
)

// TestCommand represents a nebula command to be tested
type TestCommand struct {
	Platform    string            // aws, azure, gcp
	Category    string            // recon, analyze, etc.
	Module      string            // specific module name
	Args        []string          // additional arguments
	Timeout     time.Duration     // command timeout
	Environment map[string]string // environment variables
	ExpectedToFail  bool              // whether the command is expected to fail
}

// CommandResult holds the result of a command execution
type CommandResult struct {
	Command    *TestCommand
	ExitCode   int
	Stdout     string
	Stderr     string
	Duration   time.Duration
	Error      error
	HasErrors  bool
	ErrorLines []string
}

// ErrorPattern defines patterns to detect errors in command output
var ErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)error:`),
	regexp.MustCompile(`(?i)failed:`),
	regexp.MustCompile(`(?i)panic:`),
	regexp.MustCompile(`(?i)fatal:`),
	regexp.MustCompile(`(?i)exception:`),
	regexp.MustCompile(`(?i)stack trace:`),
	regexp.MustCompile(`(?i)runtime error:`),
}

// NewTestCommand creates a new TestCommand with default settings
func NewTestCommand(platform, category, module string) *TestCommand {
	return &TestCommand{
		Platform:    platform,
		Category:    category,
		Module:      module,
		Args:        []string{},
		Timeout:     DefaultTestTimeout,
		Environment: make(map[string]string),
		ExpectedToFail:  false,
	}
}

// WithArgs adds command-line arguments
func (tc *TestCommand) WithArgs(args ...string) *TestCommand {
	tc.Args = append(tc.Args, args...)
	return tc
}

// WithTimeout sets a custom timeout
func (tc *TestCommand) WithTimeout(timeout time.Duration) *TestCommand {
	tc.Timeout = timeout
	return tc
}

// WithEnv sets environment variables
func (tc *TestCommand) WithEnv(key, value string) *TestCommand {
	tc.Environment[key] = value
	return tc
}

// WithProfile sets AWS profile or Azure subscription
func (tc *TestCommand) WithProfile(profile string) *TestCommand {
	switch tc.Platform {
	case "aws":
		// Different AWS commands have different profile flag support
		if tc.Category == "analyze" {
			// Use environment variable for analyze commands
			tc.WithEnv("AWS_PROFILE", profile)
		} else if tc.Module == "summary" {
			// Summary command needs profile via environment AND flag
			tc.WithEnv("AWS_PROFILE", profile)
		} else {
			// Most recon commands support -p
			tc.Args = append(tc.Args, "-p", profile)
		}
	case "azure":
		tc.Args = append(tc.Args, "--subscription-id", profile)
	}
	return tc
}

// ExpectFailure marks the command as expected to fail
func (tc *TestCommand) ExpectFailure() *TestCommand {
	tc.ExpectedToFail = true
	return tc
}

// BuildCommand constructs the full command arguments
func (tc *TestCommand) BuildCommand() []string {
	args := strings.Split(NebulaArgs, " ")
	args = append(args, tc.Platform)
	if tc.Category != "" {
		args = append(args, tc.Category)
	}
	if tc.Module != "" {
		args = append(args, tc.Module)
	}
	args = append(args, tc.Args...)
	return args
}

// String returns a string representation of the command
func (tc *TestCommand) String() string {
	return fmt.Sprintf("nebula %s %s %s %s", tc.Platform, tc.Category, tc.Module, strings.Join(tc.Args, " "))
}

// RunNebulaCommand executes a nebula command and returns the result
func RunNebulaCommand(t *testing.T, cmd *TestCommand) *CommandResult {
	t.Logf("Executing: %s", cmd.String())
	
	// Get the project root directory
	projectRoot, err := getProjectRoot()
	require.NoError(t, err, "Failed to find project root")
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cmd.Timeout)
	defer cancel()
	
	// Build command
	args := cmd.BuildCommand()
	execCmd := exec.CommandContext(ctx, NebulaCommand, args...)
	execCmd.Dir = projectRoot
	
	// Set environment variables
	execCmd.Env = os.Environ()
	for key, value := range cmd.Environment {
		execCmd.Env = append(execCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Record start time
	startTime := time.Now()
	
	// Execute command
	stdout, stderr, err := runCommandWithOutput(execCmd)
	duration := time.Since(startTime)
	
	// Determine exit code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}
	
	// Check for errors in output
	hasErrors, errorLines := detectErrorsInOutput(stdout, stderr)
	
	result := &CommandResult{
		Command:    cmd,
		ExitCode:   exitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		Duration:   duration,
		Error:      err,
		HasErrors:  hasErrors,
		ErrorLines: errorLines,
	}
	
	t.Logf("Command completed in %v with exit code %d", duration, exitCode)
	if hasErrors {
		t.Logf("Detected %d error lines in output", len(errorLines))
	}
	
	return result
}

// ValidateCommandResult validates the result of a command execution
func ValidateCommandResult(t *testing.T, result *CommandResult) {
	cmd := result.Command
	
	if cmd.ExpectedToFail {
		// Command was expected to fail
		if result.ExitCode == 0 && !result.HasErrors {
			t.Errorf("Command %s was expected to fail but succeeded", cmd.String())
		}
	} else {
		// Command was expected to succeed
		if result.ExitCode != 0 {
			t.Errorf("Command %s failed with exit code %d", cmd.String(), result.ExitCode)
			t.Logf("Stderr: %s", result.Stderr)
		}
		
		if result.HasErrors {
			t.Errorf("Command %s succeeded but output contains errors:", cmd.String())
			for _, errorLine := range result.ErrorLines {
				t.Errorf("  Error: %s", errorLine)
			}
		}
		
		if result.Error != nil && result.Error != context.DeadlineExceeded {
			t.Errorf("Command %s failed with error: %v", cmd.String(), result.Error)
		}
		
		if result.Error == context.DeadlineExceeded {
			t.Errorf("Command %s timed out after %v", cmd.String(), cmd.Timeout)
		}
	}
}

// ValidateJSONOutput validates that the output contains valid JSON or indicates file output
func ValidateJSONOutput(t *testing.T, result *CommandResult) {
	// Check if command indicates JSON was written to file
	if strings.Contains(result.Stdout, "JSON output written to:") {
		t.Logf("Command %s wrote JSON to file (as expected)", result.Command.String())
		return
	}
	
	if result.Stdout == "" {
		t.Errorf("Command %s produced no stdout output", result.Command.String())
		return
	}
	
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	validJSONLines := 0
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Skip banner and status lines
		if strings.Contains(line, "▗▖") || strings.Contains(line, "modules") || 
		   strings.Contains(line, "Running module") || strings.Contains(line, "Cache Stat") {
			continue
		}
		
		// Try to parse as JSON
		var jsonData interface{}
		if err := json.Unmarshal([]byte(line), &jsonData); err == nil {
			validJSONLines++
		}
	}
	
	if validJSONLines == 0 {
		t.Errorf("Command %s produced no valid JSON output", result.Command.String())
		t.Logf("Output: %s", result.Stdout)
	}
}

// runCommandWithOutput executes a command and captures stdout and stderr
func runCommandWithOutput(cmd *exec.Cmd) (string, string, error) {
	var stdoutBuf, stderrBuf strings.Builder
	
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	
	err := cmd.Run()
	
	return stdoutBuf.String(), stderrBuf.String(), err
}

// detectErrorsInOutput scans command output for error patterns
func detectErrorsInOutput(stdout, stderr string) (bool, []string) {
	var errorLines []string
	hasErrors := false
	
	// Check both stdout and stderr
	allOutput := stdout + "\n" + stderr
	scanner := bufio.NewScanner(strings.NewReader(allOutput))
	
	for scanner.Scan() {
		line := scanner.Text()
		
		for _, pattern := range ErrorPatterns {
			if pattern.MatchString(line) {
				errorLines = append(errorLines, strings.TrimSpace(line))
				hasErrors = true
				break
			}
		}
	}
	
	return hasErrors, errorLines
}

// getProjectRoot finds the project root directory
func getProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	
	// Look for go.mod or main.go to identify project root
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
			return dir, nil
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	
	return "", fmt.Errorf("could not find project root")
}

// SkipIfCredentialsMissing skips the test if required credentials are not available
func SkipIfCredentialsMissing(t *testing.T, platform string, profile string) {
	switch platform {
	case "aws":
		// Check if AWS profile exists
		cmd := exec.Command("aws", "configure", "list-profiles")
		output, err := cmd.Output()
		if err != nil {
			t.Skipf("AWS CLI not available: %v", err)
		}
		
		profiles := strings.Split(string(output), "\n")
		profileExists := false
		for _, p := range profiles {
			if strings.TrimSpace(p) == profile {
				profileExists = true
				break
			}
		}
		
		if !profileExists {
			t.Skipf("AWS profile '%s' not found", profile)
		}
		
	case "azure":
		// Check if Azure CLI is available and user is logged in
		cmd := exec.Command("az", "account", "show")
		if err := cmd.Run(); err != nil {
			t.Skipf("Azure CLI not available or not logged in: %v", err)
		}
		
		// Check if specific subscription is accessible
		cmd = exec.Command("az", "account", "set", "--subscription", profile)
		if err := cmd.Run(); err != nil {
			t.Skipf("Azure subscription '%s' not accessible: %v", profile, err)
		}
	}
}