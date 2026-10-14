package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/serve"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as a subprocess evaluator, reading NDJSON requests from stdin",
	Long: `Start Aurelian in subprocess evaluator mode. Reads newline-delimited JSON
requests from stdin and writes NDJSON responses to stdout.

Supported methods:
  capabilities   - returns the list of supported methods
  check_specific - evaluates a single (actor, action, resource) triple
  verify_pairs   - batch-evaluates multiple (actor, action, resource) triples

Requires a GAAD JSON file (--gaad-file) containing the IAM authorization
account details to evaluate against.`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().String("gaad-file", "", "Path to GAAD JSON file (required)")
	_ = serveCmd.MarkFlagRequired("gaad-file")
}

func runServe(cmd *cobra.Command, args []string) error {
	gaadFile, _ := cmd.Flags().GetString("gaad-file")

	// Load GAAD data
	gaad, err := loadGaadFile(gaadFile)
	if err != nil {
		return fmt.Errorf("loading GAAD file: %w", err)
	}

	// Build evaluator and state
	orgPolicies := orgpolicies.NewDefaultOrgPolicies()
	policyData := iam.NewPolicyData(gaad, orgPolicies, nil, nil)
	evaluator := iam.NewPolicyEvaluator(policyData)
	state := serve.NewGaadState(gaad, orgPolicies)

	handler := serve.NewHandler(evaluator, state)
	return handler.Serve(os.Stdin, os.Stdout)
}

// loadGaadFile reads and parses a GAAD JSON file.
func loadGaadFile(path string) (*types.AuthorizationAccountDetails, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var gaad types.AuthorizationAccountDetails
	if err := json.Unmarshal(data, &gaad); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return &gaad, nil
}
