package orgpolicies

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/rs/zerolog/log"
)

type SCPData struct {
	PolicySummary types.PolicySummary `json:"policySummary"`
	PolicyContent types.Policy        `json:"policyContent"`
	Targets       []SCPTarget         `json:"targets"`
}

type SCPTarget struct {
	TargetID string `json:"targetId"`
	Name     string `json:"name"`
	Type     string `json:"type"`
}

func CollectSCPs(profile string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
		config.WithRegion("us-east-1"),
		config.WithRetryMode(aws.RetryModeStandard),
		config.WithRetryMaxAttempts(10),
	)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	client := organizations.NewFromConfig(cfg)
	if err := os.MkdirAll("./analysis", 0755); err != nil {
		return fmt.Errorf("failed to create analysis directory: %w", err)
	}
	var scpDataList []SCPData
	policies, err := listPolicies(client)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, policy := range policies {
		wg.Add(1)
		go func(policy types.PolicySummary) {
			defer wg.Done()
			log.Debug().Str("policy", *policy.Name).Msg("processing policy")
			rawContent, err := getPolicyContent(client, *policy.Id)
			if err != nil {
				log.Warn().Err(err).Str("policy", *policy.Name).Msg("failed to get policy content")
				return
			}
			var policyContent types.Policy
			if err := json.Unmarshal([]byte(rawContent), &policyContent); err != nil {
				log.Warn().Err(err).Str("policy", *policy.Name).Msg("failed to parse policy content")
				return
			}
			targets, err := listPolicyTargets(client, *policy.Id)
			if err != nil {
				log.Warn().Err(err).Str("policy", *policy.Name).Msg("failed to get policy targets")
				return
			}
			scpData := SCPData{
				PolicySummary: policy,
				PolicyContent: policyContent,
				Targets:       targets,
			}
			mu.Lock()
			scpDataList = append(scpDataList, scpData)
			mu.Unlock()
		}(policy)
	}
	wg.Wait()

	outputFile := filepath.Join("./analysis", "organization-scps.json")
	jsonData, err := json.MarshalIndent(scpDataList, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SCP data: %w", err)
	}
	if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write SCP data: %w", err)
	}
	log.Info().Int("policies", len(scpDataList)).Str("file", outputFile).Msg("SCP data collected")
	return nil
}

func listPolicies(client *organizations.Client) ([]types.PolicySummary, error) {
	var policies []types.PolicySummary
	var nextToken *string
	for {
		input := &organizations.ListPoliciesInput{
			Filter: types.PolicyTypeServiceControlPolicy,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListPolicies(context.TODO(), input)
		if err != nil {
			return nil, fmt.Errorf("failed to list policies: %w", err)
		}
		policies = append(policies, output.Policies...)
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return policies, nil
}

func getPolicyContent(client *organizations.Client, policyID string) (string, error) {
	input := &organizations.DescribePolicyInput{
		PolicyId: &policyID,
	}
	output, err := client.DescribePolicy(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe policy: %w", err)
	}
	return *output.Policy.Content, nil
}

func listPolicyTargets(client *organizations.Client, policyID string) ([]SCPTarget, error) {
	var targets []SCPTarget
	var nextToken *string
	for {
		input := &organizations.ListTargetsForPolicyInput{
			PolicyId: &policyID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListTargetsForPolicy(context.TODO(), input)
		if err != nil {
			return nil, fmt.Errorf("failed to list policy targets: %w", err)
		}
		for _, target := range output.Targets {
			targets = append(targets, SCPTarget{
				TargetID: *target.TargetId,
				Name:     *target.Name,
				Type:     string(target.Type),
			})
		}
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return targets, nil
}
