package orgpolicies

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	awstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type AWSOrganizationPolicies struct {
	*base.AwsReconLink
}

type OrgUnit struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Children []OrgUnit `json:"children"`
	Accounts []Account `json:"accounts"`
}

type Account struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

func NewAWSOrganizationPolicies(configs ...cfg.Config) chain.Link {
	slog.Debug("Creating AWSOrganizationPolicies link")
	ad := &AWSOrganizationPolicies{}
	slog.Debug("Config:", configs)
	ad.AwsReconLink = base.NewAwsReconLink(ad, configs...)
	return ad
}

func (ad *AWSOrganizationPolicies) Initialize() error {
	slog.Debug("Initializing AWSOrganizationPolicies")
	if err := ad.AwsReconLink.Initialize(); err != nil {
		return err
	}
	return nil
}

func (ad *AWSOrganizationPolicies) Process(resource string) error {
	slog.Debug("Begin processing AWSOrganizationPolicies", "regions", ad.Regions, "profile", ad.Profile)
	org_hierarchy, error := ad.CollectOrganizationHierarchy()
	if error != nil {
		slog.Error("Error collecting organization hierarchy", "error", error)
		return error
	}
	ad.Send(org_hierarchy)
	return nil
}

func (a *AWSOrganizationPolicies) CollectOrganizationHierarchy() (*OrgUnit, error) {
	slog.Debug("Getting Account Authorization Details", "profile", a.Profile)
	print("Getting Account Authorization Details", "profile", a.Profile)

	// We'll use us-east-1 for IAM since it's a global service
	region := "us-east-1"

	slog.Debug("Getting Account Authorization Details: Set region to ", "region", region)

	config, err := a.GetConfig(region, options.JanusParamAdapter(a.Params()))
	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return nil, err
	}

	client := organizations.NewFromConfig(config)
	roots, err := client.ListRoots(context.TODO(), &organizations.ListRootsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list roots: %w", err)
	}
	if len(roots.Roots) == 0 {
		return nil, fmt.Errorf("no root OU found")
	}
	rootOU := OrgUnit{
		ID:   *roots.Roots[0].Id,
		Name: *roots.Roots[0].Name,
	}
	// if err := processOU(client, &rootOU); err != nil {
	// 	return nil, err
	// }
	return &rootOU, nil
}

func processOU(client *organizations.Client, ou *OrgUnit) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	var childOUs []awstypes.OrganizationalUnit
	var nextToken *string

	for {
		input := &organizations.ListOrganizationalUnitsForParentInput{
			ParentId: &ou.ID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListOrganizationalUnitsForParent(context.TODO(), input)
		if err != nil {
			return fmt.Errorf("failed to list child OUs for %s: %w", ou.ID, err)
		}
		childOUs = append(childOUs, output.OrganizationalUnits...)
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	for _, childOU := range childOUs {
		wg.Add(1)
		go func(child awstypes.OrganizationalUnit) {
			defer wg.Done()
			childUnit := OrgUnit{
				ID:   *child.Id,
				Name: *child.Name,
			}
			if err := processOU(client, &childUnit); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			ou.Children = append(ou.Children, childUnit)
			mu.Unlock()
		}(childOU)
	}

	var accounts []awstypes.Account
	nextToken = nil
	for {
		input := &organizations.ListAccountsForParentInput{
			ParentId: &ou.ID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListAccountsForParent(context.TODO(), input)
		if err != nil {
			return fmt.Errorf("failed to list accounts for %s: %w", ou.ID, err)
		}
		accounts = append(accounts, output.Accounts...)
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	for _, acct := range accounts {
		account := Account{
			ID:     *acct.Id,
			Name:   *acct.Name,
			Email:  *acct.Email,
			Status: string(acct.Status),
		}
		ou.Accounts = append(ou.Accounts, account)
		slog.Debug("Account found in OU:", "account", account)
	}

	wg.Wait()
	if len(errs) > 0 {
		return fmt.Errorf("errors occurred while processing OUs: %v", errs)
	}
	return nil
}
