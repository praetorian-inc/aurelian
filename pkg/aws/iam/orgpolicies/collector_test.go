package orgpolicies

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	awstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// mockOrganizationsClient implements the OrganizationsClient interface for testing.
type mockOrganizationsClient struct {
	listRootsFunc                        func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	listOrganizationalUnitsForParentFunc func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	listAccountsForParentFunc            func(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
	listPoliciesFunc                     func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	describePolicyFunc                   func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	listTargetsForPolicyFunc             func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

func (m *mockOrganizationsClient) ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if m.listRootsFunc != nil {
		return m.listRootsFunc(ctx, params, optFns...)
	}
	return &organizations.ListRootsOutput{}, nil
}

func (m *mockOrganizationsClient) ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if m.listOrganizationalUnitsForParentFunc != nil {
		return m.listOrganizationalUnitsForParentFunc(ctx, params, optFns...)
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
}

func (m *mockOrganizationsClient) ListAccountsForParent(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	if m.listAccountsForParentFunc != nil {
		return m.listAccountsForParentFunc(ctx, params, optFns...)
	}
	return &organizations.ListAccountsForParentOutput{}, nil
}

func (m *mockOrganizationsClient) ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if m.listPoliciesFunc != nil {
		return m.listPoliciesFunc(ctx, params, optFns...)
	}
	return &organizations.ListPoliciesOutput{}, nil
}

func (m *mockOrganizationsClient) DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if m.describePolicyFunc != nil {
		return m.describePolicyFunc(ctx, params, optFns...)
	}
	return &organizations.DescribePolicyOutput{}, nil
}

func (m *mockOrganizationsClient) ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	if m.listTargetsForPolicyFunc != nil {
		return m.listTargetsForPolicyFunc(ctx, params, optFns...)
	}
	return &organizations.ListTargetsForPolicyOutput{}, nil
}

func TestCollectOrganizationHierarchy_Success(t *testing.T) {
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []awstypes.Root{
					{
						Id:   strPtr("r-root"),
						Name: strPtr("Root"),
					},
				},
			}, nil
		},
		listOrganizationalUnitsForParentFunc: func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			if *params.ParentId == "r-root" {
				return &organizations.ListOrganizationalUnitsForParentOutput{
					OrganizationalUnits: []awstypes.OrganizationalUnit{
						{
							Id:   strPtr("ou-child-1"),
							Name: strPtr("ChildOU"),
						},
					},
				}, nil
			}
			return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
		},
		listAccountsForParentFunc: func(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
			if *params.ParentId == "ou-child-1" {
				return &organizations.ListAccountsForParentOutput{
					Accounts: []awstypes.Account{
						{
							Id:     strPtr("111111111111"),
							Name:   strPtr("TestAccount"),
							Email:  strPtr("test@example.com"),
							Status: awstypes.AccountStatusActive,
						},
					},
				}, nil
			}
			return &organizations.ListAccountsForParentOutput{}, nil
		},
	}

	ctx := context.Background()
	ou, err := collectOrganizationHierarchy(ctx, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ou == nil {
		t.Fatal("expected non-nil OrgUnit")
	}
	if ou.ID != "r-root" {
		t.Errorf("expected root ID r-root, got %s", ou.ID)
	}
	if ou.Name != "Root" {
		t.Errorf("expected root Name Root, got %s", ou.Name)
	}
	if len(ou.Children) != 1 {
		t.Fatalf("expected 1 child OU, got %d", len(ou.Children))
	}
	if ou.Children[0].ID != "ou-child-1" {
		t.Errorf("expected child OU ID ou-child-1, got %s", ou.Children[0].ID)
	}
	if len(ou.Children[0].Accounts) != 1 {
		t.Fatalf("expected 1 account in child OU, got %d", len(ou.Children[0].Accounts))
	}
	if ou.Children[0].Accounts[0].ID != "111111111111" {
		t.Errorf("expected account ID 111111111111, got %s", ou.Children[0].Accounts[0].ID)
	}
}

func TestCollectOrganizationHierarchy_ListRootsError(t *testing.T) {
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
	}

	ctx := context.Background()
	_, err := collectOrganizationHierarchy(ctx, mock)
	if err == nil {
		t.Fatal("expected error from ListRoots failure")
	}
}

func TestCollectOrganizationHierarchy_NoRoots(t *testing.T) {
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []awstypes.Root{},
			}, nil
		},
	}

	ctx := context.Background()
	_, err := collectOrganizationHierarchy(ctx, mock)
	if err == nil {
		t.Fatal("expected error when no roots found")
	}
}

func TestCollectOrganizationHierarchy_ListOUsError(t *testing.T) {
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []awstypes.Root{
					{Id: strPtr("r-root"), Name: strPtr("Root")},
				},
			}, nil
		},
		listOrganizationalUnitsForParentFunc: func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			return nil, fmt.Errorf("OU listing failed")
		},
	}

	ctx := context.Background()
	_, err := collectOrganizationHierarchy(ctx, mock)
	if err == nil {
		t.Fatal("expected error from ListOUs failure")
	}
}

func TestCollectOrganizationHierarchy_ListAccountsError(t *testing.T) {
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []awstypes.Root{
					{Id: strPtr("r-root"), Name: strPtr("Root")},
				},
			}, nil
		},
		listOrganizationalUnitsForParentFunc: func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
		},
		listAccountsForParentFunc: func(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
			return nil, fmt.Errorf("account listing failed")
		},
	}

	ctx := context.Background()
	_, err := collectOrganizationHierarchy(ctx, mock)
	if err == nil {
		t.Fatal("expected error from ListAccounts failure")
	}
}

func TestCollectOrganizationHierarchy_ChildOUProcessingError(t *testing.T) {
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []awstypes.Root{
					{Id: strPtr("r-root"), Name: strPtr("Root")},
				},
			}, nil
		},
		listOrganizationalUnitsForParentFunc: func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			if *params.ParentId == "r-root" {
				return &organizations.ListOrganizationalUnitsForParentOutput{
					OrganizationalUnits: []awstypes.OrganizationalUnit{
						{Id: strPtr("ou-child-bad"), Name: strPtr("BadChildOU")},
					},
				}, nil
			}
			// For the child OU, error out
			return nil, fmt.Errorf("child OU processing failed")
		},
		listAccountsForParentFunc: func(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
			return &organizations.ListAccountsForParentOutput{}, nil
		},
	}

	ctx := context.Background()
	_, err := collectOrganizationHierarchy(ctx, mock)
	if err == nil {
		t.Fatal("expected error from child OU processing failure")
	}
}

func TestCollectOrganizationHierarchy_OUPagination(t *testing.T) {
	callCount := 0
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []awstypes.Root{
					{Id: strPtr("r-root"), Name: strPtr("Root")},
				},
			}, nil
		},
		listOrganizationalUnitsForParentFunc: func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			if *params.ParentId == "r-root" {
				callCount++
				if callCount == 1 {
					return &organizations.ListOrganizationalUnitsForParentOutput{
						OrganizationalUnits: []awstypes.OrganizationalUnit{
							{Id: strPtr("ou-page1"), Name: strPtr("Page1OU")},
						},
						NextToken: strPtr("token1"),
					}, nil
				}
				return &organizations.ListOrganizationalUnitsForParentOutput{
					OrganizationalUnits: []awstypes.OrganizationalUnit{
						{Id: strPtr("ou-page2"), Name: strPtr("Page2OU")},
					},
				}, nil
			}
			return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
		},
		listAccountsForParentFunc: func(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
			return &organizations.ListAccountsForParentOutput{}, nil
		},
	}

	ctx := context.Background()
	ou, err := collectOrganizationHierarchy(ctx, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ou.Children) != 2 {
		t.Fatalf("expected 2 child OUs from paginated results, got %d", len(ou.Children))
	}
}

func TestCollectOrganizationHierarchy_AccountPagination(t *testing.T) {
	acctCallCount := 0
	mock := &mockOrganizationsClient{
		listRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []awstypes.Root{
					{Id: strPtr("r-root"), Name: strPtr("Root")},
				},
			}, nil
		},
		listOrganizationalUnitsForParentFunc: func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
		},
		listAccountsForParentFunc: func(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
			acctCallCount++
			if acctCallCount == 1 {
				return &organizations.ListAccountsForParentOutput{
					Accounts: []awstypes.Account{
						{Id: strPtr("111111111111"), Name: strPtr("Acct1"), Email: strPtr("a1@x.com"), Status: awstypes.AccountStatusActive},
					},
					NextToken: strPtr("acct-token"),
				}, nil
			}
			return &organizations.ListAccountsForParentOutput{
				Accounts: []awstypes.Account{
					{Id: strPtr("222222222222"), Name: strPtr("Acct2"), Email: strPtr("a2@x.com"), Status: awstypes.AccountStatusActive},
				},
			}, nil
		},
	}

	ctx := context.Background()
	ou, err := collectOrganizationHierarchy(ctx, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ou.Accounts) != 2 {
		t.Fatalf("expected 2 accounts from paginated results, got %d", len(ou.Accounts))
	}
}

func TestCollectPolicies_Success(t *testing.T) {
	policyContent := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

	mock := &mockOrganizationsClient{
		listPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []awstypes.PolicySummary{
					{
						Arn:         strPtr("arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"),
						AwsManaged:  true,
						Description: strPtr("Full AWS access"),
						Id:          strPtr("p-FullAWSAccess"),
						Name:        strPtr("FullAWSAccess"),
						Type:        awstypes.PolicyTypeServiceControlPolicy,
					},
				},
			}, nil
		},
		describePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &awstypes.Policy{
					Content: strPtr(policyContent),
				},
			}, nil
		},
		listTargetsForPolicyFunc: func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
			return &organizations.ListTargetsForPolicyOutput{
				Targets: []awstypes.PolicyTargetSummary{
					{
						TargetId: strPtr("r-root"),
						Name:     strPtr("Root"),
						Type:     awstypes.TargetTypeRoot,
					},
				},
			}, nil
		},
	}

	ctx := context.Background()
	policies, err := collectPolicies(ctx, mock, awstypes.PolicyTypeServiceControlPolicy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if *policies[0].PolicySummary.Name != "FullAWSAccess" {
		t.Errorf("expected FullAWSAccess, got %s", *policies[0].PolicySummary.Name)
	}
	if *policies[0].PolicySummary.Arn != "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess" {
		t.Errorf("unexpected ARN: %s", *policies[0].PolicySummary.Arn)
	}
	if policies[0].PolicyContent.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", policies[0].PolicyContent.Version)
	}
	if len(policies[0].Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(policies[0].Targets))
	}
	if policies[0].Targets[0].TargetID != "r-root" {
		t.Errorf("expected target ID r-root, got %s", policies[0].Targets[0].TargetID)
	}
}

func TestCollectPolicies_ListPoliciesError(t *testing.T) {
	mock := &mockOrganizationsClient{
		listPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return nil, fmt.Errorf("list policies failed")
		},
	}

	ctx := context.Background()
	_, err := collectPolicies(ctx, mock, awstypes.PolicyTypeServiceControlPolicy)
	if err == nil {
		t.Fatal("expected error from ListPolicies failure")
	}
}

func TestCollectPolicies_DescribePolicyError(t *testing.T) {
	mock := &mockOrganizationsClient{
		listPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []awstypes.PolicySummary{
					{
						Arn:  strPtr("arn:aws:test"),
						Id:   strPtr("p-1"),
						Name: strPtr("TestPolicy"),
						Type: awstypes.PolicyTypeServiceControlPolicy,
					},
				},
			}, nil
		},
		describePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return nil, fmt.Errorf("describe policy failed")
		},
	}

	ctx := context.Background()
	policies, err := collectPolicies(ctx, mock, awstypes.PolicyTypeServiceControlPolicy)
	if err != nil {
		t.Fatalf("collectPolicies should not return error for individual policy failure: %v", err)
	}
	// Policy with describe error should be skipped
	if len(policies) != 0 {
		t.Errorf("expected 0 policies (skipped due to error), got %d", len(policies))
	}
}

func TestCollectPolicies_InvalidJSON(t *testing.T) {
	mock := &mockOrganizationsClient{
		listPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []awstypes.PolicySummary{
					{
						Arn:  strPtr("arn:aws:test"),
						Id:   strPtr("p-1"),
						Name: strPtr("TestPolicy"),
						Type: awstypes.PolicyTypeServiceControlPolicy,
					},
				},
			}, nil
		},
		describePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &awstypes.Policy{
					Content: strPtr("not-valid-json"),
				},
			}, nil
		},
	}

	ctx := context.Background()
	policies, err := collectPolicies(ctx, mock, awstypes.PolicyTypeServiceControlPolicy)
	if err != nil {
		t.Fatalf("collectPolicies should not return error for unmarshal failure: %v", err)
	}
	// Policy with invalid JSON should be skipped
	if len(policies) != 0 {
		t.Errorf("expected 0 policies (skipped due to unmarshal error), got %d", len(policies))
	}
}

func TestCollectPolicies_ListTargetsError(t *testing.T) {
	policyContent := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

	mock := &mockOrganizationsClient{
		listPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []awstypes.PolicySummary{
					{
						Arn:  strPtr("arn:aws:test"),
						Id:   strPtr("p-1"),
						Name: strPtr("TestPolicy"),
						Type: awstypes.PolicyTypeServiceControlPolicy,
					},
				},
			}, nil
		},
		describePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &awstypes.Policy{
					Content: strPtr(policyContent),
				},
			}, nil
		},
		listTargetsForPolicyFunc: func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
			return nil, fmt.Errorf("list targets failed")
		},
	}

	ctx := context.Background()
	policies, err := collectPolicies(ctx, mock, awstypes.PolicyTypeServiceControlPolicy)
	if err != nil {
		t.Fatalf("collectPolicies should not return error for individual target list failure: %v", err)
	}
	// Policy with target listing error should be skipped
	if len(policies) != 0 {
		t.Errorf("expected 0 policies (skipped due to target list error), got %d", len(policies))
	}
}

func TestListPolicies_Pagination(t *testing.T) {
	callCount := 0
	mock := &mockOrganizationsClient{
		listPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			callCount++
			if callCount == 1 {
				return &organizations.ListPoliciesOutput{
					Policies: []awstypes.PolicySummary{
						{
							Arn:  strPtr("arn:policy1"),
							Id:   strPtr("p-1"),
							Name: strPtr("Policy1"),
							Type: awstypes.PolicyTypeServiceControlPolicy,
						},
					},
					NextToken: strPtr("page2"),
				}, nil
			}
			return &organizations.ListPoliciesOutput{
				Policies: []awstypes.PolicySummary{
					{
						Arn:  strPtr("arn:policy2"),
						Id:   strPtr("p-2"),
						Name: strPtr("Policy2"),
						Type: awstypes.PolicyTypeServiceControlPolicy,
					},
				},
			}, nil
		},
	}

	ctx := context.Background()
	policies, err := listPolicies(ctx, mock, awstypes.PolicyTypeServiceControlPolicy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies from paginated results, got %d", len(policies))
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls for pagination, got %d", callCount)
	}
}

func TestListPolicies_Error(t *testing.T) {
	mock := &mockOrganizationsClient{
		listPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return nil, fmt.Errorf("listing failed")
		},
	}

	ctx := context.Background()
	_, err := listPolicies(ctx, mock, awstypes.PolicyTypeServiceControlPolicy)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListPolicyTargets_Pagination(t *testing.T) {
	callCount := 0
	mock := &mockOrganizationsClient{
		listTargetsForPolicyFunc: func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
			callCount++
			if callCount == 1 {
				return &organizations.ListTargetsForPolicyOutput{
					Targets: []awstypes.PolicyTargetSummary{
						{
							TargetId: strPtr("r-root"),
							Name:     strPtr("Root"),
							Type:     awstypes.TargetTypeRoot,
						},
					},
					NextToken: strPtr("page2"),
				}, nil
			}
			return &organizations.ListTargetsForPolicyOutput{
				Targets: []awstypes.PolicyTargetSummary{
					{
						TargetId: strPtr("ou-1"),
						Name:     strPtr("OU1"),
						Type:     awstypes.TargetTypeOrganizationalUnit,
					},
				},
			}, nil
		},
	}

	ctx := context.Background()
	targets, err := listPolicyTargets(ctx, mock, "p-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets from paginated results, got %d", len(targets))
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls for pagination, got %d", callCount)
	}
	if targets[0].TargetID != "r-root" {
		t.Errorf("expected first target r-root, got %s", targets[0].TargetID)
	}
	if targets[1].TargetID != "ou-1" {
		t.Errorf("expected second target ou-1, got %s", targets[1].TargetID)
	}
}

func TestListPolicyTargets_Error(t *testing.T) {
	mock := &mockOrganizationsClient{
		listTargetsForPolicyFunc: func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
			return nil, fmt.Errorf("target listing failed")
		},
	}

	ctx := context.Background()
	_, err := listPolicyTargets(ctx, mock, "p-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetPolicyContent_Function(t *testing.T) {
	policyContent := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
	mock := &mockOrganizationsClient{
		describePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &awstypes.Policy{
					Content: strPtr(policyContent),
				},
			}, nil
		},
	}

	ctx := context.Background()
	content, err := getPolicyContent(ctx, mock, "p-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != policyContent {
		t.Errorf("unexpected content: %s", content)
	}
}

func TestGetPolicyContent_FunctionError(t *testing.T) {
	mock := &mockOrganizationsClient{
		describePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return nil, fmt.Errorf("describe failed")
		},
	}

	ctx := context.Background()
	_, err := getPolicyContent(ctx, mock, "p-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildOrgPoliciesFromHierarchy(t *testing.T) {
	fullAccessArn := "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
	denyS3Arn := "arn:aws:organizations::111111111111:policy/service_control_policy/p-deny-s3"
	rcpArn := "arn:aws:organizations::111111111111:policy/resource_control_policy/p-rcp"

	rootOU := &OrgUnit{
		ID:   "r-root",
		Name: "Root",
		Children: []OrgUnit{
			{
				ID:   "ou-child-1",
				Name: "ChildOU",
				Accounts: []Account{
					{
						ID:     "111111111111",
						Name:   "TestAccount",
						Email:  "test@example.com",
						Status: "ACTIVE",
					},
				},
			},
		},
	}

	scps := []PolicyData{
		{
			PolicySummary: PolicySummaryRef{
				Arn:  strPtr(fullAccessArn),
				Name: strPtr("FullAWSAccess"),
				Id:   strPtr("p-FullAWSAccess"),
			},
			Targets: []PolicyTarget{
				{TargetID: "r-root", Name: "Root", Type: "ROOT"},
			},
		},
		{
			PolicySummary: PolicySummaryRef{
				Arn:  strPtr(denyS3Arn),
				Name: strPtr("DenyS3Delete"),
				Id:   strPtr("p-deny-s3"),
			},
			Targets: []PolicyTarget{
				{TargetID: "ou-child-1", Name: "ChildOU", Type: "ORGANIZATIONAL_UNIT"},
			},
		},
	}

	rcps := []PolicyData{
		{
			PolicySummary: PolicySummaryRef{
				Arn:  strPtr(rcpArn),
				Name: strPtr("RCP"),
				Id:   strPtr("p-rcp"),
			},
			Targets: []PolicyTarget{
				{TargetID: "ou-child-1", Name: "ChildOU", Type: "ORGANIZATIONAL_UNIT"},
			},
		},
	}

	result := BuildOrgPoliciesFromHierarchy(rootOU, scps, rcps)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.SCPs) != 2 {
		t.Errorf("expected 2 SCPs, got %d", len(result.SCPs))
	}
	if len(result.RCPs) != 1 {
		t.Errorf("expected 1 RCP, got %d", len(result.RCPs))
	}

	// Should have 3 targets: Root OU, ChildOU, TestAccount
	if len(result.Targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(result.Targets))
	}

	// Find the account target
	var acctTarget *OrgPolicyTarget
	for i := range result.Targets {
		if result.Targets[i].Type == "ACCOUNT" {
			acctTarget = &result.Targets[i]
			break
		}
	}
	if acctTarget == nil {
		t.Fatal("expected to find account target")
	}
	if acctTarget.ID != "111111111111" {
		t.Errorf("expected account ID 111111111111, got %s", acctTarget.ID)
	}
	// Account should inherit SCPs from Root and ChildOU
	if len(acctTarget.SCPs.ParentPolicies) != 2 {
		t.Errorf("expected 2 parent SCP groups, got %d", len(acctTarget.SCPs.ParentPolicies))
	}

	// Find the root target
	var rootTarget *OrgPolicyTarget
	for i := range result.Targets {
		if result.Targets[i].ID == "r-root" {
			rootTarget = &result.Targets[i]
			break
		}
	}
	if rootTarget == nil {
		t.Fatal("expected to find root target")
	}
	if len(rootTarget.SCPs.DirectPolicies) != 1 {
		t.Errorf("expected 1 direct SCP on root, got %d", len(rootTarget.SCPs.DirectPolicies))
	}
	if rootTarget.SCPs.DirectPolicies[0] != fullAccessArn {
		t.Errorf("expected FullAWSAccess ARN, got %s", rootTarget.SCPs.DirectPolicies[0])
	}

	// Find ChildOU target
	var childTarget *OrgPolicyTarget
	for i := range result.Targets {
		if result.Targets[i].ID == "ou-child-1" {
			childTarget = &result.Targets[i]
			break
		}
	}
	if childTarget == nil {
		t.Fatal("expected to find child OU target")
	}
	if len(childTarget.RCPs.DirectPolicies) != 1 {
		t.Errorf("expected 1 direct RCP on child OU, got %d", len(childTarget.RCPs.DirectPolicies))
	}
}

func TestBuildOrgPoliciesFromHierarchy_EmptyHierarchy(t *testing.T) {
	rootOU := &OrgUnit{
		ID:   "r-root",
		Name: "Root",
	}

	result := BuildOrgPoliciesFromHierarchy(rootOU, []PolicyData{}, []PolicyData{})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Should have 1 target: the root OU
	if len(result.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(result.Targets))
	}
	if result.Targets[0].ID != "r-root" {
		t.Errorf("expected r-root, got %s", result.Targets[0].ID)
	}
}

func TestMapTargetsToPolicies(t *testing.T) {
	policies := []PolicyData{
		{
			PolicySummary: PolicySummaryRef{
				Arn: strPtr("arn:policy1"),
			},
			Targets: []PolicyTarget{
				{TargetID: "target-a"},
				{TargetID: "target-b"},
			},
		},
		{
			PolicySummary: PolicySummaryRef{
				Arn: strPtr("arn:policy2"),
			},
			Targets: []PolicyTarget{
				{TargetID: "target-a"},
			},
		},
	}

	result := mapTargetsToPolicies(policies)

	if len(result) != 2 {
		t.Fatalf("expected 2 target entries, got %d", len(result))
	}
	if len(result["target-a"]) != 2 {
		t.Errorf("expected 2 policies for target-a, got %d", len(result["target-a"]))
	}
	if len(result["target-b"]) != 1 {
		t.Errorf("expected 1 policy for target-b, got %d", len(result["target-b"]))
	}
}

func TestMapTargetsToPolicies_Empty(t *testing.T) {
	result := mapTargetsToPolicies([]PolicyData{})
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestPolicyTypeToString(t *testing.T) {
	pt := awstypes.PolicyTypeServiceControlPolicy
	result := policyTypeToString(pt)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if *result != string(awstypes.PolicyTypeServiceControlPolicy) {
		t.Errorf("expected %s, got %s", string(awstypes.PolicyTypeServiceControlPolicy), *result)
	}
}

func TestBoolPtr(t *testing.T) {
	trueVal := boolPtr(true)
	if trueVal == nil || !*trueVal {
		t.Error("expected true pointer")
	}
	falseVal := boolPtr(false)
	if falseVal == nil || *falseVal {
		t.Error("expected false pointer")
	}
}
