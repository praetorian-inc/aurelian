package orgpolicies

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

// buildTestOrgPolicies constructs a realistic OrgPolicies fixture:
//
//	Root OU (r-root)
//	  - FullAWSAccess SCP attached
//	  Child OU (ou-child-1)
//	    - DenyS3Delete SCP attached
//	    - RestrictRCP RCP attached
//	    Account (111111111111) in child OU
//	      - AccountSCP direct SCP attached
//	      - AccountRCP direct RCP attached
func buildTestOrgPolicies() *OrgPolicies {
	fullAccessArn := "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
	denyS3Arn := "arn:aws:organizations::111111111111:policy/service_control_policy/p-deny-s3"
	accountScpArn := "arn:aws:organizations::111111111111:policy/service_control_policy/p-account-scp"
	childRcpArn := "arn:aws:organizations::111111111111:policy/resource_control_policy/p-child-rcp"
	accountRcpArn := "arn:aws:organizations::111111111111:policy/resource_control_policy/p-account-rcp"

	account := Account{
		ID:     "111111111111",
		Name:   "TestAccount",
		Email:  "test@example.com",
		Status: "ACTIVE",
	}

	return &OrgPolicies{
		SCPs: []PolicyData{
			{
				PolicySummary: PolicySummaryRef{
					Arn:  strPtr(fullAccessArn),
					Name: strPtr("FullAWSAccess"),
					Id:   strPtr("p-FullAWSAccess"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Sid:      "FullAccess",
							Effect:   "Allow",
							Action:   types.NewDynaString([]string{"*"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
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
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Sid:      "DenyS3Delete",
							Effect:   "Deny",
							Action:   types.NewDynaString([]string{"s3:DeleteBucket"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
				},
				Targets: []PolicyTarget{
					{TargetID: "ou-child-1", Name: "ChildOU", Type: "ORGANIZATIONAL_UNIT"},
				},
			},
			{
				PolicySummary: PolicySummaryRef{
					Arn:  strPtr(accountScpArn),
					Name: strPtr("AccountSCP"),
					Id:   strPtr("p-account-scp"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Sid:      "DenyIAMDelete",
							Effect:   "Deny",
							Action:   types.NewDynaString([]string{"iam:DeleteUser"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
				},
				Targets: []PolicyTarget{
					{TargetID: "111111111111", Name: "TestAccount", Type: "ACCOUNT"},
				},
			},
		},
		RCPs: []PolicyData{
			{
				PolicySummary: PolicySummaryRef{
					Arn:  strPtr(childRcpArn),
					Name: strPtr("RestrictRCP"),
					Id:   strPtr("p-child-rcp"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Sid:      "DenyS3Public",
							Effect:   "Deny",
							Action:   types.NewDynaString([]string{"s3:PutBucketPolicy"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
				},
				Targets: []PolicyTarget{
					{TargetID: "ou-child-1", Name: "ChildOU", Type: "ORGANIZATIONAL_UNIT"},
				},
			},
			{
				PolicySummary: PolicySummaryRef{
					Arn:  strPtr(accountRcpArn),
					Name: strPtr("AccountRCP"),
					Id:   strPtr("p-account-rcp"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Sid:      "DenyLambdaPublic",
							Effect:   "Deny",
							Action:   types.NewDynaString([]string{"lambda:AddPermission"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
				},
				Targets: []PolicyTarget{
					{TargetID: "111111111111", Name: "TestAccount", Type: "ACCOUNT"},
				},
			},
		},
		Targets: []OrgPolicyTarget{
			{
				Name: "Root",
				ID:   "r-root",
				Type: "OU",
				SCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{fullAccessArn},
					ParentPolicies: []ParentPolicy{},
				},
				RCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{},
					ParentPolicies: []ParentPolicy{},
				},
			},
			{
				Name: "ChildOU",
				ID:   "ou-child-1",
				Type: "OU",
				SCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{denyS3Arn},
					ParentPolicies: []ParentPolicy{
						{Name: "Root", ID: "r-root", Policies: []string{fullAccessArn}},
					},
				},
				RCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{childRcpArn},
					ParentPolicies: []ParentPolicy{},
				},
			},
			{
				Name:    "TestAccount",
				ID:      "111111111111",
				Type:    "ACCOUNT",
				Account: &account,
				SCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{accountScpArn},
					ParentPolicies: []ParentPolicy{
						{Name: "Root", ID: "r-root", Policies: []string{fullAccessArn}},
						{Name: "ChildOU", ID: "ou-child-1", Policies: []string{denyS3Arn}},
					},
				},
				RCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{accountRcpArn},
					ParentPolicies: []ParentPolicy{
						{Name: "Root", ID: "r-root", Policies: []string{}},
						{Name: "ChildOU", ID: "ou-child-1", Policies: []string{childRcpArn}},
					},
				},
			},
		},
	}
}

func TestGetAccount_Found(t *testing.T) {
	op := buildTestOrgPolicies()
	acct := op.GetAccount("111111111111")
	if acct == nil {
		t.Fatal("expected account to be found")
	}
	if acct.ID != "111111111111" {
		t.Errorf("expected account ID 111111111111, got %s", acct.ID)
	}
	if acct.Name != "TestAccount" {
		t.Errorf("expected account name TestAccount, got %s", acct.Name)
	}
	if acct.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", acct.Email)
	}
}

func TestGetAccount_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	acct := op.GetAccount("999999999999")
	if acct != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetAccount_OUTargetSkipped(t *testing.T) {
	op := buildTestOrgPolicies()
	// r-root is an OU, not an ACCOUNT, so GetAccount should not find it
	acct := op.GetAccount("r-root")
	if acct != nil {
		t.Error("expected nil for OU target queried as account")
	}
}

func TestGetPolicyForTarget_Found(t *testing.T) {
	op := buildTestOrgPolicies()
	target := op.GetPolicyForTarget("111111111111")
	if target == nil {
		t.Fatal("expected policy target to be found")
	}
	if target.ID != "111111111111" {
		t.Errorf("expected target ID 111111111111, got %s", target.ID)
	}
	if target.Account == nil {
		t.Fatal("expected target to have an account")
	}
}

func TestGetPolicyForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	target := op.GetPolicyForTarget("999999999999")
	if target != nil {
		t.Error("expected nil for non-existent target")
	}
}

func TestGetPolicyContent_SCP(t *testing.T) {
	op := buildTestOrgPolicies()
	arn := "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
	content := op.GetPolicyContent(arn, "scps")
	if content == nil {
		t.Fatal("expected SCP policy content")
	}
	if content.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", content.Version)
	}
	if content.Statement == nil || len(*content.Statement) != 1 {
		t.Fatal("expected 1 statement in FullAWSAccess SCP")
	}
	if (*content.Statement)[0].Effect != "Allow" {
		t.Errorf("expected Allow effect, got %s", (*content.Statement)[0].Effect)
	}
}

func TestGetPolicyContent_RCP(t *testing.T) {
	op := buildTestOrgPolicies()
	arn := "arn:aws:organizations::111111111111:policy/resource_control_policy/p-child-rcp"
	content := op.GetPolicyContent(arn, "rcps")
	if content == nil {
		t.Fatal("expected RCP policy content")
	}
	if content.Statement == nil || len(*content.Statement) != 1 {
		t.Fatal("expected 1 statement in RestrictRCP")
	}
	if (*content.Statement)[0].Sid != "DenyS3Public" {
		t.Errorf("expected Sid DenyS3Public, got %s", (*content.Statement)[0].Sid)
	}
}

func TestGetPolicyContent_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	content := op.GetPolicyContent("arn:aws:nonexistent", "scps")
	if content != nil {
		t.Error("expected nil for non-existent policy ARN")
	}
}

func TestGetPolicyContent_UnknownType(t *testing.T) {
	op := buildTestOrgPolicies()
	content := op.GetPolicyContent("arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess", "unknown")
	if content != nil {
		t.Error("expected nil for unknown policy type")
	}
}

func TestGetDirectScpStatementsForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetDirectScpStatementsForTarget("111111111111")
	if stmts == nil {
		t.Fatal("expected direct SCP statements")
	}
	if len(*stmts) != 1 {
		t.Fatalf("expected 1 direct SCP statement, got %d", len(*stmts))
	}
	if (*stmts)[0].Sid != "DenyIAMDelete" {
		t.Errorf("expected Sid DenyIAMDelete, got %s", (*stmts)[0].Sid)
	}
	// Verify OriginArn is set
	expectedArn := "arn:aws:organizations::111111111111:policy/service_control_policy/p-account-scp"
	if (*stmts)[0].OriginArn != expectedArn {
		t.Errorf("expected OriginArn %s, got %s", expectedArn, (*stmts)[0].OriginArn)
	}
}

func TestGetDirectScpStatementsForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetDirectScpStatementsForTarget("999999999999")
	if stmts != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetParentScpStatementsForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetParentScpStatementsForTarget("111111111111")
	if stmts == nil {
		t.Fatal("expected parent SCP statements")
	}
	// Account has 2 parent policies: Root (FullAWSAccess) and ChildOU (DenyS3Delete)
	if len(*stmts) != 2 {
		t.Fatalf("expected 2 parent SCP statements, got %d", len(*stmts))
	}

	sids := make(map[string]bool)
	for _, stmt := range *stmts {
		sids[stmt.Sid] = true
	}
	if !sids["FullAccess"] {
		t.Error("expected FullAccess statement from root parent")
	}
	if !sids["DenyS3Delete"] {
		t.Error("expected DenyS3Delete statement from child OU parent")
	}
}

func TestGetParentScpStatementsForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetParentScpStatementsForTarget("999999999999")
	if stmts != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetMergedParentScpsForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	merged := op.GetMergedParentScpsForTarget("111111111111")
	if merged == nil {
		t.Fatal("expected merged parent SCPs")
	}
	// Should have entries for r-root and ou-child-1
	if len(merged) != 2 {
		t.Fatalf("expected 2 parent groups, got %d", len(merged))
	}
	rootStmts, ok := merged["r-root"]
	if !ok {
		t.Fatal("expected entry for r-root")
	}
	if len(*rootStmts) != 1 || (*rootStmts)[0].Sid != "FullAccess" {
		t.Error("unexpected root SCP statements")
	}
	childStmts, ok := merged["ou-child-1"]
	if !ok {
		t.Fatal("expected entry for ou-child-1")
	}
	if len(*childStmts) != 1 || (*childStmts)[0].Sid != "DenyS3Delete" {
		t.Error("unexpected child OU SCP statements")
	}
}

func TestGetMergedParentScpsForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	merged := op.GetMergedParentScpsForTarget("999999999999")
	if merged != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetMergedParentRcpsForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	merged := op.GetMergedParentRcpsForTarget("111111111111")
	if merged == nil {
		t.Fatal("expected merged parent RCPs")
	}
	// Root has no RCPs (empty policies list), ChildOU has childRcpArn
	// Only ou-child-1 should be in the map since r-root has empty policies
	if len(merged) != 1 {
		t.Fatalf("expected 1 parent group with RCPs, got %d", len(merged))
	}
	childStmts, ok := merged["ou-child-1"]
	if !ok {
		t.Fatal("expected entry for ou-child-1")
	}
	if len(*childStmts) != 1 || (*childStmts)[0].Sid != "DenyS3Public" {
		t.Error("unexpected child OU RCP statements")
	}
}

func TestGetMergedParentRcpsForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	merged := op.GetMergedParentRcpsForTarget("999999999999")
	if merged != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetAllScpPoliciesForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	all := op.GetAllScpPoliciesForTarget("111111111111")
	if all == nil {
		t.Fatal("expected all SCP statements")
	}
	// 1 direct (DenyIAMDelete) + 2 parent (FullAccess, DenyS3Delete) = 3
	if len(*all) != 3 {
		t.Fatalf("expected 3 total SCP statements, got %d", len(*all))
	}
	sids := make(map[string]bool)
	for _, stmt := range *all {
		sids[stmt.Sid] = true
	}
	if !sids["DenyIAMDelete"] {
		t.Error("missing DenyIAMDelete from direct policies")
	}
	if !sids["FullAccess"] {
		t.Error("missing FullAccess from parent policies")
	}
	if !sids["DenyS3Delete"] {
		t.Error("missing DenyS3Delete from parent policies")
	}
}

func TestGetAllScpPoliciesForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	all := op.GetAllScpPoliciesForTarget("999999999999")
	if all != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetDirectRcpStatementsForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetDirectRcpStatementsForTarget("111111111111")
	if stmts == nil {
		t.Fatal("expected direct RCP statements")
	}
	if len(*stmts) != 1 {
		t.Fatalf("expected 1 direct RCP statement, got %d", len(*stmts))
	}
	if (*stmts)[0].Sid != "DenyLambdaPublic" {
		t.Errorf("expected Sid DenyLambdaPublic, got %s", (*stmts)[0].Sid)
	}
	expectedArn := "arn:aws:organizations::111111111111:policy/resource_control_policy/p-account-rcp"
	if (*stmts)[0].OriginArn != expectedArn {
		t.Errorf("expected OriginArn %s, got %s", expectedArn, (*stmts)[0].OriginArn)
	}
}

func TestGetDirectRcpStatementsForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetDirectRcpStatementsForTarget("999999999999")
	if stmts != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetParentRcpStatementsForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetParentRcpStatementsForTarget("111111111111")
	if stmts == nil {
		t.Fatal("expected parent RCP statements")
	}
	// Root has no RCPs, ChildOU has 1 (DenyS3Public)
	if len(*stmts) != 1 {
		t.Fatalf("expected 1 parent RCP statement, got %d", len(*stmts))
	}
	if (*stmts)[0].Sid != "DenyS3Public" {
		t.Errorf("expected Sid DenyS3Public, got %s", (*stmts)[0].Sid)
	}
}

func TestGetParentRcpStatementsForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	stmts := op.GetParentRcpStatementsForTarget("999999999999")
	if stmts != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestGetAllRcpPoliciesForTarget(t *testing.T) {
	op := buildTestOrgPolicies()
	all := op.GetAllRcpPoliciesForTarget("111111111111")
	if all == nil {
		t.Fatal("expected all RCP statements")
	}
	// 1 direct (DenyLambdaPublic) + 1 parent (DenyS3Public) = 2
	if len(*all) != 2 {
		t.Fatalf("expected 2 total RCP statements, got %d", len(*all))
	}
	sids := make(map[string]bool)
	for _, stmt := range *all {
		sids[stmt.Sid] = true
	}
	if !sids["DenyLambdaPublic"] {
		t.Error("missing DenyLambdaPublic from direct RCPs")
	}
	if !sids["DenyS3Public"] {
		t.Error("missing DenyS3Public from parent RCPs")
	}
}

func TestGetAllRcpPoliciesForTarget_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	all := op.GetAllRcpPoliciesForTarget("999999999999")
	if all != nil {
		t.Error("expected nil for non-existent account")
	}
}

func TestTargetHasParentAllowed_Found(t *testing.T) {
	op := buildTestOrgPolicies()
	result := op.TargetHasParentAllowed("111111111111")
	// The function is a stub that always returns false
	if result {
		t.Error("expected false from stub TargetHasParentAllowed")
	}
}

func TestTargetHasParentAllowed_NotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	result := op.TargetHasParentAllowed("999999999999")
	if result {
		t.Error("expected false when target not found")
	}
}

func TestNewDefaultOrgPolicies(t *testing.T) {
	op := NewDefaultOrgPolicies()
	if op == nil {
		t.Fatal("expected non-nil default OrgPolicies")
	}

	// Check SCPs
	if len(op.SCPs) != 1 {
		t.Fatalf("expected 1 SCP, got %d", len(op.SCPs))
	}
	if *op.SCPs[0].PolicySummary.Name != "FullAWSAccess" {
		t.Errorf("expected FullAWSAccess, got %s", *op.SCPs[0].PolicySummary.Name)
	}
	expectedArn := "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
	if *op.SCPs[0].PolicySummary.Arn != expectedArn {
		t.Errorf("expected ARN %s, got %s", expectedArn, *op.SCPs[0].PolicySummary.Arn)
	}

	// Verify the statement allows everything
	stmts := op.SCPs[0].PolicyContent.Statement
	if stmts == nil || len(*stmts) != 1 {
		t.Fatal("expected 1 statement in default SCP")
	}
	if (*stmts)[0].Effect != "Allow" {
		t.Errorf("expected Allow effect, got %s", (*stmts)[0].Effect)
	}

	// Check RCPs empty
	if len(op.RCPs) != 0 {
		t.Errorf("expected 0 RCPs, got %d", len(op.RCPs))
	}

	// Check targets
	if len(op.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(op.Targets))
	}
	if op.Targets[0].Name != "Root" {
		t.Errorf("expected target name Root, got %s", op.Targets[0].Name)
	}
	if op.Targets[0].ID != "r-root" {
		t.Errorf("expected target ID r-root, got %s", op.Targets[0].ID)
	}
	if len(op.Targets[0].SCPs.DirectPolicies) != 1 {
		t.Fatalf("expected 1 direct SCP in root target, got %d", len(op.Targets[0].SCPs.DirectPolicies))
	}
	if op.Targets[0].SCPs.DirectPolicies[0] != expectedArn {
		t.Errorf("expected direct policy ARN %s, got %s", expectedArn, op.Targets[0].SCPs.DirectPolicies[0])
	}
}

func TestGetDirectScpStatementsForTarget_NoDirectPolicies(t *testing.T) {
	// OU target (r-root) has FullAWSAccess direct SCP
	op := buildTestOrgPolicies()
	stmts := op.GetDirectScpStatementsForTarget("r-root")
	// r-root has no Account field, so GetPolicyForTarget won't find it (requires Account != nil)
	// Actually, GetPolicyForTarget checks Account != nil, so OU targets without an Account won't be found
	// Wait -- let me re-check: GetPolicyForTarget checks target.Account != nil && target.Account.ID == accountID
	// So for OU targets that have Account == nil, it will return nil
	if stmts != nil {
		t.Error("expected nil since OU targets have nil Account in GetPolicyForTarget")
	}
}

func TestGetPolicyContent_RCPNotFound(t *testing.T) {
	op := buildTestOrgPolicies()
	content := op.GetPolicyContent("arn:aws:nonexistent", "rcps")
	if content != nil {
		t.Error("expected nil for non-existent RCP ARN")
	}
}

func TestEmptyOrgPolicies(t *testing.T) {
	op := &OrgPolicies{
		SCPs:    []PolicyData{},
		RCPs:    []PolicyData{},
		Targets: []OrgPolicyTarget{},
	}
	if acct := op.GetAccount("anything"); acct != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if target := op.GetPolicyForTarget("anything"); target != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if content := op.GetPolicyContent("arn", "scps"); content != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if stmts := op.GetDirectScpStatementsForTarget("anything"); stmts != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if stmts := op.GetParentScpStatementsForTarget("anything"); stmts != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if merged := op.GetMergedParentScpsForTarget("anything"); merged != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if merged := op.GetMergedParentRcpsForTarget("anything"); merged != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if all := op.GetAllScpPoliciesForTarget("anything"); all != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if all := op.GetAllRcpPoliciesForTarget("anything"); all != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if stmts := op.GetDirectRcpStatementsForTarget("anything"); stmts != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if stmts := op.GetParentRcpStatementsForTarget("anything"); stmts != nil {
		t.Error("expected nil from empty OrgPolicies")
	}
	if result := op.TargetHasParentAllowed("anything"); result {
		t.Error("expected false from empty OrgPolicies")
	}
}

func TestStrPtr(t *testing.T) {
	s := "hello"
	ptr := strPtr(s)
	if ptr == nil {
		t.Fatal("expected non-nil pointer")
	}
	if *ptr != "hello" {
		t.Errorf("expected hello, got %s", *ptr)
	}
}
