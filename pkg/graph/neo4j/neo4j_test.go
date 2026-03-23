package neo4j

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
	"strings"
	"testing"
)

func TestCompileMethod01(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:CreatePolicyVersion"), dsl.ManagedPolicy())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_CREATEPOLICYVERSION'\n" +
		"  AND n1._resourceType = 'AWS::IAM::ManagedPolicy'\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileReturnsPath(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:CreatePolicyVersion"), dsl.ManagedPolicy())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	if !strings.HasSuffix(got, "RETURN path") {
		t.Errorf("compiled query must end with RETURN path, got:\n%s", got)
	}
}

func TestActionToRelType(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"iam:CreatePolicyVersion", "IAM_CREATEPOLICYVERSION"},
		{"sts:AssumeRole", "STS_ASSUMEROLE"},
		{"lambda:InvokeFunction", "LAMBDA_INVOKEFUNCTION"},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := actionToRelType(tt.action)
			if got != tt.want {
				t.Errorf("actionToRelType(%q) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

func TestCompileMethod02(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:SetDefaultPolicyVersion"), dsl.ManagedPolicy())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_SETDEFAULTPOLICYVERSION'\n" +
		"  AND n1._resourceType = 'AWS::IAM::ManagedPolicy'\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod03(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:CreateAccessKey"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_CREATEACCESSKEY'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod04(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:CreateLoginProfile"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_CREATELOGINPROFILE'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod05(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:UpdateLoginProfile"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_UPDATELOGINPROFILE'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod06(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:AttachUserPolicy"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_ATTACHUSERPOLICY'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod07(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:AttachGroupPolicy"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_ATTACHGROUPPOLICY'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod08(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:AttachRolePolicy"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_ATTACHROLEPOLICY'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod09(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:PutUserPolicy"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_PUTUSERPOLICY'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileMethod10(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:PutGroupPolicy"), dsl.Principal())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_PUTGROUPPOLICY'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND n0 <> n1\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileSelfReferentialAllowed(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Query{
		From:                    dsl.Principal(),
		Permission:              dsl.HasPermission("iam:CreateAccessKey"),
		To:                      dsl.Principal(),
		SelfReferentialBehavior: dsl.AllowSelfReferential,
	}

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	want := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_CREATEACCESSKEY'\n" +
		"  AND n1._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"RETURN path"

	if got != want {
		t.Errorf("Compile() mismatch.\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestCompileDifferentKindsNoSelfReferentialClause(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Principal(), dsl.HasPermission("iam:CreatePolicyVersion"), dsl.ManagedPolicy())

	got, err := compiler.Compile(q)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	// Different node kinds → no n0 <> n1 clause even with default ForbidSelfReferential
	if strings.Contains(got, "n0 <> n1") {
		t.Errorf("should not have self-referential clause for different node kinds:\n%s", got)
	}
}

func TestCompileUnknownNodeKind(t *testing.T) {
	compiler := DefaultNeo4jCompiler()
	q := dsl.Match(dsl.Node{Kind: "Unknown"}, dsl.HasPermission("iam:Foo"), dsl.ManagedPolicy())

	_, err := compiler.Compile(q)
	if err == nil {
		t.Fatal("expected error for unknown node kind, got nil")
	}
}
