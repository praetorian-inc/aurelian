package dsl

import (
	"context"
)

// Node represents a semantic graph node (e.g. "Principal", "ManagedPolicy").
// The Kind field is interpreted by the Compiler to produce backend-specific predicates.
type Node struct {
	Kind string
}

// Permission models an action requirement between two nodes.
type Permission struct {
	Action string
}

// Query is the minimal AST: a single-hop path from one node to another via a permission.
type Query struct {
	From       Node
	Permission Permission
	To         Node
}

// Compiler transforms a Query AST into a backend-specific query string.
type Compiler interface {
	Compile(Query) (string, error)
}

// MatchResult represents a single directed hop in a privilege escalation path.
type MatchResult struct {
	SourceID string   `json:"source_id"` // Identifier for the source node (ARN or key)
	TargetID string   `json:"target_id"` // Identifier for the target node (ARN or key)
	Actions  []string `json:"actions"`   // Permissions on the edge between source and target
}

// MatchedPath represents one discovered instance of a privilege escalation path.
// A single-hop query produces one hop per MatchedPath.
// Multi-hop paths (A→B→C) produce multiple hops in a single MatchedPath.
type MatchedPath struct {
	Hops []MatchResult `json:"hops"`
}

// Queryer compiles and executes a privesc DSL query against a graph backend.
type Queryer interface {
	// Connect initializes the backend connection. No-op for pre-connected backends.
	Connect(uri, username, password string) error
	// Query compiles the DSL query and returns one MatchedPath per discovered escalation instance.
	Query(ctx context.Context, q Query) ([]MatchedPath, error)
	// Close releases resources. No-op for externally-managed connections.
	Close() error
}

// --- DSL constructor functions ---

// Principal returns a node representing any IAM principal (User, Role, Group).
func Principal() Node {
	return Node{Kind: "Principal"}
}

// ManagedPolicy returns a node representing an IAM managed policy.
func ManagedPolicy() Node {
	return Node{Kind: "ManagedPolicy"}
}

// HasPermission returns a permission edge for the given IAM action string.
func HasPermission(action string) Permission {
	return Permission{Action: action}
}

// Match builds a single-hop query: from --[permission]--> to.
func Match(from Node, perm Permission, to Node) Query {
	return Query{From: from, Permission: perm, To: to}
}
