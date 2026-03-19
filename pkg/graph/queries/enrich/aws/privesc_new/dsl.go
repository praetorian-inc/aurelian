package privescnew

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/graph"
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

// Queryer compiles and executes a privesc DSL query against a graph backend.
type Queryer interface {
	// Connect initializes the backend connection. No-op for pre-connected backends.
	Connect(uri, username, password string) error
	// Query compiles the DSL query and returns results.
	Query(ctx context.Context, q Query) (*graph.QueryResult, error)
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
