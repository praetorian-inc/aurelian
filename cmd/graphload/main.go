package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	awstransformers "github.com/praetorian-inc/aurelian/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

const (
	defaultURI      = "bolt://localhost:7687"
	defaultUsername = "neo4j"
	defaultPassword = "aurelian-test"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: graphload <json-file> [neo4j-uri] [username] [password]\n")
		fmt.Fprintf(os.Stderr, "       graphload --enrich-only [neo4j-uri] [username] [password]\n")
		os.Exit(1)
	}

	if args[0] == "--enrich-only" {
		uri := defaultURI
		username := defaultUsername
		password := defaultPassword
		if len(args) >= 2 {
			uri = args[1]
		}
		if len(args) >= 3 {
			username = args[2]
		}
		if len(args) >= 4 {
			password = args[3]
		}

		ctx := context.Background()

		cfg := graph.NewConfig(uri, username, password)
		db, err := adapters.NewNeo4jAdapter(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "creating Neo4j adapter: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()

		if err := db.VerifyConnectivity(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "connecting to Neo4j at %s: %v\n", uri, err)
			os.Exit(1)
		}
		fmt.Printf("Connected to Neo4j at %s\n", uri)

		fmt.Println("\nRunning AWS enrichment queries...")
		enrichStart := time.Now()
		if err := queries.EnrichAWS(ctx, db); err != nil {
			fmt.Fprintf(os.Stderr, "enriching AWS graph: %v\n", err)
			os.Exit(1)
		}
		enrichDuration := time.Since(enrichStart)
		fmt.Printf("Enrichment completed in %s\n", enrichDuration.Round(time.Millisecond))

		fmt.Println("\n--- Graph Metrics ---")

		totalNodes, err := db.Query(ctx, "MATCH (n) RETURN count(n) AS count", nil)
		if err != nil {
			slog.Warn("querying total nodes", "error", err)
		} else if len(totalNodes.Records) > 0 {
			fmt.Printf("Total nodes: %v\n", totalNodes.Records[0]["count"])
		}

		totalRels, err := db.Query(ctx, "MATCH ()-[r]->() RETURN count(r) AS count", nil)
		if err != nil {
			slog.Warn("querying total relationships", "error", err)
		} else if len(totalRels.Records) > 0 {
			fmt.Printf("Total relationships: %v\n", totalRels.Records[0]["count"])
		}

		privescRels, err := db.Query(ctx, "MATCH ()-[r:CAN_PRIVESC]->() RETURN count(r) AS count", nil)
		if err != nil {
			slog.Warn("querying privesc edges", "error", err)
		} else if len(privescRels.Records) > 0 {
			fmt.Printf("Privesc edges (CAN_PRIVESC): %v\n", privescRels.Records[0]["count"])
		}

		relBreakdown, err := db.Query(ctx, "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS count ORDER BY count(r) DESC", nil)
		if err != nil {
			slog.Warn("querying relationship breakdown", "error", err)
		} else {
			fmt.Println("\nRelationship breakdown:")
			for _, rec := range relBreakdown.Records {
				fmt.Printf("  %-40s %v\n", rec["rel_type"], rec["count"])
			}
		}

		fmt.Println("\n--- Running AWS Analysis Queries ---")
		analyzeStart := time.Now()
		analysisResults, err := queries.AnalyzeAWS(ctx, db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "analyzing AWS graph: %v\n", err)
			os.Exit(1)
		}
		analyzeDuration := time.Since(analyzeStart)
		fmt.Printf("Analysis completed in %s\n", analyzeDuration.Round(time.Millisecond))

		for i, result := range analysisResults {
			fmt.Printf("\nQuery %d: %d records\n", i+1, len(result.Records))
			limit := len(result.Records)
			if limit > 10 {
				limit = 10
			}
			for j, rec := range result.Records[:limit] {
				fmt.Printf("  [%d] %v\n", j+1, rec)
			}
			if len(result.Records) > 10 {
				fmt.Printf("  ... (%d more records)\n", len(result.Records)-10)
			}
		}
		return
	}

	jsonFile := args[0]
	uri := defaultURI
	username := defaultUsername
	password := defaultPassword

	if len(args) >= 2 {
		uri = args[1]
	}
	if len(args) >= 3 {
		username = args[2]
	}
	if len(args) >= 4 {
		password = args[3]
	}

	ctx := context.Background()

	// Step 1: Parse JSON file
	entities, relationships, err := parseJSONFile(jsonFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing JSON file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Parsed %d entities and %d relationships\n", len(entities), len(relationships))

	// Step 2: Connect to Neo4j
	cfg := graph.NewConfig(uri, username, password)
	db, err := adapters.NewNeo4jAdapter(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating Neo4j adapter: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.VerifyConnectivity(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connecting to Neo4j at %s: %v\n", uri, err)
		os.Exit(1)
	}
	fmt.Printf("Connected to Neo4j at %s\n", uri)

	// Step 3: Clear existing data
	if _, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
		fmt.Fprintf(os.Stderr, "clearing database: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Cleared existing data")

	// Step 4: Transform entities to nodes
	nodes := make([]*graph.Node, 0, len(entities))
	for _, entity := range entities {
		nodes = append(nodes, awstransformers.NodeFromAWSIAMResource(entity))
	}

	// Step 5: Create nodes
	nodeResult, err := db.CreateNodes(ctx, nodes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating nodes: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created nodes: %d created, %d properties set (%dms)\n",
		nodeResult.NodesCreated, nodeResult.PropertiesSet, nodeResult.ExecutionTimeMs)

	// Step 6: Transform relationships
	rels := make([]*graph.Relationship, 0, len(relationships))
	for _, rel := range relationships {
		rels = append(rels, awstransformers.RelationshipFromAWSIAMRelationship(rel))
	}

	// Step 7: Create relationships
	relResult, err := db.CreateRelationships(ctx, rels)
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating relationships: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created relationships: %d created, %d properties set (%dms)\n",
		relResult.RelationshipsCreated, relResult.PropertiesSet, relResult.ExecutionTimeMs)

	// Step 8: Patch Principal labels
	// AWSIAMResource objects deserialized from JSON have nil OriginalData, causing
	// NodeFromAWSIAMResource to fall back to NodeFromAWSResource which assigns "Resource"
	// instead of "Principal". Fix this before enrichment queries run, since they match
	// on (attacker:Principal).
	patchResult, err := db.Query(ctx,
		"MATCH (n) WHERE (n:Role OR n:User OR n:Group) AND NOT n:Principal SET n:Principal RETURN count(n) AS cnt",
		nil,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "patching Principal labels: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Patched %v nodes with Principal label\n", patchResult.Records[0]["cnt"])

	// Step 9: Run EnrichAWS
	fmt.Println("\nRunning AWS enrichment queries...")
	enrichStart := time.Now()
	if err := queries.EnrichAWS(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "enriching AWS graph: %v\n", err)
		os.Exit(1)
	}
	enrichDuration := time.Since(enrichStart)
	fmt.Printf("Enrichment completed in %s\n", enrichDuration.Round(time.Millisecond))

	// Step 10: Print metrics
	fmt.Println("\n--- Graph Metrics ---")

	totalNodes, err := db.Query(ctx, "MATCH (n) RETURN count(n) AS count", nil)
	if err != nil {
		slog.Warn("querying total nodes", "error", err)
	} else if len(totalNodes.Records) > 0 {
		fmt.Printf("Total nodes: %v\n", totalNodes.Records[0]["count"])
	}

	totalRels, err := db.Query(ctx, "MATCH ()-[r]->() RETURN count(r) AS count", nil)
	if err != nil {
		slog.Warn("querying total relationships", "error", err)
	} else if len(totalRels.Records) > 0 {
		fmt.Printf("Total relationships: %v\n", totalRels.Records[0]["count"])
	}

	privescRels, err := db.Query(ctx, "MATCH ()-[r:CAN_PRIVESC]->() RETURN count(r) AS count", nil)
	if err != nil {
		slog.Warn("querying privesc edges", "error", err)
	} else if len(privescRels.Records) > 0 {
		fmt.Printf("Privesc edges (CAN_PRIVESC): %v\n", privescRels.Records[0]["count"])
	}

	relBreakdown, err := db.Query(ctx, "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS count ORDER BY count(r) DESC", nil)
	if err != nil {
		slog.Warn("querying relationship breakdown", "error", err)
	} else {
		fmt.Println("\nRelationship breakdown:")
		for _, rec := range relBreakdown.Records {
			fmt.Printf("  %-40s %v\n", rec["rel_type"], rec["count"])
		}
	}

	// Step 11: Run AnalyzeAWS
	fmt.Println("\n--- Running AWS Analysis Queries ---")
	analyzeStart := time.Now()
	analysisResults, err := queries.AnalyzeAWS(ctx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyzing AWS graph: %v\n", err)
		os.Exit(1)
	}
	analyzeDuration := time.Since(analyzeStart)
	fmt.Printf("Analysis completed in %s\n", analyzeDuration.Round(time.Millisecond))

	for i, result := range analysisResults {
		fmt.Printf("\nQuery %d: %d records\n", i+1, len(result.Records))
		limit := len(result.Records)
		if limit > 10 {
			limit = 10
		}
		for j, rec := range result.Records[:limit] {
			fmt.Printf("  [%d] %v\n", j+1, rec)
		}
		if len(result.Records) > 10 {
			fmt.Printf("  ... (%d more records)\n", len(result.Records)-10)
		}
	}
}

// parseJSONFile reads the JSON array and splits elements into entities and relationships.
// An element is a relationship if it has a non-empty "action" field; otherwise it is an entity.
func parseJSONFile(path string) ([]output.AWSIAMResource, []output.AWSIAMRelationship, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading file: %w", err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling JSON array: %w", err)
	}

	var entities []output.AWSIAMResource
	var relationships []output.AWSIAMRelationship

	for i, elem := range raw {
		// Peek at the "action" field to distinguish type
		var probe struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(elem, &probe); err != nil {
			return nil, nil, fmt.Errorf("probing element %d: %w", i, err)
		}

		if probe.Action != "" {
			var rel output.AWSIAMRelationship
			if err := json.Unmarshal(elem, &rel); err != nil {
				return nil, nil, fmt.Errorf("unmarshaling relationship at index %d: %w", i, err)
			}
			relationships = append(relationships, rel)
		} else {
			var entity output.AWSIAMResource
			if err := json.Unmarshal(elem, &entity); err != nil {
				return nil, nil, fmt.Errorf("unmarshaling entity at index %d: %w", i, err)
			}
			entities = append(entities, entity)
		}
	}

	return entities, relationships, nil
}
