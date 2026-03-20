package queries

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"gopkg.in/yaml.v3"
)

//go:embed enrich
var enrichFS embed.FS

//go:embed analysis
var analysisFS embed.FS

var queryRegistry map[string]*Query

func init() {
	queryRegistry = make(map[string]*Query)
	loadFromFS(enrichFS, "enrich")
	loadFromFS(analysisFS, "analysis")
}

func loadFromFS(fs embed.FS, rootDir string) {
	entries, err := fs.ReadDir(rootDir)
	if err != nil {
		slog.Error("failed to read queries directory", "dir", rootDir, "error", err)
		return
	}
	loadQueriesRecursive(fs, entries, rootDir)
}

func loadQueriesRecursive(fsys embed.FS, entries []fs.DirEntry, prefix string) {
	for _, entry := range entries {
		fullPath := filepath.Join(prefix, entry.Name())

		if entry.IsDir() {
			subEntries, err := fsys.ReadDir(fullPath)
			if err != nil {
				slog.Error("failed to read subdirectory", "path", fullPath, "error", err)
				continue
			}
			loadQueriesRecursive(fsys, subEntries, fullPath)
		} else if strings.HasSuffix(entry.Name(), ".yaml") {
			data, err := fsys.ReadFile(fullPath)
			if err != nil {
				slog.Error("failed to read query file", "path", fullPath, "error", err)
				continue
			}

			var metadata QueryMetadata
			if err := yaml.Unmarshal(data, &metadata); err != nil {
				slog.Error("failed to parse query YAML", "path", fullPath, "error", err)
				continue
			}

			query := &Query{
				Metadata: metadata,
				Cypher:   metadata.Cypher,
			}

			queryRegistry[metadata.ID] = query
			slog.Debug("loaded query", "id", metadata.ID, "name", metadata.Name)
		}
	}
}

// EnrichAWS runs all AWS enrichment queries in order
func EnrichAWS(ctx context.Context, db graph.GraphDatabase) error {
	var enrichQueries []*Query
	for _, query := range queryRegistry {
		if query.Metadata.Type == "enrich" && query.Metadata.Platform == "aws" {
			enrichQueries = append(enrichQueries, query)
		}
	}

	sort.Slice(enrichQueries, func(i, j int) bool {
		return enrichQueries[i].Metadata.Order < enrichQueries[j].Metadata.Order
	})

	slog.Info("running AWS enrichment queries", "count", len(enrichQueries))

	for _, query := range enrichQueries {
		slog.Debug("executing enrichment query", "id", query.Metadata.ID, "name", query.Metadata.Name)

		result, err := db.Query(ctx, query.Cypher, nil)
		if err != nil {
			return fmt.Errorf("query %s failed: %w", query.Metadata.ID, err)
		}

		slog.Debug("query completed",
			"id", query.Metadata.ID,
			"nodes_created", result.Summary.NodesCreated,
			"relationships_created", result.Summary.RelationshipsCreated)
	}

	return nil
}

// AnalyzeAWS runs all AWS analysis queries in order and returns results
func AnalyzeAWS(ctx context.Context, db graph.GraphDatabase) ([]*graph.QueryResult, error) {
	var analysisQueries []*Query
	for _, query := range queryRegistry {
		if query.Metadata.Type == "analysis" && query.Metadata.Platform == "aws" {
			analysisQueries = append(analysisQueries, query)
		}
	}

	sort.Slice(analysisQueries, func(i, j int) bool {
		return analysisQueries[i].Metadata.Order < analysisQueries[j].Metadata.Order
	})

	slog.Info("running AWS analysis queries", "count", len(analysisQueries))

	var results []*graph.QueryResult
	for _, query := range analysisQueries {
		slog.Debug("executing analysis query", "id", query.Metadata.ID, "name", query.Metadata.Name)

		result, err := db.Query(ctx, query.Cypher, nil)
		if err != nil {
			return nil, fmt.Errorf("query %s failed: %w", query.Metadata.ID, err)
		}

		results = append(results, result)

		slog.Debug("query completed",
			"id", query.Metadata.ID,
			"records", len(result.Records))
	}

	return results, nil
}

// RunPlatformQuery executes a specific query by ID
func RunPlatformQuery(ctx context.Context, db graph.GraphDatabase, queryID string, params map[string]any) (*graph.QueryResult, error) {
	query, exists := queryRegistry[queryID]
	if !exists {
		return nil, fmt.Errorf("query not found: %s", queryID)
	}
	return db.Query(ctx, query.Cypher, params)
}

// ListQueries returns all loaded query IDs
func ListQueries() []string {
	ids := make([]string, 0, len(queryRegistry))
	for id := range queryRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// GetQuery returns a query by ID
func GetQuery(id string) (*Query, bool) {
	q, ok := queryRegistry[id]
	return q, ok
}
