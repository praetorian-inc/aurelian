package aws

import (
	"context"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
	"github.com/praetorian-inc/konstellation/pkg/graph/queries"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type ApolloQuery struct {
	*chain.Base
	db graph.GraphDatabase
}

func NewApolloQuery(configs ...cfg.Config) chain.Link {
	a := &ApolloQuery{}
	a.Base = chain.NewBase(a, configs...)
	return a
}

func (a *ApolloQuery) Params() []cfg.Param {
	params := a.Base.Params()
	params = append(params, options.Query())
	params = append(params, options.List())
	params = append(params, options.Neo4jOptions()...)
	return params
}

func (a *ApolloQuery) Initialize() error {
	graphConfig := &graph.Config{
		URI:      a.Args()[options.Neo4jURI().Name()].(string),
		Username: a.Args()[options.Neo4jUsername().Name()].(string),
		Password: a.Args()[options.Neo4jPassword().Name()].(string),
	}

	db, err := adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		return err
	}
	a.db = db

	err = a.db.VerifyConnectivity(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func (a *ApolloQuery) Process(query string) error {
	if a.Args()[options.List().Name()].(bool) {
		qs, err := queries.GetPlatformQueries("aws", "analysis")
		if err != nil {
			return err
		}
		for _, q := range qs {
			a.Send(q.ID)
		}
		return nil
	}

	qs, err := queries.GetPlatformQueries("aws", "analysis")
	if err != nil {
		return err
	}

	for _, q := range qs {
		if q.ID == query || query == "all" {
			res, err := queries.RunPlatformQuery(a.db, q.ID, nil)
			if err != nil {
				return err
			}

			for _, r := range res.Records {
				vuln, ok := r["vulnerable"].(string)
				if !ok {
					a.Logger.Error("Vulnerable entity is not a string", "vulnerable", r["vulnerable"], "query", q.ID)
					continue
				}

				// var proofKey string
				// var proofValue any
				// for k, _ := range r {
				// 	if k != "vulnerable" {
				// 		proofKey = k
				// 		proofValue = r.String()
				// 		break
				// 	}
				// }

				// if proofKey == "" {
				// 	proofKey = "attack-path"
				// 	proofValue = r.String()
				// }

				risk := model.Risk{
					Name:     q.QueryMetadata.Name,
					DNS:      vuln,
					Priority: GetPriority(q.QueryMetadata.Severity),
					// Proof:    map[string]any{proofKey: proofValue},
					// Metadata: map[string]any{
					// 	"name":              q.QueryMetadata.Name,
					// 	"description":       q.QueryMetadata.Description,
					// 	"severity":          q.QueryMetadata.Severity,
					// 	"impacted-services": q.QueryMetadata.ImpactedServices,
					// },
				}
				a.Send(risk)
			}
		}
	}
	return nil
}

func (a *ApolloQuery) Close() {
	a.db.Close()
}

func GetPriority(severity string) int {
	switch severity {
	case "LOW":
		return 3
	case "MEDIUM":
		return 5
	case "HIGH":
		return 8
	case "CRITICAL":
		return 10
	default:
		return 3
	}
}
