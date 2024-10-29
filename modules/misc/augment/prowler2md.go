package augment

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type MiscProwlerToMDTable struct {
	modules.BaseModule
}

var MiscProwlerToMDTableOptions = []*types.Option{&options.DirPathOpt, &options.ProviderType}

var MiscProwlerToMDTableOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewMarkdownFileProvider,
}

var MiscProwlerToMDTableMetadata = modules.Metadata{
	Id:          "prowlertomdtable", // this will be the CLI command name
	Name:        "ProwlerToMDTable",
	Description: "Convert Prowler results to a Markdown table.",
	Platform:    modules.Universal,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.None,
	References:  []string{},
}

func NewMiscProwlerToMDTable(options []*types.Option) (<-chan string, stages.Stage[string, types.MarkdownTable], error) {
	pipeline, err := stages.ChainStages[string, types.MarkdownTable](
		stages.GetFilesOfType,
		prowlerToMDTableStage,
	)

	if err != nil {
		return nil, nil, err
	}
	return stages.Generator([]string{"csv"}), pipeline, nil
	// testing pipeline creation with manually created channel
	// test := make(chan string)
	// go func() {
	// 	test <- "csv"
	// 	defer close(test)
	// }()
	// return test, pipeline, nil
}
