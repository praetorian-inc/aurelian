package outputproviders

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/nebula/internal/message"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type JsonFileProvider struct {
	types.OutputProvider
	OutputPath string
	FileName   string
}

func NewJsonFileProvider(opts []*types.Option) types.OutputProvider {
	return &JsonFileProvider{
		OutputPath: options.GetOptionByName(options.OutputOpt.Name, opts).Value,
		FileName:   "",
	}
}

func (fp *JsonFileProvider) Write(result types.Result) error {
	var filename string

	_, ok := result.Data.(types.MarkdownTable)
	if ok {
		// Skip if not the correct type
		slog.Info("JSON provider is skipping markdown table output")
		return nil
	}

	if result.Filename == "" {
		filename = fp.DefaultFileName(result.Module)
	} else {
		filename = result.Filename
	}
	fullpath := GetFullPath(filename, fp.OutputPath)
	dir := filepath.Dir(fullpath)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	file, err := os.Create(fullpath)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(result.Data)
	if err != nil {
		return err
	}

	message.Success("Output written to %s", fullpath)

	return nil
}

func (fp *JsonFileProvider) DefaultFileName(prefix string) string {
	return DefaultFileName(prefix, "json")
}
