package outputproviders

import (
	"os"
	"path/filepath"

	"github.com/praetorian-inc/nebula/internal/message"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type PlainFileProvider struct {
	types.OutputProvider
	OutputPath string
	FileName   string
}

func NewPlainFileProvider(opts []*types.Option) types.OutputProvider {
	return &PlainFileProvider{
		OutputPath: options.GetOptionByName(options.OutputOpt.Value, opts).Value,
		FileName:   "",
	}
}

func (fp *PlainFileProvider) Write(result types.Result) error {
	var filename string

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

	file, err := os.OpenFile(fullpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString(result.String())

	message.Success("Output written to %s", fullpath)

	return nil
}

func (fp *PlainFileProvider) DefaultFileName(prefix string) string {
	return DefaultFileName(prefix, "txt")
}
