package outputproviders

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/praetorian-inc/nebula/internal/logs"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type PlainFileProvider struct {
	types.OutputProvider
	OutputPath string
	FileName   string
}

func NewPlainFileProvider(options []*types.Option) types.OutputProvider {
	return &PlainFileProvider{
		OutputPath: types.GetOptionByName(o.OutputOpt.Value, options).Value,
		FileName:   "",
	}
}

func (fp *PlainFileProvider) Write(result types.Result) error {
	var filename string

	// TODO we should centralize this logic
	if result.Filename == "" {
		filename = DefaultFileName(result.Module)
	} else {
		filename = result.Filename
	}
	fullpath := fp.GetFullPath(filename)
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
	file.WriteString(result.String())

	logs.ConsoleLogger().Info("Output written", "path", fullpath)

	return nil
}

func (fp *PlainFileProvider) GetFullPath(filename string) string {
	return fp.OutputPath + string(os.PathSeparator) + filename
}

func (fp *PlainFileProvider) DefaultFileName(prefix string) string {
	return prefix + "-" + strconv.FormatInt(time.Now().Unix(), 10) + ".txt"
}
