package outputproviders

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/praetorian-inc/nebula/internal/logs"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type JsonFileProvider struct {
	types.OutputProvider
	OutputPath string
	FileName   string
}

func NewJsonFileProvider(options []*types.Option) types.OutputProvider {
	return &JsonFileProvider{
		OutputPath: types.GetOptionByName(o.OutputOpt.Value, options).Value,
		FileName:   "",
	}
}

func (fp *JsonFileProvider) Write(result types.Result) error {
	var filename string

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
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(result)
	if err != nil {
		return err
	}

	logs.ConsoleLogger().Info("Output written", "path", fullpath)

	return nil
}

func (fp *JsonFileProvider) GetFullPath(filename string) string {
	return fp.OutputPath + string(os.PathSeparator) + filename
}

// Generate a random 10-character UUID
func generateShortUUIDJson() string {
	b := make([]byte, 5) // 5 bytes = 10 hex characters
	if _, err := rand.Read(b); err != nil {
		return "" // In case of error, return empty string
	}
	return hex.EncodeToString(b)
}

func DefaultFileName(prefix string) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	uuid := generateShortUUIDJson()
	return prefix + "-" + timestamp + "-" + uuid + ".json"
}
