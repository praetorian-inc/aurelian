package testutils

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"sync"
)

//go:embed .env
var embeddedEnv string

type environment struct {
	once sync.Once
	err  error
}

var env = &environment{}

func (e *environment) Load() error {
	e.once.Do(func() {
		e.err = loadDotEnv(embeddedEnv)
		if e.err != nil {
			return
		}

		if _, ok := os.LookupEnv("INTEGRATION_AWS_PROFILE"); !ok {
			e.err = os.Setenv("INTEGRATION_AWS_PROFILE", "aurelian")
		}
	})

	return e.err
}

func (e *environment) Get(key string) string {
	return os.Getenv(key)
}

func (e *environment) Set(key string, value string) error {
	return os.Setenv(key, value)
}

func loadDotEnv(dotEnv string) error {
	scanner := bufio.NewScanner(strings.NewReader(dotEnv))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		eqIdx := strings.IndexRune(line, '=')
		if eqIdx <= 0 {
			return fmt.Errorf("invalid .env line: %q", line)
		}

		key := strings.TrimSpace(line[:eqIdx])
		value := strings.TrimSpace(line[eqIdx+1:])
		value = strings.Trim(value, "\"")
		value = strings.Trim(value, "'")

		if key == "" {
			return fmt.Errorf("invalid .env key in line: %q", line)
		}

		if _, ok := os.LookupEnv(key); ok {
			continue
		}

		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
