//go:build integration

package fixture

import (
	"context"
	"errors"
	"testing"
)

type stubM struct{ code int }

func (s stubM) Run() int { return s.code }

func TestRunTestsWith_TestsFailed_SkipsDestroy(t *testing.T) {
	called := false
	got := runTestsWith(stubM{code: 2}, func(context.Context) error {
		called = true
		return nil
	}, func(string) string { return "" })

	if got != 2 {
		t.Errorf("want exit code 2, got %d", got)
	}
	if called {
		t.Errorf("destroy should not run on test failure")
	}
}

func TestRunTestsWith_KeepFlagSet_SkipsDestroy(t *testing.T) {
	called := false
	got := runTestsWith(stubM{code: 0}, func(context.Context) error {
		called = true
		return nil
	}, func(key string) string {
		if key == "AURELIAN_KEEP_FIXTURES" {
			return "1"
		}
		return ""
	})

	if got != 0 {
		t.Errorf("want exit code 0, got %d", got)
	}
	if called {
		t.Errorf("destroy should not run when AURELIAN_KEEP_FIXTURES=1")
	}
}

func TestRunTestsWith_Success_InvokesDestroy(t *testing.T) {
	called := false
	got := runTestsWith(stubM{code: 0}, func(context.Context) error {
		called = true
		return nil
	}, func(string) string { return "" })

	if got != 0 {
		t.Errorf("want exit code 0, got %d", got)
	}
	if !called {
		t.Errorf("destroy should run on success with no opt-out")
	}
}

func TestRunTestsWith_DestroyFailure_ReturnsOne(t *testing.T) {
	got := runTestsWith(stubM{code: 0}, func(context.Context) error {
		return errors.New("destroy boom")
	}, func(string) string { return "" })

	if got != 1 {
		t.Errorf("want exit code 1 when destroy fails on otherwise-passing run, got %d", got)
	}
}
