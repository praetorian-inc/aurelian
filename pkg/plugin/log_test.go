package plugin

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggerSuccess(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.Success("found %d items", 3)
	got := buf.String()
	if !strings.Contains(got, "[+]") {
		t.Errorf("expected [+] prefix, got: %q", got)
	}
	if !strings.Contains(got, "found 3 items") {
		t.Errorf("expected formatted message, got: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("expected trailing newline, got: %q", got)
	}
}

func TestLoggerFail(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.Fail("could not connect")
	got := buf.String()
	if !strings.Contains(got, "[-]") {
		t.Errorf("expected [-] prefix, got: %q", got)
	}
	if !strings.Contains(got, "could not connect") {
		t.Errorf("expected message, got: %q", got)
	}
}

func TestLoggerInfo(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.Info("scanning %d regions", 12)
	got := buf.String()
	if !strings.Contains(got, "[*]") {
		t.Errorf("expected [*] prefix, got: %q", got)
	}
	if !strings.Contains(got, "scanning 12 regions") {
		t.Errorf("expected formatted message, got: %q", got)
	}
}

func TestLoggerWarn(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.Warn("permission denied for %s", "s3")
	got := buf.String()
	if !strings.Contains(got, "[!]") {
		t.Errorf("expected [!] prefix, got: %q", got)
	}
	if !strings.Contains(got, "permission denied for s3") {
		t.Errorf("expected formatted message, got: %q", got)
	}
}

func TestLoggerQuiet(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, true) // quiet=true
	l.Success("should not appear")
	l.Fail("should not appear")
	l.Info("should not appear")
	l.Warn("should not appear")
	if buf.Len() != 0 {
		t.Errorf("expected no output in quiet mode, got: %q", buf.String())
	}
}

func TestLoggerStatusNonTTY(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	// Status is a no-op on non-TTY writers
	l.Status("authenticating...")
	if buf.Len() != 0 {
		t.Errorf("expected no status output on non-TTY, got: %q", buf.String())
	}
}

func TestRenderProgressNonTTY(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	// RenderProgress is a no-op on non-TTY writers
	l.RenderProgress("scanning", 5, 10)
	if buf.Len() != 0 {
		t.Errorf("expected no progress output on non-TTY, got: %q", buf.String())
	}
}

func TestRenderProgressQuiet(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, true) // quiet=true
	l.isTTY = true
	l.RenderProgress("scanning", 5, 10)
	assert.Empty(t, buf.String(), "RenderProgress should be suppressed in quiet mode")
}

func TestRenderProgressZeroTotal(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true
	// zero total should be a no-op
	l.RenderProgress("scanning", 0, 0)
	assert.Empty(t, buf.String(), "RenderProgress should be no-op when total is 0")
}

func TestRenderProgressTTY(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true

	l.RenderProgress("scanning", 5, 10)
	got := buf.String()

	assert.Contains(t, got, "[~]", "should use status prefix")
	assert.Contains(t, got, "scanning")
	assert.True(t, strings.HasSuffix(got, "\n"), "each progress bar should end with newline")
}

func TestRenderProgressMultiLine(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true

	l.RenderProgress("listing resources", 3, 10)
	l.RenderProgress("enriching resources", 1, 5)
	got := buf.String()

	assert.Contains(t, got, "listing resources")
	assert.Contains(t, got, "enriching resources")

	// Second render should use cursor-up to redraw both bars.
	assert.Contains(t, got, "\033[1A", "should move cursor up to redraw")
}

func TestRenderProgressRemoveOnSentinel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true

	l.RenderProgress("listing", 5, 10)
	l.RenderProgress("enriching", 2, 5)
	assert.Equal(t, 2, l.numProgLines)

	// Signal completion of "listing" bar.
	l.RenderProgress("listing", -1, -1)
	assert.Equal(t, 1, l.numProgLines)

	buf.Reset()
	l.RenderProgress("enriching", 4, 5)
	got := buf.String()

	assert.Contains(t, got, "enriching")
	assert.NotContains(t, got, "listing", "removed bar should not appear")
}

func TestRenderProgressPermanentMessagePreservesBars(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true

	l.RenderProgress("listing", 3, 10)
	buf.Reset()

	l.Info("found something")
	got := buf.String()

	// Should clear progress area, print message, then redraw the bar.
	assert.Contains(t, got, "[*]")
	assert.Contains(t, got, "found something")
	assert.Contains(t, got, "listing", "progress bar should be redrawn after message")
}

func TestLoggerMultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.Info("step 1")
	l.Success("step 2")
	l.Warn("step 3")
	got := buf.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d: %q", len(lines), got)
	}
}

func TestLoggerStatusTTY(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true

	l.Status("authenticating to %s", "aws")
	got := buf.String()

	assert.Contains(t, got, "[~]")
	assert.Contains(t, got, "authenticating to aws")
	assert.True(t, strings.HasPrefix(got, "\r"), "should start with carriage return")
	assert.False(t, strings.HasSuffix(got, "\n"), "status should NOT end with newline")
}

func TestLoggerPermanentMessageClearsStatus(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true

	l.Status("loading...")
	buf.Reset() // clear status output to isolate permanent message behavior
	l.Success("done")
	got := buf.String()

	assert.Contains(t, got, "\r\033[2K", "should clear status line before permanent message")
	assert.Contains(t, got, "[+]")
	assert.Contains(t, got, "done")
}

func TestLoggerConcurrentAccess(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	l.isTTY = true

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			l.Info("msg %d", n)
			l.Status("status %d", n)
		}(i)
	}
	wg.Wait()
	// No assertions beyond "didn't race or panic"
}

func TestLoggerStatusQuiet(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, true) // quiet=true
	l.isTTY = true

	l.Status("should not appear")
	assert.Empty(t, buf.String(), "Status should be suppressed in quiet mode")
}

func TestSlogHandlerRoutesErrorToFail(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	h := NewSlogHandler(l, slog.LevelInfo)
	logger := slog.New(h)
	logger.Error("something broke")
	assert.Contains(t, buf.String(), "[-]")
	assert.Contains(t, buf.String(), "something broke")
}

func TestSlogHandlerRoutesWarnToWarn(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	h := NewSlogHandler(l, slog.LevelInfo)
	logger := slog.New(h)
	logger.Warn("careful now")
	assert.Contains(t, buf.String(), "[!]")
	assert.Contains(t, buf.String(), "careful now")
}

func TestSlogHandlerRoutesInfoAndFilters(t *testing.T) {
	t.Run("info passes at info level", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, false)
		h := NewSlogHandler(l, slog.LevelInfo)
		logger := slog.New(h)
		logger.Info("hello info")
		assert.Contains(t, buf.String(), "[*]")
		assert.Contains(t, buf.String(), "hello info")
	})

	t.Run("info suppressed at warn level", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, false)
		h := NewSlogHandler(l, slog.LevelWarn)
		logger := slog.New(h)
		logger.Info("should not appear")
		assert.Empty(t, buf.String())
	})

	t.Run("warn still passes at warn level", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, false)
		h := NewSlogHandler(l, slog.LevelWarn)
		logger := slog.New(h)
		logger.Warn("should appear")
		assert.Contains(t, buf.String(), "[!]")
	})
}

func TestSlogHandlerWithAttrsFormatsKeyValue(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, true, false)
	h := NewSlogHandler(l, slog.LevelInfo)
	derived := h.WithAttrs([]slog.Attr{slog.String("region", "us-east-1")})
	logger := slog.New(derived)
	logger.Info("scanning")
	got := buf.String()
	assert.Contains(t, got, "region=us-east-1")
	assert.Contains(t, got, "scanning")
}

func TestSlogHandlerWithGroupPrefixesAttrs(t *testing.T) {
	t.Run("single group", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, false)
		h := NewSlogHandler(l, slog.LevelInfo)
		derived := h.WithGroup("aws").WithAttrs([]slog.Attr{slog.String("region", "us-east-1")})
		logger := slog.New(derived)
		logger.Info("test")
		assert.Contains(t, buf.String(), "aws.region=us-east-1")
	})

	t.Run("nested groups", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, false)
		h := NewSlogHandler(l, slog.LevelInfo)
		derived := h.WithGroup("cloud").WithGroup("aws").WithAttrs([]slog.Attr{slog.String("key", "val")})
		logger := slog.New(derived)
		logger.Info("test")
		assert.Contains(t, buf.String(), "cloud.aws.key=val")
	})
}

func TestBannerOutput(t *testing.T) {
	t.Run("prints text with newline", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, false)
		l.Banner("AURELIAN")
		got := buf.String()
		assert.Contains(t, got, "AURELIAN")
		assert.True(t, strings.HasSuffix(got, "\n"))
	})

	t.Run("quiet suppresses banner", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, true)
		l.Banner("AURELIAN")
		assert.Empty(t, buf.String())
	})
}

func TestLoggerColorEnabled(t *testing.T) {
	t.Run("noColor false produces styled output", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, false, false)
		l.Success("test")
		got := buf.String()
		assert.Contains(t, got, "[+]")
		// lipgloss will produce ANSI escape codes when color is enabled
		assert.Contains(t, got, "\033[")
	})

	t.Run("noColor true produces plain prefix", func(t *testing.T) {
		var buf bytes.Buffer
		l := NewLogger(&buf, true, false)
		l.Success("test")
		got := buf.String()
		assert.Contains(t, got, "[+]")
		assert.NotContains(t, got, "\033[")
	})
}

func TestDiscardLoggerIsNoOp(t *testing.T) {
	l := DiscardLogger()
	assert.NotPanics(t, func() {
		l.Info("test %d", 1)
		l.Success("test")
		l.Warn("test")
		l.Fail("test")
		l.Status("test")
		l.RenderProgress("test", 5, 10)
	})
}
