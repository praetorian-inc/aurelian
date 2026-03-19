package plugin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"
)

// DiscardLogger returns a Logger that silently discards all output.
// Used as a default when no Logger is configured (e.g., library usage, tests).
func DiscardLogger() *Logger {
	return NewLogger(io.Discard, true, true)
}

// progressEntry tracks one active progress bar in the multi-line display.
type progressEntry struct {
	label     string
	completed int64
	total     int64
	final     bool // true when total is final (upstream fully drained)
}

// Logger provides pwnlib-style terminal output for modules.
// User-facing messages (Success, Fail, Info, Warn) always print unless quiet.
// Status provides transient in-place updates for phase messages.
// RenderProgress manages a multi-line progress area at the bottom of output.
// Framework/debug messages should use slog directly.
type Logger struct {
	w       io.Writer
	mu      sync.Mutex
	quiet   bool
	noColor bool
	isTTY   bool

	// pre-rendered prefix strings using lipgloss
	successPrefix string
	failPrefix    string
	infoPrefix    string
	warnPrefix    string
	statusPrefix  string

	renderer    *lipgloss.Renderer
	progressBar progress.Model

	hasStatus    bool              // whether a transient status line is on screen
	progressBars []progressEntry   // active progress bars (ordered by first appearance)
	progressIdx  map[string]int    // label -> index in progressBars
	numProgLines int               // number of progress lines currently rendered on screen
}

// NewLogger creates a Logger writing to w.
// If noColor is true, ANSI colors are disabled.
// If quiet is true, all user messages are suppressed.
func NewLogger(w io.Writer, noColor, quiet bool) *Logger {
	isTTY := false
	if f, ok := w.(*os.File); ok {
		isTTY = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}

	renderer := lipgloss.NewRenderer(w)
	if noColor {
		renderer.SetColorProfile(termenv.Ascii)
	} else {
		renderer.SetColorProfile(termenv.TrueColor)
	}

	var pb progress.Model
	if noColor {
		pb = progress.New(
			progress.WithWidth(30),
			progress.WithoutPercentage(),
			progress.WithColorProfile(termenv.Ascii),
		)
		pb.FullColor = ""
		pb.EmptyColor = ""
	} else {
		pb = progress.New(
			progress.WithSolidFill("#00B4D8"),
			progress.WithWidth(30),
			progress.WithoutPercentage(),
			progress.WithColorProfile(termenv.TrueColor),
		)
	}

	l := &Logger{
		w:        w,
		quiet:    quiet,
		noColor:  noColor,
		isTTY:    isTTY,
		renderer: renderer,
	}

	l.successPrefix = renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("#00CC66")).Render("[+]")
	l.failPrefix = renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("#E63948")).Render("[-]")
	l.infoPrefix = renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("#11C3DB")).Render("[*]")
	l.warnPrefix = renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("#D4AF37")).Render("[!]")
	l.statusPrefix = renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("#00B4D8")).Render("[~]")
	l.progressBar = pb

	return l
}

// Banner prints ASCII art or banner text.
func (l *Logger) Banner(text string) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	styled := l.renderer.NewStyle().Bold(true).Foreground(lipgloss.Color("#E63948")).Render(text)
	_, _ = fmt.Fprintln(l.w, styled)
}

// Success prints a [+] message (green).
func (l *Logger) Success(format string, args ...any) {
	l.print(l.successPrefix, format, args...)
}

// Fail prints a [-] message (red).
func (l *Logger) Fail(format string, args ...any) {
	l.print(l.failPrefix, format, args...)
}

// Info prints a [*] message (blue).
func (l *Logger) Info(format string, args ...any) {
	l.print(l.infoPrefix, format, args...)
}

// Warn prints a [!] message (yellow).
func (l *Logger) Warn(format string, args ...any) {
	l.print(l.warnPrefix, format, args...)
}

// Status displays a transient in-place message (cyan [~]).
// On non-TTY or quiet mode, status messages are suppressed.
// When progress bars are active, Status is a no-op (progress bars provide
// the visual feedback).
func (l *Logger) Status(format string, args ...any) {
	if l.quiet || !l.isTTY {
		return
	}
	msg := fmt.Sprintf(format, args...)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.numProgLines > 0 {
		return
	}

	l.clearStatus()
	_, _ = fmt.Fprintf(l.w, "\r%s %s", l.statusPrefix, msg)
	l.hasStatus = true
}

// ProgressFunc returns a callback bound to the given label, suitable for
// passing directly to pipeline.PipeOpts.Progress.
func (l *Logger) ProgressFunc(label string) func(completed, total int64) {
	return func(completed, total int64) {
		l.RenderProgress(label, completed, total)
	}
}

// RenderProgress renders a progress bar for the given label.
// Each unique label gets its own dedicated line in a multi-line progress area.
//
// When completed and total are both negative, the bar for that label is removed
// (used as a completion signal by the pipeline).
//
// When total is negative (but not -1,-1 sentinel), it signals that the
// upstream input is still flowing — the absolute value is the current item
// count and the bar is capped at 99% to prevent false 100% readings.
// Once total becomes positive, the denominator is final and real progress
// is shown.
//
// On non-TTY or quiet mode, progress updates are suppressed.
func (l *Logger) RenderProgress(label string, completed, total int64) {
	if l.quiet || !l.isTTY {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Sentinel: remove this progress bar (pipe finished).
	if completed < 0 && total < 0 {
		l.removeProgressLocked(label)
		return
	}

	// Decode total sign: negative means upstream is still streaming.
	final := total >= 0
	if total < 0 {
		total = -total
	}

	if total <= 0 {
		return
	}

	if l.progressIdx == nil {
		l.progressIdx = make(map[string]int)
	}

	if idx, ok := l.progressIdx[label]; ok {
		l.progressBars[idx].completed = completed
		l.progressBars[idx].total = total
		l.progressBars[idx].final = final
	} else {
		l.progressIdx[label] = len(l.progressBars)
		l.progressBars = append(l.progressBars, progressEntry{
			label: label, completed: completed, total: total, final: final,
		})
	}

	l.clearArea()
	l.redrawProgress()
}

// removeProgressLocked removes a progress bar by label and redraws.
// Must be called with l.mu held.
func (l *Logger) removeProgressLocked(label string) {
	idx, ok := l.progressIdx[label]
	if !ok {
		return
	}

	l.clearArea()

	l.progressBars = slices.Delete(l.progressBars, idx, idx+1)
	delete(l.progressIdx, label)
	// Rebuild index after removal.
	for i, entry := range l.progressBars {
		l.progressIdx[entry.label] = i
	}

	l.redrawProgress()
}

func (l *Logger) print(prefix, format string, args ...any) {
	if l.quiet {
		return
	}
	msg := fmt.Sprintf(format, args...)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.clearArea()
	_, _ = fmt.Fprintf(l.w, "%s %s\n", prefix, msg)
	l.redrawProgress()
}

// clearStatus erases a transient status line (single-line, no newline).
// Must be called with l.mu held.
func (l *Logger) clearStatus() {
	if l.hasStatus && l.isTTY {
		_, _ = fmt.Fprintf(l.w, "\r\033[2K")
		l.hasStatus = false
	}
}

// clearArea erases the progress area and any transient status line.
// After this call the cursor is at the position where the first cleared line was.
// Must be called with l.mu held.
func (l *Logger) clearArea() {
	if !l.isTTY {
		return
	}

	if l.numProgLines > 0 {
		_, _ = fmt.Fprintf(l.w, "\033[%dA\033[J", l.numProgLines)
		l.numProgLines = 0
		l.hasStatus = false
	} else if l.hasStatus {
		_, _ = fmt.Fprintf(l.w, "\r\033[2K")
		l.hasStatus = false
	}
}

// redrawProgress renders all active progress lines, one per stage.
// Each line shows: [~] <label> <done> <queue bar> <queued> queued
// The queue bar is a fixed 20-block gauge where each block = 1 queued item.
// 20+ items fills the bar completely; the exact count follows.
// Must be called with l.mu held.
func (l *Logger) redrawProgress() {
	if len(l.progressBars) == 0 {
		return
	}

	const barBlocks = 20

	// Compute max widths for alignment.
	var maxLabelLen int
	var maxDone, maxPending int64
	for _, entry := range l.progressBars {
		maxLabelLen = max(maxLabelLen, len(entry.label))
		maxDone = max(maxDone, entry.completed)
		maxPending = max(maxPending, entry.total-entry.completed)
	}

	doneWidth := len(fmt.Sprintf("%d", maxDone))
	pendingDigits := len(fmt.Sprintf("%d", maxPending))
	// " N processing / M processed" suffix width
	//   1 + pendingDigits + 15 + doneWidth + 9
	suffixWidth := 1 + pendingDigits + 15 + doneWidth + 9

	// Layout: [~] <label> <bar> N processing / M processed
	// Ensure bar fits in 80 cols; shrink if labels are very long.
	const maxTermWidth = 80
	barWidth := max(min(maxTermWidth-4-maxLabelLen-1-suffixWidth, barBlocks), 5)
	l.progressBar.Width = barWidth

	for _, entry := range l.progressBars {
		padded := entry.label + strings.Repeat(" ", maxLabelLen-len(entry.label))
		pending := max(entry.total-entry.completed, 0)

		pct := float64(min(pending, int64(barWidth))) / float64(barWidth)
		bar := l.progressBar.ViewAs(pct)
		suffix := fmt.Sprintf("%*d processing / %*d processed", pendingDigits, pending, doneWidth, entry.completed)

		_, _ = fmt.Fprintf(l.w, "%s %s %s %s\n", l.statusPrefix, padded, bar, suffix)
	}

	l.numProgLines = len(l.progressBars)
}

// SlogHandler routes slog messages through the Logger for clean terminal output.
// Warn messages render as [!], Error messages render as [-].
// Info and Debug are controlled by the minimum level.
type SlogHandler struct {
	logger   *Logger
	minLevel slog.Level
	attrs    []slog.Attr
	group    string
}

// NewSlogHandler creates a slog.Handler that routes through the Logger.
// Messages below minLevel are suppressed. Warn/Error always route through
// the Logger regardless of level (they use [!] and [-] prefixes).
func NewSlogHandler(logger *Logger, minLevel slog.Level) *SlogHandler {
	return &SlogHandler{logger: logger, minLevel: minLevel}
}

func (h *SlogHandler) Enabled(_ context.Context, level slog.Level) bool {
	// Always allow Warn and Error through
	if level >= slog.LevelWarn {
		return true
	}
	return level >= h.minLevel
}

func (h *SlogHandler) Handle(_ context.Context, r slog.Record) error {
	// Build message with key-value pairs
	msg := r.Message
	pairs := h.formatAttrs(r)
	if pairs != "" {
		msg = msg + " " + pairs
	}

	switch {
	case r.Level >= slog.LevelError:
		h.logger.Fail("%s", msg)
	case r.Level >= slog.LevelWarn:
		h.logger.Warn("%s", msg)
	case r.Level >= slog.LevelInfo:
		h.logger.Info("%s", msg)
	default:
		h.logger.Info("%s", msg)
	}
	return nil
}

func (h *SlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &SlogHandler{
		logger:   h.logger,
		minLevel: h.minLevel,
		attrs:    merged,
		group:    h.group,
	}
}
func (h *SlogHandler) WithGroup(name string) slog.Handler {
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &SlogHandler{
		logger:   h.logger,
		minLevel: h.minLevel,
		attrs:    h.attrs,
		group:    g,
	}
}
func (h *SlogHandler) formatAttrs(r slog.Record) string {
	var b strings.Builder
	for i, a := range h.attrs {
		if i > 0 {
			b.WriteByte(' ')
		}
		h.writeAttr(&b, a)
	}
	offset := len(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		if offset > 0 || b.Len() > 0 {
			b.WriteByte(' ')
		}
		h.writeAttr(&b, a)
		return true
	})
	return b.String()
}

func (h *SlogHandler) writeAttr(b *strings.Builder, a slog.Attr) {
	if h.group != "" {
		fmt.Fprintf(b, "%s.%s=%v", h.group, a.Key, a.Value)
	} else {
		fmt.Fprintf(b, "%s=%v", a.Key, a.Value)
	}
}
