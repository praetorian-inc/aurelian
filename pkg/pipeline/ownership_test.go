package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errStageSentinel is the error a stage function returns AFTER it has already
// handed the caller-owned out pipeline to an inner Pipe. It stands in for the
// "incomplete enumeration" error AWSFindSecretsModule.Run would return at the
// end of its body (ENG-8770 / ENG-8768).
var errStageSentinel = errors.New("stage sentinel failure")

// forward is a trivial stage that copies each item straight through.
func forward(s string, out *P[string]) error {
	out.Send(s)
	return nil
}

// --- slog capture -----------------------------------------------------------

// warnRecorder is a slog.Handler that captures WARN-and-above records on a
// buffered channel, so a test can BLOCK until the record it expects arrives.
//
// Blocking is load-bearing, not fastidiousness. In the ownership-transfer shape
// the caller's Wait() is released by the INNER Pipe closing done, which happens
// strictly before the outer Pipe's stage function has even returned — so the
// guardrail slog.Warn is emitted some time after the test body would otherwise
// finish. Reading a buffer after Wait() returns is therefore a race that is
// usually lost; waiting on the record is the only honest way to assert it.
type warnRecorder struct {
	ch chan slog.Record
}

func (h *warnRecorder) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= slog.LevelWarn
}

func (h *warnRecorder) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.ch <- r.Clone():
	default: // never block the logging goroutine
	}
	return nil
}

func (h *warnRecorder) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *warnRecorder) WithGroup(_ string) slog.Handler      { return h }

// captureWarnings installs a warnRecorder as the default slog logger for the
// duration of the test and returns it.
//
// slog.SetDefault is process-global, so a test using this must not call
// t.Parallel(); no test in this package does.
func captureWarnings(t *testing.T) *warnRecorder {
	t.Helper()
	rec := &warnRecorder{ch: make(chan slog.Record, 8)}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return rec
}

// next blocks for the next WARN record, failing the test if none arrives.
func (h *warnRecorder) next(t *testing.T) slog.Record {
	t.Helper()
	select {
	case r := <-h.ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the guardrail slog.Warn record")
		return slog.Record{}
	}
}

// requireNone asserts that no WARN record arrives within a short grace period.
// The grace period is what makes this an assertion rather than a coin flip: the
// guardrail is emitted from the Pipe goroutine, so a bare non-blocking read
// would pass even if the warning were about to arrive.
func (h *warnRecorder) requireNone(t *testing.T, grace time.Duration) {
	t.Helper()
	select {
	case r := <-h.ch:
		t.Fatalf("expected no guardrail warning, got %q", r.Message)
	case <-time.After(grace):
	}
}

// recordErr extracts the "error" attribute from a captured record.
func recordErr(t *testing.T, r slog.Record) error {
	t.Helper()
	var got error
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != "error" {
			return true
		}
		if e, ok := a.Value.Any().(error); ok {
			got = e
		}
		return false
	})
	return got
}

// assertDroppedStageErrWarning asserts that the captured record is the
// guardrail warning and that it names err.
func assertDroppedStageErrWarning(t *testing.T, r slog.Record, err error) {
	t.Helper()
	assert.Equal(t, slog.LevelWarn, r.Level)
	assert.True(t, strings.HasPrefix(r.Message, "pipeline: stage error dropped"),
		"guardrail warning should identify itself; got %q", r.Message)
	assert.ErrorIs(t, recordErr(t, r), err,
		"the guardrail warning must name the error it could not deliver")
}

// --- ownership contract ------------------------------------------------------

// TestPipe_OwnershipTransferDropsStageErrorAndWarns pins the contract for the
// UNSUPPORTED shape AWSFindSecretsModule.Run used to have:
//
//	pipeline.Pipe(scanned, secrets.RiskFromScanResult, out) // inner Pipe OWNS out
//	if err := out.Wait(); err != nil { return err }
//	return someError                                        // ← cannot be seen
//
// A stage that hands its caller-owned `out` to an inner Pipe has transferred
// ownership of it. The inner Pipe's close consumes out's closeOnce and releases
// the caller's Wait() BEFORE the stage function has returned at all — so at the
// moment the caller is released, the error the stage is about to return does
// not yet exist.
//
// That is a LOGICAL ORDERING problem, not a memory-visibility one, and no
// library change can fix it: CloseWithError gives the error a happens-before
// edge to Wait(), but an edge cannot deliver a value to a reader that was
// already released. The fix for the production bug was to delete this shape
// (Run now forwards through a pipeline it owns), not to make it work.
//
// So the contract this test pins is: the error is NOT delivered, and the
// library says so loudly via the guardrail warning rather than losing it in
// silence. The silent loss was the actual ENG-8768 defect.
func TestPipe_OwnershipTransferDropsStageErrorAndWarns(t *testing.T) {
	warnings := captureWarnings(t)
	out := New[string]()

	stage := func(_ int, out *P[string]) error {
		// Hand the caller-owned `out` to an inner Pipe. The inner Pipe will
		// close it (both ch and done) when its own input drains.
		Pipe(From("a", "b"), forward, out)
		if err := out.Wait(); err != nil {
			return err
		}
		// Everything downstream succeeded, but this stage still has a failure
		// to report to its caller.
		return errStageSentinel
	}

	Pipe(From(1), stage, out)

	var got []string
	for v := range out.Range() {
		got = append(got, v)
	}
	require.Equal(t, []string{"a", "b"}, got,
		"ownership transfer must not cost items; only the error is unreportable")

	require.NoError(t, out.Wait(),
		"documented limitation: a stage that gives `out` away cannot report an "+
			"error through it — the caller was already released by the inner Pipe")

	assertDroppedStageErrWarning(t, warnings.next(t), errStageSentinel)
}

// TestPipe_OwnershipTransferWithDeferredCleanupDropsStageErrorAndWarns is the
// test above with one difference: the stage carries a deferred cleanup doing
// real filesystem I/O, modelling AWSFindSecretsModule.Run's
// `defer func() { _ = lister.Close() }()` → Enumerator.Close() →
// Skipped.WriteDetailFile() (MkdirAll + MarshalIndent + WriteFile).
//
// Go evaluates the return value first, then runs the deferred I/O, and only
// then hands control back to pipeSequential. The deferred work widens the
// window but does not change the outcome: the caller was released when the
// inner Pipe closed `out`, long before any of this. It is included because the
// production bug was first observed in exactly this shape, and because it
// proves the guardrail still fires when the stage lingers.
func TestPipe_OwnershipTransferWithDeferredCleanupDropsStageErrorAndWarns(t *testing.T) {
	warnings := captureWarnings(t)
	out := New[string]()

	stage := func(_ int, out *P[string]) error {
		dir := t.TempDir()
		defer func() {
			data, _ := json.MarshalIndent([]string{"skipped-op"}, "", "  ")
			_ = os.WriteFile(filepath.Join(dir, "enumeration-skips.json"), data, 0o644)
		}()
		Pipe(From("a", "b"), forward, out)
		if err := out.Wait(); err != nil {
			return err
		}
		return errStageSentinel
	}

	Pipe(From(1), stage, out)

	var got []string
	for v := range out.Range() {
		got = append(got, v)
	}
	require.Equal(t, []string{"a", "b"}, got)

	require.NoError(t, out.Wait(),
		"deferred cleanup widens the window but cannot recall a caller already released")

	assertDroppedStageErrWarning(t, warnings.next(t), errStageSentinel)
}

// TestPipe_StageErrorWithPrivateInnerPipeline is the control, and the shape
// production now uses. Same stage signature and sentinel, different ownership:
// the stage forwards through a pipeline it owns privately and Sends into `out`
// itself, so nothing but the outer Pipe ever closes `out`.
//
// The only FREE variable is ownership; the private pipeline and the copy loop
// are entailed by it — keeping `out` means the stage must supply the inner
// Pipe with some other sink and move the items across itself. With `out` still
// owned by the outer Pipe, publishStageErr's CloseWithError records the error
// INSIDE closeOnce.Do before close(done), which happens-before the caller's
// Wait() returning.
func TestPipe_StageErrorWithPrivateInnerPipeline(t *testing.T) {
	out := New[string]()

	stage := func(_ int, out *P[string]) error {
		private := New[string]()
		Pipe(From("a", "b"), forward, private)
		for v := range private.Range() {
			out.Send(v)
		}
		if err := private.Wait(); err != nil {
			return err
		}
		return errStageSentinel
	}

	Pipe(From(1), stage, out)

	var got []string
	for v := range out.Range() {
		got = append(got, v)
	}
	require.Equal(t, []string{"a", "b"}, got)

	require.ErrorIs(t, out.Wait(), errStageSentinel,
		"caller lost the error the stage function returned")
}

// TestPipe_PrivateInnerPipelineSucceedsCleanly separates "the error is lost"
// from "ownership breaks the pipeline". Identical to the control except the
// stage returns nil: items arrive, Wait() is clean, and no guardrail warning is
// emitted. Without this, a reader cannot tell whether the owned shape merely
// relocates the failure or actually works.
func TestPipe_PrivateInnerPipelineSucceedsCleanly(t *testing.T) {
	warnings := captureWarnings(t)
	out := New[string]()

	stage := func(_ int, out *P[string]) error {
		private := New[string]()
		Pipe(From("a", "b"), forward, private)
		for v := range private.Range() {
			out.Send(v)
		}
		return private.Wait()
	}

	Pipe(From(1), stage, out)

	got, err := out.Collect()
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, got)

	warnings.requireNone(t, 200*time.Millisecond)
}
