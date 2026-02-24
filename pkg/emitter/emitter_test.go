package emitter

import (
	"fmt"
	"testing"
)

func TestEmitter_BasicProduceConsume(t *testing.T) {
	e := From(0, 1, 2, 3, 4)

	var got []int
	for v := range e.Range() {
		got = append(got, v)
	}

	if err := e.Wait(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("expected 5 items, got %d", len(got))
	}
	for i, v := range got {
		if v != i {
			t.Errorf("got[%d] = %d, want %d", i, v, i)
		}
	}
}

func TestEmitter_ErrorPropagation(t *testing.T) {
	e := New[int]()
	go func() {
		e.Emit(1)
		e.CloseWithError(fmt.Errorf("producer failed"))
	}()

	for range e.Range() {
	}

	if err := e.Wait(); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestPipe(t *testing.T) {
	in := From(1, 2, 3)
	out := New[string]()

	Pipe(in, out, func(v int, o *Emitter[string]) error {
		o.Emit(fmt.Sprintf("item-%d", v))
		return nil
	})

	var got []string
	for v := range out.Range() {
		got = append(got, v)
	}

	if err := out.Wait(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 items, got %d", len(got))
	}
	expected := []string{"item-1", "item-2", "item-3"}
	for i, v := range got {
		if v != expected[i] {
			t.Errorf("got[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestPipe_FnError(t *testing.T) {
	in := From(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
	out := New[int]()

	Pipe(in, out, func(v int, o *Emitter[int]) error {
		if v == 3 {
			return fmt.Errorf("bad value")
		}
		o.Emit(v * 2)
		return nil
	})

	var got []int
	for v := range out.Range() {
		got = append(got, v)
	}

	if err := out.Wait(); err == nil {
		t.Fatal("expected error from Pipe, got nil")
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 items before error, got %d", len(got))
	}
}

func TestPipe_UpstreamErrorPropagates(t *testing.T) {
	in := New[int]()
	out := New[int]()

	go func() {
		in.Emit(1)
		in.CloseWithError(fmt.Errorf("upstream failed"))
	}()

	Pipe(in, out, func(v int, o *Emitter[int]) error {
		o.Emit(v)
		return nil
	})

	for range out.Range() {
	}

	if err := out.Wait(); err == nil {
		t.Fatal("expected upstream error to propagate")
	}
}

func TestFrom_Empty(t *testing.T) {
	e := From[int]()

	var got []int
	for v := range e.Range() {
		got = append(got, v)
	}

	if err := e.Wait(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 items, got %d", len(got))
	}
}
