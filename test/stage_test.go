package test

import (
	"context"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
)

func TestChainStages(t *testing.T) {
	stage1 := func(ctx context.Context, opts []*options.Option, in <-chan int) <-chan int {
		out := make(chan int)
		go func() {
			defer close(out)
			for i := range in {
				out <- i + 1
			}
		}()
		return out
	}

	stage2 := func(ctx context.Context, opts []*options.Option, in <-chan int) <-chan int {
		out := make(chan int)
		go func() {
			defer close(out)
			for i := range in {
				out <- i * 2
			}
		}()
		return out
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// test single stage
	input := make(chan int, 1)
	input <- 1
	close(input)

	chain, err := stages.ChainStages[int, int](stage1)
	if err != nil {
		t.Errorf("Error chaining stages: %v", err)
	}

	output := chain(ctx, nil, input)
	result := <-output
	if result != 2 {
		t.Errorf("Expected 2, but got %d", result)
	}

	// test multiple stages
	input = make(chan int, 1)
	input <- 1
	close(input)

	chain, err = stages.ChainStages[int, int](stage1, stage2)
	if err != nil {
		t.Errorf("Error chaining stages: %v", err)
	}

	output = chain(ctx, nil, input)

	result = <-output
	expected := 4 // (1 + 1) * 2

	if result != expected {
		t.Errorf("Expected %d, but got %d", expected, result)
	}
}
func TestChainStagesDifferentTypes(t *testing.T) {
	stage1 := func(ctx context.Context, opts []*options.Option, in <-chan int) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for i := range in {
				out <- strconv.Itoa(i)
			}
		}()
		return out
	}

	stage2 := func(ctx context.Context, opts []*options.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for i := range in {
				out <- i + "!"
			}
		}()
		return out
	}

	stage3 := func(ctx context.Context, opts []*options.Option, in <-chan string) <-chan int {
		out := make(chan int)
		go func() {
			defer close(out)
			for i := range in {
				out <- len(i)
			}
		}()
		return out
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	input := make(chan int, 1)
	input <- 1
	close(input)

	chain, err := stages.ChainStages[int, int](stage1, stage2, stage3)
	if err != nil {
		t.Errorf("Error chaining stages: %v", err)
	}

	output := chain(ctx, nil, input)

	result := <-output
	expected := 2

	if result != expected {
		t.Errorf("Expected %d, but got %d", expected, result)
	}
}

// TestValidateStageCompaibility tests the validateStageCompatibility function to ensure it correctly identifies
// incompatible and compatible stages.
func TestValidateStages(t *testing.T) {
	stage1 := func(ctx context.Context, opts []*options.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for s := range in {
				out <- s + "!"
			}
		}()
		return out
	}

	stage2 := func(ctx context.Context, opts []*options.Option, in <-chan int) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for i := range in {
				out <- strconv.Itoa(i) + " items"
			}
		}()
		return out
	}

	stage3 := func(ctx context.Context, opts []*options.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for s := range in {
				out <- s + "!"
			}
		}()
		return out
	}

	var in1 string
	var out1 string

	// should fail as the input of stage2 is an int and we expect a string as the type of in1
	err := stages.ValidateStages(in1, out1, stage2, stage1, stage3)
	if err == nil {
		t.Error("Expected error, but got nil")

	}

	// valid
	err = stages.ValidateStages(in1, out1, stage1, stage3)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	var in2 int
	var out2 string

	// stage2 - in:int -> out:string
	// stage1 - in:string -> out:string
	// stage3 - in:string -> out:string
	err = stages.ValidateStages(in2, out2, stage2, stage1, stage3)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
}

func TestFanStages(t *testing.T) {
	stage1 := func(ctx context.Context, opts []*options.Option, in <-chan int) <-chan int {
		out := make(chan int)
		go func() {
			defer close(out)
			for i := range in {
				out <- i + 1
			}
		}()
		return out
	}

	stage2 := func(ctx context.Context, opts []*options.Option, in <-chan int) <-chan int {
		out := make(chan int)
		go func() {
			defer close(out)
			for i := range in {
				out <- i * 2
			}
		}()
		return out
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	input := make(chan int)
	defer close(input)

	output := make(chan int)
	defer close(output)
	go func() {
		stages.FanStages(ctx, nil, input, output, stage1, stage2)
	}()

	input <- 2

	results := []int{}
	for result := range output {
		results = append(results, result)
		if len(results) == 2 {
			break
		}
	}

	expected := []int{3, 4} // 2 + 1 = 3, 2 * 2 = 4
	sort.Ints(results)

	if len(results) != len(expected) {
		t.Errorf("Expected %v, but got %v", expected, results)
	}
}

func TestGeneratorStage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	input := make(chan string, 1)
	input <- "test"
	close(input)

	in := stages.Generator([]string{"test"})

	output := stages.Echo[string, string](ctx, nil, in)

	result := <-output
	expected := "test"

	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}
