package stages

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/praetorian-inc/nebula/pkg/types"
)

// Stage represents a pipeline stage that processes input of type I and produces output of type O.
// It takes a context for cancellation, a slice of options for configuration, and an input channel of type I.
// It returns an output channel of type O.
type Stage[I any, O any] func(ctx context.Context, opts []*types.Option, in <-chan I) <-chan O

type StageFactory[I any, O any] func(opts []*types.Option) (<-chan I, Stage[I, O], error)

// ChainStages chains multiple stages together, ensuring that the output type of each stage
// matches the input type of the next stage. It returns a single stage function that processes
// the input through all the provided stages sequentially.
//
// Type Parameters:
//   - I: The input type for the first stage.
//   - O: The output type for the last stage.
//
// Parameters:
//   - stages: A variadic parameter of stages to be chained. Each stage must be a function that
//     takes a context, a slice of options, and an input channel, and returns an output channel.
//
// Returns:
//   - (Stage[I, O], error): A function that represents the chained stages, or an error if the
//     stages are not compatible or if no stages are provided.
//
// Errors:
//   - Returns an error if no stages are provided or if the stages are not compatible.
//
// Example:
//
//	stage1 := func(ctx context.Context, opts []*types.Option, in <-chan int) <-chan string { /* ... */ }
//	stage2 := func(ctx context.Context, opts []*types.Option, in <-chan string) <-chan float64 { /* ... */ }
//	chainedStage, err := ChainStages[int, float64](stage1, stage2)
//	if err != nil {
//	    log.Fatal(err)
//	}
func ChainStages[I any, O any](stages ...any) (Stage[I, O], error) {
	if len(stages) == 0 {
		return nil, fmt.Errorf("no stages provided")
	}

	for i, stage := range stages {
		if err := validateFunctionSignature(stage); err != nil {
			return nil, fmt.Errorf("stage %d: %v", i, err)
		}
	}

	// Validate the stages are compatible
	var inType I
	var outType O
	if err := ValidateStages(inType, outType, stages...); err != nil {
		return nil, err
	}

	// Return the chained stage function
	return func(ctx context.Context, opts []*types.Option, in <-chan I) <-chan O {

		var chanIn reflect.Value
		var chanOut reflect.Value
		chanIn = reflect.ValueOf(in)
		for i := 0; i < len(stages); i++ {
			stageFunc := reflect.ValueOf(stages[i])
			chanOut = stageFunc.Call([]reflect.Value{
				reflect.ValueOf(ctx),
				reflect.ValueOf(opts),
				chanIn,
			})[0]

			chanIn = chanOut
		}

		// We can be confident that the last stage is compatible with the output type because of the checks in validateStages
		return chanOut.Interface().(<-chan O)
	}, nil
}

// validateStages checks the compatibility of a series of stages to ensure they can be chained together.
// It validates that the output type of each stage matches the input type of the next stage, and that the
// input type of the first stage matches the provided input type (In), and the output type of the last stage
// matches the provided output type (Out).
//
// Parameters:
// - In: The expected input type for the first stage.
// - Out: The expected output type for the last stage.
// - stages: A variadic parameter representing the stages to be validated.
//
// Returns:
// - error: An error if any of the stages are incompatible, or if the input/output types do not match the expected types.
func ValidateStages(In any, Out any, stages ...any) error {

	// Validate chaining each stage together is compatible
	if len(stages) > 1 {
		for i := 0; i < len(stages)-1; i++ {
			if err := validateStageCompatibility(stages[i], stages[i+1]); err != nil {
				return err
			}
		}
	}

	stageTypeIn := reflect.TypeOf(stages[0]).In(2).Elem() // Input type of stage1's channel
	if stageTypeIn != reflect.TypeOf(In) {
		return fmt.Errorf("first stage input type %s does not match ChainStages input type %s",
			stageTypeIn, reflect.TypeOf(In))
	}

	lastStageOutType := reflect.TypeOf(stages[len(stages)-1]).Out(0).Elem() // Output type of last stage's channel
	if lastStageOutType != reflect.TypeOf(Out) {
		return fmt.Errorf("last stage output type %s does not match ChainStages output type %s",
			lastStageOutType, reflect.TypeOf(Out))
	}

	return nil
}

func validateFunctionSignature(stage interface{}) error {
	stageType := reflect.TypeOf(stage)
	if stageType.Kind() != reflect.Func {
		return fmt.Errorf("stage is not a function")
	}

	if stageType.NumIn() != 3 {
		return fmt.Errorf("stage function must have exactly 3 input parameters")
	}

	if stageType.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		return fmt.Errorf("first parameter of stage function must be context.Context")
	}

	if stageType.In(1) != reflect.TypeOf([]*types.Option{}) {
		return fmt.Errorf("second parameter of stage function must be []*types.Option")
	}

	if stageType.In(2).Kind() != reflect.Chan {
		return fmt.Errorf("third parameter of stage function must be a channel")
	}

	if stageType.NumOut() != 1 {
		return fmt.Errorf("stage function must have exactly 1 output parameter")
	}

	if stageType.Out(0).Kind() != reflect.Chan {
		return fmt.Errorf("output parameter of stage function must be a channel")
	}

	return nil
}

// Helper function to validate that the output type of one stage matches the input type of the next
func validateStageCompatibility(stage1, stage2 interface{}) error {
	stage1Type := reflect.TypeOf(stage1)
	stage2Type := reflect.TypeOf(stage2)

	// Ensure stage1 outputs the type that stage2 accepts
	stage1OutType := stage1Type.Out(0).Elem() // Output type of stage1's channel
	stage2InType := stage2Type.In(2).Elem()   // Input type of stage2's channel

	if !stage1OutType.AssignableTo(stage2InType) {
		return fmt.Errorf("stage output of type %s is not compatible with next stage input of type %s",
			stage1OutType, stage2InType)
	}
	return nil
}

// FanStages concurrently executes multiple stages on the input channel and sends the results to the output channel.
// Each input is fanned to the stages, and the output of each stage is sent to the output channel.
//
// Parameters:
//   - ctx: The context to control the lifecycle of the stages.
//   - opts: A slice of options to configure the stages.
//   - in: The input channel from which data is read.
//   - out: The output channel to which processed data is sent.
//   - stages: A variadic list of Stage functions that process the input data.
//
// The function
func FanStages[In, Out any](ctx context.Context, opts []*types.Option, in <-chan In, out chan Out, stages ...Stage[In, Out]) {

	wg := sync.WaitGroup{} //
	for i := range in {
		wg.Add(1)
		go func() {
			defer close(out)
			wg2 := sync.WaitGroup{}
			wg2.Add(len(stages))
			for _, stage := range stages {
				go func() {
					fChan := make(chan In, 1)
					fChan <- i
					close(fChan)
					sout := stage(ctx, opts, fChan)
					for data := range sout {
						out <- data
					}
					defer wg2.Done()
				}()
			}
			wg2.Wait()
			wg.Done()
		}()
	}
	wg.Wait()
}

// Tee creates a stage that splits processing into multiple parallel pipelines and merges their outputs.
func Tee[In any, Out any](pipelines ...[]Stage[In, Out]) Stage[In, Out] {
	return func(ctx context.Context, opts []*types.Option, in <-chan In) <-chan Out {
		out := make(chan Out)

		// Create slice of intermediate stages for fan out
		var intermediateStages []Stage[In, Out]

		// Chain the pipelines together
		for _, pipeline := range pipelines {
			// Convert []Stage[In, Out] to []any for ChainStages
			anyStages := make([]any, len(pipeline))
			for i, s := range pipeline {
				anyStages[i] = s
			}

			// Create chained stage
			stage, err := ChainStages[In, Out](anyStages...)
			if err != nil {
				panic(err)
			}
			intermediateStages = append(intermediateStages, stage)
		}

		// Fan out to all pipelines and collect results
		go FanStages(ctx, opts, in, out, intermediateStages...)

		return out
	}
}

// Generator takes a slice of any type and returns a read-only channel that emits each element of the slice.
// The function runs a goroutine that sends each element of the input slice to the channel and then closes the channel.
//
// Type Parameters:
//
//	T: The type of elements in the input slice.
//
// Parameters:
//
//	inputs: A slice of elements of type T.
//
// Returns:
//
//	A read-only channel that emits each element of the input slice.
func Generator[T any](inputs []T) <-chan T {
	out := make(chan T)
	go func() {
		defer close(out)
		for _, input := range inputs {
			out <- input
		}
	}()
	return out
}

func Echo[In any](ctx context.Context, opts []*types.Option, in <-chan In) <-chan In {
	out := make(chan In)
	go func() {
		defer close(out)
		for i := range in {
			fmt.Printf("echo: %v\n", i)
			out <- i
		}
	}()
	return out
}
