package types

type Run struct {
	Output chan Result
	Input  chan any
}

func NewRun() Run {
	return Run{
		Input:  make(chan interface{}, 1),
		Output: make(chan Result, 1),
	}
}
