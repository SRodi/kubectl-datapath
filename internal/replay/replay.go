package replay

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func Stream(ctx context.Context, reader io.Reader) (<-chan model.Observation, <-chan error) {
	observations := make(chan model.Observation)
	errors := make(chan error, 1)
	go func() {
		defer close(observations)
		defer close(errors)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			select {
			case <-ctx.Done():
				errors <- ctx.Err()
				return
			default:
			}
			observation, err := model.Decode(scanner.Bytes())
			if err != nil {
				errors <- fmt.Errorf("line %d: %w", line, err)
				return
			}
			observations <- observation
		}
		if err := scanner.Err(); err != nil {
			errors <- fmt.Errorf("read replay: %w", err)
		}
	}()
	return observations, errors
}
