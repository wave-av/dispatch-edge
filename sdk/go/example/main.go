package main

import (
	"context"
	"fmt"
	"os"

	dispatch "github.com/wave-av/dispatch-edge/sdk/go"
)

func main() {
	c := dispatch.New(os.Getenv("WAVE_LICENSE"))
	d, err := c.Route(context.Background(), "find the auth handler")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Printf("route=%s prob=%.2f margin=%.2f forward=%v\n", d.Route, d.Probability, d.Margin, d.Forward)
}
