package main

import (
	"fmt"
	"os"
	"strings"
)

func helperAlpha(values []string) string { return strings.Join(values, ",") }

func helperBeta(count int) int {
	total := 0
	for i := 0; i < count; i++ {
		total += i * i
	}
	return total
}

func main() {
	fmt.Fprintln(os.Stdout, helperAlpha([]string{"a", "b"}), helperBeta(len(os.Args)))
}
