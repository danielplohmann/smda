package main

/*
#include <stdlib.h>
static int doubler(int value) { return value * 2; }
*/
import "C"

import (
	"fmt"
	"os"
)

func helperAlpha(value int) int { return int(C.doubler(C.int(value))) }

func main() {
	fmt.Fprintln(os.Stdout, helperAlpha(len(os.Args)))
}
