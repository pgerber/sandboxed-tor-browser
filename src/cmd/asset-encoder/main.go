// main.go - asset-encoder
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

// asset-encoder is a quick and dirty static asset encoder.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
)

func main() {
	pkg := flag.String("package", "", "The package that the encoded asset belongs in")
	varName := flag.String("varName", "", "The variable name for the static asset")
	flag.Parse() 

	if *pkg == "" {
		fmt.Fprintf(os.Stderr, "package is undefined\n")
		os.Exit(-1)
	}
	if *varName == "" {
		fmt.Fprintf(os.Stderr, "varName is undefined\n")
		os.Exit(-1)
	}

	args := flag.Args()
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "expected source and destination paths\n")
		os.Exit(-1)
	}

	srcPath := args[0]
	dstPath := args[1]
	_, dstFile := path.Split(dstPath)

	src, err := ioutil.ReadFile(srcPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read src file %v: %v", srcPath, err)
		os.Exit(-1)
	}

	b := fmt.Sprintf("// %v - machine generated static asset\n\n", dstFile)
	b += fmt.Sprintf("package %s\n\nvar %s = []byte{\n\t", *pkg, *varName)
	cnt := 0
	for _, v := range src {
		b += fmt.Sprintf("0x%02x, ", v)
		cnt++
		if cnt == 15 {
			b += "\n\t"
			cnt = 0
		}
	}
	b += "\n}"

	
	if err := ioutil.WriteFile(dstPath, []byte(b), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write dst file %v: %v", dstPath, err)
		os.Exit(-1)
	}
}
