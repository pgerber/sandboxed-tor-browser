// main.go - asset-encoder
// Copyright (C) 2016  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
		fmt.Fprintf(os.Stderr, "failed to read src file %v: %v\n", srcPath, err)
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
		fmt.Fprintf(os.Stderr, "failed to write dst file %v: %v\n", dstPath, err)
		os.Exit(-1)
	}
}
