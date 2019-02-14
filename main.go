package main

import (
	"fmt"

	"github.com/ropnop/kerbrute/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	author  = "Ronnie Flathers (@ropnop)"
)

func banner() {
	banner := `
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
`
	fmt.Printf("%v\nVersion: %v(%v) - %v\t%v\n\n", banner, version, commit, date, author)
}

func main() {
	banner()
	cmd.Execute()
}
