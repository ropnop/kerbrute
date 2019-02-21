package util

import "fmt"

func PrintBanner() {
	banner := `
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
`
	fmt.Printf("%v\nVersion: %v (%v) - %v - %v\n\n", banner, Version, GitCommit, BuildDate, Author)
}
