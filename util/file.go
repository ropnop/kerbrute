package util

import (
	"os"
	"bufio"
)


// reads passwords from file and adds them to the current array if
// they are not in the tried array
func GetPasswords(passwordfile string, current []string, tried []string, verbose bool, logger *Logger) (array []string, err error) {
    // read passwords 
    var password_scanner *bufio.Scanner

    passfile, err := os.Open(passwordfile)
    if err != nil {
        return []string{}, err
    }
    defer passfile.Close()

    password_scanner = bufio.NewScanner(passfile)
    for password_scanner.Scan() {
        passwordline := password_scanner.Text()
        if !is_present(current,passwordline) && !is_present(tried,passwordline) {
            current=append(current,passwordline)
            if verbose {
                logger.Log.Infof("[*] %s loaded\n",passwordline)
            }
        }
    }
    return current,nil
}

func is_present(arr []string, val string) bool {
  for _, item := range arr {
    if item == val {
      return true
    }
  }
  return false
}
