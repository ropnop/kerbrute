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

//type Logger struct {
	//Log *logging.Logger
//}

//func NewLogger(verbose bool, logFileName string) Logger {
	//log := logging.MustGetLogger("kerbrute")
	//format := logging.MustStringFormatter(
		//`%{color}%{time:2006/01/02 15:04:05} >  %{message}%{color:reset}`,
	//)
	//formatNoColor := logging.MustStringFormatter(
		//`%{time:2006/01/02 15:04:05} >  %{message}`,
	//)
	//backend := logging.NewLogBackend(os.Stdout, "", 0)
	//backendFormatter := logging.NewBackendFormatter(backend, format)

	//if logFileName != "" {
		//outputFile, err := os.Create(logFileName)
		//if err != nil {
			//panic(err)
		//}
		//fileBackend := logging.NewLogBackend(outputFile, "", 0)
		//fileFormatter := logging.NewBackendFormatter(fileBackend, formatNoColor)
		//logging.SetBackend(backendFormatter, fileFormatter)
	//} else {
		//logging.SetBackend(backendFormatter)
	//}

	//if verbose {
		//logging.SetLevel(logging.DEBUG, "")
	//} else {
		//logging.SetLevel(logging.INFO, "")
	//}
	//return Logger{log}
//}
