package cmd

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

func makeSprayWorker(ctx context.Context, usernames <-chan string, wg *sync.WaitGroup, password string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			break
		case username, ok := <-usernames:
			if !ok {
				return
			}
			testLogin(ctx, username, password)
		}
	}
}

func makeBruteWorker(ctx context.Context, passwords <-chan string, wg *sync.WaitGroup, username string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			break
		case password, ok := <-passwords:
			if !ok {
				return
			}
			testLogin(ctx, username, password)
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

func testLogin(ctx context.Context, username string, password string) {
	atomic.AddInt32(&counter, 1)
	login := fmt.Sprintf("%v@%v:%v", username, domain, password)
	if ok, err := kSession.TestLogin(username, password); ok {
		atomic.AddInt32(&successes, 1)
		logger.Log.Noticef("[+] VALID LOGIN:\t %s", login)
		if stopOnSuccess {
			cancel()
		}
	} else {
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", login, errorString)
			cancel()
		}
		logger.Log.Debugf("[!] %v - %v", login, errorString)
	}
}

func testUsername(ctx context.Context, username string) {
	atomic.AddInt32(&counter, 1)
	usernamefull := fmt.Sprintf("%v@%v", username, domain)
	if ok, err := kSession.TestUsername(username); ok {
		atomic.AddInt32(&successes, 1)
		logger.Log.Notice("[+] VALID USERNAME:\t %s", usernamefull)
	} else {
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", usernamefull, errorString)
			cancel()
		}
		logger.Log.Debugf("[!] %v - %v", usernamefull, errorString)
	}
}
