package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestParsePasswordSprayArgs(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		userAsPass       bool
		expectedUserList string
		expectedPassword string
		expectedAsPass   bool
		expectErr        bool
		errContains      string
	}{
		{
			name:             "standard password",
			args:             []string{"users.txt", "Password123"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "Password123",
			expectedAsPass:   false,
		},
		{
			name:             "leading single dash password",
			args:             []string{"users.txt", "-dog123"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "flag-like leading dash password",
			args:             []string{"users.txt", "-password123"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "-password123",
			expectedAsPass:   false,
		},
		{
			name:             "double dash password",
			args:             []string{"users.txt", "--secret123"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "--secret123",
			expectedAsPass:   false,
		},
		{
			name:             "password following argument terminator",
			args:             []string{"users.txt", "--", "-dog123"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "terminator before wordlist and password",
			args:             []string{"--", "users.txt", "-dog123"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "stdin wordlist with leading dash password",
			args:             []string{"-", "-dog123"},
			userAsPass:       false,
			expectedUserList: "-",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "stdin wordlist with terminator and leading dash password",
			args:             []string{"-", "--", "-dog123"},
			userAsPass:       false,
			expectedUserList: "-",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "user as pass via flag",
			args:             []string{"users.txt"},
			userAsPass:       true,
			expectedUserList: "users.txt",
			expectedPassword: "foobar",
			expectedAsPass:   true,
		},
		{
			name:             "user as pass supplied as trailing argument",
			args:             []string{"users.txt", "--user-as-pass"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "foobar",
			expectedAsPass:   true,
		},
		{
			name:             "literal user-as-pass password after argument terminator",
			args:             []string{"users.txt", "--", "--user-as-pass"},
			userAsPass:       false,
			expectedUserList: "users.txt",
			expectedPassword: "--user-as-pass",
			expectedAsPass:   false,
		},
		{
			name:        "missing password without user as pass",
			args:        []string{"users.txt"},
			userAsPass:  false,
			expectErr:   true,
			errContains: "You must specify a password to spray with, or --user-as-pass",
		},
		{
			name:        "empty arguments",
			args:        []string{},
			userAsPass:  false,
			expectErr:   true,
			errContains: "requires at least 1 arg(s)",
		},
		{
			name:        "only terminator provided",
			args:        []string{"--"},
			userAsPass:  false,
			expectErr:   true,
			errContains: "requires at least 1 arg(s)",
		},
		{
			name:        "too many arguments",
			args:        []string{"users.txt", "pass1", "pass2"},
			userAsPass:  false,
			expectErr:   true,
			errContains: "You must specify a password to spray with, or --user-as-pass",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userList, pass, asPass, err := parsePasswordSprayArgs(tc.args, tc.userAsPass)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if userList != tc.expectedUserList {
				t.Errorf("expected userList %q, got %q", tc.expectedUserList, userList)
			}
			if pass != tc.expectedPassword {
				t.Errorf("expected password %q, got %q", tc.expectedPassword, pass)
			}
			if asPass != tc.expectedAsPass {
				t.Errorf("expected asPass %v, got %v", tc.expectedAsPass, asPass)
			}
		})
	}
}

func TestPasswordSprayCommandCLI(t *testing.T) {
	tests := []struct {
		name             string
		cliArgs          []string
		expectedDomain   string
		expectedUserList string
		expectedPassword string
		expectedAsPass   bool
	}{
		{
			name:             "CLI standard password",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "users.txt", "Password123"},
			expectedDomain:   "example.com",
			expectedUserList: "users.txt",
			expectedPassword: "Password123",
			expectedAsPass:   false,
		},
		{
			name:             "CLI leading dash -dog123",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "users.txt", "-dog123"},
			expectedDomain:   "example.com",
			expectedUserList: "users.txt",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "CLI flag-like -password123",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "users.txt", "-password123"},
			expectedDomain:   "example.com",
			expectedUserList: "users.txt",
			expectedPassword: "-password123",
			expectedAsPass:   false,
		},
		{
			name:             "CLI double dash --secret123",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "users.txt", "--secret123"},
			expectedDomain:   "example.com",
			expectedUserList: "users.txt",
			expectedPassword: "--secret123",
			expectedAsPass:   false,
		},
		{
			name:             "CLI with terminator before leading dash password",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "users.txt", "--", "-dog123"},
			expectedDomain:   "example.com",
			expectedUserList: "users.txt",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "CLI with terminator before wordlist",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "--", "users.txt", "-dog123"},
			expectedDomain:   "example.com",
			expectedUserList: "users.txt",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "CLI stdin with leading dash password",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "-", "-dog123"},
			expectedDomain:   "example.com",
			expectedUserList: "-",
			expectedPassword: "-dog123",
			expectedAsPass:   false,
		},
		{
			name:             "CLI with user-as-pass flag before wordlist",
			cliArgs:          []string{"passwordspray", "-d", "example.com", "--user-as-pass", "users.txt"},
			expectedDomain:   "example.com",
			expectedUserList: "users.txt",
			expectedPassword: "foobar",
			expectedAsPass:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			domain = ""
			userAsPass = false

			cmd := rootCmd
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tc.cliArgs)

			subCmd, parsedArgs, err := cmd.Find(tc.cliArgs)
			if err != nil {
				t.Fatalf("cmd.Find failed: %v", err)
			}
			if err := subCmd.ParseFlags(parsedArgs); err != nil {
				t.Fatalf("subCmd.ParseFlags failed: %v", err)
			}

			userList, pass, asPass, err := parsePasswordSprayArgs(subCmd.Flags().Args(), userAsPass)
			if err != nil {
				t.Fatalf("parsePasswordSprayArgs failed: %v", err)
			}

			if domain != tc.expectedDomain {
				t.Errorf("expected domain %q, got %q", tc.expectedDomain, domain)
			}
			if userList != tc.expectedUserList {
				t.Errorf("expected userList %q, got %q", tc.expectedUserList, userList)
			}
			if pass != tc.expectedPassword {
				t.Errorf("expected password %q, got %q", tc.expectedPassword, pass)
			}
			if asPass != tc.expectedAsPass {
				t.Errorf("expected asPass %v, got %v", tc.expectedAsPass, asPass)
			}
		})
	}
}

func TestSubcommandsDoubleDash(t *testing.T) {
	t.Run("bruteuser with leading dash username", func(t *testing.T) {
		cmd := rootCmd
		args := []string{"bruteuser", "-d", "example.com", "passwords.txt", "-user1"}
		subCmd, parsedArgs, err := cmd.Find(args)
		if err != nil {
			t.Fatalf("Find failed: %v", err)
		}
		if err := subCmd.ParseFlags(parsedArgs); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		posArgs := cleanArgs(subCmd.Flags().Args())
		if len(posArgs) != 2 {
			t.Fatalf("expected 2 positional args, got %d: %v", len(posArgs), posArgs)
		}
		if posArgs[0] != "passwords.txt" || posArgs[1] != "-user1" {
			t.Errorf("unexpected posArgs: %v", posArgs)
		}
	})

	t.Run("bruteuser with double dash terminator", func(t *testing.T) {
		cmd := rootCmd
		args := []string{"bruteuser", "-d", "example.com", "passwords.txt", "--", "-user1"}
		subCmd, parsedArgs, err := cmd.Find(args)
		if err != nil {
			t.Fatalf("Find failed: %v", err)
		}
		if err := subCmd.ParseFlags(parsedArgs); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		posArgs := cleanArgs(subCmd.Flags().Args())
		if len(posArgs) != 2 {
			t.Fatalf("expected 2 positional args, got %d: %v", len(posArgs), posArgs)
		}
		if posArgs[0] != "passwords.txt" || posArgs[1] != "-user1" {
			t.Errorf("unexpected posArgs: %v", posArgs)
		}
	})

	t.Run("bruteforce with double dash terminator", func(t *testing.T) {
		cmd := rootCmd
		args := []string{"bruteforce", "-d", "example.com", "--", "combos.txt"}
		subCmd, parsedArgs, err := cmd.Find(args)
		if err != nil {
			t.Fatalf("Find failed: %v", err)
		}
		if err := subCmd.ParseFlags(parsedArgs); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		posArgs := cleanArgs(subCmd.Flags().Args())
		if len(posArgs) != 1 || posArgs[0] != "combos.txt" {
			t.Errorf("unexpected posArgs: %v", posArgs)
		}
	})

	t.Run("userenum with double dash terminator", func(t *testing.T) {
		cmd := rootCmd
		args := []string{"userenum", "-d", "example.com", "--", "users.txt"}
		subCmd, parsedArgs, err := cmd.Find(args)
		if err != nil {
			t.Fatalf("Find failed: %v", err)
		}
		if err := subCmd.ParseFlags(parsedArgs); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		posArgs := cleanArgs(subCmd.Flags().Args())
		if len(posArgs) != 1 || posArgs[0] != "users.txt" {
			t.Errorf("unexpected posArgs: %v", posArgs)
		}
	})
}
