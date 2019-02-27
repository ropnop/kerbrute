package cmd

import (
	"fmt"

	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version info and quit",
	Run:   showVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func showVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("Version: %v\nCommit: %v\nBuilt: %v with %v\n", util.Version, util.GitCommit, util.BuildDate, util.GoVersion)
}
