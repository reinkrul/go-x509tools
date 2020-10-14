package cmd

import "github.com/spf13/cobra"

func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "x509tools",
		Short: "Useful X.509 tools",
		Args: cobra.ExactArgs(1),
	}
	rootCmd.AddCommand(CreateCACommand())
	return rootCmd.Execute()
}
