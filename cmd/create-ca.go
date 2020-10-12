package cmd

import (
	"crypto/x509/pkix"
	"github.com/spf13/cobra"
)

func CreateCACommand() *cobra.Command {
	var subject string
	cmd := &cobra.Command{
		Use:   "create-ca",
		Short: "Creates a self-signed CA",
		Args:  nil,
		RunE:  nil,
	}
	pkix.RDNSequence{}
	cmd.Flags().StringVarP(&subject, "Subject", "s", "", "Name (subject) of the certificate being issued. Must be in the form of ")
	return cmd
}
