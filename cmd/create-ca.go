package cmd

import (
	"fmt"
	"github.com/reinkrul/go-x509tools/pkg/ca"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tsaarni/x500dn"
)

const defaultCAKeyFile = "ca-certificate.key"
const defaultCACertificateFile = "ca-certificate.pem"

func CreateCACommand() *cobra.Command {
	return &cobra.Command{
		Use: "ca [NAME]",
		Short: "Creates a CA key and certificate so certificates can be issued. The NAME parameter must be an X.500 distinguished name.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logrus.Infof("Creating CA with name: %s", args[0])
			if name, err := x500dn.ParseDN(args[0]); err != nil {
				return fmt.Errorf("invalid name: %s: %w", args[0], err)
			} else {
				if _, err := ca.NewCertificateAuthority(*name, defaultCAKeyFile, defaultCACertificateFile); err != nil {
					return fmt.Errorf("unable to create CA: %w", err)
				}
			}
			logrus.Infof("CA created, key file = %s, certificate file = %s", defaultCAKeyFile, defaultCACertificateFile)
			return nil
		},
	}
}
