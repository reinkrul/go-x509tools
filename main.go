package main

import (
	"github.com/reinkrul/go-x509tools/cmd"
	"github.com/sirupsen/logrus"
)

const defaultCAKeyFile = "ca-certificate.key"
const defaultCACertificateFile = "ca-certificate.pem"

func main() {
	if err := cmd.Execute(); err != nil {
		logrus.Fatalf("error: %v", err)
	}
	//var certificateAuthority ca.CertificateAuthority
	//var err error
	//caName := "Root CA"
	//if certificateAuthority, err = ca.NewCertificateAuthority(caName); err != nil {
	//	logrus.Fatalf("Unable to create certificate authority: %v", err)
	//}
	//
	//issueServerCert := func(dnsName string) {
	//	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	//	if err != nil {
	//		logrus.Fatalf("Unable to generate key pair: %v", err)
	//	}
	//	pkAsPEM := pem.EncodeToMemory(&pem.Block{
	//		Type:  "RSA PRIVATE KEY",
	//		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	//	})
	//	if err = ioutil.WriteFile(fmt.Sprintf("%s_key.pem", dnsName), pkAsPEM, os.ModePerm); err != nil {
	//		logrus.Fatalf("Unable to write private key to file: %v", err)
	//	}
	//	certificate, err := certificateAuthority.IssueServerCertificate(dnsName, privateKey.Public())
	//	if err != nil {
	//		logrus.Fatalf("Unable to issue server certificate to %s: %v", dnsName, err)
	//	}
	//	certAsPEM := pem.EncodeToMemory(&pem.Block{
	//		Type:  "CERTIFICATE",
	//		Bytes: certificate.Raw,
	//	})
	//	if err = ioutil.WriteFile(fmt.Sprintf("%s_certificate.pem", dnsName), certAsPEM, os.ModePerm); err != nil {
	//		logrus.Fatalf("Unable to write certificate to file: %v", err)
	//	}
	//}
	//
	//issueServerCert("nodeA")
	//issueServerCert("nodeB")
	//
	////if server, err = http.NewHTTPServer(caName, users, certificateAuthority); err != nil {
	////	logrus.Fatalf("Unable to start HTTP server: %v", err)
	////}
	//server.Start()
}