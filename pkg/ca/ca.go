package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/sirupsen/logrus"
	"log"
	"math/big"
	"time"
)

const defaultDaysValid = 365
const defaultCADaysValid = 1095

type CertificateAuthority interface {
	IssueSigningCertificate(subject pkix.Name, key crypto.PublicKey, options... CertificateOption) (*x509.Certificate, error)
	IssueServerCertificate(host string, key crypto.PublicKey, options... CertificateOption) (*x509.Certificate, error)
	IssueIntermediateCACertificate(subject pkix.Name, key crypto.PublicKey, options... CertificateOption) (*x509.Certificate, error)
}

func NewCertificateAuthority(name pkix.Name, privatekeyFile string, certificateFile string) (CertificateAuthority, error) {
	certAuth := &certificateAuthority{}
	if err := certAuth.initialize(name); err != nil {
		return nil, err
	}
	return certAuth, nil
}

type certificateAuthority struct {
	privateKey  crypto.PrivateKey
	certificate *x509.Certificate
}

func (ca *certificateAuthority) IssueIntermediateCACertificate(subject pkix.Name, key crypto.PublicKey, options... CertificateOption) (*x509.Certificate, error) {
	logrus.Infof("Issuing intermediate CA certificate to %s", subject)
	template := &x509.Certificate{
		PublicKey:    key,
		SerialNumber: serialNumber(),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, defaultCADaysValid),
	}
	CACertificate()(template)
	return ca.issueCertificate(template, options)
}

func (ca *certificateAuthority) IssueSigningCertificate(subject pkix.Name, key crypto.PublicKey, options... CertificateOption) (*x509.Certificate, error) {
	logrus.Infof("Issuing signing certificate to %s", subject)
	template := &x509.Certificate{
		PublicKey:    key,
		SerialNumber: serialNumber(),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, defaultDaysValid),
		KeyUsage:     x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
	}
	return ca.issueCertificate(template, options)
}

func (ca *certificateAuthority) IssueServerCertificate(host string, key crypto.PublicKey, options... CertificateOption) (*x509.Certificate, error) {
	logrus.Infof("Issuing server certificate to %s", host)
	template := &x509.Certificate{
		PublicKey:    key,
		SerialNumber: serialNumber(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, defaultDaysValid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	return ca.issueCertificate(template, options)
}

func (ca *certificateAuthority) initialize(name pkix.Name, options... CertificateOption) error {
	var err error
	if ca.certificate, ca.privateKey, err = loadCertificateAndKey(); err != nil {
		return err
	} else if ca.certificate == nil || ca.privateKey == nil {
		logrus.Info("Generating new CA certificate and key")
		if ca.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return err
		}
		template := &x509.Certificate{
			PublicKey:             (ca.privateKey.(crypto.Signer)).Public(),
			SerialNumber:          serialNumber(),
			Issuer:                name,
			Subject:               name,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(0, 0, defaultCADaysValid),
		}
		CACertificate()(template)
		ca.certificate = template
		if certificate, err := ca.issueCertificate(template, options); err != nil {
			return err
		} else {
			ca.certificate = certificate
			return saveCertificateAndKey(ca.certificate, ca.privateKey)
		}
	}
	logrus.Info("CA certificate and key loaded")
	return nil
}

func (ca *certificateAuthority) issueCertificate(template *x509.Certificate, options []CertificateOption) (*x509.Certificate, error) {
	for _, opt := range options {
		opt(template)
	}
	certificateAsASN1, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, template.PublicKey, ca.privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certificateAsASN1)
}

func serialNumber() *big.Int {
	// Taken from https://golang.org/src/crypto/tls/generate_cert.go
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	return serialNumber

}

func fileExists(fileName string) bool {
	info, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}