package ca

import (
	"crypto/x509"
	"time"
)

type CertificateOption func(receiver *x509.Certificate)

func DaysValid(days int) CertificateOption {
	return func(receiver *x509.Certificate) {
		receiver.NotBefore = time.Now()
		receiver.NotAfter = time.Now().AddDate(0, 0, days)
	}
}

func KeyUsage(value x509.KeyUsage) CertificateOption {
	return func(receiver *x509.Certificate) {
		receiver.KeyUsage = value
	}
}

func CACertificate() CertificateOption {
	return func(receiver *x509.Certificate) {
		receiver.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign
		receiver.BasicConstraintsValid = true
		receiver.IsCA = true
	}
}
