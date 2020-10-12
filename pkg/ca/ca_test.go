package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"reflect"
	"testing"
)

func TestNewCertificateAuthority(t *testing.T) {
	ca, err := createCA()
	assert.NoError(t, err)
	assert.NotNil(t, ca)
}

func Test_certificateAuthority_IssueIntermediateCACertificate(t *testing.T) {
	ca, err := NewCertificateAuthority(pkix.Name{CommonName: "Root CA"})
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certificate, err := ca.IssueIntermediateCACertificate(pkix.Name{CommonName: "Intermediate CA"}, keyPair.Public())
	assert.NoError(t, err)
	assert.NotNil(t, certificate)
}

func Test_certificateAuthority_IssueServerCertificate(t *testing.T) {
	ca, err := NewCertificateAuthority(pkix.Name{CommonName: "Root CA"})
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	host := "myhost.nl"
	certificate, err := ca.IssueServerCertificate(host, keyPair.Public())
	assert.NoError(t, err)
	assert.NotNil(t, certificate)
	assert.Len(t, certificate.DNSNames, 1)
	assert.Equal(t, host, certificate.DNSNames[0])
	assert.Equal(t, host, certificate.Subject.CommonName)
}

func Test_certificateAuthority_IssueSigningCertificate(t *testing.T) {
	ca, err := NewCertificateAuthority(pkix.Name{CommonName: "Root CA"})
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	endEntity := pkix.Name{CommonName: "Signer"}
	certificate, err := ca.IssueSigningCertificate(endEntity, keyPair.Public())
	assert.NoError(t, err)
	assert.NotNil(t, certificate)
	assert.Equal(t, endEntity.String(), certificate.Subject.String())
}

func Test_certificateAuthority_initialize(t *testing.T) {
	type fields struct {
		privateKey  crypto.PrivateKey
		certificate *x509.Certificate
	}
	type args struct {
		name    pkix.Name
		options []CertificateOption
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &certificateAuthority{
				privateKey:  tt.fields.privateKey,
				certificate: tt.fields.certificate,
			}
			if err := ca.initialize(tt.args.name, tt.args.options...); (err != nil) != tt.wantErr {
				t.Errorf("initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_certificateAuthority_issueCertificate(t *testing.T) {
	type fields struct {
		privateKey  crypto.PrivateKey
		certificate *x509.Certificate
	}
	type args struct {
		template *x509.Certificate
		options  []CertificateOption
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &certificateAuthority{
				privateKey:  tt.fields.privateKey,
				certificate: tt.fields.certificate,
			}
			got, err := ca.issueCertificate(tt.args.template, tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("issueCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("issueCertificate() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_serialNumber(t *testing.T) {
	tests := []struct {
		name string
		want *big.Int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serialNumber(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("serialNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func createCA() (CertificateAuthority, error) {
	return NewCertificateAuthority(pkix.Name{CommonName: "Root CA"})
}
