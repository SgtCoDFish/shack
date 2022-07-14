package shack

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

type CertificateProvisioner interface {
	Provision(dnsName string) error
	Retrieve(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// CertManagerProvisioner creates + retrieves proxy/MitM certificates from cert-manager
type CertManagerProvisioner struct {
	issuerRef cmmeta.ObjectReference

	clientSet clientset.Interface

	namespace string
}

var _ CertificateProvisioner = (*CertManagerProvisioner)(nil)

func NewCertManagerProvisioner(namespace string, issuerName string) (*CertManagerProvisioner, error) {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes InClusterConfig: %w", err)
	}

	clientSet, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert-manager clientset: %w", err)
	}

	return &CertManagerProvisioner{
		issuerRef: cmmeta.ObjectReference{
			Name:  issuerName,
			Kind:  "Issuer",
			Group: "cert-manager.io",
		},

		clientSet: clientSet,

		namespace: namespace,
	}, nil
}

func (cmp *CertManagerProvisioner) Provision(dnsName string) error {
	nameHash := dnsNameHash(dnsName)

	testCertificate := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shack-" + nameHash,
			Namespace: cmp.namespace,
		},
		Spec: cmapi.CertificateSpec{
			SecretName: "shack-secret-" + nameHash,
			IssuerRef:  cmp.issuerRef,
			DNSNames:   []string{dnsName},
			PrivateKey: &cmapi.CertificatePrivateKey{
				Algorithm:      cmapi.ECDSAKeyAlgorithm,
				Size:           256,
				RotationPolicy: "Always",
			},
		},
	}

	return fmt.Errorf("NYI %s", testCertificate.ObjectMeta.Name)
}

func (cmp *CertManagerProvisioner) Retrieve(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, fmt.Errorf("NYI")
}

type StaticProvisioner struct {
	certificate *tls.Certificate
}

var _ CertificateProvisioner = (*StaticProvisioner)(nil)

func NewStaticProvisioner(chainFile string, keyFile string) (*StaticProvisioner, error) {
	tlsCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &StaticProvisioner{
		certificate: &tlsCert,
	}, nil
}

func (sp *StaticProvisioner) Provision(_ string) error {
	// a static provisioner is not capable of provisioning new certs, so just do nothing
	return nil
}

func (sp *StaticProvisioner) Retrieve(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return sp.certificate, nil
}

func dnsNameHash(dnsName string) string {
	sum := md5.Sum([]byte(dnsName))
	return hex.EncodeToString(sum[:])
}
