package shack

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmcertmanagerclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CertificateProvisioner interface {
	Provision(dnsName string) error
	Retrieve(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// CertManagerProvisioner creates + retrieves proxy/MitM certificates from cert-manager
type CertManagerProvisioner struct {
	issuerRef cmmeta.ObjectReference

	certManagerClientSet cmclientset.Interface
	kubernetesClientSet  kubernetes.Interface

	namespace string
}

var _ CertificateProvisioner = (*CertManagerProvisioner)(nil)

func NewCertManagerProvisioner(namespace string, issuerName string) (*CertManagerProvisioner, error) {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes InClusterConfig: %w", err)
	}

	certManagerClientSet, err := cmclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert-manager client set: %w", err)
	}

	kubernetesClientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client set: %w", err)
	}

	return &CertManagerProvisioner{
		issuerRef: cmmeta.ObjectReference{
			Name:  issuerName,
			Kind:  "Issuer",
			Group: "cert-manager.io",
		},

		certManagerClientSet: certManagerClientSet,
		kubernetesClientSet:  kubernetesClientSet,

		namespace: namespace,
	}, nil
}

func (cmp *CertManagerProvisioner) Provision(dnsName string) error {
	nameHash := dnsNameHash(dnsName)

	certificate := &cmapi.Certificate{
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

	_, err := cmp.certManagerClientSet.CertmanagerV1().Certificates(cmp.namespace).Create(context.TODO(), certificate, metav1.CreateOptions{})

	// if the cert already exists we assume it's fine
	// TODO: it might not be fine if there's somehow a clash and the cert has a different dnsName to what we expect
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

// waitForCertificate waits until a certificate is ready to be used
func waitForCertificate(client cmcertmanagerclientset.CertificateInterface, name string) error {
	timeout := time.Second * 10

	return wait.PollImmediate(500*time.Millisecond, timeout, func() (bool, error) {
		certificate, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to get Certificate when waiting for it to be ready: %w", err)
		}

		existingConditions := certificate.Status.Conditions

		for _, cond := range existingConditions {
			if cond.Type == cmapi.CertificateConditionReady && cond.Status == cmmeta.ConditionTrue {
				return true, nil
			}
		}

		return false, nil
	})
}

func (cmp *CertManagerProvisioner) Retrieve(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if clientHello.ServerName == "" {
		return nil, fmt.Errorf("client didn't use SNI, can't determine cert for MitM")
	}

	dnsName := clientHello.ServerName

	err := cmp.Provision(dnsName)
	if err != nil {
		return nil, fmt.Errorf("failed to provision a certificate using cert-manager: %w", err)
	}

	nameHash := dnsNameHash(dnsName)

	err = waitForCertificate(cmp.certManagerClientSet.CertmanagerV1().Certificates(cmp.namespace), "shack-"+nameHash)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for certificate to come ready: %w", err)
	}

	secretName := "shack-secret-" + nameHash

	// TODO: ensure these requests for secrets are cached

	secret, err := cmp.kubernetesClientSet.CoreV1().Secrets(cmp.namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve k8s secret: %w", err)
	}

	certPEM, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("couldn't find valid 'tls.crt' in cert-manager issued secret")
	}

	keyPEM, ok := secret.Data["tls.key"]
	if !ok {
		return nil, fmt.Errorf("couldn't find valid 'tls.key' in cert-manager issued secret")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keypair from k8s secret: %w", err)
	}

	return &cert, nil
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
