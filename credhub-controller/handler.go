package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"code.cloudfoundry.org/credhub-cli/credhub/auth"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials/values"

	"code.cloudfoundry.org/credhub-cli/credhub"
	log "github.com/Sirupsen/logrus"
	"github.com/oskoss/kubernetes-credhub/credhub-controller/config"
	"gopkg.in/yaml.v2"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AppConfig struct {
	CredhubEndpoint struct {
		URL               string `yaml:"url"`
		SkipTLSValidation bool   `yaml:"skip_tls_validation"`
	} `yaml:"credhub_endpoint"`
	CredhubClient struct {
		Name   string `yaml:"name"`
		Secret string `yaml:"secret"`
	} `yaml:"credhub_client"`
	CredhubTrustedCa struct {
		PemPrivateKey string `yaml:"pem_private_key"`
		CaCertificate string `yaml:"ca_certificate"`
	} `yaml:"credhub_trusted_ca"`
}

type InitContainerPackage struct {
	Certificate credentials.Certificate `json:"certificate"`
	CredhubURL  string                  `json:"credhub_url"`
	Namespace   string                  `json:"namespace"`
}

type Handler interface {
	Init() error
	ObjectCreated(obj interface{})
	ObjectDeleted(obj interface{})
	ObjectUpdated(objOld, objNew interface{})
}

type CredhubHandler struct{}

func (t *CredhubHandler) Init() error {
	log.Info("CredhubHandler.Init")
	return nil
}

func (t *CredhubHandler) ObjectCreated(obj interface{}) {
	log.Info("CredhubHandler.ObjectCreated")

	pod := obj.(*core_v1.Pod)
	annotations := pod.GetAnnotations()
	log.Infof("    Name: %s", pod.Name)
	log.Infof("    Namespace: %s", pod.Namespace)
	log.Infof("    ResourceVersion: %s", pod.ObjectMeta.ResourceVersion)
	log.Infof("    NodeName: %s", pod.Spec.NodeName)
	log.Infof("    Phase: %s", pod.Status.Phase)
	log.Infof("    Annotations: %s", annotations)

	value, found := annotations["credhub.pivotal.io"]
	if found == false {
		log.Infof("Annotation not found. Skipping Pod")
		return
	}
	if value != "injected" {
		log.Errorf("Pod requesting kubernetes-credhub integration but init container has not been injected...")
		return
	}
	if len(pod.Status.PodIP) == 0 {
		log.Infof("Pod requesting kubernetes-credhub integration but it has not been scheduled yet...")
		return
	}

	client := getKubernetesClient()
	attempts := 0
	for attempts < 30 {
		log.Infof("Attempt %v to get the status of kubernetes-credhub init container....", attempts)
		latestPod, err := client.CoreV1().Pods(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
		if err != nil {
			log.Errorf("Failed! Could not get latest status of Pods! %+v", err)
			return
		}
		podStatus := latestPod.Status
		for _, initContainerStatus := range podStatus.InitContainerStatuses {
			if initContainerStatus.Name == "kubernetes-credhub-init" {
				if initContainerStatus.State.Running != nil {
					cert, err := obtainCert(pod)
					if err != nil {
						log.Errorf("could not set cert for init container %+v", err)
						return
					}
					err = sendInitPackage(pod, cert)
					if err != nil {
						log.Errorf("could not send cert over to init container %+v", err)
						return
					}
					markPodFinished(pod)
					return
				}
			}
		}
		attempts++
		time.Sleep(time.Second)
	}
	log.Errorf("Failed! Waited 30 sec for init container to become ready!")
	return
}

func (t *CredhubHandler) ObjectDeleted(obj interface{}) {
	log.Info("CredhubHandler.ObjectDeleted")
}

func (t *CredhubHandler) ObjectUpdated(objOld, objNew interface{}) {
	log.Info("CredhubHandler.ObjectUpdated")
}

func enableCertToReadCreds(namespaceUID string, credentialPath string) error {

	curConfig := getConfig()

	skipTLSValidation := false
	if curConfig.CredhubEndpoint.SkipTLSValidation {
		skipTLSValidation = true
	}

	credhubClient, err := credhub.New(
		curConfig.CredhubEndpoint.URL,
		credhub.SkipTLSValidation(skipTLSValidation),
		credhub.Auth(auth.UaaClientCredentials(curConfig.CredhubClient.Name, curConfig.CredhubClient.Secret)),
	)
	if err != nil {
		log.Errorf("Failed to create credhub client! %v", err)
		return err
	}
	credentials, err := credhubClient.FindByPath(credentialPath)
	if err != nil {
		log.Errorf("failed to get credentials from credhub in %s path", credentialPath)
		return err
	}

	for _, credential := range credentials.Credentials {
		path := credential.Name
		actor := fmt.Sprintf("mtls-app:%s", namespaceUID)
		permission, err := credhubClient.AddPermission(path, actor, []string{"read", "read_acl"})
		if err != nil {
			if strings.Contains(err.Error(), "permission entry for this actor and path already exists") {
				log.Infof("Permission for %s credential is already in place", credentialPath)
			} else {
				log.Errorf("could not add %+v permission to credhub usercert %v", permission, namespaceUID)
				return err
			}
		}
	}
	log.Infof("Added Permission to all %s credentials", credentialPath)
	return nil
}

func markPodFinished(pod *core_v1.Pod) error {
	currentPodAnnotations := pod.GetAnnotations()
	for _, currentPodAnnotation := range currentPodAnnotations {
		log.Info(currentPodAnnotation)
		if currentPodAnnotation == "credhub.pivotal.io" {
			log.Infof("FOUND THE ANNOTATIONSDJKSJDLKSJKDJSLDJKLSJDKLJSLKJD!J#!@!@!@!!!")
		}
	}
	return nil
}

func sendInitPackage(pod *core_v1.Pod, cert credentials.Certificate) error {

	log.Infof("Send cert to init container %+v", cert)
	for _, initContainer := range pod.Spec.InitContainers {
		if initContainer.Name == "kubernetes-credhub-init" {
			hostname := pod.Status.PodIP
			port := initContainer.Ports[0].ContainerPort
			endpoint := "v1/receivecreds"
			URL := fmt.Sprintf("http://%s:%v/%s", hostname, port, endpoint)
			payload := InitContainerPackage{
				Certificate: cert,
				CredhubURL:  getConfig().CredhubEndpoint.URL,
				Namespace:   pod.Namespace,
			}
			log.Infof("Sending JSON %+v to %s!", payload, URL)
			requestByte, err := json.Marshal(payload)
			if err != nil {
				log.Errorf("Failed marshalling payload to init container! %s ", err.Error())
				return err
			}
			rs, err := http.Post(URL, "application/json", bytes.NewReader(requestByte))
			if err != nil {
				log.Errorf("Failed sending payload to init container! %s ", err.Error())
				return err
			}
			defer rs.Body.Close()

			bodyBytes, err := ioutil.ReadAll(rs.Body)
			if err != nil {
				log.Errorf("Failed reading response when sending payload to init container! %s ", err.Error())
				return err
			}

			log.Infof(string(bodyBytes))
			return nil
		}
	}
	err := fmt.Errorf("Never found init container to send payload to! %+v are the containers we found", pod.Spec.InitContainers)
	log.Error(err.Error())
	return err
}

func obtainCert(pod *core_v1.Pod) (credentials.Certificate, error) {

	client := getKubernetesClient() //TODO: Pass the k8s client?

	namespace, err := client.CoreV1().Namespaces().Get(pod.Namespace, metav1.GetOptions{})
	if err != nil {
		log.Errorf("could not get namespace from pod %v", err)
		return credentials.Certificate{}, err
	}
	namespaceK8sUID := string(namespace.UID)
	tempHolder := []rune(namespaceK8sUID)
	tempHolder[14] = '4'
	saltedNamespaceUID := string(tempHolder)
	curConfig := getConfig()
	pemKeyString := curConfig.CredhubTrustedCa.PemPrivateKey
	pemCACertificateString := curConfig.CredhubTrustedCa.CaCertificate
	x509Cert, err := generateCert(saltedNamespaceUID, pemKeyString, pemCACertificateString)
	if err != nil {
		log.Errorf("issue creating new cert")
		return credentials.Certificate{}, err
	}
	pemCertString := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509Cert.Raw}))
	log.Infof("new cert created")
	fmt.Printf("CA CERT: %+v \n\n\n\n GEN CERT: %+v \n\n\n\n", pemCACertificateString, pemCertString)
	credhubCert := credentials.Certificate{
		Value: values.Certificate{
			Certificate: pemCertString,
			Ca:          pemCACertificateString,
			PrivateKey:  pemKeyString,
		},
	}

	credentialsPath := fmt.Sprintf("/kubernetes-credhub/credentials/%s", namespace.Name)
	err = enableCertToReadCreds(saltedNamespaceUID, credentialsPath)
	if err != nil {
		log.Errorf("could not set permissions on creds in path %s for userCert %s in credhub", credentialsPath, credhubCert.Name)
		return credentials.Certificate{}, err
	}
	log.Infof("enabled userCert %s with permissions on %s creds", credhubCert.Name, credentialsPath)
	return credhubCert, nil
}

func generateCert(namespaceUID string, pemKeyString string, pemCACertificateString string) (x509.Certificate, error) {

	ouApp := fmt.Sprintf("app:%s", namespaceUID)
	certTemplate := &x509.Certificate{
		IsCA: false,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          big.NewInt(1234),
		Subject: pkix.Name{
			OrganizationalUnit: []string{
				ouApp,
			},
			CommonName: namespaceUID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(5, 5, 5),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	}
	caBlock, caRest := pem.Decode([]byte(pemCACertificateString))
	if caBlock == nil || len(caRest) > 0 {
		err := fmt.Errorf("error decoding CA Cert, check the CA Cert")
		return x509.Certificate{}, err
	}
	signingCA, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return x509.Certificate{}, err
	}

	keyBlock, keyRest := pem.Decode([]byte(pemKeyString))
	if keyBlock == nil || len(keyRest) > 0 {
		err := fmt.Errorf("error decoding private key, check the private key")
		return x509.Certificate{}, err
	}
	privatekey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return x509.Certificate{}, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, signingCA, &privatekey.PublicKey, privatekey)
	if err != nil {
		return x509.Certificate{}, err
	}
	actualCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return x509.Certificate{}, err
	}

	return *actualCert, nil
}

func getConfig() AppConfig {

	topSecretFile, err := config.ReadFile("controller_config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	curConfig := AppConfig{}
	err = yaml.Unmarshal(topSecretFile, &curConfig)
	if err != nil {
		log.Fatal(err)
	}
	return curConfig
}
