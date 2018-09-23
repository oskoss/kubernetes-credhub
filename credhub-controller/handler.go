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
	"time"

	"code.cloudfoundry.org/credhub-cli/credhub/auth"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials/values"

	"code.cloudfoundry.org/credhub-cli/credhub"
	log "github.com/Sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type InitContainerPackage struct {
	Certificate credentials.Certificate `json:"certificate"`
	CredhubURL  string                  `json:"credhub_url"`
}

type Handler interface {
	Init() error
	ObjectCreated(obj interface{})
	ObjectDeleted(obj interface{})
	ObjectUpdated(objOld, objNew interface{})
}

type TestHandler struct{}

func (t *TestHandler) Init() error {
	log.Info("TestHandler.Init")
	return nil
}

func (t *TestHandler) ObjectCreated(obj interface{}) {
	log.Info("TestHandler.ObjectCreated")

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
	for attempts < 60 {
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
	log.Errorf("Failed! Waited 1 minutes for init container to become ready!")
	return
}

func enableCertToReadCreds(namespaceUID string, credentialPath string) error {
	credhubEndpoint := "https://104.198.242.241:8844"
	credhubClientUser := "credhub_admin_client"
	credhubClientSecret := "ajf7lrmg3bacrggfy6t2"

	credhubClient, err := credhub.New(
		credhubEndpoint,
		credhub.SkipTLSValidation(true),
		credhub.Auth(auth.UaaClientCredentials(credhubClientUser, credhubClientSecret)),
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
		actor := fmt.Sprintf("app:%s", namespaceUID)
		permission, err := credhubClient.AddPermission(path, actor, []string{"read", "read_acl"})
		if err != nil {
			log.Errorf("could not add %+v permission to credhub usercert %v", permission, namespaceUID)
			return err
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
	credhubURL := "https://104.198.242.241:8844"
	log.Infof("Send cert to init container %+v", cert)
	for _, initContainer := range pod.Spec.InitContainers {
		if initContainer.Name == "kubernetes-credhub-init" {
			hostname := pod.Status.PodIP
			port := initContainer.Ports[0].ContainerPort
			endpoint := "v1/receivecreds"
			URL := fmt.Sprintf("http://%s:%v/%s", hostname, port, endpoint)
			payload := InitContainerPackage{
				Certificate: cert,
				CredhubURL:  credhubURL,
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

	pemKeyString := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA8el4ijjnahsJSXzyMf7ASL3fjAaUlyXxjVVhyvMlHGHEBaFO\n4M7SOLxRnEpMIS8/K2uUHzdRW6w0kPwsXyDrvdn4I2a3l1oOR2igD5Cw8EYsBfiQ\nKbmNj35sf4+bWoLNvD9Whyc2jLc5zwIDFPpXx4EioEvPspZBPM/zp8rKM7Zj7uV/\n8skRzQa15Cy7iFTank7kV/vvTAuKwFPK5ajL5GADJKsvX35N+ZAT+hTQv+N5eMcO\nVRoUmy852o5gzckbk/crJ4pH48qM1Xlj+JhpR1YlDHH5+zrqbvjhGDYU2nTavzTo\nU5/kDDEEIROdmBf+zQsXoPxulM0Kdyt6DT8PcQIDAQABAoIBAQDj6yYohGhzrblY\nRaIivHQJlOrzkJeauKMWl+UlQ2Qpk2sOKuaYJAQodDUn3VBQy6Tmkdridknu5xY3\nq39auTeijaSeJf6/WJeva8GyKI6sMlDz5zZcOXhIQ8KRhInIAwk3XS129NkORuru\nQGUK9LqTOvWWtRagmbQpSXu1EPjlMhNztU2ypTdCKYJpqtI5jsNFTjDfoXrSjX+q\nExF/LPsDbs4nM54VRMMOyOjREXYxWcQx1j5j92p2j7Ly9qPtI9GKNtGUrgKx3u8G\ngDja7wPHAPE9+0jpd//HTsOjN0H63l09Ua0LC05bIHp4MSN08c9YWucYh+cJP2gZ\nPe3nD43hAoGBAPM0d5/MRBFN4YLn/QkggLaHP3ifct97EWlH24CU5kWYibZ4+BOp\nQEJRyMPyR8T/KE/OEO0Z3gbottGpzGrH5XII3EpHJ2Avn2DRApwWyEibee2aVaRm\nDB2kOLzcT8ovwkotYwvPF+wA35uPLdNvNVGA8G+12zTp9P3ZbLKkFnXVAoGBAP6j\nlv1uCvfs3uFcmdobNMf9e0ZIdXMBaNY43e+TIJjRpXxqjNGPkrbSSr43EpxhEOme\n7TidMo6uCq42xWYGQVWnGPBePHt+Q38/N1dSOolO9ilN0pKs4s58h4+h68rpL1OE\nRExbkSizOE9mm0VHjWziUlS38nwfjXC0557qqnUtAoGAZx+vPZ3ymtfIMKbH32/d\nxAfTPQV3QxW/C0JB6+K3RXlpo2rl3ghdTAG7vIJmNjzvTe+Vs8PNJmbU5lA2cmyy\neMkTB5fmNV3cGcRmc+MhJ9BtQfe4Ks5ugr8Yo9RTLOtVWfimz+IPRa4VIrPyfX3h\nQN8IlIWrHmO50023ToRPVcUCgYEAxxnMVo4zf1UzlEyec55wL6twNy0ywGCqw02l\nosyMYVETLuv0/WpgUhitnntbTvDKk5DTdT/cpxlIep2SzUo4zasg4dkdO4YnaphY\nQiumX3RhHzydWFhb4w4VxOXbg0W+3nN+H6I9JvCzJ8pXv9zJpQh1TY6iyBC3vBeH\nP4fHDmUCgYAJe3/ioI8Njlggrjyrv0IgFBGy5/4s0YxErIMMZOpWu0v78lO2xGQs\nT2Owmw5IJd/4/1PwZQfFiSjnBijzqVUdpBlcUw3kJLHTsqkR2MGZXGIh0S5Wo2X0\nXJgCvQSNmucjR2pHo9N4oHhTx3wWUUu5A9/M4b7voyqP8/S+VkZISA==\n-----END RSA PRIVATE KEY-----"
	pemCACertificateString := "-----BEGIN CERTIFICATE-----\nMIIDLjCCAhagAwIBAgIRAKVP+Bnp+Uwx/qy6ZrDS9jUwDQYJKoZIhvcNAQELBQAw\nQDEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MRgwFgYDVQQD\nEw9jcmVkaHViLW10bHMtY2EwHhcNMTgwOTIwMTgxMzI1WhcNMTkwOTIwMTgxMzI1\nWjBAMQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoTDUNsb3VkIEZvdW5kcnkxGDAWBgNV\nBAMTD2NyZWRodWItbXRscy1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\nggEBAPHpeIo452obCUl88jH+wEi934wGlJcl8Y1VYcrzJRxhxAWhTuDO0ji8UZxK\nTCEvPytrlB83UVusNJD8LF8g673Z+CNmt5daDkdooA+QsPBGLAX4kCm5jY9+bH+P\nm1qCzbw/VocnNoy3Oc8CAxT6V8eBIqBLz7KWQTzP86fKyjO2Y+7lf/LJEc0GteQs\nu4hU2p5O5Ff770wLisBTyuWoy+RgAySrL19+TfmQE/oU0L/jeXjHDlUaFJsvOdqO\nYM3JG5P3KyeKR+PKjNV5Y/iYaUdWJQxx+fs66m744Rg2FNp02r806FOf5AwxBCET\nnZgX/s0LF6D8bpTNCncreg0/D3ECAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8G\nA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKt87wyWY2Hdy+SaUxOj\n1tYldn6Uf+7UH/KMJJzg185NSptmDcOJhYAW1DB4Ps48ftZUlw54HdKY9ZJD6Vqq\nivHP6vNEGIaDYMHHTV3K082X8SLElA1nCNU1Eu48hygtgo08DrstFVU0wx3ost/z\nHdayI4VNmh6RbcPl3D+5YazmHbGpROrjtPYKyOuK9PMqNFiCgoXr0rvVZgZ6mU0/\nqeAbvDJVR2TnUsk9W+ZcKZbA4qKC6pnoqPWukJJfWQYCiyjivZwUa3kQWeOzsxEQ\n+VrzfwQY2i5dsQZ9L94tMn5TA30XqCSFJ1s+gl2xVzY+flKj9JunCXjiciziQVVJ\nJsg=\n-----END CERTIFICATE-----"
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

func (t *TestHandler) ObjectDeleted(obj interface{}) {
	log.Info("TestHandler.ObjectDeleted")
}

func (t *TestHandler) ObjectUpdated(objOld, objNew interface{}) {
	log.Info("TestHandler.ObjectUpdated")
}
