package main

import (
	"fmt"
	"time"

	"code.cloudfoundry.org/credhub-cli/credhub/credentials"

	"code.cloudfoundry.org/credhub-cli/credhub"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials/generate"
	log "github.com/Sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
	//Connect to CredHub to Obtain Credentials for The Pod
	// credhubEndpoint := "https://10.0.3.3:8844"
	// fmt.Printf("Connecting to: %s....", credhubEndpoint)
	// credhubClient, err := credhub.New(credhubEndpoint, credhub.SkipTLSValidation(true), credhub.Auth(auth.UaaClientCredentials("ops_manager", "SzDgzZcrXGMVNS8H39hOshRGz-xEXiCA")))
	// if err != nil {
	// 	fmt.Printf("Failed!\n")
	// 	log.Fatal(err)
	// 	os.Exit(1)
	// }
	// fmt.Printf("Success!\n")
	// cert, err := obtainCert(pod, credhubClient)
	// if err != nil {
	// 	log.Fatal(err)
	// 	os.Exit(1)
	// }
	cert := credentials.Certificate{}
	client := getKubernetesClient() //TODO: Pass the k8s client?
	attempts := 0
	for attempts < 100 {
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
					err = sendCert(pod, cert)
					if err != nil {
						log.Errorf("Failed! Could not send cert over to init container! %+v", err)
						return
					}
					log.Infof("Successfully send credhub cert to init container!")
					return
				}
			}
		}
		attempts += 1
		time.Sleep(time.Second * 3)
	}
	log.Errorf("Failed! Waited 5 minutes for init container to become ready!")
	return
}
func sendCert(pod *core_v1.Pod, cert credentials.Certificate) error {
	log.Infof("Send cert to init pod %+v", cert)
	return nil
}

func obtainCert(pod *core_v1.Pod, credhubClient *credhub.CredHub) (credentials.Certificate, error) {

	//*Always* store our CA with the following path: "/kubernetes-credhub/ca"
	//*Always* store each new cert with the following path: "/kubernetes-credhub/certs/*"

	rootPath := "/kubernetes-credhub/"
	caName := "ca"
	certPath := rootPath + "certs/"
	certName := pod.UID

	// If the certificate already exists, return it, if it doesn't create it
	log.Infof("Getting certificate with the following path: %s%s......", certPath, certName)
	cert, err := credhubClient.GetLatestCertificate(fmt.Sprintf("%s%s", certPath, certName))
	if err != nil {
		log.Infof("Failed!\n Creating a new one......")

		ca, err := obtainCA(credhubClient, rootPath, caName)
		if err != nil {
			log.Errorf("Failed to obtain or create new CA! %v", err)
			return credentials.Certificate{}, err
		}

		client := getKubernetesClient() //TODO: Pass the k8s client?

		namespace, err := client.CoreV1().Namespaces().Get(pod.Namespace, metav1.GetOptions{})
		if err != nil {
			log.Errorf("Failed! Could Not get Namespace from Pod! %v", err)
			return credentials.Certificate{}, err
		}

		//Generate each certificate for auth with the correct organizationunit. In this case we use the UID of the K8s namespace.
		certificate := generate.Certificate{
			Ca:               ca.Name,
			OrganizationUnit: fmt.Sprintf("app:%s", namespace.UID),
		}
		cert, err = credhubClient.GenerateCertificate(fmt.Sprintf("%s%s", certPath, certName), certificate, credhub.NoOverwrite)
		if err != nil {
			log.Errorf("Failed! Couldn't Generate new Certificate!! Error: %+v \n", err)
			return credentials.Certificate{}, err
		}

		log.Info("Succeeded! Created new Certificate! \n")
	} else {
		log.Info("Succeeded! Using existing Certificate! \n")
	}
	return cert, nil
}

func obtainCA(credhubClient *credhub.CredHub, caPath string, caName string) (credentials.Certificate, error) {

	log.Infof("Getting CA with the following path: %s%s......", caPath, caName)
	cert, err := credhubClient.GetLatestCertificate(caPath + caName)
	if err != nil {
		log.Infof("Failed!\n Creating a new one......")
		gen := generate.Certificate{
			CommonName: "kubernetes-credhub",
			KeyLength:  2048,
			IsCA:       true,
		}
		cert, err = credhubClient.GenerateCertificate(caPath+caName, gen, credhub.NoOverwrite)
		if err != nil {
			log.Errorf("Failed! Couldn't Generate new CA!! Error: %+v \n", err)
			return credentials.Certificate{}, err
		}
		log.Info("Succeeded! Created new CA! \n")
	} else {
		log.Info("Succeeded! Using existing CA! \n")
	}
	return cert, nil
}

func (t *TestHandler) ObjectDeleted(obj interface{}) {
	log.Info("TestHandler.ObjectDeleted")
}

func (t *TestHandler) ObjectUpdated(objOld, objNew interface{}) {
	log.Info("TestHandler.ObjectUpdated")
}
