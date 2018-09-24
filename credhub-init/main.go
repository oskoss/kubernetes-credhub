package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/credhub-cli/credhub/credentials"
	"github.com/gin-gonic/gin"
)

const (
	keysDirName         = "keys"
	listenPort          = ":8080"
	clientKeyFileName   = "client_key.pem"
	clientCertFileName  = "client.pem"
	caCertFileName      = "server_ca_cert.pem"
	credhubInfoFileName = "credhub.json"
	//TODO Get VolumeMountPath from the controller via the InitContainerPackage
	volumeMountPath = "/credhub"
)

type InitContainerPackage struct {
	Certificate credentials.Certificate `json:"certificate"`
	CredhubURL  string                  `json:"credhub_url"`
	Namespace   string                  `json:"namespace"`
}

type CredhubResponse struct {
	Credentials []struct {
		VersionCreatedAt string `json:"version_created_at"`
		Name             string `json:"name"`
	} `json:"credentials"`
}

type CredhubInfo struct {
	CredhubURL string `json:"credhub_URL"`
}

func main() {

	router := gin.Default()
	v1 := router.Group("/v1")
	{
		v1.POST("/receivecreds", receiveCreds)
		v1.GET("/health", healthEndpoint)
	}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	log.Println("Server exiting")
}

func receiveCreds(c *gin.Context) {
	var initJSON InitContainerPackage
	if err := c.ShouldBindJSON(&initJSON); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("Received kubernetes-credhub-controller payload successfully!\n")
	c.JSON(200, gin.H{
		"status": "success",
	})

	_, err := getPodCreds(initJSON)
	if err != nil {
		log.Fatal("Server Shutdown:", err)
		c.JSON(500, gin.H{
			"status": "failed",
		})
	}
	//Need to kill ourselves since we are disposable init container
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
}

func getPodCreds(initJSON InitContainerPackage) ([]credentials.Credential, error) {
	client, err := setupCredhubClient(initJSON.Certificate)
	if err != nil {
		return []credentials.Credential{}, err
	}

	request := "/api/v1/data?name-like=/kubernetes-credhub/credentials/" + initJSON.Namespace
	bodyBytes, err := credhubGet(request, initJSON.CredhubURL, client)
	if err != nil {
		log.Printf("Issue getting creds from credhub! Error: %v\n", err)
		return []credentials.Credential{}, err
	}

	var cred CredhubResponse
	err = json.Unmarshal(bodyBytes, &cred)
	if err != nil {
		log.Printf("Credhub response json un-marshalling error: %v\n", err)
		return []credentials.Credential{}, err
	}

	for _, credential := range cred.Credentials {

		request = "/api/v1/data?name=" + credential.Name
		bodyBytes, err := credhubGet(request, initJSON.CredhubURL, client)
		if err != nil {
			if strings.Contains(err.Error(), "credential does not exist or you do not have sufficient authorization") {
				log.Printf("Access to %s was denied!", credential.Name)
			} else {
				log.Printf("Error getting credential: %s! %v", credential.Name, err)
				return []credentials.Credential{}, err
			}
		} else {
			storeCreds(credential.Name, string(bodyBytes))
		}

	}
	return []credentials.Credential{}, nil
}

func setupCredhubClient(creds credentials.Certificate) (*http.Client, error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(creds.Value.Ca))
	log.Printf("CA cert pool created\n")

	cert, err := tls.X509KeyPair([]byte(creds.Value.Certificate), []byte(creds.Value.PrivateKey))
	if err != nil {
		return nil, err
	}
	log.Printf("Cert pair created\n")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}

	return client, nil
}

func healthEndpoint(c *gin.Context) {

	c.JSON(200, gin.H{
		"message": "alive",
	})

}

func credhubGet(request string, credhubURL string, client *http.Client) ([]byte, error) {

	resp, err := client.Get(credhubURL + request)
	if err != nil {
		log.Printf("Credhub API connection err: %s\n", err.Error())
		return []byte{}, err
	}
	log.Printf("Credhub GET request %s executed\n", request)

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Read body err: %s\n", err.Error())
		return []byte{}, err
	}

	bodyString := string(bodyBytes)
	if resp.StatusCode != 200 {
		log.Printf("Credhub can't process request. Response is %v\n", bodyString)
		err := fmt.Errorf("Credhub can't process request. Response is %v", bodyString)
		return []byte{}, err
	}

	return bodyBytes, nil
}

func storeCreds(fullCredName string, credValue string) error {

	pathSeg := strings.Split(fullCredName, "/")
	credName := pathSeg[len(pathSeg)-1]

	file, err := os.Create(volumeMountPath + "/" + credName)
	if err != nil {
		log.Printf("Creating file to write credential to volume error: %s\n", err.Error())
		return err
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, credValue)
	if err != nil {
		log.Printf("Writing credential to volume error: %s\n", err.Error())
		return err
	}
	return nil
}
