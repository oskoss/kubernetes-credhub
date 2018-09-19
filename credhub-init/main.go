package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

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
	volumePath          = "/tmp"
)

type InitContainerPackage struct {
	Certificate credentials.Certificate `json:"certificate"`
	CredhubURL  string                  `json:"credhub_url"`
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
		// v1.POST("/receiveKeys", receiveKeys)
		v1.POST("/receivecreds", receiveCreds)
		v1.GET("/health", healthEndpoint)
	}
	router.Run(listenPort)
}

func receiveCreds(c *gin.Context) {
	var json InitContainerPackage
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("%+v was uploaded!\n", json)
	return

}

// Gets certs, as files, connects to credhub, gets all accessable creds and store in file
func receiveKeys(c *gin.Context) {

	// TODO: Check if cert_files exist.
	form, err := c.MultipartForm()
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("Uploading File Error: %s", err.Error()))
		return
	}

	files := form.File["upload[]"]
	for _, file := range files {

		if file.Filename != clientKeyFileName && file.Filename != clientCertFileName && file.Filename != caCertFileName && file.Filename != credhubInfoFileName {
			log.Printf("%s was uploaded, but it's not allowed\n", file.Filename)
			c.String(http.StatusBadRequest, fmt.Sprintf("%s was received, but only %s, %s, %s allowed", file.Filename, clientKeyFileName, clientCertFileName, caCertFileName))
			return
		}
		fmt.Printf("%s is saved\n", file.Filename)
		c.SaveUploadedFile(file, file.Filename)
	}

	c.String(http.StatusOK, fmt.Sprintf("%d files uploaded!\n", len(files)))

	credhubFile, err := os.Open(credhubInfoFileName)
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("Error Opening CredHub Info File, %s", err.Error()))
		return
	}
	var clusterCredhub CredhubInfo
	jsonParser := json.NewDecoder(credhubFile)
	err = jsonParser.Decode(&clusterCredhub)
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("Error Parsing CredHub Info File, %s", err.Error()))
		return
	}

	// Connect to credhub
	client := credhubClient()
	// Find all credentials, using root /

	request := "/api/v1/data?name-like=/"
	bodyBytes, err := credhubGet(request, clusterCredhub.CredhubURL, client)

	c.String(http.StatusOK, fmt.Sprintf("Credhub responce is %s\n", string(bodyBytes)))

	var cred CredhubResponse

	err = json.Unmarshal(bodyBytes, &cred)
	if err != nil {
		log.Printf("Credhub response json un-marshalling error: %v\n", err)
		return
	}

	for _, credential := range cred.Credentials {

		// Get creds by name
		request := "/api/v1/data?name=" + credential.Name
		bodyBytes, err := credhubGet(request, clusterCredhub.CredhubURL, client)
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("Request: %s unsuccessful. %v\n", request, err))
			continue
		}
		c.String(http.StatusOK, fmt.Sprintf("Credhub responce is %s\n", string(bodyBytes)))

		storeCreds(credential.Name, string(bodyBytes))
		c.String(http.StatusOK, fmt.Sprintf("Cred %s stored at %s\n", credential.Name, volumePath))

		fmt.Printf("name: %v, value: %v \n", credential.Name, string(bodyBytes))
	}

}

// Health will return alive message with HTTP 200 code
func healthEndpoint(c *gin.Context) {

	c.JSON(200, gin.H{
		"message": "alive",
	})

}

// Utility functions
// func upload_files

// Connect to credhub API using certs. Return http client
func credhubClient() *http.Client {

	// Connect to credhub, using recieved certs
	caCert, err := ioutil.ReadFile(caCertFileName)
	log.Printf("%v CA cert processed\n", caCertFileName)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	log.Printf("CA cert pool created\n")

	cert, err := tls.LoadX509KeyPair(clientCertFileName, clientKeyFileName)
	log.Printf("Cert pair created\n")
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	return client
}

// Sent get request to credhub API and return response body.
func credhubGet(request string, credhubURL string, client *http.Client) ([]byte, error) {

	resp, err := client.Get("https://" + credhubURL + request)
	if err != nil {
		log.Printf("Credhub API connection err: %s\n", err.Error())
		return nil, err
	}
	log.Printf("Credhub GET request %s executed\n", request)

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Read body err: %s\n", err.Error())
	}

	bodyString := string(bodyBytes)
	if resp.StatusCode != 200 {
		//log.Printf("Credhub can't process request. Response is %v\n", bodyString)
		err := fmt.Errorf("Credhub can't process request. Response is %v", bodyString)
		return nil, err
	}
	log.Printf("Credentials found in credhub: %s \n", bodyString)

	return bodyBytes, nil
}

// TODO: consider multivalue creds processing
func storeCreds(credName string, credValue string) {

	err := ioutil.WriteFile(volumePath+"/"+credName, []byte(credValue), 0644)
	if err != nil {
		return
	}
}

// Helpers
