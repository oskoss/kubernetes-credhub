package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {

	router := gin.Default()
	router.LoadHTMLFiles("templates/index.html")
	router.Static("/v1/assets", "./assets")

	v1 := router.Group("/v1")
	{
		v1.GET("/creds", getCreds)
		v1.GET("/health", healthEndpoint)
	}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		// service connections
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

func getCreds(c *gin.Context) {

	credsDir := "/credhub"

	if len(credsDir) == 0 {

		c.JSON(503, gin.H{
			"status": "CREDS_FILE_PATH variable is not set up. Please do...",
		})
		return
	}

	files, err := ioutil.ReadDir(credsDir)
	if err != nil {
		c.JSON(503, gin.H{
			"status": "Creds directory can't be read",
		})
	}
	strDat := ""
	for _, f := range files {
		dat, err := ioutil.ReadFile(credsDir + "/" + f.Name())
		if err != nil {

			c.JSON(503, gin.H{
				"status": "Creds file can't be read",
			})
		}
		strDat = fmt.Sprintf("%s\n%s", strDat, string(dat))
	}

	c.HTML(http.StatusOK, "index.html", gin.H{
		"content": strDat,
	})

}

func healthEndpoint(c *gin.Context) {

	c.JSON(200, gin.H{
		"status": "healthy",
	})
}
