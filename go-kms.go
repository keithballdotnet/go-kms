package main

import (
	"github.com/keithballdotnet/go-kms/kms"
	"log"
	"os"
)

// main will start up the application
func main() {

	// Set up logging
	log.SetOutput(os.Stdout)
	log.SetPrefix("GO-KMS:")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Println("Starting GO-KMS...")

	kms.Start()
}
