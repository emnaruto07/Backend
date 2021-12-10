package main

import (
	"Backend/router"
	"fmt"
	"log"
	"net/http"
)

func main() {
	r := router.Router()

	fmt.Println("Starting server on port 8000.")

	log.Fatal(http.ListenAndServe(":8000", r))
}
