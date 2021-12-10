package router

import (
	"Backend/middleware"

	"github.com/gorilla/mux"
)

func Router() *mux.Router {

	router := mux.NewRouter()

	router.HandleFunc("/api/newuser", middleware.CreateUser).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/login", middleware.Login).Methods("POST", "OPTIONS")

	return router
}
