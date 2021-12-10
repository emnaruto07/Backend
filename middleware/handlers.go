package middleware

import (
	"Backend/models"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jinzhu/gorm"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Email       string `json:"role"`
	TokenString string `json:"token"`
}

func createConnection() *gorm.DB {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	db, err := gorm.Open("postgres", os.Getenv("POSTGRES_URL"))

	if err != nil {
		panic(err)
	}
	sqldb := db.DB()

	err = sqldb.Ping()

	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully connected!")

	return db

}

func InitialMigration() {
	connection := createConnection()
	defer connection.Close()
	connection.AutoMigrate(models.User{})
}

func CreateUser(w http.ResponseWriter, r *http.Request) {

}

func GeneratehashPassword(password string) (string, error) {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func Login(w http.ResponseWriter, r *http.Request) {

}
