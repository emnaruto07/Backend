package middleware

import (
	"Backend/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
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

type Error struct {
	IsError bool   `json:"isError"`
	Message string `json:"message"`
}

//function to create a connection with the database
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

func SetError(err Error, message string) Error {
	err.IsError = true
	err.Message = message
	return err
}

//func to create new user into the database
func CreateUser(w http.ResponseWriter, r *http.Request) {

	//connecting to db
	connection := createConnection()
	defer connection.Close()

	//defining the user
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		var err Error
		err = SetError(err, "Error in reading body")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	var dbuser models.User

	//Checking for the email in db
	connection.Where("email = ?", user.Email).First(&dbuser)

	if dbuser.Email != "" {
		var err Error
		err = SetError(err, "Email already in use")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	//creating hash for the provided password
	user.Password, err = GeneratehashPassword(user.Password)
	if err != nil {
		log.Fatalln("error in password hash")
	}

	//saving data into the database
	connection.Create(&user)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)

}

//Password hashing function
func GeneratehashPassword(password string) (string, error) {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

//func to check password hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//func for the user login api
func Login(w http.ResponseWriter, r *http.Request) {
	connection := createConnection()
	defer connection.Close()

	var authdetails Authentication
	err := json.NewDecoder(r.Body).Decode(&authdetails)
	if err != nil {
		var err Error
		err = SetError(err, "Error in reading body")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	var authuser models.User
	connection.Where("email = ?", authdetails.Email).First(&authuser)
	if authuser.Email == "" {
		var err Error
		err = SetError(err, "Username or password is incorrect")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	check := CheckPasswordHash(authdetails.Password, authdetails.Password)

	if !check {
		var err Error
		err = SetError(err, "Username or Password is incorrect")
		w.Header().Set("Contect-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	validToken, err := GenerateJwt(authuser.Email)
	if err != nil {
		var err Error
		err = SetError(err, "Failed to generate token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	var token Token
	token.Email = authuser.Email
	token.TokenString = validToken
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)

}

//func to Generate JWT tokens
func GenerateJwt(email string) (string, error) {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	secretkey := os.Getenv("SECRET_KEY")
	var mySigningKey = (secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["email"] = email
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("Something went wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}
