package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// User struct
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Blog struct
type Blog struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Author    string `json:"author"`
	Pageviews int32  `json:"pageviews"`
}

var jwtSecret = []byte("thepolyglotdeveloper")

var accountsMock = []User{
	User{
		ID:       "1",
		Username: "nraboy",
		Password: "1234",
	},
	User{
		ID:       "2",
		Username: "mraboy",
		Password: "5678",
	},
}

var blogsMock = []Blog{
	Blog{
		ID:        "1",
		Author:    "nraboy",
		Title:     "Sample Article",
		Content:   "This is a sample article written by Nic Raboy",
		Pageviews: 1000,
	},
}

// ValidateJWT validates JWT token
func ValidateJWT(t string) (interface{}, error) {
	return nil, nil
}

// CreateTokenEndpoint is an endpoint to create a new token
func CreateTokenEndpoint(response http.ResponseWriter, request *http.Request) {
	var user User
	_ = json.NewDecoder(request.Body).Decode(&user)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"password": user.Password,
	})
	tokenString, error := token.SignedString(jwtSecret)
	if error != nil {
		fmt.Println(error)
	}
	response.Header().Set("content-type", "application/json")
	response.Write([]byte(`{ "token": "` + tokenString + `" }`))
}

func main() {
	fmt.Println("Starting the application at :12345...")
	http.HandleFunc("/login", CreateTokenEndpoint)
	http.ListenAndServe(":12345", nil)
}
