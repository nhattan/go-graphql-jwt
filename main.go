package main

import (
	"fmt"
	"net/http"
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

// CreateTokenEndpoint creates a token endpoint
func CreateTokenEndpoint(response http.ResponseWriter, request *http.Request) {}

func main() {
	fmt.Println("Starting the application at :12345...")
	http.HandleFunc("/login", CreateTokenEndpoint)
	http.ListenAndServe(":12345", nil)
}
