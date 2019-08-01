package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
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

// ValidateJWT validates a JWT token
func ValidateJWT(t string) (interface{}, error) {
	if t == "" {
		return nil, errors.New("Authorization token must be present")
	}
	var err error
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse the token")
		}
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return jwtSecret, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var decodedToken interface{}
		mapstructure.Decode(claims, &decodedToken)
		return decodedToken, nil
	}

	return nil, errors.New("Invalid authorization token")
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
