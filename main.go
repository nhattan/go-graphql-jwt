package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/graphql-go/graphql"
	"github.com/mitchellh/mapstructure"
)

type tokenKey string

const (
	myToken tokenKey = "token"
)

func (tk tokenKey) toString() string {
	return string(tk)
}

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

var accountType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Account",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.String,
		},
		"username": &graphql.Field{
			Type: graphql.String,
		},
		"password": &graphql.Field{
			Type: graphql.String,
		},
	},
})

var blogType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Blog",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.String,
		},
		"title": &graphql.Field{
			Type: graphql.String,
		},
		"content": &graphql.Field{
			Type: graphql.String,
		},
		"author": &graphql.Field{
			Type: graphql.String,
		},
		"pageviews": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				_, err := ValidateJWT(params.Context.Value(myToken).(string))
				if err != nil {
					return nil, err
				}
				return params.Source.(Blog).Pageviews, nil
			},
		},
	},
})

// ValidateJWT validates a JWT token
func ValidateJWT(t string) (interface{}, error) {
	if t == "" {
		return nil, errors.New("Authorization token must be present")
	}
	var err error
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if err != nil {
			return nil, fmt.Errorf("Failed to parse the token: %v", err)
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
	rootQuery := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"account": &graphql.Field{
				Type: accountType,
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					account, err := ValidateJWT(params.Context.Value(myToken).(string))
					if err != nil {
						return nil, err
					}
					for _, accountMock := range accountsMock {
						if accountMock.Username == account.(User).Username {
							return accountMock, nil
						}
					}
					return &User{}, nil
				},
			},
			"blogs": &graphql.Field{
				Type: graphql.NewList(blogType),
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					return blogsMock, nil
				},
			},
		},
	})

	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query: rootQuery,
	})

	http.HandleFunc("/login", CreateTokenEndpoint)
	http.HandleFunc("/graphql", func(response http.ResponseWriter, request *http.Request) {
		result := graphql.Do(graphql.Params{
			Schema:        schema,
			RequestString: request.URL.Query().Get("query"),
			Context:       context.WithValue(context.Background(), myToken, request.URL.Query().Get("token")),
		})
		json.NewEncoder(response).Encode(result)
	})
	http.ListenAndServe(":12345", nil)
}
