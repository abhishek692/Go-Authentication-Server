package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// since we need a secret key to create the signature of the jwt-token

var jwtSecretKey = []byte("this-is-a-secret-key")

// we will only have two verified users on our server
var Users = map[string]string{
	"user1":    "password1",
	"user2":    "password2",
	"abhishek": "soni",
	"shiva":    "shiva",
}

// Creating a struct to read the username and password from the request body

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// Creating a struct that will be encoded to JWT
// jwt.StandardClaims provides fields lile expiry time

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// the SignIn Hanlder

func SignIn(w http.ResponseWriter, r *http.Request) {

	var Creds Credentials

	// the next line will decode the body of request and put the information in Creds variable. Since Creds is passed by reference, the information will be in that same variable
	err := json.NewDecoder(r.Body).Decode(&Creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest) // this means there is an error in decoding the body, there is some problem with the request
		json.NewEncoder(w).Encode("Error in decoding request body", err)
		return
	}

	// Fetching the password from the map we created to store users
	expectedPassword, ok := Users[Creds.Username] // Creds is the variable in which the request's parameters are stored.

	// if the password matches with the password we recieved in the request, we can move ahead
	// if not matches, we can return "unauthorized"

	if !ok || expectedPassword != Creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// else we move ahead

	// since the user has been authenticated, we can give them a JWT token.

	// Declaring a expiration time of the toker

	expirationTime := time.Now().Add(5 * time.Minute)

	// Create a JWT claim which will contain the Username and expiry time
	claims := &Claims{
		Username: Creds.Username, //  a jwt claims contain the username, the username should be the username from the request
		StandardClaims: jwt.StandardClaims{ // jwt claims also contain expirytime which will determine the expiration time of the token
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declaring the token with the algorithm for signing and claims we just created

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// converting this token into string which contains the header, payload and the secret key
	tokenString, err := token.SignedString(jwtSecretKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // this means there was an error in Generating token string.
		return
	}

	// finally setting the client cookie for token as the jwt we just created
	// we also set an exiration time which is equal to the expiration time of token itslef

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

// SetCookie adds a Set-Cookie header to the provided ResponseWriter's headers.
// The provided cookie must have a valid Name. Invalid cookies may be
// // silently dropped.

// func SetCookie(w ResponseWriter, cookie *Cookie) {
// 	if v := cookie.String(); v != "" {
// 		w.Header().Add("Set-Cookie", v)
// 	}
// }

//If a user logs in with the correct credentials, this handler will then set a cookie on the client side with the JWT value. Once a cookie is set on a client, it is sent along with every request henceforth

// The welcome handler will

func Welcome(w http.ResponseWriter, r *http.Request) {

	// firstly we need to obtain session cookie token from the requests cookies, which comes with every request
	c, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			// cookie is not set, so return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// if there is any other kind of error, send a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// the cookie contains the JWT string, so need to decode it to get the key
	tokenString := c.Value

	// We initialize a new Claims object

	claims := &Claims{}

	// Parsing the JWT string and storing the result in claims
	// we are passing the key in this parser method, so this method can give error as well
	// if the token is invalid, if it has expired or if the signature doesn't match
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// returning the welcome message to the user, along with their username
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

// also we need a function to renew our token from time to time

// so I created a new /refersh route that takes the previous token(which would be still valid at that time) and returns a new token

func Refresh(w http.ResponseWriter, r *http.Request) {

	c, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknString := c.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Now we ensure that a new token is not genrated until enough time has elapsed
	// here a new token is issued if the old token is about to expire in the next 30 seconds.

	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Previous token is still valid.")
		return
	}

	// now we create a new token

	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// now we set this new token as user's token cookiw

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func main() {
	fmt.Println("Starting the authorization server...")

	http.HandleFunc("/api/signin", SignIn)   // handler to handle user's signing in
	http.HandleFunc("/api/welcome", Welcome) // handler to display welcome messaage
	http.HandleFunc("/api/refresh", Refresh) // handler to refresh the JWT key continuously

	log.Fatal(http.ListenAndServe(":8081", nil))
}
