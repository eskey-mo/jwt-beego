package jwtbeego

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"

	"github.com/dgrijalva/jwt-go"
)

type EasyToken struct {
	Username string
	Expires  int64
}

// https://gist.github.com/cryptix/45c33ecf0ae54828e63b
// location of the files used for signing and verification
const (
	privKeyPath = "keys/rsakey.pem"     // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "keys/rsakey.pem.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

var (
	verifyKey    *rsa.PublicKey
	mySigningKey *rsa.PrivateKey
)

func init() {
	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Fatal(err)
	}

	signBytes, err := ioutil.ReadFile(privKeyPath)

	if err != nil {
		log.Fatal(err)
	}

	mySigningKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		log.Fatal(err)
	}
}

func (e EasyToken) GetToken() (string, error) {

	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: e.Expires, //time.Unix(c.ExpiresAt, 0)
		Issuer:    e.Username,
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		log.Fatal(err)
	}

	return tokenString, err
}

func (e EasyToken) ValidateToken(tokenString string) (bool, error) {
	// Token from another example.  This token is expired
	//var tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c"
	if tokenString == "" {
		return false, errors.New("Token vacio")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if token == nil {
		log.Fatal(err)
		return false, errors.New("No funcionó")
	}

	if token.Valid {
		//"You look nice today"
		return true, nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return false, errors.New("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			return false, errors.New("Timing is everything")
		} else {
			//"Couldn't handle this token:"
			return false, err
		}
	} else {
		//"Couldn't handle this token:"
		return false, err
	}
}

func (e EasyToken) GetIss(tokenString string) (string, error) {
	// Token from another example.  This token is expired
	//var tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c"
	if tokenString == "" {
		return "", errors.New("Token vacio")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if token == nil {
		log.Fatal(err)
		return "", errors.New("No funcionó")
	}

	if token.Valid {
		//"You look nice today"
		if iss, ok := token.Claims.(jwt.MapClaims)["iss"]; ok {
			//do something here
			return iss.(string), nil
		}
		return "", nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return "", errors.New("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			return "", errors.New("Timing is everything")
		} else {
			//"Couldn't handle this token:"
			return "", err
		}
	} else {
		//"Couldn't handle this token:"
		return "", err
	}
}

func (e EasyToken) GetTokenForReset() (string, error) {

	// Create the Claims
	claims := &jwt.MapClaims{
		"exp":   e.Expires, //time.Unix(c.ExpiresAt, 0)
		"iss":   e.Username,
		"reset": "true",
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		log.Fatal(err)
	}

	return tokenString, err
}

func (e EasyToken) GetReset(tokenString string) (bool, error) {
	// Token from another example.  This token is expired
	//var tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c"
	if tokenString == "" {
		return false, errors.New("Token vacio")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if token == nil {
		log.Fatal(err)
		return false, errors.New("No funcionó")
	}

	if token.Valid {
		//"You look nice today"
		reset := token.Claims.(jwt.MapClaims)["reset"]
		if reset == "true" {
			return true, nil
		} else {
			return false, nil
		}
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return false, errors.New("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			return false, errors.New("Timing is everything")
		} else {
			//"Couldn't handle this token:"
			return false, err
		}
	} else {
		//"Couldn't handle this token:"
		return false, err
	}
}

func (e EasyToken) GetClaims(tokenString string) (map[string]interface{}, error) {
	if tokenString == "" {
		return nil, errors.New("Token vacio")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if token == nil {
		log.Fatal(err)
		return nil, errors.New("No funcionó")
	}

	if token.Valid {
		//"You look nice today"
		return token.Claims.(jwt.MapClaims), nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, errors.New("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			return nil, errors.New("Timing is everything")
		} else {
			//"Couldn't handle this token:"
			return nil, err
		}
	} else {
		//"Couldn't handle this token:"
		return nil, err
	}
}
