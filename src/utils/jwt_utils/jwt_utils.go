package jwt_utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Nistagram-Organization/agent-shared/src/utils/rest_error"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"strings"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type CustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

func JwtMiddleware(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeaderParts := strings.Split(c.GetHeader("Authorization"), " ")
		token := authHeaderParts[1]

		hasScope := checkScope(scope, token)

		if !hasScope {
			err := rest_error.NewUnauthorizedError("insufficient scope")
			c.JSON(err.Status(), err)
			return
		}

		c.Next()
	}
}

func checkScope(scope string, tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		cert, err := getPemCert(token)
		if err != nil {
			return nil, err
		}
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	})

	claims, ok := token.Claims.(*CustomClaims)

	hasScope := false
	if ok && token.Valid {
		result := strings.Split(claims.Scope, " ")
		for i := range result {
			if result[i] == scope {
				hasScope = true
			}
		}
	}

	return hasScope
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	domain := os.Getenv("domain")
	resp, err := http.Get(fmt.Sprintf("https://%s/.well-known/jwks.json", domain))

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}
