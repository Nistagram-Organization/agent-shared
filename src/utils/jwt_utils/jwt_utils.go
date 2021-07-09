package jwt_utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Nistagram-Organization/agent-shared/src/utils/rest_error"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
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
	Permissions []string `json:"permissions"`
	jwt.StandardClaims
}

func checkForMatch(providedPermission string, requiredPermissions []string) bool {
	for _, requiredPermission := range requiredPermissions {
		if providedPermission == requiredPermission {
			return true
		}
	}
	return false
}

func checkPermissions(permission string, tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		cert, err := getPemCert(token)
		if err != nil {
			return nil, err
		}
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	})

	claims, ok := token.Claims.(*CustomClaims)

	hasPermission := false
	if ok && token.Valid {
		hasPermission = checkForMatch(permission, claims.Permissions)
	}

	return hasPermission
}

func CheckScope(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeaderParts := strings.Split(c.GetHeader("Authorization"), " ")
		token := authHeaderParts[1]

		hasScope := checkPermissions(permission, token)

		if !hasScope {
			err := rest_error.NewUnauthorizedError("insufficient permission")
			c.AbortWithError(err.Status(), err)
			return
		}
		c.Next()
	}
}

func GetJwtMiddleware() gin.HandlerFunc {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			aud := "http://nistagram-agent"
			fmt.Sprintln("Checked audience")
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				return token, errors.New("invalid audience")
			}
			// Verify 'iss' claim
			iss := "https://dev-6w-2hyw1.eu.auth0.com/"
			fmt.Sprintln("Checked issuer")
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := getPemCert(token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})

	return asGin(jwtMiddleware.Handler)
}

func asGin(middleware func(next http.Handler) http.Handler) gin.HandlerFunc {
	return func(gctx *gin.Context) {
		var skip = true
		var handler http.HandlerFunc = func(http.ResponseWriter, *http.Request) {
			skip = false
		}
		middleware(handler).ServeHTTP(gctx.Writer, gctx.Request)
		switch {
		case skip:
			gctx.Abort()
		default:
			gctx.Next()
		}
	}
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get("https://dev-6w-2hyw1.eu.auth0.com/.well-known/jwks.json")

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
