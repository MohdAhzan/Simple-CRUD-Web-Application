package middleware

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func ValidateCookies(c *gin.Context) bool {
	cookie, _ := c.Cookie("cookie")

	if cookie == "" {
		fmt.Println("Cookie not Found")
		return false
	} else {
		fmt.Println("cookie", cookie)
		return true
	}

}

func DeleteCookie(c *gin.Context) {
	c.SetCookie("cookie", "", 0, "", "", false, true)
	fmt.Println("cookie deleted")
}

func FindRole(c *gin.Context) (string, string, error) {
	cookie, _ := c.Cookie("cookie")
	if cookie == "" {
		return "", "", fmt.Errorf("cookie not found")
	}

	token, err := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("key")), nil
	})
	fmt.Println("jwt finding...")
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	fmt.Println("jwt finised finding...")
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("invalid token")
	}
	role := claims["role"].(string)
	user := claims["user"].(string)
	return role, user, nil
}
