package jwt

import (
	"admin/models"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func CreateToken(user models.User, c *gin.Context) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": user.Role,
		"user": user.Username,
		"exp":  time.Now().Add(time.Hour * 24 * 30).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("key")))
	if err != nil {
		fmt.Println("Error creating Token", err)
	}
	fmt.Println("<<<Token Created>>>")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("cookie", tokenString, 3600*24*7, "", "", false, true)

}
