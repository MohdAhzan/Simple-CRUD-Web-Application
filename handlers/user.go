package handlers

import (
	database "admin/Database"
	"admin/jwt"
	"admin/middleware"
	"admin/models"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// USER SIGNUP

func UserSignupHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")

	//validate cookie
	ok := middleware.ValidateCookies(c)
	if !ok {
		c.HTML(http.StatusOK, "usersignup.html", nil)
		return
	}
	c.Redirect(http.StatusFound, "/")

}

func UserSignupPost(c *gin.Context) {

	fmt.Println(" WOORKING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")

	var errMsg models.Invalid
	userName := c.PostForm("Name")
	userEmail := c.PostForm("Email")

	fmt.Println(userName)
	fmt.Println(userEmail)

	if userName == "" {
		errMsg.NameError = "Name should not be empty"
		c.HTML(http.StatusBadRequest, "usersignup.html", errMsg)
		return
	}
	if userEmail == "" {
		errMsg.EmailError = "Email should not be empty"
		c.HTML(http.StatusBadRequest, "usersignup.html", errMsg)
		return
	}

	Pattern := `^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`
	regex := regexp.MustCompile(Pattern)
	if !regex.MatchString(userEmail) {
		errMsg.EmailError = "Enter a valid Email"
		c.HTML(http.StatusBadRequest, "usersignup.html", errMsg)
		return
	}
	userPassword := c.PostForm("Password")
	if userPassword == "" {
		errMsg.PasswordError = "Password should not be empty"
		c.HTML(http.StatusBadRequest, "usersignup.html", errMsg)
		return
	}
	userConfirmPassword := c.PostForm("ConfirmPassword")
	if userConfirmPassword != userPassword {
		errMsg.ConfirmPasswordError = "Those passwords didn’t match. Try again."
		c.HTML(http.StatusBadRequest, "usersignup.html", errMsg)
		return
	}

	//Hashing Password
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(userPassword), 10)
	if err != nil {
		fmt.Println("Error Hashing Password")
		return
	}

	// check if user already exists
	var count int
	if err := database.Db.Raw("SELECT COUNT(*) FROM users WHERE email =$1 ", userEmail).Scan(&count).Error; err != nil {
		fmt.Println(err)
		c.HTML(http.StatusOK, "usersignup.html", nil)
		return
	}
	if count > 0 {
		errMsg.EmailError = "User already exists"
		c.HTML(http.StatusBadRequest, "usersignup.html", errMsg)
		return
	}

	//Insert into database
	database.Db.Exec("insert into users(username,email,password) VALUES($1,$2,$3)", userName, userEmail, hashedPass)
	if err != nil {
		fmt.Println(err)
		c.HTML(http.StatusOK, "usersignup.html", nil)
		return
	}

	c.Redirect(http.StatusFound, "/")

}

// LOGIN

func LoginHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")
	fmt.Println("workking")
	// cookie validation
	ok := middleware.ValidateCookies(c)
	role, _, _ := middleware.FindRole(c)

	if !ok {
		c.HTML(http.StatusOK, "login.html", nil)
		return
	} else {
		if role == "user" {
			c.Redirect(http.StatusFound, "/home")
			return
		} else if role == "admin" {
			c.Redirect(http.StatusFound, "/admin")
			return
		}
		c.HTML(http.StatusBadRequest, "login.html", nil)
	}

}

func LoginPost(c *gin.Context) {

	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")

	var errMsg models.Invalid
	Newemail := c.Request.FormValue("Name")
	NewPassword := c.Request.FormValue("Password")

	if Newemail == "" {
		errMsg.EmailError = "Email should not be empty"
		c.HTML(http.StatusBadRequest, "login.html", errMsg)
		return
	}

	Pattern := `^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`
	regex := regexp.MustCompile(Pattern)
	if !regex.MatchString(Newemail) {
		errMsg.EmailError = "Enter a valid Email"
		c.HTML(http.StatusBadRequest, "login.html", errMsg)
		return
	}

	if NewPassword == "" {
		errMsg.PasswordError = "Password should not be empty"
		c.HTML(http.StatusBadRequest, "login.html", errMsg)
		return
	}

	var compare models.Compare
	fmt.Println(NewPassword, Newemail, "New login details")
	if err := database.Db.Raw("select username,role,password from users where email =$1", Newemail).Scan(&compare).Error; err != nil {
		fmt.Println(err)
		c.HTML(http.StatusBadRequest, "login.html", nil)
		return
	}

	// Compare the hashedpass

	err := bcrypt.CompareHashAndPassword([]byte(compare.Password), []byte(NewPassword))
	if err != nil {
		errMsg.PasswordError = "Check password again"
		c.HTML(http.StatusUnauthorized, "login.html", errMsg)

	}
	// fmt.Println(compare)

	if compare.Role == "user" {
		user := models.User{
			Role:     compare.Role,
			Username: compare.Username,
		}
		fmt.Println("Its User....")
		jwt.CreateToken(user, c)
		c.Redirect(http.StatusFound, "/home")
		return
	} else if compare.Role == "admin" {
		fmt.Println("Its Admin....")
		user := models.User{
			Role:     compare.Role,
			Username: compare.Username,
		}
		jwt.CreateToken(user, c)
		c.Redirect(http.StatusFound, "/admin")
		return
	}
}

func HomeHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")

	ok := middleware.ValidateCookies(c)
	role, User, _ := middleware.FindRole(c)
	// fmt.Print(ok, "\n", "user is...", User, "ROle is..", role)
	if !ok {
		c.HTML(http.StatusOK, "login.html", nil)
	} else {
		if role == "user" {
			c.HTML(http.StatusAccepted, "userhome.html", gin.H{"Username": User})
			return
		} else {
			c.Redirect(http.StatusFound, "/")
			return
		}
	}

}

func LogoutHandler(c *gin.Context) {

	middleware.DeleteCookie(c)
	c.Redirect(http.StatusFound, "/")

}
