package handlers

import (
	database "admin/Database"
	"admin/middleware"
	"admin/models"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AdminResponse struct {
	Name    string
	Users   []models.UserDetails
	Invalid models.Invalid
}

var errMsg models.Invalid

func AdminSignupHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")

	//validate cookie
	ok := middleware.ValidateCookies(c)
	if !ok {
		c.HTML(http.StatusOK, "adminsignup.html", nil)
		return
	}
	c.Redirect(http.StatusFound, "/")

}

func AdminSignupPost(c *gin.Context) {
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
		c.HTML(http.StatusBadRequest, "adminsignup.html", errMsg)
		return
	}
	if userEmail == "" {
		errMsg.EmailError = "Email should not be empty"
		c.HTML(http.StatusBadRequest, "adminsignup.html", errMsg)
		return
	}

	Pattern := `^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`
	regex := regexp.MustCompile(Pattern)
	if !regex.MatchString(userEmail) {
		errMsg.EmailError = "Enter a valid Email"
		c.HTML(http.StatusBadRequest, "adminsignup.html", errMsg)
		return
	}
	userPassword := c.PostForm("Password")
	if userPassword == "" {
		errMsg.PasswordError = "Password should not be empty"
		c.HTML(http.StatusBadRequest, "adminsignup.html", errMsg)
		return
	}
	userConfirmPassword := c.PostForm("ConfirmPassword")
	if userConfirmPassword != userPassword {
		errMsg.ConfirmPasswordError = "Those passwords didn't match. Try again."
		c.HTML(http.StatusBadRequest, "adminsignup.html", errMsg)
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
		c.HTML(http.StatusOK, "adminsignup.html", nil)
		return
	}
	if count > 0 {
		errMsg.EmailError = "User already exists"
		c.HTML(http.StatusBadRequest, "adminsignup.html", errMsg)
		return
	}

	//Insert into database
	role := "admin"
	database.Db.Exec("insert into users(username,email,password,role) VALUES($1,$2,$3,$4)", userName, userEmail, hashedPass, role)
	if err != nil {
		fmt.Println(err)
		c.HTML(http.StatusOK, "adminsignup.html", nil)
		return
	}

	c.Redirect(http.StatusFound, "/")

}

func AdminHome(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")

	ok := middleware.ValidateCookies(c)
	if !ok {
		c.HTML(http.StatusOK, "login.html", nil)
	}
	role, name, err := middleware.FindRole(c)
	if err != nil {
		fmt.Println(err)
	}
	if role != "admin" {
		c.Redirect(http.StatusFound, "/")
		return
	}

	var Collect []models.UserDetails

	if err := database.Db.Raw("select username, email from users").Scan(&Collect).Error; err != nil {
		fmt.Println("Couldnt fetch User details")
	}
	fmt.Println(Collect)

	c.HTML(http.StatusOK, "adminhome.html", gin.H{
		"title": AdminResponse{
			Name:    name,
			Users:   Collect,
			Invalid: errMsg,
		},
	})

}

func AdminAddUser(c *gin.Context) {

	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")
	ok := middleware.ValidateCookies(c)
	role, _, _ := middleware.FindRole(c)
	if !ok || role != "admin" {
		c.HTML(http.StatusOK, "login.html", nil)
	}

	userName := c.Request.FormValue("Name")
	userEmail := c.Request.FormValue("Email")
	userPassword := c.Request.FormValue("Password")

	errMsg.NameError = ""
	errMsg.EmailError = ""
	errMsg.PasswordError = ""
	errMsg.CommonError = ""

	if userName == "" {
		errMsg.EmailError = ""
		errMsg.PasswordError = ""
		errMsg.CommonError = ""
		errMsg.NameError = "Username should not be empty"
		c.Redirect(http.StatusFound, "/admin")
		return
	} else if userEmail == "" {
		errMsg.NameError = ""
		errMsg.PasswordError = ""
		errMsg.CommonError = ""
		errMsg.EmailError = "Email should not be empty"
		c.Redirect(http.StatusFound, "/admin")
		return
	} else if userPassword == "" {
		errMsg.NameError = ""
		errMsg.EmailError = ""
		errMsg.CommonError = ""
		errMsg.PasswordError = "Password should not be empty"
		c.Redirect(http.StatusFound, "/admin")
		return
	}

	pattern := `^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`
	regex := regexp.MustCompile(pattern)
	if !regex.MatchString(userEmail) {
		errMsg.EmailError = "Enter a valid Email"
		c.Redirect(http.StatusFound, "/admin")
		return
	}
	// hash pass
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(userPassword), 10)
	if err != nil {
		fmt.Println("Error Hashing Password")
		return
	}
	fmt.Println(hashedPass, "hash")
	// check if user exists
	var count int
	if err := database.Db.Raw("SELECT COUNT(*) FROM users WHERE email=$1", userEmail).Scan(&count).Error; err != nil {
		fmt.Println(err)
		c.Redirect(http.StatusFound, "/admin")
		return
	}

	if count > 0 {
		errMsg.CommonError = "user already exists"
		c.Redirect(http.StatusFound, "/admin")
		return
	}

	var userRole string
	if c.Request.FormValue("checkbox") == "on" {
		userRole = "admin"
	} else {
		userRole = "user"
	}

	if err := database.Db.Exec("INSERT INTO users (username,role,email,password) VALUES($1,$2,$3,$4)", userName, userRole, userEmail, hashedPass).Error; err != nil {
		fmt.Println(err)
		c.Redirect(http.StatusFound, "/admin")
		return
	}
	c.Redirect(http.StatusFound, "/admin")

}

func UpdateUsername(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")
	ok := middleware.ValidateCookies(c)
	if !ok {
		c.HTML(http.StatusOK, "login.html", nil)
	}
	username := c.Query("Username")
	email := c.Query("Email")
	fmt.Println(username, "namee")
	c.HTML(http.StatusOK, "updateuser.html", gin.H{
		"Username": username,
		"Email":    email,
	})
}

func UpdateUsernamePost(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")
	fmt.Println("Update handler........#####################")
	ok := middleware.ValidateCookies(c)
	if !ok {
		c.HTML(http.StatusOK, "login.html", nil)
	}

	email := c.Query("Email")
	fmt.Println(email, "new email")
	userName := c.Request.FormValue("Name")
	fmt.Println(userName, "new name")
	err := database.Db.Exec("UPDATE users SET username=$1 where email=$2", userName, email).Error
	if err != nil {
		fmt.Println(err)
	}
	c.Redirect(http.StatusFound, "/admin")

}

func AdminDeleteUser(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")
	ok := middleware.ValidateCookies(c)
	role, _, _ := middleware.FindRole(c)
	if !ok || role == "users" {
		c.HTML(http.StatusOK, "login", nil)
	}
	email := c.Query("Email")
	if err := database.Db.Exec("DELETE from users where email = ?", email).Error; err != nil {
		fmt.Println(err, "Could not fetch user details")
	}
	c.Redirect(http.StatusFound, "/admin")
}

func LogoutadminHandler(c *gin.Context) {
	middleware.DeleteCookie(c)
	c.Redirect(http.StatusFound, "/")
}
