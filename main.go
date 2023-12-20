package main

import (
	database "admin/Database"
	"admin/handlers"
	"admin/models"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	fmt.Println("asdfsd")
	err := godotenv.Load(".env")

	if err != nil {
		fmt.Println("error loading .env file")
	}
	router := gin.New()
	dsn := os.Getenv("DB")
	database.Db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("error loading database...")
	}

	database.Db.AutoMigrate(&models.User{})
	router.LoadHTMLGlob("templates/*.html")
	router.Static("/static", "./static")

	//loginhandlers
	router.GET("/", handlers.LoginHandler)
	router.POST("/", handlers.LoginPost)
	// user
	router.GET("/usersignup", handlers.UserSignupHandler)
	router.POST("/usersignup", handlers.UserSignupPost)
	router.GET("/home", handlers.HomeHandler)
	router.GET("/logout", handlers.LogoutHandler)

	// admin
	router.GET("/adminsignup", handlers.AdminSignupHandler)
	router.POST("/adminsignup", handlers.AdminSignupPost)
	router.GET("/admin", handlers.AdminHome)
	router.POST("/admin", handlers.AdminAddUser)
	router.GET("/logoutadmin", handlers.LogoutadminHandler)
	router.GET("/usernameupdate", handlers.UpdateUsername)
	router.POST("/usernameupdate", handlers.UpdateUsernamePost)
	router.GET("/admindelete", handlers.AdminDeleteUser)

	//Run server........
	router.Run()
}
