package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Role     string `gorm:"not null;default: user"`
	Username string
	Email    string `gorm:"not null;unique"`
	Password string
}

type Invalid struct {
	NameError            string
	EmailError           string
	PasswordError        string
	ConfirmPasswordError string
	RoleError            string
	CommonError          string
}
type Compare struct {
	Username string
	Password string
	Role     string
}

type UserDetails struct {
	UserName string `gorm:"column:username"`
	Email    string `gorm:"column:email"`
}
