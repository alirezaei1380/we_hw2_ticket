package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type RegisterInput struct {
	Email       string `json:"email" binding:"required,email"`
	PhoneNumber string `json:"phone_number" binding:"required,numeric,len=11"`
	Gender      string `json:"gender" binding:"omitempty,len=1,uppercase"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"Last_name"`
	Password    string `json:"password" binding:"required"`
}

func Register(c *gin.Context) {
	var data RegisterInput
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if data.Gender != "" && data.Gender != "M" && data.Gender != "F" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid gender"})
		return
	}
	user := UserAccount{
		FirstName:      data.FirstName,
		LastName:       data.LastName,
		Gender:         data.Gender,
		Email:          data.Email,
		PhoneNumber:    data.PhoneNumber,
		HashedPassword: data.Password,
	}
	_, err := user.SaveUser()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusCreated, gin.H{"status": "succeeded"})
}

type LoginInput struct {
	Email       string `json:"email" binding:"omitempty,email"`
	PhoneNumber string `json:"phone_number" binding:"omitempty,numeric,len=11"`
	Password    string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {

	var input LoginInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Email == "" && input.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enter email or phone_number"})
		return
	}

	token, err := LoginCheck(input.Email, input.PhoneNumber, input.Password)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username or password is incorrect."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})

}

func Info(c *gin.Context) {
	userId, _, err := ExtractTokenID(c)
	if err != nil || userId == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect token"})
		return
	}
	user, err := GetUserById(userId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	authorized, err := CheckToken(ExtractToken(c))
	if !authorized {
		c.JSON(http.StatusForbidden, gin.H{"error": "user logged out"})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{
		"user_id":      user.UserId,
		"email":        user.Email,
		"phone_number": user.PhoneNumber,
		"gender":       user.Gender,
		"first_name":   user.FirstName,
		"last_name":    user.LastName,
	})
}

func Logout(c *gin.Context) {
	userId, exp, err := ExtractTokenID(c)
	if err != nil || userId == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect token"})
		return
	}
	user, err := GetUserById(userId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	authorized, err := CheckToken(ExtractToken(c))
	if !authorized {
		c.JSON(http.StatusForbidden, gin.H{"error": "user logged out"})
		return
	}
	token := UnauthorizedToken{
		Token:      ExtractToken(c),
		Expiration: exp,
		User:       user,
	}
	_, err = token.SaveUnauthorizedToken()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "successful"})
}
