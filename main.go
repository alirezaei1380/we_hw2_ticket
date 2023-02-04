package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	ConnectDataBase()
	router := gin.Default()
	router.POST("/register", Register)
	router.POST("/login", Login)
	router.GET("/info", Info)
	router.GET("/logout", Logout)
	router.Run("localhost:8080")
}
