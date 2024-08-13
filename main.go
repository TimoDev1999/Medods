package main

import (
	"apiMedods/db"
	env "apiMedods/envVar"
	"apiMedods/handlers"
	"github.com/gin-gonic/gin"
)

func init() {
	env.LoadEnv()
	database.ConnectDB()
}
func main() {
	r := gin.Default()
	r.POST("/auth", handlers.Auth)
	r.POST("/refresh", handlers.Refresh)
	r.Run()
}
