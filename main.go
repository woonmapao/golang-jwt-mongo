package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/woonmapao/golang-jwt-mongo/routes"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r := gin.Default()

	routes.AuthRoutes(r)
	routes.UserRoutes(r)

	r.GET("/api-1", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": "Access granted for api-1",
		})
	})

	r.GET("api-2", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": "Access granted for api-2",
		})
	})

	r.Run(":" + port)

}
