package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/woonmapao/golang-jwt-mongo/controllers"
	"github.com/woonmapao/golang-jwt-mongo/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:user_id", controllers.GetUser())
}
