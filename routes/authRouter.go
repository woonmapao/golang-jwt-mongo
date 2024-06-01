package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/woonmapao/golang-jwt-mongo/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/users/signup", controllers.SignUp())
	incomingRoutes.POST("/users/login", controllers.Login())
}
