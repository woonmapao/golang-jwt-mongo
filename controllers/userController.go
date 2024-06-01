package controllers

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/woonmapao/golang-jwt-mongo/database"
	"github.com/woonmapao/golang-jwt-mongo/helpers"
	"github.com/woonmapao/golang-jwt-mongo/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	bsp, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Panic(err)
	}
	return string(bsp)
}

func VerifyPassword(userPassword, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = "email or password is incorrect"
		check = false
	}
	return check, msg
}

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Context with a timeout to handle request deadline
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User

		// Bind the JSON payload to the user model
		err := c.BindJSON(&user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Validate the user struct
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": validationErr.Error(),
			})
			return
		}

		// Check if email already exist
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "error occur while checking for the email",
			})
			return
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "this email of phone number already existed",
			})
			return
		}

		// Hash the password
		password := HashPassword(*user.Password)
		user.Password = &password

		// Check if phone number already exists
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "error occur while checking for the phone number",
			})
			return
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "this email of phone number already existed",
			})
			return
		}

		// Set creation and update timestamps
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		// Generate a new objectID for the user
		user.ID = primitive.NewObjectID()
		user.UserID = user.ID.Hex()

		// Generate JWT tokens for the user
		token, refreshToken, _ := helpers.GenerateAllTokens(
			*user.Email, *user.FirstName, *user.LastName, *user.UserType, user.UserID,
		)
		user.Token = &token
		user.RefreshToken = &refreshToken

		// Insert the new user document into the collection
		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := "User item was not created"
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": msg,
			})
			return
		}

		//Respond with the result of the insertion
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Context with a timeout to handle request deadline
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		var foundUser models.User

		// Bind the JSON payload to the user model
		err := c.BindJSON(&user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		err = userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "email or password is not correct",
			})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": msg,
			})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "user not found",
			})
			return
		}
		token, refreshToken, _ := helpers.GenerateAllTokens(
			*foundUser.Email, *foundUser.FirstName, *foundUser.LastName, *foundUser.UserType, foundUser.UserID,
		)
		helpers.UpdateAllTokens(token, refreshToken, foundUser.UserID)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.UserID}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := helpers.CheckUserType(c, "ADMIN")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		page, err := strconv.Atoi(c.Query("page"))
		if err != nil || page < 1 {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		startIndexQuery := c.Query("startIndex")
		if startIndexQuery != "" {
			startIndex, err = strconv.Atoi(startIndexQuery)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "invalid startIndex query parameter",
				})
				return
			}
		}

		// Define the match stage to filter documents (empty filter in this case).
		matchStage := bson.D{{Key: "$match", Value: bson.D{}}}

		// Define the group stage to aggregate data.
		groupStage := bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "null"},                                   // Group all documents together.
				{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},  // Count the total number of documents.
				{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}, // Collect the entire documents into an array.
			}},
		}

		// Define the project stage to shape the final output.
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},         // Exclude the _id field from the output.
				{Key: "total_count", Value: 1}, // Include the total_count field.
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}}, // Paginate the data array.
			}},
		}

		// Run the aggregation pipeline
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage,
		})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "error occur while listing user items",
			})
			return
		}

		// Parse the result into a slice of users
		var allUsers []bson.M
		err = result.All(ctx, &allUsers)
		if err != nil {
			log.Fatal(err)
		}

		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		err := helpers.MatchUserTypeToUid(c, userId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err = userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, user)

	}
}
