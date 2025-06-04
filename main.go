package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"
	"veritas/config"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return string(bytes), err
}

func Authenticate(user string, rawpass string) bool {
	config.InitDB()

	var password string

	// Search for the username
	err := config.DB.QueryRow(context.Background(),
		"SELECT password FROM users WHERE username = $1", user).Scan(&password)

	if err != nil {
		if err == pgx.ErrNoRows {
			return false
		} else {
			log.Panic(err)
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(rawpass))
	if err != nil {
		return false
	} else {
		return true
	}

}

func Register(username string, password string) error {
	config.InitDB()

	_, err := config.DB.Exec(context.Background(),
		"INSERT INTO users (username, password) VALUES ($1, $2)", username, password)
	if err != nil {
		return err
	}

	return nil
}

func AuthAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("AccessToken")

		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, "/service/refresh")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		if tokenString == "" {
			c.Redirect(http.StatusTemporaryRedirect, "/service/refresh")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		claims, err := config.TokenAuthenticate(tokenString)
		if claims == nil {
			c.Redirect(http.StatusTemporaryRedirect, "/service/refresh")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, "/service/refresh")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if claims.TokenType != "access" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

func AuthRefresh() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("RefreshToken")

		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		claims, err := config.TokenAuthenticate(tokenString)
		if claims == nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if claims.TokenType != "refresh" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

func main() {

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://servidordomal.fun", "*://31.97.20.160"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))
	r.POST("/service/login", func(c *gin.Context) {

		var req LoginRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"response": "badrequest"})
			return
		}

		value := Authenticate(req.Username, req.Password)

		if value == true {
			token, err := config.GenerateJWTAccessToken(req.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"response": "failed to generate tokens"})
				return
			}
			refresh, err := config.GenerateJWTRefreshToken(req.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"response": "failed to generate tokens"})
				return
			}

			http.SetCookie(c.Writer, &http.Cookie{
				Name:     "AccessToken",
				Value:    token,
				MaxAge:   900,
				Path:     "/",
				Domain:   "servidordomal.fun",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})

			http.SetCookie(c.Writer, &http.Cookie{
				Name:     "RefreshToken",
				Value:    refresh,
				MaxAge:   345600,
				Path:     "/",
				Domain:   "servidordomal.fun",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})

			c.Status(http.StatusOK)
			return
		}
		if value == false {
			c.Status(http.StatusUnauthorized)
			return
		}

	})

	r.POST("/service/register", func(c *gin.Context) {

		var req LoginRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		if strings.ContainsAny(req.Username, " ") || strings.ContainsAny(req.Password, " ") || req.Password == "" || req.Username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"response": "invalid username or password"})
			return
		}

		password, _ := HashPassword(req.Password)

		err := Register(req.Username, password)
		if err != nil {
			c.JSON(http.StatusConflict, gin.H{"response": "username alredy been taken"})
			return
		} else {
			c.Status(http.StatusCreated)
			return
		}

	})

	r.GET("/service/validate", AuthAccess(), func(c *gin.Context) {

		c.JSON(http.StatusOK, gin.H{"response": c.MustGet("username").(string)})
	})

	r.GET("/service/refresh", AuthRefresh(), func(c *gin.Context) {

		username := c.MustGet("username").(string)

		token, err := config.GenerateJWTAccessToken(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"response": "error generating token"})
			return
		}
		refresh, err := config.GenerateJWTRefreshToken(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"response": "error generating refresh token"})
			return
		}

		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "AccessToken",
			Value:    token,
			MaxAge:   900,
			Path:     "/",
			Domain:   "servidordomal.fun",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "RefreshToken",
			Value:    refresh,
			MaxAge:   345600,
			Path:     "/",
			Domain:   "servidordomal.fun",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		c.Redirect(http.StatusSeeOther, "/home")

	})

	r.GET("/home", AuthAccess(), func(c *gin.Context) {
		r.LoadHTMLFiles("pages/home.html")

		username := c.MustGet("username").(string)

		c.HTML(http.StatusOK, "home.html", gin.H{"Name": username})
	})

	r.GET("/service/createRoom", AuthAccess(), func(c *gin.Context) {
		r.LoadHTMLFiles("pages/home.html")

		username := c.MustGet("username").(string)

		c.HTML(http.StatusOK, "home.html", gin.H{"Name": username})
	})

	r.Run(":8080")

}
