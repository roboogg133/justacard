package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"veritas/config"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Game struct {
	Id         string   `json:"id"`
	Status     string   `json:"status"`
	MatchType  string   `json:"matchType"`
	Owner      string   `json:"owner"`
	Players    []string `json:"players"`
	Many       int      `json:"many"`
	MaxPlayers int      `json:"maxPlayers"`
	Winner     string   `json:"winner"`
}

type GameCreate struct {
	MatchType  string `json:"matchType"`
	MaxPlayers int    `json:"maxPlayers"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return string(bytes), err
}

var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
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
			return
		}

		if tokenString == "" {
			c.Redirect(http.StatusTemporaryRedirect, "/service/refresh")
			return
		}

		claims, err := config.TokenAuthenticate(tokenString)
		if claims == nil {
			c.Redirect(http.StatusTemporaryRedirect, "/service/refresh")
			return
		}
		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, "/service/refresh")
			return
		}
		if claims.TokenType != "access" {
			return
		}

		var revoke time.Time

		err = config.DB.QueryRow(context.Background(),
			"SELECT revoke FROM users WHERE username = $1", claims.Username).Scan(&revoke)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims.IssuedAt.Time.UTC().Before(revoke) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		log.Printf("%s\n", claims.IssuedAt.Time.UTC())
		log.Printf("Access token authenticated for user: %s", claims.Username)

		c.Set("username", claims.Username)
		c.Next()
	}
}

func AuthRefresh() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("RefreshToken")

		if err != nil {
			c.Redirect(http.StatusSeeOther, "/service/login")
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

		var revoke time.Time

		err = config.DB.QueryRow(context.Background(),
			"SELECT revoke FROM users WHERE username = $1", claims.Username).Scan(&revoke)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		if claims.IssuedAt.Time.UTC().Before(revoke) {
			c.AbortWithStatus(http.StatusUnauthorized)
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
			c.Status(http.StatusBadRequest)
			return
		}

		value := Authenticate(req.Username, req.Password)

		if value {
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
		if !value {
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

		if strings.ContainsAny(req.Username, " ") || strings.ContainsAny(req.Password, " ") || req.Password == "" || req.Username == "" || len(req.Username) > 20 || len(req.Username) < 2 {
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

	r.GET("/service/refresh", AuthRefresh(), func(c *gin.Context) {
		lastPage := c.Request.Referer()
		if lastPage == "" {
			lastPage = "/"
		}
		c.Header("Location", lastPage)

		usernameRaw, exists := c.Get("username")

		username := usernameRaw.(string)

		if !exists {
			log.Println("Username not found")
			c.Redirect(http.StatusSeeOther, "/home/refresh")
			return
		}

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

		c.Status(http.StatusSeeOther)

	})

	r.GET("/home/", AuthAccess(), func(c *gin.Context) {
		r.LoadHTMLFiles("pages/home.html")

		usernameRaw, exists := c.Get("username")

		username := usernameRaw.(string)

		if !exists {
			log.Println("Username not found")
			c.Redirect(http.StatusSeeOther, "/home/")
			return
		}

		c.HTML(http.StatusOK, "home.html", gin.H{"Name": username})

	})

	r.POST("/service/createRoom", AuthAccess(), func(c *gin.Context) {

		// Creating the room

		usernameFuck, exist := c.Get("username")
		if !exist {
			c.Redirect(http.StatusSeeOther, "/service/createRoom")
			return
		}
		username := usernameFuck.(string)

		var req_game GameCreate

		if err := c.ShouldBindJSON(&req_game); err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		if req_game.MatchType != "Casual" || req_game.MaxPlayers < 2 {
			c.Status(http.StatusBadRequest)
			return
		} else if req_game.MatchType != "Ranked" {
			c.Status(http.StatusBadRequest)
			return
		} else if req_game.MatchType != "Private" {
			c.Status(http.StatusBadRequest)
			return
		}

		id, err := gonanoid.Generate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 9)
		if err != nil {
			log.Printf("error: %s", err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

		game := Game{
			Id:         id,
			Status:     "open",
			MatchType:  req_game.MatchType,
			MaxPlayers: req_game.MaxPlayers,
			Players:    []string{},
			Owner:      username,
			Many:       1,
			Winner:     "no one",
		}
		config.InitDB()

		_, err = config.DB.Exec(context.Background(),
			"INSERT INTO games (id, owner, status, matchType, players, many, winner, maxPlayers) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", game.Id, game.Owner, game.Status, game.MatchType, game.Players, game.Many, game.Winner, game.MaxPlayers)

		if err != nil {
			log.Printf("error: %s", err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

		c.JSON(http.StatusCreated, gin.H{"id": id})

		// room addded on database

		//	r.LoadHTMLFiles("pages/home.html")

		//		c.HTML(http.StatusOK, "home.html", gin.H{"Name": username})

	})

	r.GET("/play/:id", AuthAccess(), func(c *gin.Context) {

		id := c.Param("id")

		if id == "" {
			c.Redirect(http.StatusTemporaryRedirect, "/home")
			return
		}

		config.InitDB()

		var roomID string

		err := config.DB.QueryRow(context.Background(),
			"SELECT id FROM games WHERE id = $1", id).Scan(&roomID)

		if err != nil {
			log.Printf("error: %s", err.Error())
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		r.LoadHTMLFiles("pages/home.html")

		usernameRaw, exists := c.Get("username")

		username := usernameRaw.(string)

		if !exists {
			log.Println("Username not found")
			c.Redirect(http.StatusSeeOther, fmt.Sprintf("/home/%s", id))
			return
		}

		c.HTML(http.StatusOK, "home.html", gin.H{"Name": username})

	})

	r.GET("/service/game/:id", AuthAccess(), func(c *gin.Context) {

		id := c.Param("id")

		if id == "" {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		config.InitDB()

		var roomID string

		err := config.DB.QueryRow(context.Background(),
			"SELECT id FROM games WHERE id = $1", id).Scan(&roomID)

		if err != nil {
			log.Printf("error: %s", err.Error())
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		conn, err := Upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %s", err.Error())
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		log.Println("New connection established")

		value, exists := c.Get("username")
		if !exists {
			log.Println("Username not found")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		config.InitDB()

		_, err = config.DB.Exec(context.Background(),
			"INSERT INTO games (players) VALUES ($1) WHERE games = $2", value, id)

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("error: %s", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			log.Println(msg)

			// Process the message
			// ...

		}

	})

	r.Run(":8080")

}
