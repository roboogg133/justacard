package config

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

var Dsn string
var DB *pgxpool.Pool
var Pass string

type Claims struct {
	Username  string `json:"username"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func InitDB() {

	godotenv.Load()

	var host = os.Getenv("DB_HOST")
	var port = os.Getenv("DB_PORT")
	var user = os.Getenv("DB_USER")
	var passwordnotgood = os.Getenv("DB_PASSWORD")
	var dbname = os.Getenv("DB_NAME")

	var password = url.QueryEscape(passwordnotgood)

	var Dsn = fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, password, host, port, dbname)

	dbpool, err := pgxpool.New(context.Background(), Dsn)
	if err != nil {
		log.Panic("Error connecting to DATABASE : ", err)
	}

	err = dbpool.Ping(context.Background())
	if err != nil {
		log.Panic("Database isn't reachable : ", err)
	}

	DB = dbpool

}

func GenerateJWTAccessToken(username string) (string, error) {

	godotenv.Load()

	var Secret = []byte(Pass)
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &Claims{
		Username:  username,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(Secret)

}

func TokenAuthenticate(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(Pass), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

func GenerateJWTRefreshToken(username string) (string, error) {

	godotenv.Load()

	var Secret = []byte(Pass)
	expirationTime := time.Now().Add(168 * time.Hour)

	claims := &Claims{
		Username:  username,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(Secret)

}
