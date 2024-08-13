package handlers

import (
	database "apiMedods/db"
	"apiMedods/models"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"
)

func Auth(c *gin.Context) {
	var body struct {
		Id string `json:"id"`
	}
	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", body.Id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found",
		})
		return
	}

	accesstoken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Minute * 20).Unix(),
		"ip":  user.IPAddress,
	})
	accessTokenString, err := accesstoken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	refreshToken, err := GenerateUniqueToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
		return
	}

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash refresh token"})
		return
	}

	refreshTokenEntry := models.RefreshToken{
		UserID:    user.ID,
		TokenHash: string(refreshTokenHash),
		IPAddress: user.IPAddress,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := database.DB.Create(&refreshTokenEntry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenString,
		"refresh_token": refreshToken,
	})
}

func Refresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
		UserID       string `json:"user_id"`
	}

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	log.Println("Received refresh token:", body.RefreshToken)

	var refreshTokenEntry models.RefreshToken
	if err := database.DB.First(&refreshTokenEntry, "user_id = ? AND expires_at > ?", body.UserID, time.Now()).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token or token expired"})
		return
	}

	log.Println("Stored hash in DB:", refreshTokenEntry.TokenHash)

	// Я не смог нормально сравнить токен и хэш, или не понял что нужно сравнить если храним мы только рефреш токен в виде хэша(
	// поскольку запись в хэш всегда уникальна, я не могу пройти дальше этого этапа...
	//никогда раньше не рефрешил токены(
	err := bcrypt.CompareHashAndPassword([]byte(refreshTokenEntry.TokenHash), []byte(body.RefreshToken))
	if err != nil {
		log.Println("Error comparing token with hash:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	clientIP := c.ClientIP()
	if clientIP != refreshTokenEntry.IPAddress {
		var user models.User
		if err := database.DB.First(&user, "id = ?", refreshTokenEntry.UserID).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
			return
		}

		if err := SendWarnMail(user.Email); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send warning email"})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "IP address changed"})
		return
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": refreshTokenEntry.UserID,
		"exp": time.Now().Add(time.Minute * 20).Unix(),
		"ip":  refreshTokenEntry.IPAddress,
	})

	newAccessTokenString, err := newAccessToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create new access token"})
		return
	}

	newRefreshToken, err := GenerateUniqueToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create new refresh token"})
		return
	}
	newRefreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new refresh token"})
		return
	}

	refreshTokenEntry.TokenHash = string(newRefreshTokenHash)
	refreshTokenEntry.IPAddress = clientIP
	refreshTokenEntry.CreatedAt = time.Now()
	refreshTokenEntry.ExpiresAt = time.Now().Add(24 * time.Hour)
	if err := database.DB.Save(&refreshTokenEntry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save new refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessTokenString,
		"refresh_token": newRefreshToken,
	})
}

// по хорошему встроить брокер
func SendWarnMail(email string) error {
	auth := smtp.PlainAuth(
		"",
		"rtimosenko16@gmail.com",
		"iyqlxhboecukpoko",
		"smtp.gmail.com")

	subject := "Strange activity"
	body := "There is suspicious activity on your account!!!"
	msg := fmt.Sprintf("Subject: %s\n\n%s", subject, body)

	err := smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"rtimosenko16@gmail.com",
		[]string{email},
		[]byte(msg),
	)

	return err
}

func GenerateUniqueToken() (string, error) {
	tokenInBytes := make([]byte, 32)
	if _, err := rand.Read(tokenInBytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(tokenInBytes), nil
}
