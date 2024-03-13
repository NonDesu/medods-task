package tokens

import (
	"context"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("secretkey")

type User struct {
	GUID         string `bson:"_id"`
	RefreshToken string
}

func randomHex() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func NewAccessToken(userID string, pair string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["guid"] = userID
	claims["issued"] = time.Now().Unix()
	claims["pair"] = pair

	t, err := token.SignedString(jwtKey)
	if err != nil {
		panic(err)
	}
	return t
}

func NewRefreshToken(pair string) string {
	t := pair + strconv.FormatInt(time.Now().Unix(), 10)

	return t
}

func NewTokens(userID string, coll *mongo.Collection) (string, string) {

	pair := randomHex()
	accessToken := NewAccessToken(userID, pair)
	refreshToken := NewRefreshToken(pair)
	refreshTokenEnc := b64.URLEncoding.EncodeToString([]byte(refreshToken))

	refreshTokenHashed, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	filter := bson.D{{"_id", userID}}
	update := bson.D{{"$set", bson.D{{"_id", userID}, {"refreshtoken", string(refreshTokenHashed)}}}}
	opts := options.Update().SetUpsert(true)
	result, err := coll.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		panic(err)
	}
	fmt.Println(result)

	return accessToken, refreshTokenEnc
}

func TokenParser(tokenString string) *jwt.Token {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		panic(err)
	}

	return token
}

func RenewTokens(inputAccessToken string, inputRefreshTokenEnc string, coll *mongo.Collection) (string, string) {
	accessClaims := TokenParser(inputAccessToken).Claims.(jwt.MapClaims)
	inputRefreshTokenDec, _ := b64.URLEncoding.DecodeString(inputRefreshTokenEnc)

	if accessClaims["pair"] != string(inputRefreshTokenDec)[:32] {
		fmt.Println("Token mismatch")
		return inputAccessToken, inputRefreshTokenEnc
	}

	filter := bson.D{{"_id", accessClaims["guid"]}}
	var result User
	coll.FindOne(context.TODO(), filter).Decode(&result)
	err := bcrypt.CompareHashAndPassword([]byte(result.RefreshToken), inputRefreshTokenDec)

	if err != nil {
		fmt.Println("Bad or expired token")
		return inputAccessToken, inputRefreshTokenEnc
	}

	fmt.Println(accessClaims["pair"], string(inputRefreshTokenDec))
	return NewTokens(result.GUID, coll)
}
