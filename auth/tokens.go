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

// Секретный ключ
var jwtKey = []byte("secretkey")

type User struct {
	GUID         string `bson:"_id"`
	RefreshToken string
}

// randomHex возвращает случайную строку длинной 32 символа
func randomHex() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

// Возвращает новый подписанный Access токен
func NewAccessToken(userID string, pair string) string {
	token := jwt.New(jwt.SigningMethodHS256) //Формирование нового токена
	claims := token.Claims.(jwt.MapClaims)
	claims["guid"] = userID //Заполнение полей
	claims["issued"] = time.Now().Unix()
	claims["pair"] = pair

	t, err := token.SignedString(jwtKey) //Подпись токена
	if err != nil {
		panic(err)
	}
	return t
}

// Возвращает Refresh токен, сформированный из парной с Access токеном случайной строки и времени создания, преобразованного в строку
func NewRefreshToken(pair string) string {
	t := pair + strconv.FormatInt(time.Now().Unix(), 10)

	return t
}

// Возвращает пару Access и Refresh токенов, добавляет хеш Refresh токен в БД
// Возвращаемый Refresh токен закодирован в base64
func NewTokens(userID string, coll *mongo.Collection) (string, string) {

	pair := randomHex()                                                     //Новая случайная строка для связи токенов
	accessToken := NewAccessToken(userID, pair)                             //Новый Access токен
	refreshToken := NewRefreshToken(pair)                                   //Новый Refresh токен
	refreshTokenEnc := b64.URLEncoding.EncodeToString([]byte(refreshToken)) //кодировка Refresh токена в base64

	refreshTokenHashed, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)    //хеширование Refresh токена
	filter := bson.D{{"_id", userID}}                                                                 //Фильтр для поиска в БД
	update := bson.D{{"$set", bson.D{{"_id", userID}, {"refreshtoken", string(refreshTokenHashed)}}}} //Обновляемые значения в БД
	opts := options.Update().SetUpsert(true)                                                          //
	result, err := coll.UpdateOne(context.TODO(), filter, update, opts)                               //Обновление или добавление значений в БД
	if err != nil {
		panic(err)
	}
	fmt.Println(result)

	return accessToken, refreshTokenEnc
}

// Формирует и возвращает Access токен из подписанной строки
func TokenParser(tokenString string) *jwt.Token {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { //Проверка алгоритма подписи
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		panic(err)
	}

	return token
}

// Возвращает новую пару токенов, выполнив проверки, иначе возвращает старую пару
func RenewTokens(inputAccessToken string, inputRefreshTokenEnc string, coll *mongo.Collection) (string, string) {
	accessClaims := TokenParser(inputAccessToken).Claims.(jwt.MapClaims)          //Обработка Access токена
	inputRefreshTokenDec, _ := b64.URLEncoding.DecodeString(inputRefreshTokenEnc) //Расшифровка Refresh токена

	if accessClaims["pair"] != string(inputRefreshTokenDec)[:32] { //Сравнение парных строк токенов
		fmt.Println("Token mismatch")
		return inputAccessToken, inputRefreshTokenEnc
	}

	filter := bson.D{{"_id", accessClaims["guid"]}}
	var result User
	coll.FindOne(context.TODO(), filter).Decode(&result)
	err := bcrypt.CompareHashAndPassword([]byte(result.RefreshToken), inputRefreshTokenDec) //Сравнение refresh токена с хешем в БД
	if err != nil {
		fmt.Println("Bad or expired token")
		return inputAccessToken, inputRefreshTokenEnc
	}

	fmt.Println(accessClaims["pair"], string(inputRefreshTokenDec))
	return NewTokens(result.GUID, coll)
}
