package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	tokens "github.com/NonDesu/medods-task/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// "C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe" --dbpath="f:\mongo\data\db"
const uri = "mongodb://localhost:27017"

var coll *mongo.Collection

type User struct {
	GUID         string `bson:"_id"`
	RefreshToken string
}

func main() {
	//http server init
	mux := http.NewServeMux()

	mux.Handle("/auth/token", &TokenHandler{})
	mux.Handle("/auth/renew", &TokenHandler{})

	http.ListenAndServe(":8080", mux)

	//MongoDB init
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(context.TODO(), opts)

	if err != nil {
		panic(err)
	}
	defer func() {
		if err = client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()
	var result bson.M
	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Decode(&result); err != nil {
		panic(err)
	}
	fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")

	//Заполнение БД начальными данными
	coll := client.Database("testing").Collection("users")
	docs := []interface{}{
		User{GUID: "guid1000", RefreshToken: "10000000"},
		User{GUID: "guid1001"},
		User{GUID: "guid1010", RefreshToken: "10000010"},
		User{GUID: "guid1011", RefreshToken: "10000011"},
		User{GUID: "guid1100", RefreshToken: "10000100"},
	}

	coll.InsertMany(context.TODO(), docs)

	a, r := tokens.NewTokens("guid1001", coll)
	fmt.Println(a, r)

	tokens.RenewTokens(a, r, coll)

	tokens.RenewTokens(a, r, coll)

}

// REST маршруты
type TokenHandler struct{}

var (
	AuthNew   = regexp.MustCompile(`^/auth/token/*$`)
	AuthRenew = regexp.MustCompile(`^/auth/renew/*$`)
)

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && AuthNew.MatchString(r.URL.Path):
		h.GetTokens(w, r)
		return
	case r.Method == http.MethodGet && AuthRenew.MatchString(r.URL.Path):
		h.RenewTokens(w, r)
		return
	default:
		return
	}
}

type InputGuid struct {
	GUID string `json:"guid"`
}

func (h *TokenHandler) GetTokens(w http.ResponseWriter, r *http.Request) {

	var res InputGuid
	json.NewDecoder(r.Body).Decode(&res)

	accessToken, refreshToken := tokens.NewTokens(res.GUID, coll)
	rmap := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	jsonStr, err := json.Marshal(rmap)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	} else {
		fmt.Println(string(jsonStr))
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonStr)
}

type InputTokens struct {
	Access_Token  string `json:"access_token"`
	Refresh_Token string `json:"refresh_token"`
}

func (h *TokenHandler) RenewTokens(w http.ResponseWriter, r *http.Request) {

	var res InputTokens
	json.NewDecoder(r.Body).Decode(&res)

	accessToken, refreshToken := tokens.RenewTokens(res.Access_Token, res.Refresh_Token, coll)
	rmap := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	jsonStr, err := json.Marshal(rmap)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	} else {
		fmt.Println(string(jsonStr))
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonStr)
}

/*
func InternalServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("500 Internal Server Error"))
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 Not Found"))
}
*/
