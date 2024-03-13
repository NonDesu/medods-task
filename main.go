package main

import (
	"context"
	"fmt"

	tokens "github.com/NonDesu/medods-task/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// "C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe" --dbpath="f:\mongo\data\db"
const uri = "mongodb://localhost:27017"

type User struct {
	GUID         string `bson:"_id"`
	RefreshToken string
}

func main() {
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
