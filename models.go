package main

import (
	"context"
	"fmt"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"os"
)

type UnauthorizedToken struct {
	gorm.Model
	User       UserAccount `gorm:"foreignKey:UserId;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"user"`
	UserId     uint        `json:"user_id"`
	Token      string      `gorm:"size:255;not null;" json:"token"`
	Expiration int64       `gorm:"not null;" json:"expiration"`
}

type UserAccount struct {
	gorm.Model
	UserId         uint   `gorm:"primaryKey;autoIncrement;" json:"user_id"`
	Email          string `gorm:"size:255;not null;" json:"email"`
	PhoneNumber    string `gorm:"size:15;not null;" json:"phone_number"`
	Gender         string `gorm:"size:1;not null;" json:"gender"`
	FirstName      string `gorm:"size:255;" json:"first_name"`
	LastName       string `gorm:"size:255;" json:"last_name"`
	HashedPassword string `gorm:"size:127;not null;" json:"hashed_password"`
}

var DB *gorm.DB
var rdb *redis.Client
var ctx context.Context

func ConnectDataBase() {

	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	Dbdriver := os.Getenv("DB_DRIVER")
	DbHost := os.Getenv("DB_HOST")
	DbUser := os.Getenv("DB_USER")
	DbPassword := os.Getenv("DB_PASSWORD")
	DbName := os.Getenv("DB_NAME")
	DbPort := os.Getenv("DB_PORT")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Tehran", DbHost, DbUser, DbPassword, DbName, DbPort)
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		fmt.Println("Cannot connect to database ", Dbdriver)
		log.Fatal("connection error:", err)
	} else {
		fmt.Println("We are connected to the database ", Dbdriver)
	}

	DB.AutoMigrate(&UserAccount{})
	DB.AutoMigrate(&UnauthorizedToken{})

	ctx = context.Background()
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URL"),
		Password: "", // no password set
		DB:       0,  // use default DB
	})

}

func (u *UserAccount) SaveUser() (*UserAccount, error) {

	var err error
	err = DB.Create(&u).Error
	if err != nil {
		return &UserAccount{}, err
	}
	return u, nil
}

func (t *UnauthorizedToken) SaveUnauthorizedToken() (*UnauthorizedToken, error) {

	var err error
	err = DB.Create(&t).Error
	if err != nil {
		return &UnauthorizedToken{}, err
	}
	return t, nil
}

func (u *UserAccount) BeforeSave(db *gorm.DB) error {

	//turn password into hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.HashedPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.HashedPassword = string(hashedPassword)

	return nil
}

func VerifyPassword(password, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func LoginCheck(Email string, PhoneNumber string, password string) (string, error) {

	var err error

	u := UserAccount{}

	if Email != "" {
		err = DB.Model(UserAccount{}).Where("email = ?", Email).Take(&u).Error
	} else {
		err = DB.Model(UserAccount{}).Where("phone_number = ?", PhoneNumber).Take(&u).Error
	}

	if err != nil {
		return "", err
	}

	err = VerifyPassword(password, u.HashedPassword)

	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return "", err
	}

	token, err := GenerateToken(u.UserId)

	if err != nil {
		return "", err
	}

	return token, nil

}

func GetUserById(id uint) (UserAccount, error) {
	var err error

	u := UserAccount{}
	err = DB.Model(UserAccount{}).Where("user_id = ?", id).Take(&u).Error

	if err != nil {
		return UserAccount{}, err
	}

	return u, err
}

func CheckToken(token string) (bool, error) {
	valid := rdb.Exists(ctx, token)

	if valid.Val() != 0 {
		return false, nil
	}
	var err error
	t := UnauthorizedToken{}
	err = DB.Model(UnauthorizedToken{}).Where("token = ?", token).Take(&t).Error

	if err != nil {
		return true, err
	}

	rdb.Set(ctx, token, '1', redis.KeepTTL)
	return false, err
}
