package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var keyFile = filepath.Join(os.Getenv("HOME"), "/.ssh/id_rsa")

type claims struct {
	jwt.StandardClaims
	UID string
	Key string
}

func (c claims) String() string {
	return fmt.Sprintf(`Issuer: %s
Subject: %s
Audience: %s
ExpiresAt: %s
UID: %s
Key: %s`,
		c.Issuer, c.Subject, c.Audience, time.Unix(c.ExpiresAt, 0), c.UID, c.Key)
}

func main() {
	if err := process(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func process() error {
	encoded, err := getToekn()
	if err != nil {
		return err
	}
	fmt.Printf("JWT: %s\n", *encoded)
	c, err := parseToken(encoded)
	if err != nil {
		return err
	}
	fmt.Printf("claims:\n%s", c)
	return nil
}

func getToekn() (*string, error) {
	key, err := readKey()
	if err != nil {
		return nil, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "https://example.com",
			Subject:   "https://example.com/testjwt",
			Audience:  "https://receiver.example.com",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
		},
		UID: uuid.Must(uuid.NewUUID()).String(),
		Key: "hogefuga",
	})
	encoded, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}
	return &encoded, nil
}

func parseToken(encoded *string) (c *claims, err error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return readKey()
	}
	var token *jwt.Token
	token, err = jwt.ParseWithClaims(*encoded, &claims{}, keyFunc)
	if err != nil {
		return
	}
	var ok bool
	c, ok = token.Claims.(*claims)
	if !ok || !token.Valid {
		err = fmt.Errorf("jwt is invalid: %+v", token.Claims)
	}
	return
}

func readKey() (_ []byte, err error) {
	var f *os.File
	f, err = os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return ioutil.ReadAll(f)
}
