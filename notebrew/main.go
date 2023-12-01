package main

import (
	"database/sql"
	"log"

	"github.com/bokwoon95/nb9"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	err = nb9.Automigrate("sqlite", db)
	if err != nil {
		log.Fatal(err)
	}
}
