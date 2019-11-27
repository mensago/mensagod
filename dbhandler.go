package main

/*
	This module is for abstracting away all the messy details of interacting with the database.
	By doing so, it will be easier to add support for databases other than Postgresql. It will also
	eliminate cluttering up the otherwise-clean Go code with the ugly SQL queries.
*/

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type dbHandler struct {
	connected bool
}

// NewdbHandler - constructor for dbHandler instances
func NewdbHandler() {
	var handler dbHandler
	handler.connect()
}

func (db dbHandler) connect() {
	if viper.GetString("database.engine") != "postgresql" {
		ServerLog.Println("Database password not set in config file. Exiting.")
		fmt.Println("Database password not set in config file. Exiting.")
		os.Exit(1)
	}
}
