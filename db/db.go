package db

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(filepath string) {
	var err error
	DB, err = sql.Open("sqlite", filepath)
	if err != nil {
		log.Fatalf("Failed to connect to db: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Failed to ping db: %v", err)
	}

	createTables()
}

func createTables() {
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash BLOB NOT NULL,
		salt BLOB NOT NULL
	);`

	sessionsTable := `
	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		data BLOB NOT NULL,
		expiry REAL NOT NULL
	);
	CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expiry);
	`

	_, err := DB.Exec(usersTable)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	_, err = DB.Exec(sessionsTable)
	if err != nil {
		log.Fatalf("Failed to create sessions table: %v", err)
	}
}
