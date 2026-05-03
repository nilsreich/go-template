package auth

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/nilsreich/go-template/db"
)

type User struct {
	ID       int
	Username string
}

func RegisterUser(username, password string) error {
	hash, salt, err := CreatePasswordHash(password)
	if err != nil {
		return err
	}

	_, err = db.DB.Exec("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", username, hash, salt)
	if err != nil {
		return err
	}
	return nil
}

func AuthenticateUser(username, password string) (*User, error) {
	row := db.DB.QueryRow("SELECT id, username, password_hash, salt FROM users WHERE username = ?", username)
	var user User
	var hash, salt []byte

	err := row.Scan(&user.ID, &user.Username, &hash, &salt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, err
	}

	if !ComparePasswordAndHash(password, salt, hash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return &user, nil
}

func GetUserFromSession(ctx context.Context) *User {
	userID := SessionManager.GetInt(ctx, "userID")
	if userID == 0 {
		return nil
	}
	// Depending on your requirements, you could fetch the user from DB again here,
	// or assume the user exists if the ID is in the session.
	// For simplicity, we just return the ID if we only need to know they're logged in.
	return &User{ID: userID, Username: SessionManager.GetString(ctx, "username")}
}

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !SessionManager.Exists(r.Context(), "userID") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
