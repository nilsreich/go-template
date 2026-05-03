package auth

import (
	"database/sql"
	"time"

	"net/http"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
)

var SessionManager *scs.SessionManager

func InitSessionManager(db *sql.DB) {
	SessionManager = scs.New()
	SessionManager.Store = sqlite3store.New(db)
	SessionManager.Lifetime = 24 * time.Hour
	SessionManager.Cookie.SameSite = http.SameSiteLaxMode
	SessionManager.Cookie.Secure = true // GitHub Codespaces proxy uses HTTPS
}
