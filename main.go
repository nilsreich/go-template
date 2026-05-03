package main

import (
	"log"
	"net/http"

	"github.com/a-h/templ"
	"github.com/nilsreich/go-template/auth"
	"github.com/nilsreich/go-template/db"
	"github.com/nilsreich/go-template/views"
)

func render(c templ.Component) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("HX-Request") == "true" {
			c.Render(r.Context(), w)
		} else {
			views.Layout(c).Render(r.Context(), w)
		}
	}
}

func main() {
	db.InitDB("data.db")
	defer db.DB.Close()
	auth.InitSessionManager(db.DB)

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	mux.HandleFunc("/", render(views.Index()))
	mux.HandleFunc("/about", render(views.About()))

	mux.Handle("/protected", auth.RequireAuth(render(views.Protected())))

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if auth.GetUserFromSession(r.Context()) != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodGet {
			render(views.AuthForm("login", ""))(w, r)
			return
		}

		if r.Method == http.MethodPost {
			username := r.FormValue("username")
			password := r.FormValue("password")

			user, err := auth.AuthenticateUser(username, password)
			if err != nil {
				render(views.AuthForm("login", "Invalid credentials"))(w, r)
				return
			}

			auth.SessionManager.Put(r.Context(), "userID", user.ID)
			auth.SessionManager.Put(r.Context(), "username", user.Username)

			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if auth.GetUserFromSession(r.Context()) != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodGet {
			render(views.AuthForm("register", ""))(w, r)
			return
		}

		if r.Method == http.MethodPost {
			username := r.FormValue("username")
			password := r.FormValue("password")

			err := auth.RegisterUser(username, password)
			if err != nil {
				render(views.AuthForm("register", "Registration failed. Username might be taken."))(w, r)
				return
			}

			user, err := auth.AuthenticateUser(username, password)
			if err == nil {
				auth.SessionManager.Put(r.Context(), "userID", user.ID)
				auth.SessionManager.Put(r.Context(), "username", user.Username)
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			err := auth.SessionManager.Destroy(r.Context())
			if err != nil {
				http.Error(w, "Failed to logout", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})

	log.Println("Listening on :3000...")
	// Wrap the mux with the SessionManager middleware
	log.Fatal(http.ListenAndServe(":3000", auth.SessionManager.LoadAndSave(mux)))
}
