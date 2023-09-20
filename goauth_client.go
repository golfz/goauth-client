package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	servicePort = "8080"

	authServer  = "http://localhost:5000/oauth/v2/authorize"
	tokenServer = "http://localhost:5000/oauth/v2/token"

	codeVerifier = "f52g787EWIcyOK3jZiE8nYzRsv3kLEZ9vsJVcQDyfVE"
	callbackURL  = "http://localhost:8080/callback"

	clientID     = "web_public"
	clientSecret = "web_public_secret"
	grantType    = "authorization_code"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	r := mux.NewRouter()

	r.HandleFunc("/home", home).Methods(http.MethodGet)
	r.HandleFunc("/callback", callback).Methods(http.MethodGet)

	headersOk := handlers.AllowedHeaders([]string{"Origin", "X-Requested-With", "Accept", "Content-Type", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST" /*"PUT", "PATCH", "DELETE",*/, "OPTIONS"})

	sv := http.Server{
		Addr:         fmt.Sprintf(":%s", servicePort),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler:      handlers.CORS(originsOk, headersOk, methodsOk)(r),
	}
	log.Printf("Listening on port %s...\n", servicePort)
	log.Panic(sv.ListenAndServe())
}

func home(w http.ResponseWriter, r *http.Request) {
	bHTML, _ := os.ReadFile("static/html/home.html")

	data := struct {
		AuthServer    string
		ClientID      string
		ClientSecret  string
		CodeChallenge string
		CallbackURL   string
	}{
		AuthServer:    authServer,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		CodeChallenge: getCodeChallenge(codeVerifier),
		CallbackURL:   callbackURL,
	}

	tpl, err := template.New("home").Parse(string(bHTML))
	if err != nil {
		log.Println(err)
		w.Write([]byte(err.Error()))
		return
	}

	tpl.Execute(w, data)
}

func callback(w http.ResponseWriter, r *http.Request) {
	log.Println("callback is called")

	r.ParseForm()
	code := r.FormValue("code")
	state := r.FormValue("state")

	bHtml, err := os.ReadFile("static/html/callback_success.html")
	if err != nil {
		log.Println(err)
		w.Write([]byte(err.Error()))
		return
	}
	data := struct {
		Code         string
		State        string
		TokenServer  string
		ClientID     string
		ClientSecret string
		CallbackURL  string
		CodeVerifier string
		GrantType    string
	}{
		Code:         code,
		State:        state,
		TokenServer:  tokenServer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CallbackURL:  callbackURL,
		CodeVerifier: codeVerifier,
		GrantType:    grantType,
	}

	tpl, err := template.New("callback").Parse(string(bHtml))
	if err != nil {
		log.Println(err)
		w.Write([]byte(err.Error()))
		return
	}
	tpl.Execute(w, data)
}

func getCodeChallenge(codeVerifier string) string {
	sha2 := sha256.New()
	io.WriteString(sha2, codeVerifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

	return codeChallenge
}
