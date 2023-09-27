package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	codeVerifier = "f52g787EWIcyOK3jZiE8nYzRsv3kLEZ9vsJVcQDyfVE"
	grantType    = "authorization_code"
)

var clients = []struct {
	ClientType   string
	ClientID     string
	ClientSecret string
}{
	{
		ClientType:   "Public Client",
		ClientID:     "web_public",
		ClientSecret: "web_public_secret",
	},
	{
		ClientType:   "Credential Client",
		ClientID:     "web_credential",
		ClientSecret: "web_credential_secret",
	},
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	err := viper.ReadInConfig()
	if err != nil {
		log.Panic(err)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	initConfig()

	r := mux.NewRouter()

	r.HandleFunc("/home", home).Methods(http.MethodGet)
	r.HandleFunc("/callback", callback).Methods(http.MethodGet)

	headersOk := handlers.AllowedHeaders([]string{"Origin", "X-Requested-With", "Accept", "Content-Type", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST" /*"PUT", "PATCH", "DELETE",*/, "OPTIONS"})

	sv := http.Server{
		Addr:         fmt.Sprintf(":%v", viper.GetInt("app.port")),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler:      handlers.CORS(originsOk, headersOk, methodsOk)(r),
	}
	log.Printf("Listening on port %v...\n", viper.GetInt("app.port"))
	log.Panic(sv.ListenAndServe())
}

func home(w http.ResponseWriter, r *http.Request) {
	bHTML, _ := os.ReadFile("static/html/home.go.html")

	data := struct {
		AuthServer string
		Clients    []struct {
			ClientType   string
			ClientID     string
			ClientSecret string
		}
		CodeChallenge string
		CallbackURL   string
	}{
		AuthServer:    viper.GetString("auth.server"),
		CodeChallenge: getCodeChallenge(codeVerifier),
		CallbackURL:   viper.GetString("app.callback_url"),
	}
	data.Clients = clients

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
	errorVal := r.FormValue("error")
	errorDescription := r.FormValue("error_description")
	errorURI := r.FormValue("error_uri")

	var bHtml []byte
	var err error

	if errorVal != "" {
		bHtml, err = os.ReadFile("static/html/callback_error.go.html")
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
	} else {
		bHtml, err = os.ReadFile("static/html/callback_success.go.html")
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
	}

	data := struct {
		Code        string
		State       string
		TokenServer string
		Clients     []struct {
			ClientType   string
			ClientID     string
			ClientSecret string
		}
		CallbackURL      string
		CodeVerifier     string
		GrantType        string
		Error            string
		ErrorDescription string
		ErrorURI         string
	}{
		Code:             code,
		State:            state,
		TokenServer:      viper.GetString("token.server"),
		CallbackURL:      viper.GetString("app.callback_url"),
		CodeVerifier:     codeVerifier,
		GrantType:        grantType,
		Error:            errorVal,
		ErrorDescription: errorDescription,
		ErrorURI:         errorURI,
	}
	data.Clients = clients

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
