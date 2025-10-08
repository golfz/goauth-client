package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type Config struct {
	App struct {
		Port        int    `json:"port"`
		CallbackUri string `json:"callback_uri"`
	} `json:"app"`
	Clients      []Client `json:"clients"`
	LoginButtons []struct {
		Text    string `json:"text"`
		Path    string `json:"path"`
		Enabled bool   `json:"enabled"`
	} `json:"login_buttons"`
}

type Client struct {
	Name                string `json:"name"`
	ClientId            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	AuthUri             string `json:"auth_uri"`
	TokenUri            string `json:"token_uri"`
	Scopes              string `json:"scopes"`
	UsePkce             bool   `json:"use_pkce"`
	AllowPlainPkce      bool   `json:"allow_plain_pkce"`
	Enabled             bool   `json:"enabled"`
	RandomState         string `json:"random_state"`
	RandomCodeVerifier  string `json:"random_code_verifier"`
	RandomCodeChallenge string `json:"random_code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

const (
	grantType = "authorization_code"
)

var (
	config *Config
)

func loadConfig() {
	log.Println("config loading...")

	jsonBytes, err := os.ReadFile("config.json")
	if err != nil {
		log.Panic(err)
	}

	err = json.Unmarshal(jsonBytes, &config)
	if err != nil {
		log.Panic(err)
	}

	log.Println("config loaded successfully")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	loadConfig()

	r := mux.NewRouter()

	r.HandleFunc("/home", home).Methods(http.MethodGet)
	r.HandleFunc("/callback", callback).Methods(http.MethodGet)

	headersOk := handlers.AllowedHeaders([]string{"Origin", "X-Requested-With", "Accept", "Content-Type", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST" /*"PUT", "PATCH", "DELETE",*/, "OPTIONS"})

	sv := http.Server{
		Addr:         fmt.Sprintf(":%v", config.App.Port),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler:      handlers.CORS(originsOk, headersOk, methodsOk)(r),
	}
	log.Printf("Listening on port %v..., http://localhost:%v/home\n", config.App.Port, config.App.Port)
	log.Panic(sv.ListenAndServe())
}

func home(w http.ResponseWriter, r *http.Request) {
	log.Println("Home")

	randomSessionToConfig(config)

	bHTML, _ := os.ReadFile("static/html/home.go.html")

	tpl, err := template.New("home").Parse(string(bHTML))
	if err != nil {
		log.Println(err)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	err = tpl.Execute(w, config)
	if err != nil {
		log.Println(err)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
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
			_, _ = w.Write([]byte(err.Error()))
			return
		}
	} else {
		bHtml, err = os.ReadFile("static/html/callback_success.go.html")
		if err != nil {
			log.Println(err)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
	}

	client := getClientByState(state)
	if client == nil {
		log.Println("invalid state, no client found")
		_, _ = w.Write([]byte("invalid state, no client found"))
		return
	}

	data := struct {
		ClientName       string
		ClientID         string
		ClientSecret     string
		Code             string
		State            string
		TokenServer      string
		CallbackURL      string
		CodeVerifier     string
		GrantType        string
		Error            string
		ErrorDescription string
		ErrorURI         string
	}{
		ClientName:       client.Name,
		ClientID:         client.ClientId,
		ClientSecret:     client.ClientSecret,
		Code:             code,
		State:            state,
		TokenServer:      client.TokenUri,
		CallbackURL:      config.App.CallbackUri,
		CodeVerifier:     client.RandomCodeVerifier,
		GrantType:        grantType,
		Error:            errorVal,
		ErrorDescription: errorDescription,
		ErrorURI:         errorURI,
	}

	tpl, err := template.New("callback").Parse(string(bHtml))
	if err != nil {
		log.Println(err)
		w.Write([]byte(err.Error()))
		return
	}
	tpl.Execute(w, data)
}

func randomSessionToConfig(config *Config) {
	enabledClient := make([]Client, 0)

	for _, client := range config.Clients {
		if client.Enabled {
			state := getState(client.ClientId)
			var codeVerifier, codeChallenge, codeChallengeMethod string
			if client.UsePkce {
				codeVerifier = randomCodeVerifier(43) // between 43 and 128
				codeChallenge = getCodeChallenge(codeVerifier)
				codeChallengeMethod = "S256"
				if client.AllowPlainPkce {
					codeChallengeMethod = "plain"
				}
			}

			client.RandomState = state
			client.RandomCodeVerifier = codeVerifier
			client.RandomCodeChallenge = codeChallenge
			client.CodeChallengeMethod = codeChallengeMethod

			enabledClient = append(enabledClient, client)
		}
	}
	config.Clients = enabledClient
}

func randomCodeVerifier(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		b[i] = letters[num.Int64()]
		time.Sleep(time.Nanosecond) // ensure different seed
	}
	return string(b)
}

func getCodeChallenge(codeVerifier string) string {
	sha2 := sha256.New()
	io.WriteString(sha2, codeVerifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

	return codeChallenge
}

// state will like this pattern {client_id}-{unix timestamp}
func getState(clientId string) string {
	return fmt.Sprintf("%s-%d", clientId, time.Now().UnixNano())
}

// decode state to get client_id, and get Client from config
func getClientByState(state string) *Client {
	var clientId string
	clientId = state[0:strings.LastIndex(state, "-")]
	if clientId == "" {
		return nil
	}

	for _, c := range config.Clients {
		if c.ClientId == clientId {
			return &c
		}
	}

	return nil
}
