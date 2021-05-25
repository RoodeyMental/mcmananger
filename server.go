package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

var webAuthn *webauthn.WebAuthn
var sessionStore *session.Store
var userDB *userdb

func main() {

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",         // display name for your site
		RPID:          "stammdisch.zapto.org", // generally the domain name for your site
		RPOrigin:      "https://stammdisch.zapto.org:29336",
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")
	r.HandleFunc("/restart", Restart).Methods("GET")
	r.HandleFunc("/start/", Start).Methods("GET")
	r.HandleFunc("/stop", Stop).Methods("GET")
	r.HandleFunc("/checkAlive", CheckAlive).Methods("GET")

	r.PathPrefix("/internal/").HandlerFunc(GetData)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web")))

	serverAddress := ":29336"
	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServeTLS(serverAddress, "./cert/server.crt", "./cert/server.key", r))
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(user)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func textResponse(w http.ResponseWriter, data string, c int) {
	w.Header().Set("Content-Type", "application/text")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", data)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
	return
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation we should perform additional
	// checks on the returned 'credential'
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("User " + username + " successfully Logged in.")

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

func GetData(w http.ResponseWriter, r *http.Request) {
	if _, err := sessionStore.GetWebauthnSession("authentication", r); err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}

	fileName := strings.Split(r.RequestURI, "/")
	data, err := ioutil.ReadFile("web/" + r.RequestURI)
	if err != nil {
		w.WriteHeader(501)
		return
	}
	http.ServeContent(w, r, fileName[len(fileName)-1], time.Now(), bytes.NewReader(data))
}

func Start(w http.ResponseWriter, r *http.Request) {
	_, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}
	//TODO: Log which user executed command
	cmd := exec.Command("~/minecraft/checkalive.sh")
	stdout, errCmd := cmd.Output()
	if errCmd != nil {
		log.Println(errCmd)
	}
	log.Print("Stdout: ")
	log.Println(stdout)
	textResponse(w, string(stdout), http.StatusOK)
}

func Stop(w http.ResponseWriter, r *http.Request) {
	_, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}
	//TODO: Log which user executed command
	cmd := exec.Command("~/minecraft/checkalive.sh")
	stdout, errCmd := cmd.Output()
	if errCmd != nil {
		log.Println(errCmd)
	}
	log.Print("Stdout: ")
	log.Println(stdout)
	textResponse(w, string(stdout), http.StatusOK)
}

func Restart(w http.ResponseWriter, r *http.Request) {
	_, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}
	//TODO: Log which user executed command
	cmd := exec.Command("~/minecraft/checkalive.sh")
	stdout, errCmd := cmd.Output()
	if errCmd != nil {
		log.Println(errCmd)
	}
	log.Print("Stdout: ")
	log.Println(stdout)
	textResponse(w, string(stdout), http.StatusOK)
}

func CheckAlive(w http.ResponseWriter, r *http.Request) {
	_, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}
	//TODO: Log which user executed command
	cmd := exec.Command("~/minecraft/checkalive.sh")
	stdout, errCmd := cmd.Output()
	if errCmd != nil {
		log.Println(errCmd)
	}
	log.Print("Stdout: ")
	log.Println(stdout)
	textResponse(w, string(stdout), http.StatusOK)
}
