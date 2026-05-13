package main

import (
	"bufio"
	"net/http"
	"os"
	"strings"
)

type AuthJob struct {
	Ok       bool
	username string
	Data     chan string
}
type Auth struct {
	db   map[string]string
	Jobs chan *AuthJob
}

func New(path string) *Auth {
	db := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		var p []string
		if strings.Contains(l, ":") {
			p = strings.SplitN(l, ":", 2)
		} else if strings.Contains(l, ",") {
			p = strings.SplitN(l, ",", 2)
		}
		if len(p) == 2 {
			db[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	return &Auth{db: db, Jobs: make(chan *AuthJob, 150)}
}
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	u := r.PostFormValue("username")
	p := r.PostFormValue("password")
	ok := false
	if pw, exists := a.db[u]; exists && pw == p && u != "" {
		ok = true
	}
	job := &AuthJob{
		Ok:       ok,
		username: u,
		Data:     make(chan string),
	}
	a.Jobs <- job
	w.Write([]byte(<-job.Data))
}
