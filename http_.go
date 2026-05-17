package main

import (
	"bufio"
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type AuthJob struct {
	Ok       bool
	username string
	password string
	Data     chan string
	Ctx      context.Context
}

type ipLimiter struct {
	tokens    float64
	last      time.Time
	failCount int
	lastFail  time.Time
}

type Auth struct {
	db        map[string]string
	Jobs      chan *AuthJob
	mu        sync.Mutex
	limiters  map[string]*ipLimiter
}

const (
	maxBodyBytes       = 1 << 20
	ratePerSec         = 1.0
	burstTokens        = 5.0
	baseFailDelay      = 200 * time.Millisecond
	maxFailDelay       = 2 * time.Second
	authRequestTimeout = 5 * time.Second
)

func New(path string) *Auth {
	db := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		log.Println(err)
		return &Auth{db: db, Jobs: make(chan *AuthJob, 150), limiters: make(map[string]*ipLimiter)}
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
	return &Auth{db: db, Jobs: make(chan *AuthJob, 150), limiters: make(map[string]*ipLimiter)}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Auth) allowRequest(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	lim := a.limiters[ip]
	if lim == nil {
		lim = &ipLimiter{tokens: burstTokens, last: now}
		a.limiters[ip] = lim
	}

	elapsed := now.Sub(lim.last).Seconds()
	lim.tokens += elapsed * ratePerSec
	if lim.tokens > burstTokens {
		lim.tokens = burstTokens
	}
	lim.last = now

	if lim.tokens < 1 {
		return false
	}
	lim.tokens -= 1
	return true
}

func (a *Auth) recordFailure(ip string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()

	lim := a.limiters[ip]
	if lim == nil {
		lim = &ipLimiter{tokens: burstTokens, last: time.Now()}
		a.limiters[ip] = lim
	}
	lim.failCount++
	lim.lastFail = time.Now()

	delay := time.Duration(lim.failCount) * baseFailDelay
	if delay > maxFailDelay {
		delay = maxFailDelay
	}
	return delay
}

func (a *Auth) recordSuccess(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if lim := a.limiters[ip]; lim != nil {
		lim.failCount = 0
		lim.lastFail = time.Time{}
	}
}

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	ip := clientIP(r)
	if !a.allowRequest(ip) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}

	u := r.PostFormValue("username")
	p := r.PostFormValue("password")
	ok := false
	if pw, exists := a.db[u]; exists && pw == p && u != "" {
		ok = true
	}

	var failDelay time.Duration
	if ok {
		a.recordSuccess(ip)
	} else {
		failDelay = a.recordFailure(ip)
	}

	ctx, cancel := context.WithTimeout(r.Context(), authRequestTimeout)
	defer cancel()

	job := &AuthJob{
		Ok:       ok,
		username: u,
		password: p,
		Data:     make(chan string, 1),
		Ctx:      ctx,
	}

	select {
	case a.Jobs <- job:
	case <-ctx.Done():
		http.Error(w, "Request timeout", http.StatusGatewayTimeout)
		return
	}

	timeout := time.NewTimer(authRequestTimeout)
	defer timeout.Stop()

	select {
	case resp := <-job.Data:
		if failDelay > 0 {
			t := time.NewTimer(failDelay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				http.Error(w, "Request timeout", http.StatusGatewayTimeout)
				return
			}
		}
		w.Write([]byte(resp))
	case <-ctx.Done():
		http.Error(w, "Request timeout", http.StatusGatewayTimeout)
	case <-timeout.C:
		http.Error(w, "Request timeout", http.StatusGatewayTimeout)
	}
}
