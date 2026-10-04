package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type AuthJob struct {
	username     string
	clientpubkey string
	clientip     string
	Data         chan string
	Ctx          context.Context
}

type ipLimiter struct {
	mu        sync.Mutex
	tokens    float64
	last      time.Time
	failCount int
	lastFail  time.Time
	lastSeen  time.Time
}

type Auth struct {
	db             map[string]string
	Jobs           chan *AuthJob
	limiters       sync.Map
	limiterMu      sync.Mutex
	nonceMu        sync.Mutex
	nonces         map[string]time.Time
	stopCh         chan struct{}
	stopOnce       sync.Once
	cleanupMu      sync.Mutex
	limiterStarted bool
	nonceStarted   bool
	cleanupWG      sync.WaitGroup
	limiterCount   int64
}

const (
	maxBodyBytes       = 1 << 20
	ratePerSec         = 1.0
	burstTokens        = 5.0
	baseFailDelay      = 200 * time.Millisecond
	maxFailDelay       = 2 * time.Second
	authRequestTimeout = 5 * time.Second
	limiterIdleTTL     = 15 * time.Minute
	limiterSweepEvery  = 5 * time.Minute
	nonceTTL           = 1 * time.Minute
	nonceSweepEvery    = 1 * time.Minute
	maxNonces          = 100000
	maxLimiterEntries  = 100000
)

var (
	trustedProxyOnce sync.Once
	trustedProxyIPs  = make(map[string]struct{})
	trustedProxyNets []*net.IPNet
)

func loadTrustedProxies() {
	trustedProxyOnce.Do(func() {

		if strings.TrimSpace(os.Getenv("TRUST_PROXY")) == "" {
			return
		}

		for _, raw := range strings.Split(
			os.Getenv("TRUSTED_PROXY_IPS"),
			",",
		) {

			ip := strings.TrimSpace(raw)

			if ip == "" {
				continue
			}

			if net.ParseIP(ip) != nil {
				trustedProxyIPs[ip] = struct{}{}
			}
		}

		for _, raw := range strings.Split(
			os.Getenv("TRUSTED_PROXY_CIDRS"),
			",",
		) {

			cidr := strings.TrimSpace(raw)

			if cidr == "" {
				continue
			}

			_, n, err := net.ParseCIDR(cidr)

			if err == nil {
				trustedProxyNets = append(
					trustedProxyNets,
					n,
				)
			}
		}
	})
}

func isTrustedProxy(remoteIP string) bool {

	loadTrustedProxies()

	if len(trustedProxyIPs) == 0 &&
		len(trustedProxyNets) == 0 {

		return false
	}

	if _, ok := trustedProxyIPs[remoteIP]; ok {
		return true
	}

	ip := net.ParseIP(remoteIP)

	if ip == nil {
		return false
	}

	for _, n := range trustedProxyNets {

		if n.Contains(ip) {
			return true
		}
	}

	return false
}

func New(path string) (*Auth, error) {

	db := make(map[string]string)

	f, err := os.Open(path)

	if err != nil {

		logJSON(
			"error",
			"users_db_open_failed",
			logFields{
				"err": err.Error(),
			},
		)

		return nil, err
	}

	defer func(f *os.File) {

		err := f.Close()

		if err != nil {

			logJSON(
				"warn",
				"users_db_close_failed",
				logFields{
					"err": err.Error(),
				},
			)
		}

	}(f)

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1024), maxBodyBytes)

	lineNo := 0

	for s.Scan() {

		lineNo++

		l := strings.TrimSpace(s.Text())

		if l == "" ||
			strings.HasPrefix(l, "#") ||
			strings.HasPrefix(l, "//") {

			continue
		}

		var p []string

		if strings.Contains(l, ":") {

			p = strings.SplitN(l, ":", 2)

		} else if strings.Contains(l, ",") {

			p = strings.SplitN(l, ",", 2)
		}

		if len(p) != 2 {
			return nil, fmt.Errorf("invalid users db line %d", lineNo)
		}

		user := strings.TrimSpace(p[0])
		if err := ValidateUsername(user); err != nil {
			return nil, fmt.Errorf("invalid username at users db line %d: %w", lineNo, err)
		}

		pwHash := strings.TrimSpace(p[1])
		if pwHash == "" {
			return nil, fmt.Errorf("empty password hash for %q at users db line %d", user, lineNo)
		}
		if err := ValidatePasswordHashFormat(pwHash); err != nil {
			return nil, fmt.Errorf("invalid password hash for %q at users db line %d: %w", user, lineNo, err)
		}

		if _, exists := db[user]; exists {
			return nil, fmt.Errorf("duplicate username %q at users db line %d", user, lineNo)
		}

		db[user] = pwHash
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	return &Auth{
		db:       db,
		Jobs:     make(chan *AuthJob, 150),
		nonces:   make(map[string]time.Time),
		stopCh:   make(chan struct{}),
		limiters: sync.Map{},
	}, nil
}

func clientIP(r *http.Request) string {

	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		host = r.RemoteAddr
	}

	if isTrustedProxy(host) {

		if xff := strings.TrimSpace(
			r.Header.Get("X-Forwarded-For"),
		); xff != "" {

			parts := strings.Split(xff, ",")

			for i := len(parts) - 1; i >= 0; i-- {

				candidate := strings.TrimSpace(parts[i])

				if net.ParseIP(candidate) == nil {
					continue
				}

				if !isTrustedProxy(candidate) {
					return candidate
				}
			}
		}

		if xrip := strings.TrimSpace(
			r.Header.Get("X-Real-IP"),
		); xrip != "" {

			if net.ParseIP(xrip) != nil &&
				!isTrustedProxy(xrip) {

				return xrip
			}
		}
	}

	return host
}

func (a *Auth) allowRequest(ip string) bool {

	lim, ok := a.getLimiter(ip)
	if !ok {
		logJSON("warn", "limiter_capacity_reached", logFields{"ip": ip})
		return false
	}

	now := time.Now()

	lim.mu.Lock()
	defer lim.mu.Unlock()

	elapsed := now.Sub(lim.last).Seconds()

	lim.tokens += elapsed * ratePerSec

	if lim.tokens > burstTokens {
		lim.tokens = burstTokens
	}

	lim.last = now
	lim.lastSeen = now

	if lim.tokens < 1 {
		return false
	}

	lim.tokens -= 1

	return true
}

func (a *Auth) recordFailure(ip string) time.Duration {

	lim, ok := a.getLimiter(ip)
	if !ok {
		return maxFailDelay
	}

	lim.mu.Lock()
	defer lim.mu.Unlock()

	lim.failCount++
	lim.lastFail = time.Now()
	lim.lastSeen = lim.lastFail

	delay := time.Duration(lim.failCount) *
		baseFailDelay

	if delay > maxFailDelay {
		delay = maxFailDelay
	}

	return delay
}

func (a *Auth) recordSuccess(ip string) {

	limIface, ok := a.limiters.Load(ip)

	if !ok {
		return
	}

	lim := limIface.(*ipLimiter)

	lim.mu.Lock()
	defer lim.mu.Unlock()

	lim.failCount = 0
	lim.lastFail = time.Time{}
	lim.lastSeen = time.Now()
}

func (a *Auth) StartLimiterCleanup() {
	a.cleanupMu.Lock()
	if a.limiterStarted {
		a.cleanupMu.Unlock()
		return
	}
	a.limiterStarted = true
	a.cleanupMu.Unlock()

	a.cleanupWG.Add(1)

	go func() {

		defer a.cleanupWG.Done()

		ticker := time.NewTicker(
			limiterSweepEvery,
		)

		defer ticker.Stop()

		for {

			select {

			case <-ticker.C:

				cutoff := time.Now().Add(
					-limiterIdleTTL,
				)

				removed := 0

				a.limiterMu.Lock()
				a.limiters.Range(func(key, value interface{}) bool {

					lim := value.(*ipLimiter)

					lim.mu.Lock()

					stale := lim.lastSeen.Before(cutoff)

					lim.mu.Unlock()

					if stale {

						a.limiters.Delete(key)
						atomic.AddInt64(&a.limiterCount, -1)

						removed++
					}

					return true
				})
				a.limiterMu.Unlock()

				if removed > 0 {

					logJSON(
						"info",
						"limiter_cleanup",
						logFields{
							"removed": removed,
						},
					)
				}

			case <-a.stopCh:
				return
			}
		}
	}()
}

func (a *Auth) StartNonceCleanup() {
	a.cleanupMu.Lock()
	if a.nonceStarted {
		a.cleanupMu.Unlock()
		return
	}
	a.nonceStarted = true
	a.cleanupMu.Unlock()

	a.cleanupWG.Add(1)

	go func() {

		defer a.cleanupWG.Done()

		ticker := time.NewTicker(
			nonceSweepEvery,
		)

		defer ticker.Stop()

		for {

			select {

			case <-ticker.C:

				cutoff := time.Now().Add(
					-nonceTTL,
				)

				a.nonceMu.Lock()

				for k, t := range a.nonces {

					if t.Before(cutoff) {
						delete(a.nonces, k)
					}
				}

				a.nonceMu.Unlock()

			case <-a.stopCh:
				return
			}
		}
	}()
}

func (a *Auth) StopCleanup() {

	a.stopOnce.Do(func() {
		close(a.stopCh)
	})
}

func (a *Auth) WaitCleanup(ctx context.Context) error {

	if ctx == nil {
		ctx = context.Background()
	}

	done := make(chan struct{})

	go func() {
		a.cleanupWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Auth) checkAndStoreNonce(
	user,
	nonce string,
	now time.Time,
) bool {

	key := user + ":" + nonce

	cutoff := now.Add(-nonceTTL)

	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()

	if t, exists := a.nonces[key]; exists &&
		t.After(cutoff) {

		return false
	}

	if len(a.nonces) >= maxNonces {
		removed := 0
		for k, t := range a.nonces {
			if t.Before(cutoff) {
				delete(a.nonces, k)
				removed++
			}
		}
		if removed > 0 {
			logJSON(
				"info",
				"nonce_capacity_cleanup",
				logFields{"removed": removed},
			)
		}
		if len(a.nonces) >= maxNonces {
			logJSON(
				"warn",
				"nonce_capacity_reached",
				logFields{"user": user},
			)
			return false
		}
	}

	a.nonces[key] = now

	return true
}

func buildSignaturePayload(
	user,
	ts,
	nonce,
	pubkey string,
) string {

	return "username=" + user +
		"&timestamp=" + ts +
		"&nonce=" + nonce +
		"&pubkey=" + pubkey
}

func computeSignatureBytes(
	key []byte,
	payload string,
) []byte {

	h := hmac.New(
		sha256.New,
		key,
	)

	h.Write([]byte(payload))

	return h.Sum(nil)
}

func decodeHexSignature(sig string) ([]byte, error) {

	sig = strings.TrimSpace(sig)

	return hex.DecodeString(sig)
}

func (a *Auth) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {

	if r.Method != "POST" {

		logJSON(
			"warn",
			"method_not_allowed",
			logFields{
				"method": r.Method,
				"ip":     clientIP(r),
			},
		)

		w.WriteHeader(
			http.StatusMethodNotAllowed,
		)

		return
	}

	ip := clientIP(r)

	if !a.allowRequest(ip) {

		logJSON(
			"warn",
			"rate_limited",
			logFields{
				"ip": ip,
			},
		)

		http.Error(
			w,
			"Too Many Requests",
			http.StatusTooManyRequests,
		)

		return
	}

	now := time.Now()
	req, err := ParseAuthRequest(w, r, now)
	if err != nil {
		fields := logFields{"ip": ip, "err": err.Error()}
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			fields["field"] = vErr.Field
			fields["code"] = vErr.Code
		}
		logJSON("warn", "auth_params_invalid", fields)
		status := http.StatusUnauthorized
		msg := "Authentication failed"
		if vErr != nil && vErr.Status != 0 {
			status = vErr.Status
			switch status {
			case http.StatusRequestEntityTooLarge:
				msg = "Request too large"
			case http.StatusBadRequest:
				msg = "Invalid request"
			}
		}
		http.Error(w, msg, status)
		return
	}

	u := req.Username
	p := req.Password
	c := req.PubKey
	tsStr := req.TimestampRaw
	nonce := req.Nonce
	signature := req.Signature

	ok := false

	pwHash := dummyPasswordHash
	userExists := false

	if storedHash, exists := a.db[u]; exists {
		pwHash = storedHash
		userExists = true
	}

	valid, err := verifyPasswordContext(
		r.Context(),
		p,
		pwHash,
	)

	if err == nil && valid && userExists {

		key := sha256.Sum256(
			[]byte(p),
		)

		payload := buildSignaturePayload(
			u,
			tsStr,
			nonce,
			c,
		)

		expected := computeSignatureBytes(
			key[:],
			payload,
		)

		provided, derr := decodeHexSignature(
			signature,
		)

		if derr == nil {

			if hmac.Equal(
				expected,
				provided,
			) {

				if a.checkAndStoreNonce(
					u,
					nonce,
					now,
				) {

					ok = true
				}
			}
		}
	}

	if !ok {

		failDelay := a.recordFailure(ip)

		logJSON(
			"warn",
			"auth_failed",
			logFields{
				"ip":   ip,
				"user": u,
			},
		)

		if failDelay > 0 {
			failTimer := time.NewTimer(failDelay)
			select {
			case <-failTimer.C:
			case <-r.Context().Done():
				failTimer.Stop()
				return
			}
		}

		http.Error(
			w,
			"Authentication failed",
			http.StatusUnauthorized,
		)

		return
	}

	a.recordSuccess(ip)

	logJSON(
		"info",
		"auth_success",
		logFields{
			"ip":   ip,
			"user": u,
		},
	)

	ctx, cancel := context.WithTimeout(
		r.Context(),
		authRequestTimeout,
	)

	defer cancel()

	job := &AuthJob{
		username:     u,
		clientpubkey: c,
		clientip:     ip,
		Data:         make(chan string, 1),
		Ctx:          ctx,
	}

	select {

	case a.Jobs <- job:

	case <-ctx.Done():

		http.Error(
			w,
			"Request timeout",
			http.StatusGatewayTimeout,
		)

		return
	}

	timeout := time.NewTimer(
		authRequestTimeout,
	)

	defer timeout.Stop()

	select {

	case resp := <-job.Data:

		w.Header().Set(
			"Content-Type",
			"text/plain; charset=utf-8",
		)
		w.Header().Set(
			"Cache-Control",
			"no-store",
		)
		w.Header().Set(
			"Pragma",
			"no-cache",
		)
		w.Header().Set(
			"X-Content-Type-Options",
			"nosniff",
		)

		_, err := w.Write(
			[]byte(resp),
		)

		if err != nil {
			return
		}

	case <-ctx.Done():

		http.Error(
			w,
			"Request timeout",
			http.StatusGatewayTimeout,
		)

	case <-timeout.C:

		http.Error(
			w,
			"Request timeout",
			http.StatusGatewayTimeout,
		)
	}
}

func (a *Auth) getLimiter(ip string) (*ipLimiter, bool) {
	if limIface, ok := a.limiters.Load(ip); ok {
		return limIface.(*ipLimiter), true
	}

	a.limiterMu.Lock()
	defer a.limiterMu.Unlock()
	if limIface, ok := a.limiters.Load(ip); ok {
		return limIface.(*ipLimiter), true
	}
	if atomic.LoadInt64(&a.limiterCount) >= maxLimiterEntries {
		return nil, false
	}
	now := time.Now()
	lim := &ipLimiter{tokens: burstTokens, last: now, lastSeen: now}
	a.limiters.Store(ip, lim)
	atomic.AddInt64(&a.limiterCount, 1)
	return lim, true
}
