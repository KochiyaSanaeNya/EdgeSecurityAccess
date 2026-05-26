package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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
	db       map[string]string
	Jobs     chan *AuthJob
	limiters sync.Map
	nonceMu  sync.Mutex
	nonces   map[string]time.Time
	stopCh   chan struct{}
	stopOnce sync.Once
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
	allowedTimeSkew    = 30 * time.Second
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

	for s.Scan() {

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

		if len(p) == 2 {

			user := strings.TrimSpace(p[0])

			if _, exists := db[user]; exists {

				logJSON(
					"warn",
					"users_db_duplicate",
					logFields{
						"user": user,
					},
				)

				continue
			}

			db[user] = strings.TrimSpace(p[1])
		}
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

	now := time.Now()

	limIface, _ := a.limiters.LoadOrStore(
		ip,
		&ipLimiter{
			tokens:   burstTokens,
			last:     now,
			lastSeen: now,
		},
	)

	lim := limIface.(*ipLimiter)

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

	limIface, _ := a.limiters.LoadOrStore(
		ip,
		&ipLimiter{
			tokens:   burstTokens,
			last:     time.Now(),
			lastSeen: time.Now(),
		},
	)

	lim := limIface.(*ipLimiter)

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

	go func() {

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

				a.limiters.Range(func(key, value interface{}) bool {

					lim := value.(*ipLimiter)

					lim.mu.Lock()

					stale := lim.lastSeen.Before(cutoff)

					lim.mu.Unlock()

					if stale {

						a.limiters.Delete(key)

						removed++
					}

					return true
				})

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

	go func() {

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

func isValidNonce(nonce string) bool {

	if len(nonce) < 8 ||
		len(nonce) > 64 {

		return false
	}

	for _, r := range nonce {

		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' ||
			r == '_' {

			continue
		}

		return false
	}

	return true
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

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		maxBodyBytes,
	)

	if err := r.ParseForm(); err != nil {

		logJSON(
			"warn",
			"request_too_large",
			logFields{
				"ip":  ip,
				"err": err.Error(),
			},
		)

		http.Error(
			w,
			"Request too large",
			http.StatusRequestEntityTooLarge,
		)

		return
	}

	u := r.PostFormValue("username")
	p := r.PostFormValue("password")
	c := r.PostFormValue("pubkey")
	tsStr := r.PostFormValue("timestamp")
	nonce := r.PostFormValue("nonce")
	signature := r.PostFormValue("signature")

	if signature == "" {

		http.Error(
			w,
			"Authentication failed",
			http.StatusUnauthorized,
		)

		return
	}

	if !isValidNonce(nonce) {

		http.Error(
			w,
			"Authentication failed",
			http.StatusUnauthorized,
		)

		return
	}

	ts, err := strconv.ParseInt(
		tsStr,
		10,
		64,
	)

	if err != nil {

		http.Error(
			w,
			"Authentication failed",
			http.StatusUnauthorized,
		)

		return
	}

	if delta := time.Since(
		time.Unix(ts, 0),
	); delta > allowedTimeSkew ||
		delta < -allowedTimeSkew {

		http.Error(
			w,
			"Authentication failed",
			http.StatusUnauthorized,
		)

		return
	}

	ok := false

	if pwHash, exists := a.db[u]; exists {

		valid, err := verifyPassword(
			p,
			pwHash,
		)

		if err == nil && valid {

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

					now := time.Now()

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
			time.Sleep(failDelay)
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
