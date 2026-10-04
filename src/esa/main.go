package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logJSON("error", "http_panic", logFields{"panic": fmt.Sprint(recovered)})
				http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func safeGo(function func()) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				logJSON("error", "goroutine_panic", logFields{"panic": fmt.Sprint(recovered)})
			}
		}()
		function()
	}()
}

func deliver(job *AuthJob, message string) {
	if job == nil {
		return
	}
	ctx := job.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case job.Data <- message:
	case <-ctx.Done():
	case <-timer.C:
	}
}

func main() {
	log.SetFlags(0)
	auth, err := New("config/users.txt")
	if err != nil {
		logJSON("error", "users_db_init_failed", logFields{"err": err.Error()})
		return
	}
	store, err := LoadUserStore("config/usrwg.conf")
	if err != nil {
		logJSON("error", "usercfg_load_failed", logFields{"err": err.Error()})
		return
	}
	cfg := esacfg()
	if cfg == nil {
		return
	}
	userStore = store
	auth.StartLimiterCleanup()
	auth.StartNonceCleanup()

	server := &http.Server{
		Addr:              cfg.IPPort,
		Handler:           withRecover(auth),
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(os.Stderr, "", 0),
	}
	logJSON("info", "server_start", logFields{"addr": server.Addr})

	workerCount := configuredWorkerCount()
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	defer cancelWorkers()
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		safeGo(func() {
			defer workers.Done()
			for {
				select {
				case job, open := <-auth.Jobs:
					if !open {
						return
					}
					processWGJob(workerCtx, job, cfg)
				case <-workerCtx.Done():
					return
				}
			}
		})
	}

	serverErrors := make(chan error, 1)
	safeGo(func() { serverErrors <- server.ListenAndServe() })
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case serverErr := <-serverErrors:
		if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
			logJSON("error", "server_error", logFields{"err": serverErr.Error()})
		}
	case received := <-signals:
		logJSON("info", "shutdown_start", logFields{"signal": received.String()})
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	if err := server.Shutdown(shutdownCtx); err != nil {
		logJSON("error", "shutdown_failed", logFields{"err": err.Error()})
	}
	cancelShutdown()
	cancelWorkers()
	close(auth.Jobs)
	workersDone := make(chan struct{})
	go func() { workers.Wait(); close(workersDone) }()
	select {
	case <-workersDone:
	case <-time.After(5 * time.Second):
		logJSON("warn", "workers_stop_timeout", nil)
	}
	auth.StopCleanup()
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 2*time.Second)
	if err := auth.WaitCleanup(cleanupCtx); err != nil {
		logJSON("warn", "cleanup_stop_timeout", logFields{"err": err.Error()})
	}
	cancelCleanup()
	stopWGSaver()
	logJSON("info", "shutdown_complete", nil)
}

func configuredWorkerCount() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("ESA_WORKERS")))
	if err != nil || value < 1 || value > 128 {
		return 8
	}
	return value
}

func processWGJob(workerCtx context.Context, job *AuthJob, cfg *Config) {
	if job == nil || cfg == nil {
		return
	}
	ctx := job.Ctx
	if ctx == nil {
		ctx = workerCtx
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	user := userStore.Get(job.username)
	if user == nil {
		deliver(job, "User not found")
		return
	}
	configText := strings.Join([]string{user.ip, cfg.ServPub, cfg.Subnet, cfg.Endpoint, cfg.KeepTime}, "\n")
	peer := &upconf{
		username:   job.username,
		keeptime:   cfg.KeepTime,
		status:     true,
		userip:     user.ip,
		userpublic: job.clientpubkey,
		wgconfpath: strings.TrimSpace(os.Getenv("ESA_WG_CONF")),
	}
	if peer.wgconfpath == "" {
		peer.wgconfpath = "/etc/wireguard/esa.conf"
	}
	interfaceName := strings.TrimSpace(os.Getenv("ESA_WG_INTERFACE"))
	if interfaceName == "" {
		interfaceName = "esa"
	}
	updateCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := updatewg(updateCtx, peer, interfaceName); err != nil {
		logJSON("error", "wg_update_failed", logFields{"user": job.username, "ip": job.clientip, "pubkey_hash": pubKeyHash(job.clientpubkey), "err": err.Error()})
		deliver(job, "Internal error")
		return
	}
	logJSON("info", "wg_update_ok", logFields{"user": job.username, "ip": job.clientip})
	deliver(job, configText)
}
