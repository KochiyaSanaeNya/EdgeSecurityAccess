package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func withRecover(next http.Handler) http.Handler {

	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {

		defer func() {

			if rec := recover(); rec != nil {

				logJSON(
					"error",
					"http_panic",
					logFields{
						"panic": logRecoverValue(rec),
					},
				)

				http.Error(
					w,
					"Internal Server Error",
					http.StatusInternalServerError,
				)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func safeGo(fn func()) {

	go func() {

		defer func() {

			if rec := recover(); rec != nil {

				logJSON(
					"error",
					"goroutine_panic",
					logFields{
						"panic": logRecoverValue(rec),
					},
				)
			}
		}()

		fn()
	}()
}

func tincNodeName(username string) string {
	h := sha256.Sum256([]byte(username))
	return "u" + hex.EncodeToString(h[:16])
}

func deliver(
	job *AuthJob,
	msg string,
) {

	if job == nil {
		return
	}

	ctx := job.Ctx

	if ctx == nil {
		ctx = context.Background()
	}

	select {

	case <-ctx.Done():
		return

	default:
	}

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case job.Data <- msg:
	case <-ctx.Done():
	case <-timer.C:
	}
}

func main() {

	log.SetFlags(0)

	paths, err := LoadOrCreateAppPaths()

	if err != nil {

		logJSON(
			"error",
			"path_config_failed",
			logFields{
				"err": err.Error(),
			},
		)

		return
	}

	auth, err := New(paths.UsersFile())

	if err != nil {

		logJSON(
			"error",
			"users_db_init_failed",
			logFields{
				"err": err.Error(),
			},
		)

		return
	}

	auth.StartLimiterCleanup()
	auth.StartNonceCleanup()

	store, err := LoadUserStore(
		paths.UserTincFile(),
	)

	if err != nil {

		logJSON(
			"error",
			"usercfg_load_failed",
			logFields{
				"err": err.Error(),
			},
		)

		return
	}

	userStore = store

	cfg := esacfg(paths.ESAConfigFile())

	if cfg == nil {

		logJSON(
			"error",
			"config_load_failed",
			nil,
		)

		return
	}

	server := &http.Server{
		Addr: cfg.IPPort,

		Handler: withRecover(auth),

		ReadTimeout: 5 * time.Second,

		WriteTimeout: 10 * time.Second,

		IdleTimeout: 30 * time.Second,

		MaxHeaderBytes: 1 << 20,

		ErrorLog: log.New(
			os.Stderr,
			"",
			0,
		),
	}

	logJSON(
		"info",
		"server_start",
		logFields{
			"addr": server.Addr,
		},
	)

	srvErrCh := make(chan error, 1)

	safeGo(func() {

		srvErrCh <- server.ListenAndServe()
	})

	workerCount := 8

	processJob := func(job *AuthJob) {

		defer func() {

			if rec := recover(); rec != nil {

				logJSON(
					"error",
					"job_panic",
					logFields{
						"panic": logRecoverValue(rec),
					},
				)
			}
		}()

		ctx := job.Ctx

		if ctx == nil {
			ctx = context.Background()
		}

		select {

		case <-ctx.Done():

			logJSON(
				"warn",
				"job_canceled",
				logFields{
					"user": job.username,
					"ip":   job.clientip,
				},
			)

			return

		default:
		}

		usercfg := userStore.Get(
			job.username,
		)

		if usercfg == nil {

			logJSON(
				"warn",
				"user_not_found",
				logFields{
					"user": job.username,
					"ip":   job.clientip,
				},
			)

			deliver(
				job,
				"User not found",
			)

			return
		}

		nodeName := tincNodeName(job.username)
		tmpl := "$node\n$usrip\n$servname\n$servpub\n$subnet\n$endpoint\n$tincport"

		configStr := os.Expand(
			tmpl,
			func(k string) string {

				switch k {

				case "node":
					return nodeName

				case "usrip":
					return usercfg.ip

				case "servname":
					return cfg.ServName

				case "servpub":
					return cfg.ServPub

				case "subnet":
					return cfg.Subnet

				case "endpoint":
					return cfg.Endpoint

				case "tincport":
					return strconv.Itoa(int(cfg.TincPort))

				default:
					return ""
				}
			},
		)

		var upconfig upconf

		upconfig.username = job.username
		upconfig.nodename = nodeName
		upconfig.status = true
		upconfig.userip = usercfg.ip
		upconfig.userpublic = job.clientpubkey
		upconfig.tincDir = cfg.TincDir

		tincCtx, cancel := context.WithTimeout(
			ctx,
			5*time.Second,
		)

		defer cancel()

		err := updateTinc(
			tincCtx,
			&upconfig,
			cfg.TincNet,
			paths.TincBinDir,
			paths.TincReload,
		)

		if err != nil {

			logJSON(
				"error",
				"tinc_update_failed",
				logFields{
					"user":        job.username,
					"ip":          job.clientip,
					"pubkey_hash": pubKeyHash(job.clientpubkey),
					"err":         err.Error(),
				},
			)

			deliver(
				job,
				"Internal error",
			)

			return
		}

		logJSON(
			"info",
			"tinc_update_ok",
			logFields{
				"user": job.username,
				"ip":   job.clientip,
			},
		)

		deliver(
			job,
			configStr,
		)
	}

	var workerWG sync.WaitGroup

	workerWG.Add(workerCount)

	for i := 0; i < workerCount; i++ {

		safeGo(func() {

			defer workerWG.Done()

			for job := range auth.Jobs {

				processJob(job)
			}
		})
	}

	closeJobs := sync.Once{}

	stopWorkers := func(ctx context.Context) error {

		closeJobs.Do(func() {
			close(auth.Jobs)
		})

		done := make(chan struct{})

		go func() {
			workerWG.Wait()
			close(done)
		}()

		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	sigCh := make(chan os.Signal, 1)

	signal.Notify(
		sigCh,
		os.Interrupt,
		syscall.SIGTERM,
	)

	shutdownRequested := false

	select {

	case err := <-srvErrCh:

		if err != nil &&
			!errors.Is(
				err,
				http.ErrServerClosed,
			) {

			logJSON(
				"error",
				"server_error",
				logFields{
					"err": err.Error(),
				},
			)
		}

	case sig := <-sigCh:

		shutdownRequested = true

		logJSON(
			"info",
			"shutdown_start",
			logFields{
				"signal": sig.String(),
			},
		)
	}

	signal.Stop(sigCh)
	close(sigCh)

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)

	if err := server.Shutdown(
		shutdownCtx,
	); err != nil {

		logJSON(
			"error",
			"shutdown_failed",
			logFields{
				"err": err.Error(),
			},
		)

		if closeErr := server.Close(); closeErr != nil {
			logJSON(
				"error",
				"server_close_failed",
				logFields{
					"err": closeErr.Error(),
				},
			)
		}
	}

	cancel()

	workerCtx, workerCancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)

	if err := stopWorkers(workerCtx); err != nil {
		logJSON(
			"warn",
			"workers_stop_timeout",
			logFields{
				"err": err.Error(),
			},
		)
	}

	workerCancel()

	auth.StopCleanup()

	cleanupCtx, cleanupCancel := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)

	if err := auth.WaitCleanup(cleanupCtx); err != nil {
		logJSON(
			"warn",
			"cleanup_stop_timeout",
			logFields{
				"err": err.Error(),
			},
		)
	}

	cleanupCancel()

	logJSON(
		"info",
		"shutdown_complete",
		logFields{
			"requested": shutdownRequested,
		},
	)
}
