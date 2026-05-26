package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
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
						"panic": rec,
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
						"panic": rec,
					},
				)
			}
		}()

		fn()
	}()
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

	select {

	case job.Data <- msg:

	case <-ctx.Done():

	case <-time.After(
		500 * time.Millisecond,
	):
	}
}

func main() {

	log.SetFlags(0)

	// ====================================
	// auth init
	// ====================================

	auth, err := New("config/users.txt")

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

	// ====================================
	// user store
	// ====================================

	store, err := LoadUserStore(
		"config/usrwg.conf",
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

	// ====================================
	// config
	// ====================================

	cfg := esacfg()

	if cfg == nil {

		logJSON(
			"error",
			"config_load_failed",
			nil,
		)

		return
	}

	// ====================================
	// http server
	// ====================================

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

	// ====================================
	// start server
	// ====================================

	srvErrCh := make(chan error, 1)

	safeGo(func() {

		srvErrCh <- server.ListenAndServe()
	})

	// ====================================
	// workers
	// ====================================

	workerCount := 8

	processJob := func(job *AuthJob) {

		defer func() {

			if rec := recover(); rec != nil {

				logJSON(
					"error",
					"job_panic",
					logFields{
						"panic": rec,
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

		// ====================================
		// user lookup
		// ====================================

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

		// ====================================
		// generate config
		// ====================================

		tmpl := "$usrip\n$servpub\n$subnet\n$endpoint\n$keeptime"

		configStr := os.Expand(
			tmpl,
			func(k string) string {

				switch k {

				case "usrip":
					return usercfg.ip

				case "servpub":
					return cfg.ServPub

				case "subnet":
					return cfg.Subnet

				case "endpoint":
					return cfg.Endpoint

				case "keeptime":
					return cfg.KeepTime

				default:
					return ""
				}
			},
		)

		// ====================================
		// wg update
		// ====================================

		var upconfig upconf

		upconfig.username = job.username
		upconfig.keeptime = cfg.KeepTime
		upconfig.status = true
		upconfig.userip = usercfg.ip
		upconfig.userpublic = job.clientpubkey
		upconfig.wgconfpath = "/etc/wireguard/esa.conf"

		wgCtx, cancel := context.WithTimeout(
			ctx,
			5*time.Second,
		)

		defer cancel()

		err := updatewg(
			wgCtx,
			&upconfig,
			"esa",
		)

		if err != nil {

			logJSON(
				"error",
				"wg_update_failed",
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

		// ====================================
		// success
		// ====================================

		logJSON(
			"info",
			"wg_update_ok",
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

	for i := 0; i < workerCount; i++ {

		safeGo(func() {

			for job := range auth.Jobs {

				processJob(job)
			}
		})
	}

	// ====================================
	// signal handling
	// ====================================

	sigCh := make(chan os.Signal, 1)

	signal.Notify(
		sigCh,
		os.Interrupt,
		syscall.SIGTERM,
	)

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

			return
		}

	case <-sigCh:

		logJSON(
			"info",
			"shutdown_start",
			nil,
		)
	}

	// ====================================
	// shutdown
	// ====================================

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)

	defer cancel()

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
	}

	close(auth.Jobs)

	auth.StopCleanup()

	stopWGSaver()

	logJSON(
		"info",
		"shutdown_complete",
		nil,
	)
}
