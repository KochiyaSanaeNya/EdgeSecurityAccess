package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"
)

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic: %v", rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func safeGo(fn func()) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic: %v", rec)
			}
		}()
		fn()
	}()
}

func deliver(job *AuthJob, msg string) {
	if job == nil {
		return
	}
	ctx := job.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case job.Data <- msg:
		close(job.Data)
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
	}
}

func main() {
	log.SetFlags(log.LstdFlags)

	auth := New("config/users.txt")
	auth.StartLimiterCleanup()
	esacfg := esacfg()
	if esacfg == nil {
		log.Println("config load failed")
		return
	}

	server := &http.Server{
		Addr:           "127.0.0.1" + ":" + esacfg.HTTPPort,
		Handler:        withRecover(auth),
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 1 << 20,
		ErrorLog:       log.New(os.Stderr, "", log.LstdFlags),
	}

	safeGo(func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	})

	workerTokens := make(chan struct{}, 8)
	for job := range auth.Jobs {
		workerTokens <- struct{}{}
		safeGo(func() {
			defer func() {
				<-workerTokens
			}()
			func(job *AuthJob) {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("panic: %v", rec)
					}
				}()

				ctx := job.Ctx
				if ctx == nil {
					ctx = context.Background()
				}

				select {
				case <-ctx.Done():
					return
				default:
				}

				if job.Ok {
					tmpl := "$usrip\n$servpub\n$subnet\n$endpoint\n$keeptime"
					usercfg := usrcfg(job.username)
					if usercfg == nil {
						deliver(job, "User not found")
						return
					}

					configStr := os.Expand(tmpl, func(k string) string {
						switch k {
						case "usrip":
							return usercfg.ip
						case "servpub":
							return esacfg.ServPub
						case "subnet":
							return esacfg.Subnet
						case "endpoint":
							return esacfg.Endpoint
						case "keeptime":
							return esacfg.KeepTime
						default:
							return ""
						}
					})

					var upconfig upconf
					upconfig.username = job.username
					upconfig.keeptime = esacfg.KeepTime
					upconfig.status = true
					upconfig.userip = usercfg.ip
					upconfig.userpublic = job.clientpubkey
					upconfig.wgconfpath = "/etc/wireguard/esa.conf"

					wgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()

					err := updatewg(wgCtx, &upconfig, "esa")
					if err != nil {
						log.Println(err)
						deliver(job, "Internal error")
						return
					}

					deliver(job, configStr)
				} else {
					deliver(job, "Authentication failed")
				}
			}(job)
		})
	}
}
