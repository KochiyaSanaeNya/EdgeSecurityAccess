package main

import (
	"net/http"
	"os"
)

func main() {
	auth := New("config/users.txt")
	esacfg := esacfg()
	if esacfg == nil {
		return
	}
	go func() {
		err := http.ListenAndServe(":"+esacfg.HTTPPort, auth)
		if err != nil {
			return
		}
	}()
	for job := range auth.Jobs {
		if job.Ok {
			tmpl := "[Interface]\nPrivateKey = $usrpriv\nAddress = $usrip\n[Peer]\nPublicKey = $servpub\nAllowedIPs = $subnet\nEndpoint = $endpoint\nPersistentKeepalive = $keeptime"
			usercfg := usrcfg(job.username)
			if usercfg == nil {
				job.Data <- "User config not found"
				close(job.Data)
				continue
			}
			configStr := os.Expand(tmpl, func(k string) string {
				switch k {
				case "usrpriv":
					return usercfg.privatekey
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
			upconfig.userpublic = usercfg.publickey
			upconfig.wgconfpath = "/etc/wireguard/esa.conf"
			err := updatewg(&upconfig, "esa")
			if err != nil {
				job.Data <- "Failed to update WireGuard peer"
				close(job.Data)
				continue
			}

			job.Data <- configStr
			close(job.Data)
		} else {
			job.Data <- "Authentication failed"
			close(job.Data)
		}
	}
}
