//go:build !linux && !darwin

package routes

import (
	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/tun"
)

func SetRoutes(tun *tun.TunAdapter, log *log.Logger, cidrs []string) error {
	return nil
}

func SetAddresses(tun *tun.TunAdapter, log *log.Logger, addresses []string) error {
	return nil
}
