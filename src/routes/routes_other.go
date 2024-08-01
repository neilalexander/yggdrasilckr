//go:build !linux

package routes

import (
	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/tun"
)

func SetRoutes(tun *tun.TunAdapter, log *log.Logger, cidrs []string) error {
	return nil
}
