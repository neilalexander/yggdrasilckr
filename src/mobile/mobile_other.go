//go:build !android && !ios && !macos
// +build !android,!ios,!macos

package mobile

import "fmt"

type MobileLogger struct {
}

func (nsl MobileLogger) Write(p []byte) (n int, err error) {
	fmt.Print(string(p))
	return len(p), nil
}
