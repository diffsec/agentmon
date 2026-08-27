//go:build darwin && !cgo

package darwin

import "fmt"

var errNoCgoFilter = fmt.Errorf("content filter configuration requires CGO")

func installContentFilter(_, _ string) (ActivateResult, error) {
	return ActivateFailed, errNoCgoFilter
}

func removeContentFilter() (ActivateResult, error) {
	return ActivateFailed, errNoCgoFilter
}

func contentFilterStatus() (installed, enabled bool, err error) {
	return false, false, errNoCgoFilter
}
