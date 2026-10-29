//go:build darwin

package darwin

// Transparent proxy lifecycle.
//
// The system extension's TransparentProxyProvider sends each outbound TCP
// flow from a session process to the daemon, which applies the session's
// network policy. Like the content filter, the provider runs only while an
// enabled NETransparentProxyManager configuration exists, and that
// configuration also has to be started. The calling binary needs
// app-proxy-provider-systemextension in its networkextension entitlement.

// ProxyState describes the installed NETransparentProxyManager configuration.
type ProxyState struct {
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	Error     string `json:"error,omitempty"`
}

// InstallTransparentProxy saves an enabled transparent proxy configuration
// and starts it. The first call can raise a system prompt, and
// ActivateNeedsApproval means that the prompt is still open.
func InstallTransparentProxy() (ActivateResult, error) {
	return installTransparentProxy(contentFilterDescription)
}

// RemoveTransparentProxy stops and deletes the configuration. Call it before
// deactivating the system extension, as with RemoveContentFilter.
func RemoveTransparentProxy() (ActivateResult, error) {
	return removeTransparentProxy()
}

// CheckTransparentProxy reports the configuration state. Failures are
// recorded in State.Error.
func CheckTransparentProxy() ProxyState {
	installed, enabled, running, err := transparentProxyStatus()
	state := ProxyState{Installed: installed, Enabled: enabled, Running: running}
	if err != nil {
		state.Error = err.Error()
	}
	return state
}
