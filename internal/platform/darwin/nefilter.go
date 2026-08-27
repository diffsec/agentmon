//go:build darwin

package darwin

// Content filter lifecycle.
//
// The system extension declares FilterDataProvider under NEProviderClasses and
// main.swift calls NEProvider.startSystemExtensionMode(), but neither of those
// starts filtering. macOS instantiates the provider and calls startFilter only
// once an NEFilterManager configuration exists and is enabled. Nothing created
// that configuration, which is why network_rules have never been enforced on
// macOS however correct the policy or the provider code was.
//
// The calling binary needs com.apple.developer.networking.networkextension with
// content-filter-provider-systemextension, which agentmon claims (see
// macos/AgentMon/agentmon/agentmon.entitlements). A binary without it is killed
// by AMFI rather than returning an error, so there is no useful runtime check.

const (
	// contentFilterDescription is what the user sees in
	// System Settings > Network > Filters.
	contentFilterDescription = "AgentMon"
	// contentFilterOrganization is shown alongside it.
	contentFilterOrganization = "diffsec"
)

// ContentFilterState describes the installed NEFilterManager configuration.
//
// Installed and Enabled are reported separately on purpose: a configuration
// that exists but is disabled never has startFilter called, so from the
// provider's point of view it is indistinguishable from no configuration, and
// collapsing the two would hide a real half-configured state.
type ContentFilterState struct {
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Error     string `json:"error,omitempty"`
}

// Enforcing reports whether the filter is in the only state that causes flows
// to reach FilterDataProvider.handleNewFlow.
func (s ContentFilterState) Enforcing() bool { return s.Installed && s.Enabled }

// InstallContentFilter creates or updates the content filter configuration and
// enables it, blocking until macOS answers.
//
// The first call raises a system prompt asking the user to allow AgentMon to
// filter network content. ActivateNeedsApproval means that prompt is still
// unanswered: nothing is filtering yet, and the caller must say so rather than
// report success.
func InstallContentFilter() (ActivateResult, error) {
	return installContentFilter(contentFilterDescription, contentFilterOrganization)
}

// RemoveContentFilter deletes the content filter configuration.
//
// Call this before deactivating the system extension, while the extension is
// still present. A configuration that outlives its provider leaves a dead entry
// in System Settings > Network > Filters that the next install inherits.
func RemoveContentFilter() (ActivateResult, error) {
	return removeContentFilter()
}

// CheckContentFilter reports the current configuration state. It never returns
// an error; failures are recorded in State.Error so callers that are reporting
// status rather than acting on it do not have to branch.
func CheckContentFilter() ContentFilterState {
	installed, enabled, err := contentFilterStatus()
	state := ContentFilterState{Installed: installed, Enabled: enabled}
	if err != nil {
		state.Error = err.Error()
	}
	return state
}
