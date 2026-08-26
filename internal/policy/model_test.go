package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSignalRuleParsing(t *testing.T) {
	yamlData := `
version: 1
name: test
signal_rules:
  - name: block-external-kill
    signals: ["@fatal", "SIGKILL"]
    target:
      type: external
    decision: deny
    fallback: audit
`
	var p Policy
	err := yaml.Unmarshal([]byte(yamlData), &p)
	require.NoError(t, err)
	require.Len(t, p.SignalRules, 1)
	assert.Equal(t, "block-external-kill", p.SignalRules[0].Name)
	assert.Equal(t, []string{"@fatal", "SIGKILL"}, p.SignalRules[0].Signals)
	assert.Equal(t, "external", p.SignalRules[0].Target.Type)
	assert.Equal(t, "deny", p.SignalRules[0].Decision)
	assert.Equal(t, "audit", p.SignalRules[0].Fallback)
}

func TestPolicy_EnvInject(t *testing.T) {
	yamlData := `
version: 1
name: test-env-inject

env_inject:
  BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
  MY_CUSTOM_VAR: "custom_value"
`
	var p Policy
	err := yaml.Unmarshal([]byte(yamlData), &p)
	require.NoError(t, err)
	require.NotNil(t, p.EnvInject)
	assert.Len(t, p.EnvInject, 2)
	assert.Equal(t, "/usr/lib/agentsh/bash_startup.sh", p.EnvInject["BASH_ENV"])
	assert.Equal(t, "custom_value", p.EnvInject["MY_CUSTOM_VAR"])
}

func TestPolicy_EnvInject_Empty(t *testing.T) {
	yamlData := `
version: 1
name: test-no-env-inject
`
	var p Policy
	err := yaml.Unmarshal([]byte(yamlData), &p)
	require.NoError(t, err)
	assert.Nil(t, p.EnvInject)
}
