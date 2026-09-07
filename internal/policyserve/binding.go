// Package policyserve serves signed policy bundles to agents over HTTP.
//
// The server holds no signing key. It reads bundles that were signed
// elsewhere -- offline, or by a KMS -- and hands them out unchanged, so
// compromising the server yields no policy any agent will enforce: the
// signature is verified against the agent's own trust store on the load path
// (internal/policy/manager.go verifyBundle), whatever the source.
package policyserve

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gobwas/glob"
)

// Selector is what an agent tells the server about itself. It mirrors the
// fields internal/decisionctx already resolves and reports to Watchtower, so
// binding a policy to identity uses the signals the agent already collects
// rather than a second identity scheme.
type Selector struct {
	Tenant   string
	Hostname string
	User     string
	Tags     []string
}

// Match constrains which agents a Binding applies to.
//
// An empty list leaves that field unconstrained; every non-empty field must
// match, so adding a field narrows a binding and never widens it. That
// direction matters: a typo in a new field then serves nothing rather than
// serving everything.
type Match struct {
	Tenants   []string `yaml:"tenants,omitempty"`
	Hostnames []string `yaml:"hostnames,omitempty"`
	Users     []string `yaml:"users,omitempty"`
	Tags      []string `yaml:"tags,omitempty"`
}

// Binding maps matching agents to a policy file in the served directory.
type Binding struct {
	// Name labels the binding in logs. Optional.
	Name string `yaml:"name,omitempty"`
	// Policy is the file name within the policy directory, e.g. "strict.yaml".
	Policy string `yaml:"policy"`
	// Match is the constraint. Omitted entirely, the binding is a catch-all.
	Match *Match `yaml:"match,omitempty"`
}

// BindingFile is the on-disk bindings document.
type BindingFile struct {
	Bindings []Binding `yaml:"bindings"`
}

type compiledMatch struct {
	tenants   []glob.Glob
	hostnames []glob.Glob
	users     []glob.Glob
	tags      []string
}

type compiledBinding struct {
	name   string
	policy string
	match  *compiledMatch
}

func compileGlobs(field string, pats []string) ([]glob.Glob, error) {
	out := make([]glob.Glob, 0, len(pats))
	for _, p := range pats {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("%s: empty pattern", field)
		}
		g, err := glob.Compile(strings.ToLower(p))
		if err != nil {
			return nil, fmt.Errorf("%s: pattern %q: %w", field, p, err)
		}
		out = append(out, g)
	}
	return out, nil
}

func compileBindings(bf *BindingFile) ([]compiledBinding, error) {
	if bf == nil || len(bf.Bindings) == 0 {
		return nil, fmt.Errorf("no bindings defined")
	}
	out := make([]compiledBinding, 0, len(bf.Bindings))
	for i, b := range bf.Bindings {
		name := b.Name
		if name == "" {
			name = fmt.Sprintf("binding[%d]", i)
		}
		if strings.TrimSpace(b.Policy) == "" {
			return nil, fmt.Errorf("%s: policy is required", name)
		}
		// A binding naming a path rather than a file in the served directory
		// would read a policy the operator never staged or signed for serving.
		if strings.ContainsAny(b.Policy, `/\`) || b.Policy == "." || b.Policy == ".." {
			return nil, fmt.Errorf("%s: policy %q must be a file name in the policy directory", name, b.Policy)
		}
		cb := compiledBinding{name: name, policy: b.Policy}
		if b.Match != nil {
			cm := &compiledMatch{}
			var err error
			if cm.tenants, err = compileGlobs(name+": tenants", b.Match.Tenants); err != nil {
				return nil, err
			}
			if cm.hostnames, err = compileGlobs(name+": hostnames", b.Match.Hostnames); err != nil {
				return nil, err
			}
			if cm.users, err = compileGlobs(name+": users", b.Match.Users); err != nil {
				return nil, err
			}
			for _, t := range b.Match.Tags {
				t = strings.TrimSpace(strings.ToLower(t))
				if t == "" {
					return nil, fmt.Errorf("%s: tags: empty tag", name)
				}
				cm.tags = append(cm.tags, t)
			}
			sort.Strings(cm.tags)
			cb.match = cm
		}
		out = append(out, cb)
	}
	return out, nil
}

func matchAny(globs []glob.Glob, value string) bool {
	if len(globs) == 0 {
		return true
	}
	v := strings.ToLower(value)
	for _, g := range globs {
		if g.Match(v) {
			return true
		}
	}
	return false
}

// matches reports whether sel satisfies the binding.
func (c compiledBinding) matches(sel Selector) bool {
	if c.match == nil {
		return true
	}
	if !matchAny(c.match.tenants, sel.Tenant) {
		return false
	}
	if !matchAny(c.match.hostnames, sel.Hostname) {
		return false
	}
	if !matchAny(c.match.users, sel.User) {
		return false
	}
	// Every listed tag must be present. A host carries a set of tags, so an
	// any-of test would let one tag out of ten select the binding -- the
	// opposite of what `tags: [prod, pci]` reads as.
	if len(c.match.tags) > 0 {
		have := make(map[string]struct{}, len(sel.Tags))
		for _, t := range sel.Tags {
			have[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
		}
		for _, want := range c.match.tags {
			if _, ok := have[want]; !ok {
				return false
			}
		}
	}
	return true
}
