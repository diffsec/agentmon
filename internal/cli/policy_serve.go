package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/diffsec/agentmon/internal/policyserve"
	"github.com/diffsec/agentmon/pkg/hotreload"
)

func newPolicyServeCmd(configPath *string, dir *string) *cobra.Command {
	var (
		listen        string
		bindingsPath  string
		defaultPolicy string
		trustStore    string
		allowUnsigned bool
		watch         bool
		tlsCert       string
		tlsKey        string
		clientCA      string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve signed policy bundles to agents",
		Long: `Serve signed policy bundles over HTTP.

The server holds no signing key. It reads bundles signed elsewhere -- offline
or by a KMS -- and serves them unchanged, so compromising the server yields no
policy an agent will enforce: every agent verifies the signature against its
own trust store before installing.

Agents fetch with a conditional GET and may long-poll (?wait=30s), so a bundle
replaced in the policy directory reaches running agents without a restart.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pdir, err := resolvePolicyDir(*configPath, *dir)
			if err != nil {
				return err
			}
			if bindingsPath == "" && defaultPolicy == "" {
				// Guessing here would pick a policy from a directory that may
				// hold several, and the wrong guess is served to the fleet.
				return fmt.Errorf("pass --bindings or --default-policy to say which policy an agent gets")
			}
			store, err := policyserve.NewDirStore(policyserve.StoreConfig{
				PolicyDir:      pdir,
				BindingsPath:   bindingsPath,
				DefaultPolicy:  defaultPolicy,
				TrustStorePath: trustStore,
				AllowUnsigned:  allowUnsigned,
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			if watch {
				w, werr := hotreload.NewPolicyWatcher(hotreload.WatcherConfig{
					PolicyDir: pdir,
					Loader:    store,
					OnChange: func(path string, err error) {
						if err != nil {
							fmt.Fprintf(cmd.ErrOrStderr(), "policy serve: reload failed for %s: %v\n", filepath.Base(path), err)
							return
						}
						fmt.Fprintf(cmd.ErrOrStderr(), "policy serve: reloaded after %s\n", filepath.Base(path))
					},
					OnStaging: func(path string, err error) {
						if err != nil {
							fmt.Fprintf(cmd.ErrOrStderr(), "policy serve: staged bundle rejected %s: %v\n", filepath.Base(path), err)
							return
						}
						fmt.Fprintf(cmd.ErrOrStderr(), "policy serve: published %s\n", filepath.Base(path))
					},
				})
				if werr != nil {
					return fmt.Errorf("watch %s: %w", pdir, werr)
				}
				if werr := w.Start(ctx); werr != nil {
					return fmt.Errorf("watch %s: %w", pdir, werr)
				}
				defer func() { _ = w.Stop() }()
			}

			tlsCfg, err := serveTLSConfig(tlsCert, tlsKey, clientCA)
			if err != nil {
				return err
			}
			srv := &http.Server{
				Addr:    listen,
				Handler: policyserve.NewServer(store, nil).Handler(),
				// Long-poll holds a request open for up to policyserve.MaxWait,
				// so a write timeout below that would cut every long poll at
				// the deadline. The header timeout still bounds a slowloris.
				ReadHeaderTimeout: 15 * time.Second,
				WriteTimeout:      policyserve.MaxWait + 30*time.Second,
				IdleTimeout:       2 * time.Minute,
				TLSConfig:         tlsCfg,
			}

			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", listen, err)
			}
			scheme := "http"
			if tlsCfg != nil {
				scheme = "https"
			}
			policies, bindings := store.Stats()
			fmt.Fprintf(cmd.OutOrStdout(), "policy serve: %s://%s/v1/policy (%d policies, %d bindings, dir %s)\n",
				scheme, ln.Addr(), policies, bindings, pdir)

			errCh := make(chan error, 1)
			go func() {
				if tlsCfg != nil {
					errCh <- srv.ServeTLS(ln, "", "")
					return
				}
				errCh <- srv.Serve(ln)
			}()

			select {
			case <-ctx.Done():
				shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return srv.Shutdown(shutCtx)
			case err := <-errCh:
				if err == http.ErrServerClosed {
					return nil
				}
				return err
			}
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8787", "Listen address")
	cmd.Flags().StringVar(&bindingsPath, "bindings", "", "Bindings file mapping agents to policies")
	cmd.Flags().StringVar(&defaultPolicy, "default-policy", "", "Policy file name served to every agent when --bindings is absent")
	cmd.Flags().StringVar(&trustStore, "trust-store", "", "Directory of trusted public keys used to verify bundles before serving")
	cmd.Flags().BoolVar(&allowUnsigned, "allow-unsigned", false, "Serve bundles without verifying a signature (development only)")
	cmd.Flags().BoolVar(&watch, "watch", true, "Reload when the policy directory changes")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Server certificate (PEM)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Server private key (PEM)")
	cmd.Flags().StringVar(&clientCA, "client-ca", "", "CA bundle requiring and verifying client certificates (mTLS)")
	return cmd
}

// serveTLSConfig builds the listener's TLS config. Returns nil for plaintext.
//
// A client CA without a server certificate is refused rather than ignored: the
// flag reads as "require client certificates", and honouring it on a plaintext
// listener is impossible, so accepting it would authenticate nothing while
// looking like it authenticated everything.
func serveTLSConfig(certFile, keyFile, clientCA string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		if clientCA != "" {
			return nil, fmt.Errorf("--client-ca requires --tls-cert and --tls-key")
		}
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("--tls-cert and --tls-key must be given together")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client CA %s contains no certificates", clientCA)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
