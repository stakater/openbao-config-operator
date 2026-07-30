package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// authLog resolves lazily against the controller-runtime global logger, which
// main() configures before any reconcile can trigger a login.
var authLog = logf.Log.WithName("bao-auth")

// Kubernetes-auth mode: the client trades the pod's projected ServiceAccount
// JWT for a bao token at auth/<mount>/login and caches it until it nears
// expiry. There is no background renewal — login is cheap and repeatable, so
// expiry is handled by logging in again on the next call.

const (
	defaultAuthMount = "k8s-operator"
	defaultAuthRole  = "openbao-config-operator"
	// defaultJWTPath is where the deployment mounts the projected
	// ServiceAccount token (audience-bound to bao, distinct from the
	// default API-server audience).
	defaultJWTPath = "/var/run/secrets/openbao/token"

	loginReasonExpiry    = "expiry"
	loginReasonForbidden = "forbidden"
)

var loginTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "obx_bao_login_total",
	Help: "OpenBao kubernetes-auth login attempts by the operator, by outcome " +
		"and trigger (expiry: cache empty or past its refresh point; " +
		"forbidden: a 403 forced a re-login).",
}, []string{"outcome", "reason"})

func init() {
	metrics.Registry.MustRegister(loginTotal)
}

// loginManager holds the cached bao token for kubernetes-auth mode. The
// mutex is held across the login call itself so concurrent reconcilers
// with an expired cache trigger exactly one login instead of a stampede.
type loginManager struct {
	// login performs the actual auth/<mount>/login exchange and returns
	// the client token plus its lease duration in seconds. Injectable so
	// unit tests can drive cache behavior without a bao server.
	login func(ctx context.Context) (token string, leaseSeconds int, err error)
	// now is time.Now, injectable for expiry tests.
	now func() time.Time

	mu        sync.Mutex
	token     string
	refreshAt time.Time
}

// Token returns the cached token, logging in first when the cache is empty
// or past ~80% of the token's lease. The 20% headroom keeps a token that is
// handed out here from expiring mid-request.
func (m *loginManager) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokenLocked(ctx, loginReasonExpiry)
}

// Replace drops `failed` from the cache and returns the token to retry with.
// Dropping and logging in under one lock means concurrent callers that all saw
// a 403 on the same token produce one login, not one each: whoever gets the
// lock second finds a different cached token and takes it as-is.
func (m *loginManager) Replace(ctx context.Context, failed string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token == failed {
		m.token = ""
	}
	return m.tokenLocked(ctx, loginReasonForbidden)
}

// tokenLocked implements Token/Replace once m.mu is held; reason labels the
// metric for whichever of them triggered the login.
func (m *loginManager) tokenLocked(ctx context.Context, reason string) (string, error) {
	if m.token != "" && m.now().Before(m.refreshAt) {
		return m.token, nil
	}
	token, leaseSeconds, err := m.login(ctx)
	if err != nil {
		loginTotal.WithLabelValues("failure", reason).Inc()
		authLog.Error(err, "bao login failed", "reason", reason)
		return "", err
	}
	loginTotal.WithLabelValues("success", reason).Inc()
	authLog.Info("bao login succeeded", "reason", reason, "leaseSeconds", leaseSeconds)
	m.token = token
	// A zero lease means the token does not expire (bao only issues those
	// to root-like tokens); re-login hourly anyway so a revocation without
	// a 403-observing call still heals.
	lease := time.Duration(leaseSeconds) * time.Second
	if lease <= 0 {
		lease = time.Hour
	}
	m.refreshAt = m.now().Add(lease * 8 / 10)
	return m.token, nil
}

// authTransport injects the managed token into every request as the
// X-Vault-Token header. Injecting per-request instead of calling SetToken on
// the shared vault client keeps token replacement race-free without relying on
// SDK locking internals. The login path is exempt: it authenticates with the
// JWT in its body, and since it runs on this same client, asking the manager
// for a token here would re-enter the mutex the login already holds.
type authTransport struct {
	base      http.RoundTripper
	mgr       *loginManager
	loginPath string
}

// loginError marks the failure of a login exchange, as distinct from the
// failure of the call that triggered it. The retry policy stops on it: the
// login request has already been retried on its own terms, so retrying the
// outer call would re-run whole logins and their failure metric while bao is
// sealed or the role is missing. Reconcile requeues are the retry loop there.
type loginError struct{ err error }

func (e *loginError) Error() string { return "bao kubernetes-auth login: " + e.err.Error() }
func (e *loginError) Unwrap() error { return e.err }

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == t.loginPath {
		return t.base.RoundTrip(req)
	}
	token, err := t.mgr.Token(req.Context())
	if err != nil {
		return nil, &loginError{err}
	}
	resp, err := t.send(req, token)
	if err != nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		return resp, err
	}
	// A 403 carries no marker for which cause produced it: the cached token was
	// revoked out of band, or the call is denied by the operator's policy. So
	// replay exactly once with a replaced token — that heals a revocation,
	// while a real denial costs one extra call and reaches ClassifyErr with its
	// 403 intact. Replaying more (as a CheckRetry hook would, up to MaxRetries)
	// cannot turn a denial into a success; it only multiplies logins and
	// backoff on every reconcile of a CR that is denied by design.
	fresh, err := t.mgr.Replace(req.Context(), token)
	if err != nil || fresh == token {
		return resp, nil
	}
	replay, err := rewind(req)
	if err != nil {
		authLog.Error(err, "not replaying request after re-login", "path", req.URL.Path)
		return resp, nil
	}
	// Nobody else will close the superseded response. Drain it first, bounded,
	// so the connection returns to the pool instead of being torn down.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return t.send(replay, fresh)
}

// send issues req with the given bao token attached.
func (t *authTransport) send(req *http.Request, token string) (*http.Response, error) {
	// RoundTripper contract: do not mutate the caller's request.
	req = req.Clone(req.Context())
	req.Header.Set("X-Vault-Token", token)
	return t.base.RoundTrip(req)
}

// rewind copies req with its body reset so an already-sent request can be sent
// again. Bodies built by the vault SDK are buffered by retryablehttp, which
// populates GetBody; anything else is reported as unreplayable rather than
// resent with a consumed body.
func rewind(req *http.Request) (*http.Request, error) {
	replay := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return replay, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("request body is not rewindable")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("rewind request body: %w", err)
	}
	replay.Body = body
	return replay, nil
}

// k8sLogin performs POST auth/<mount>/login with the ServiceAccount JWT read
// fresh from jwtPath — kubelet rotates projected tokens, so the file must be
// re-read on every login, never cached.
func k8sLogin(ctx context.Context, v *vault.Client, mount, role, jwtPath string) (string, int, error) {
	jwt, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", 0, fmt.Errorf("read service account token: %w", err)
	}
	path := "auth/" + strings.Trim(mount, "/") + "/login"
	sec, err := v.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role": role,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	if err != nil {
		return "", 0, fmt.Errorf("login at %s with role %q: %w", path, role, wrapStatus(err))
	}
	if sec == nil || sec.Auth == nil || sec.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("login at %s returned no client token", path)
	}
	return sec.Auth.ClientToken, sec.Auth.LeaseDuration, nil
}

// NewKubernetesAuthClient constructs a Client that authenticates itself via
// bao's Kubernetes auth method: the pod's projected SA JWT is exchanged at
// auth/<mount>/login for a bao token, which is cached until ~80% of its
// lease and re-acquired on expiry or on an observed 403. Construction never
// contacts bao — the first login happens lazily on the first call, so a
// sealed or still-starting bao surfaces as per-reconcile errors that heal on
// requeue instead of a crash-looping process.
func NewKubernetesAuthClient(addr, mount, role, jwtPath string) (Client, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, fmt.Errorf("bao client: address is empty")
	}
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return nil, fmt.Errorf("bao client: auth mount is empty")
	}
	if role == "" {
		return nil, fmt.Errorf("bao client: auth role is empty")
	}
	if jwtPath == "" {
		return nil, fmt.Errorf("bao client: service account token path is empty")
	}
	// Same optional-CA contract as NewHTTPClient: a VAULT_CACERT pointing
	// at a file that never materialized must not crash the process.
	unsetMissingCAEnv("VAULT_CACERT")
	addr = strings.TrimRight(addr, "/")

	mgr := &loginManager{now: time.Now}

	cfg := vault.DefaultConfig()
	cfg.Address = addr
	// 403 handling lives in authTransport. The only deviation from the default
	// policy is to stop retrying a call whose login failed: the SDK reads that
	// as a transport error and would re-attempt the login twice more per call.
	cfg.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		var lerr *loginError
		if errors.As(err, &lerr) {
			return false, err
		}
		return vault.DefaultRetryPolicy(ctx, resp, err)
	}
	cfg.HttpClient.Transport = &authTransport{
		base:      cfg.HttpClient.Transport,
		mgr:       mgr,
		loginPath: "/v1/auth/" + mount + "/login",
	}
	v, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("bao client: %w", err)
	}
	// Wired after the client exists to break the construction cycle: the
	// transport needs the manager, the manager's login needs the client.
	mgr.login = func(ctx context.Context) (string, int, error) {
		return k8sLogin(ctx, v, mount, role, jwtPath)
	}
	return &sdkClient{v: v}, nil
}

// NewClientFromEnv selects the auth mode from BAO_AUTH_METHOD and builds the
// one shared Client the process uses:
//
//   - "token" (default when unset): static token from VAULT_TOKEN/BAO_TOKEN,
//     exactly the historical behavior — used by `make run` and as the
//     migration fallback.
//   - "kubernetes": ServiceAccount login against BAO_AUTH_MOUNT with
//     BAO_AUTH_ROLE, JWT read from BAO_AUTH_JWT_PATH.
//
// The address always comes from VAULT_ADDR/BAO_ADDR. Only configuration
// errors are returned (unknown mode, missing required env) — bao
// unreachability is deliberately not checked here.
func NewClientFromEnv() (Client, error) {
	addr := firstNonEmptyEnv("VAULT_ADDR", "BAO_ADDR")
	if addr == "" {
		return nil, fmt.Errorf("set VAULT_ADDR (or BAO_ADDR)")
	}
	method := os.Getenv("BAO_AUTH_METHOD")
	if method == "" {
		method = "token"
	}
	switch method {
	case "token":
		token := firstNonEmptyEnv("VAULT_TOKEN", "BAO_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("BAO_AUTH_METHOD=token: set VAULT_TOKEN (or BAO_TOKEN)")
		}
		return NewHTTPClient(addr, token)
	case "kubernetes":
		mount := envOrDefault("BAO_AUTH_MOUNT", defaultAuthMount)
		role := envOrDefault("BAO_AUTH_ROLE", defaultAuthRole)
		jwtPath := envOrDefault("BAO_AUTH_JWT_PATH", defaultJWTPath)
		return NewKubernetesAuthClient(addr, mount, role, jwtPath)
	default:
		return nil, fmt.Errorf("BAO_AUTH_METHOD=%q: must be \"token\" or \"kubernetes\"", method)
	}
}

func firstNonEmptyEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
