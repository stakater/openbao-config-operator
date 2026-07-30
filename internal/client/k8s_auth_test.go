package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// writeJWTFile drops a fake ServiceAccount JWT where a login can read it.
func writeJWTFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// ---- loginManager cache contract ----

// fakeClock is a hand-advanced time source for expiry tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestLoginManager_CachesUntil80PercentOfLease(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: time.Unix(1000, 0)}
	var logins atomic.Int32
	m := &loginManager{
		now: clock.now,
		login: func(context.Context) (string, int, error) {
			n := logins.Add(1)
			return fmt.Sprintf("tok-%d", n), 100, nil // 100s lease → refresh at 80s
		},
	}

	tok, err := m.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok)

	// Below the 80% mark the cached token is reused.
	clock.advance(79 * time.Second)
	tok, err = m.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok)
	require.EqualValues(t, 1, logins.Load())

	// Past it, the next call logs in again.
	clock.advance(2 * time.Second)
	tok, err = m.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-2", tok)
	require.EqualValues(t, 2, logins.Load())
}

func TestLoginManager_ZeroLeaseRefreshesHourly(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: time.Unix(1000, 0)}
	var logins atomic.Int32
	m := &loginManager{
		now: clock.now,
		login: func(context.Context) (string, int, error) {
			n := logins.Add(1)
			return fmt.Sprintf("tok-%d", n), 0, nil
		},
	}
	_, err := m.Token(context.Background())
	require.NoError(t, err)
	clock.advance(47 * time.Minute)
	_, err = m.Token(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, logins.Load(), "non-expiring token should be reused within the hour")
	clock.advance(2 * time.Minute) // past 80% of the 1h fallback
	_, err = m.Token(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 2, logins.Load())
}

func TestLoginManager_LoginErrorIsReturnedAndNotCached(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: time.Unix(1000, 0)}
	calls := 0
	m := &loginManager{
		now: clock.now,
		login: func(context.Context) (string, int, error) {
			calls++
			if calls == 1 {
				return "", 0, errors.New("bao sealed")
			}
			return "tok-ok", 60, nil
		},
	}
	_, err := m.Token(context.Background())
	require.ErrorContains(t, err, "bao sealed")
	tok, err := m.Token(context.Background())
	require.NoError(t, err, "a failed login must not poison the cache")
	require.Equal(t, "tok-ok", tok)
}

func TestLoginManager_ReplaceOnlySwapsTheFailedToken(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: time.Unix(1000, 0)}
	var logins atomic.Int32
	m := &loginManager{
		now: clock.now,
		login: func(context.Context) (string, int, error) {
			n := logins.Add(1)
			return fmt.Sprintf("tok-%d", n), 3600, nil
		},
	}
	tok1, err := m.Token(context.Background())
	require.NoError(t, err)

	// A stale replacement (another caller already re-logged-in) must hand back
	// the fresh token instead of logging in again.
	tok, err := m.Replace(context.Background(), "tok-0")
	require.NoError(t, err)
	require.Equal(t, tok1, tok)
	require.EqualValues(t, 1, logins.Load())

	// Replacing the current token logs in and caches the result.
	tok, err = m.Replace(context.Background(), tok1)
	require.NoError(t, err)
	require.Equal(t, "tok-2", tok)
	cached, err := m.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-2", cached)
	require.EqualValues(t, 2, logins.Load())
}

func TestLoginManager_ConcurrentCallersTriggerOneLogin(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: time.Unix(1000, 0)}
	var logins atomic.Int32
	m := &loginManager{
		now: clock.now,
		login: func(context.Context) (string, int, error) {
			logins.Add(1)
			time.Sleep(20 * time.Millisecond) // widen the race window
			return "tok-shared", 3600, nil
		},
	}
	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	toks := make([]string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			toks[i], errs[i] = m.Token(context.Background())
		}(i)
	}
	wg.Wait()
	for i := 0; i < callers; i++ {
		require.NoError(t, errs[i])
		require.Equal(t, "tok-shared", toks[i])
	}
	require.EqualValues(t, 1, logins.Load(), "16 concurrent callers must produce exactly one login")
}

// ---- k8sLogin wire contract (httptest) ----

const (
	testLoginPath = "/v1/auth/k8s-operator/login"
	// testLeaseSeconds is long enough that no test crosses the 80% refresh
	// point by accident.
	testLeaseSeconds = 3600
	// firstToken is what the fake bao mints on the first login; handlers reject
	// it to stand in for a revoked or denied credential.
	firstToken = "tok-1"
)

// loginResponse builds the bao login response body.
func loginResponse(token string) string {
	return fmt.Sprintf(`{"auth":{"client_token":%q,"lease_duration":%d,"accessor":"acc"}}`, token, testLeaseSeconds)
}

func TestNewKubernetesAuthClient_LoginRequestShape(t *testing.T) {
	t.Parallel()
	jwtPath := writeJWTFile(t, "sa-jwt-content\n")

	var loginReqs atomic.Int32
	var gotMethod, gotPath, gotLoginToken string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == testLoginPath:
			loginReqs.Add(1)
			gotMethod = r.Method
			gotPath = r.URL.Path
			gotLoginToken = r.Header.Get("X-Vault-Token")
			require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
			_, _ = fmt.Fprint(w, loginResponse("minted-token"))
		case r.URL.Path == "/v1/sys/policies/acl/team-a":
			require.Equal(t, "minted-token", r.Header.Get("X-Vault-Token"),
				"API calls must carry the minted token, not the SA JWT")
			_, _ = fmt.Fprint(w, `{"data":{"name":"team-a","policy":"path \"x\" {}"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := NewKubernetesAuthClient(srv.URL, "k8s-operator", "openbao-config-operator", jwtPath)
	require.NoError(t, err)

	body, err := c.GetPolicy(context.Background(), "team-a")
	require.NoError(t, err)
	require.Contains(t, body, "path")

	require.EqualValues(t, 1, loginReqs.Load())
	require.Equal(t, http.MethodPut, gotMethod, "vault SDK Logical().Write issues PUT")
	require.Equal(t, testLoginPath, gotPath)
	require.Empty(t, gotLoginToken,
		"the login runs on the same client as every other call, so authTransport must exempt "+
			"the login path: injecting a token here would re-enter the cache the login is filling")
	require.Equal(t, "openbao-config-operator", gotBody["role"])
	require.Equal(t, "sa-jwt-content", gotBody["jwt"], "JWT must be read from the file and trimmed")

	// Second call reuses the cached token — no extra login.
	_, err = c.GetPolicy(context.Background(), "team-a")
	require.NoError(t, err)
	require.EqualValues(t, 1, loginReqs.Load())
}

func TestNewKubernetesAuthClient_JWTFileReReadOnEachLogin(t *testing.T) {
	t.Parallel()
	jwtPath := writeJWTFile(t, "jwt-v1")

	var jwts []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testLoginPath {
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			mu.Lock()
			jwts = append(jwts, body["jwt"].(string))
			n := len(jwts)
			mu.Unlock()
			if n == 1 {
				// Rotate the JWT on disk after the first login has read
				// jwt-v1 (kubelet does this in real life). The 403 below
				// invalidates the cache, and the in-flight retry logs in
				// again — it must pick up jwt-v2 from the file.
				require.NoError(t, os.WriteFile(jwtPath, []byte("jwt-v2"), 0o600))
			}
			_, _ = fmt.Fprint(w, loginResponse(fmt.Sprintf("tok-%d", n)))
			return
		}
		// First read 403s (revoked token), any later read succeeds.
		if r.Header.Get("X-Vault-Token") == firstToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"name":"p","policy":"path \"x\" {}"}}`)
	}))
	t.Cleanup(srv.Close)

	c, err := NewKubernetesAuthClient(srv.URL, "k8s-operator", "role", jwtPath)
	require.NoError(t, err)

	_, err = c.GetPolicy(context.Background(), "p")
	require.NoError(t, err, "403 must invalidate the cache and the retry must succeed")

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"jwt-v1", "jwt-v2"}, jwts, "each login must re-read the JWT file")
}

func TestNewKubernetesAuthClient_RevokedTokenRelogsInAndRetriesOnce(t *testing.T) {
	t.Parallel()
	jwtPath := writeJWTFile(t, "jwt")

	var logins, reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testLoginPath {
			n := logins.Add(1)
			_, _ = fmt.Fprint(w, loginResponse(fmt.Sprintf("tok-%d", n)))
			return
		}
		reads.Add(1)
		if r.Header.Get("X-Vault-Token") == firstToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"name":"p","policy":"path \"x\" {}"}}`)
	}))
	t.Cleanup(srv.Close)

	c, err := NewKubernetesAuthClient(srv.URL, "k8s-operator", "role", jwtPath)
	require.NoError(t, err)

	_, err = c.GetPolicy(context.Background(), "p")
	require.NoError(t, err)
	require.EqualValues(t, 2, logins.Load(), "revocation → exactly one re-login")
	require.EqualValues(t, 2, reads.Load(), "the failed call is retried once with the fresh token")
}

func TestNewKubernetesAuthClient_PersistentForbiddenReplaysExactlyOnce(t *testing.T) {
	t.Parallel()
	jwtPath := writeJWTFile(t, "jwt")

	// Every read is denied whatever the token: a policy denial, not a
	// revocation. Indistinguishable by status, so exactly one replay is allowed.
	var logins, reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testLoginPath {
			n := logins.Add(1)
			_, _ = fmt.Fprint(w, loginResponse(fmt.Sprintf("tok-%d", n)))
			return
		}
		reads.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`)
	}))
	t.Cleanup(srv.Close)

	c, err := NewKubernetesAuthClient(srv.URL, "k8s-operator", "role", jwtPath)
	require.NoError(t, err)

	_, err = c.GetPolicy(context.Background(), "denied")
	require.Error(t, err)
	var serr *StatusError
	require.ErrorAs(t, err, &serr, "the denial must reach ClassifyErr as a 403")
	require.Equal(t, http.StatusForbidden, serr.StatusCode)
	require.EqualValues(t, 2, reads.Load(), "one original call plus one replay, never a retry chain")
	require.EqualValues(t, 2, logins.Load(), "at most one re-login per denied call")

	// A second denied call must not re-login more than once either.
	_, err = c.GetPolicy(context.Background(), "denied")
	require.Error(t, err)
	require.EqualValues(t, 4, reads.Load())
	require.EqualValues(t, 3, logins.Load())
}

func TestNewKubernetesAuthClient_ForbiddenReplayResendsTheBody(t *testing.T) {
	t.Parallel()
	jwtPath := writeJWTFile(t, "jwt")

	var logins atomic.Int32
	var bodies []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testLoginPath {
			n := logins.Add(1)
			_, _ = fmt.Fprint(w, loginResponse(fmt.Sprintf("tok-%d", n)))
			return
		}
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		if r.Header.Get("X-Vault-Token") == firstToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c, err := NewKubernetesAuthClient(srv.URL, "k8s-operator", "role", jwtPath)
	require.NoError(t, err)

	require.NoError(t, c.UpsertPolicy(context.Background(), "p", `path "x" { capabilities = ["read"] }`))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 2, "the write is replayed once after the re-login")
	require.Contains(t, bodies[0], "capabilities")
	require.Equal(t, bodies[0], bodies[1], "the replay must resend the original body, not an empty one")
}

func TestNewKubernetesAuthClient_LoginMetricLabelsTheTrigger(t *testing.T) {
	// Not parallel: the login counter is process-global, so the deltas below
	// are only attributable to this test while it runs alone.
	jwtPath := writeJWTFile(t, "jwt")

	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testLoginPath {
			n := logins.Add(1)
			_, _ = fmt.Fprint(w, loginResponse(fmt.Sprintf("metric-tok-%d", n)))
			return
		}
		if r.Header.Get("X-Vault-Token") == "metric-tok-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"name":"p","policy":"path \"x\" {}"}}`)
	}))
	t.Cleanup(srv.Close)

	expiryBefore := loginCount(t, loginReasonExpiry)
	forbiddenBefore := loginCount(t, loginReasonForbidden)

	c, err := NewKubernetesAuthClient(srv.URL, "k8s-operator", "role", jwtPath)
	require.NoError(t, err)
	_, err = c.GetPolicy(context.Background(), "p")
	require.NoError(t, err)

	require.EqualValues(t, 1, loginCount(t, loginReasonExpiry)-expiryBefore,
		"the first login is cache-driven")
	require.EqualValues(t, 1, loginCount(t, loginReasonForbidden)-forbiddenBefore,
		"the 403-driven re-login is labelled separately so denials are not read as token churn")
}

// loginCount reads the successful-login counter for one reason label.
func loginCount(t *testing.T, reason string) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, loginTotal.WithLabelValues("success", reason).Write(&m))
	return m.GetCounter().GetValue()
}

func TestNewKubernetesAuthClient_LoginFailureSurfacesAsError(t *testing.T) {
	t.Parallel()
	jwtPath := writeJWTFile(t, "jwt")
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testLoginPath {
			logins.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["role not found"]}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c, err := NewKubernetesAuthClient(srv.URL, "k8s-operator", "gone-role", jwtPath)
	require.NoError(t, err, "construction must not contact bao")

	_, err = c.GetPolicy(context.Background(), "p")
	require.Error(t, err)
	require.ErrorContains(t, err, "gone-role", "login errors must name the role for diagnosability")
	require.EqualValues(t, 1, logins.Load(),
		"a failed login must not be re-attempted by the SDK retry policy: it would triple the "+
			"login-failure metric and the reconcile latency while bao is unavailable")
}

func TestNewKubernetesAuthClient_ValidatesConfig(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, addr, mount, role, jwtPath string }{
		{"empty addr", "", "m", "r", "/p"},
		{"empty mount", "http://x", "", "r", "/p"},
		{"empty role", "http://x", "m", "", "/p"},
		{"empty jwt path", "http://x", "m", "r", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewKubernetesAuthClient(tc.addr, tc.mount, tc.role, tc.jwtPath)
			require.Error(t, err)
		})
	}
}

// ---- NewClientFromEnv mode selection ----

// setAuthEnv pins the full set of env vars the selector reads, so tests are
// hermetic regardless of the developer's shell.
func setAuthEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, name := range []string{
		"VAULT_ADDR", "BAO_ADDR", "VAULT_TOKEN", "BAO_TOKEN",
		"BAO_AUTH_METHOD", "BAO_AUTH_MOUNT", "BAO_AUTH_ROLE", "BAO_AUTH_JWT_PATH",
	} {
		t.Setenv(name, kv[name])
	}
}

func TestNewClientFromEnv_DefaultIsTokenMode(t *testing.T) {
	setAuthEnv(t, map[string]string{"VAULT_ADDR": "http://127.0.0.1:8200", "VAULT_TOKEN": "tok"})
	c, err := NewClientFromEnv()
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestNewClientFromEnv_TokenModeRequiresToken(t *testing.T) {
	setAuthEnv(t, map[string]string{"VAULT_ADDR": "http://127.0.0.1:8200"})
	_, err := NewClientFromEnv()
	require.ErrorContains(t, err, "VAULT_TOKEN")
}

func TestNewClientFromEnv_RequiresAddress(t *testing.T) {
	setAuthEnv(t, map[string]string{"VAULT_TOKEN": "tok"})
	_, err := NewClientFromEnv()
	require.ErrorContains(t, err, "VAULT_ADDR")
}

func TestNewClientFromEnv_KubernetesMode(t *testing.T) {
	jwtPath := writeJWTFile(t, "jwt")
	setAuthEnv(t, map[string]string{
		"VAULT_ADDR":        "http://127.0.0.1:8200",
		"BAO_AUTH_METHOD":   "kubernetes",
		"BAO_AUTH_JWT_PATH": jwtPath,
	})
	c, err := NewClientFromEnv()
	require.NoError(t, err, "kubernetes mode must not require VAULT_TOKEN")
	require.NotNil(t, c)
}

func TestNewClientFromEnv_UnknownMethodFailsFast(t *testing.T) {
	setAuthEnv(t, map[string]string{"VAULT_ADDR": "http://127.0.0.1:8200", "BAO_AUTH_METHOD": "approle"})
	_, err := NewClientFromEnv()
	require.ErrorContains(t, err, "approle")
}

func TestNewClientFromEnv_BAOFallbacks(t *testing.T) {
	setAuthEnv(t, map[string]string{"BAO_ADDR": "http://127.0.0.1:8200", "BAO_TOKEN": "tok"})
	c, err := NewClientFromEnv()
	require.NoError(t, err, "BAO_ADDR/BAO_TOKEN must work as fallbacks, matching historical behavior")
	require.NotNil(t, c)
}
