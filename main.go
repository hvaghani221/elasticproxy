package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	ory "github.com/ory/client-go"
)

func init() {
	if os.Getenv("ORY_APY_KEY") == "" {
		panic("'ORY_APY_KEY' env must be set")
	}

	if os.Getenv("ORY_HOST") == "" {
		panic("'ORY_HOST' env must be set")
	}
}

func NewProxy(targetHost string) (*httputil.ReverseProxy, error) {
	url, err := url.Parse(targetHost)
	if err != nil {
		return nil, err
	}

	return httputil.NewSingleHostReverseProxy(url), nil

}
func getAccessTokenFromHeader(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}
	return ""
}

func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	host := os.Getenv("ORY_HOST")
	c := ory.NewConfiguration()
	c.Servers = ory.ServerConfigurations{{URL: host}}
	c.AddDefaultHeader("Authorization", "Bearer "+os.Getenv("ORY_API_KEY"))
	oauth2 := ory.NewAPIClient(c).OAuth2API

	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info(r.URL.String(), "header", r.Header)
		token := getAccessTokenFromHeader(r)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		introspect, resp, err := oauth2.IntrospectOAuth2Token(r.Context()).Token(token).Execute()
		defer func() {
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			slog.Info(r.URL.String(), "header", r.Header, "error", err.Error())
			return
		}
		if !introspect.Active {
			w.WriteHeader(http.StatusUnauthorized)
			slog.Info(r.URL.String(), "header", r.Header, "introspect", introspect)
			return
		}

		if originalAuthHeader := r.Header.Get("X-Original-Authorization"); originalAuthHeader != "" {
			r.Header.Set("Authorization", originalAuthHeader)
		}
		proxy.ServeHTTP(w, r)
	}
}

func main() {
	proxy, err := NewProxy("http://localhost:9201")
	if err != nil {
		slog.Error(err.Error())
		os.Exit(-1)
	}
	http.HandleFunc("/", ProxyRequestHandler(proxy))
	if err := http.ListenAndServe(":9200", nil); err != nil {
		slog.Error(err.Error())
	}
}
