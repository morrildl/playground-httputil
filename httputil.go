/* Copyright © Playground Global, LLC. All rights reserved. */

// Package httputil provides a few convenience functions for frequent operations on Go's http
// objects.
package httputil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"playground/log"
	"playground/session"
)

// Send writes the indicated data to the client as the indicated content-type, handling
// the Content-Length header.
func Send(writer http.ResponseWriter, status int, contentType string, data []byte) {
	log.Debug("sendBytes", "Content-Type: '"+contentType+"'")
	if Config.EnableHSTS {
		writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	writer.Header().Add("Content-Type", contentType)
	writer.Header().Add("Content-Length", strconv.Itoa(len(data)))
	writer.WriteHeader(status)
	writer.Write(data)
}

// sendJSON is the internal implementation called by SendJSON and SendFormattedJSON.
func sendJSON(writer http.ResponseWriter, status int, object interface{}, format bool) {
	if Config.EnableHSTS {
		writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	writer.Header().Add("Content-Type", "application/json")

	s, err := json.Marshal(object)
	if err != nil {
		log.Warn("main", "error marshaling object to JSON", err)
		writer.Header().Add("Content-Length", strconv.Itoa(2))
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte("{}"))
		return
	}

	if format {
		out := bytes.Buffer{}
		json.Indent(&out, s, "", "  ")
		s = out.Bytes()
	}

	writer.Header().Add("Content-Length", strconv.Itoa(len(s)))
	writer.WriteHeader(status)
	writer.Write(s)
}

// SendJSON marshals the provided struct to a JSON string and then writes it to the client using the
// HTTP response/status code provided.
func SendJSON(writer http.ResponseWriter, status int, object interface{}) {
	sendJSON(writer, status, object, false)
}

// SendFormattedJSON is identical to SendJSON except that it sends indented JSON as output, intended
// for human consumption.
func SendFormattedJSON(writer http.ResponseWriter, status int, object interface{}) {
	sendJSON(writer, status, object, true)
}

// SendPlaintext writes a raw string to the client as text/plain, handling the Content-Length header.
func SendPlaintext(writer http.ResponseWriter, status int, body string) {
	if Config.EnableHSTS {
		writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	writer.Header().Add("Content-Type", "text/plain")
	writer.Header().Add("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	io.WriteString(writer, body)
}

func ExtractSegment(path string, n int) string {
	chunks := strings.Split(path, "/")
	if len(chunks) > n {
		return chunks[n]
	}
	return ""
}

// URLJoin safely constructs a URL from the provided components. "Safely" means that it properly
// handles duplicate / characters, etc. That is, URLJoin("/foo/", "bar") is equivalent to
// URLJoin("/foo/", "/bar"), etc.
func URLJoin(base string, elements ...string) string {
	u, err := url.Parse(base)
	if err != nil {
		log.Error("httputil.URLJoin", fmt.Sprintf("base URL '%s' does not parse", base), err)
		panic(err)
	}
	scrubbed := []string{}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path != "" {
		scrubbed = append(scrubbed, u.Path)
	}
	for _, s := range elements {
		s = strings.Trim(s, "/")
		if s != "" {
			scrubbed = append(scrubbed, s)
		}
	}
	u.Path = strings.Join(scrubbed, "/")
	return u.String()
}

var client *http.Client

// Generally we only want to transmit requests to the API server instance we trust, which we want
// to authenticate by its server certificate. So this function creates an HTTPS client instance
// configured such that its root CA list contains only our trusted server cert. It follows, then,
// that that server cert must be self-signed.
func initHTTPSClient() {
	cert, err := tls.LoadX509KeyPair(Config.ClientCertFile, Config.ClientKeyFile)
	if err != nil {
		panic(err)
	}

	serverCert, err := ioutil.ReadFile(Config.SelfSignedServerCertFile)
	if err != nil {
		panic(err)
	}
	serverRoot := x509.NewCertPool()
	serverRoot.AppendCertsFromPEM(serverCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      serverRoot,
	}
	tlsConfig.BuildNameToCertificate()
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      serverRoot,
			},
		},
	}
}

type API struct {
	Header  string
	Value   string
	URLBase string
}

// CallAPI is a convenience wrapper specifically around API calls. It handles setting the
// shared-secret header for authentication to the remote server, automatically constructs a final
// URL using the server/scheme specified in the server's config file, etc. Returns the HTTP status
// code, or the underlying error if not nil.
func (api *API) Call(endpoint string, method string, sendObj interface{}, recvObj interface{}) (int, error) {
	if client == nil {
		initHTTPSClient()
	}

	body, err := json.Marshal(sendObj)
	if err != nil {
		log.Error("httputil.CallAPI", "trivial Request failed to marshal", err)
		return -1, err
	}

	req, err := http.NewRequest(method, URLJoin(api.URLBase, endpoint), bytes.NewReader(body))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(api.Header, api.Value)
	if err != nil {
		return -1, err
	}
	res, err := client.Do(req)
	if err != nil {
		return -1, err
	}

	log.Debug("httputil.CallAPI", fmt.Sprintf("%s %s", method, api), string(body))

	if recvObj != nil {
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error("httputil.CallAPI", "low-level I/O error reading HTTP response body", err)
			return -1, err
		}
		b, ok := recvObj.(*[]byte)
		if ok {
			*b = make([]byte, len(body))
			copy(*b, body)
		} else {
			err = json.Unmarshal(body, recvObj)
			if err != nil {
				log.Error("httputil.CallAPI", "parse error unmarshaling HTTP response JSON", err)
				return -1, err
			}
		}
	}

	return res.StatusCode, nil
}

// PopulateFromBody attempts to unmarshal the body text stored in the provided request into the
// provided struct. Uses the usual Go JSON library and so the struct must follow the usual
// constraints. This simply handles the boilerplate of reading the string and handling errors.
func PopulateFromBody(dest interface{}, req *http.Request) error {
	if req.Body == nil {
		return errors.New("request with no body")
	}

	body, err := ioutil.ReadAll(req.Body)
	log.Debug("httputil.PopulateFromBody", "raw JSON string follows")
	log.Debug("httputil.PopulateFromBody", string(body))
	if err != nil {
		log.Warn("httputil.PopulateFromBody", "I/O error parsing JSON from client", err)
		return err
	}
	err = json.Unmarshal(body, dest)
	if err != nil {
		log.Warn("httputil.PopulateFromBody", "error parsing JSON from client", err)
		return err
	}
	return nil
}

// CheckAPISecret indicates whether the indicated request contains an API secret header matching the
// value required via Config.APISecretValue (and specified via config.json). Note that this is a
// very simple test, and presumes that TLS is in use (to prevent sniffing of the secret and forged
// requests) and that certificate pinning is in use.
//
// If Config.APISecretValue (or header) is not set, always returns true.
func CheckAPISecret(req *http.Request, header string, value string) bool {
	log.Debug("httputil.CheckAPISecret", req.Header)

	if header == "" || value == "" {
		return true
	}

	provided, ok := req.Header[header]
	if !ok {
		log.Warn("httputil.CheckAPISecret", "missing API secret", req.URL.Path)
		return false
	}

	if len(provided) != 1 {
		log.Warn("httputil.CheckAPISecret", "multivalued API secret", req.URL.Path)
		return false
	}

	if provided[0] == value {
		return true
	}
	log.Warn("httputil.CheckAPISecret", "bad API secret")
	return false
}

// NewHardenedTLSConfig returns a *tls.Config that enables only modern, PFS-permitting ciphers.
func NewHardenedTLSConfig() *tls.Config {
	return &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // doesn't provide PFS
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // doesn't provide PFS
		},
	}
}

// HardenedServer is a thinly-wrapped *http.Server that adds some convenience methods for starting
// servers in a more secure configuration than the Go defaults. Based on
// https://blog.cloudflare.com/exposing-go-on-the-internet/
type HardenedServer struct {
	*http.Server
	bindInterface string
	port          int
}

// NewHardenedServer returns a HardenedServer (i.e. *http.Server) with timeout and TLS
// configurations suitable for secure serving. The TLSConfig in the returned instance is a
// HardenedTLSConfig as above. The server's Handler is set to a fresh *http.ServeMux instance, which
// is also returned.
func NewHardenedServer(bindInterface string, port int) (*HardenedServer, *http.ServeMux) {
	mux := http.NewServeMux()
	return &HardenedServer{
		Server: &http.Server{
			Addr:         fmt.Sprintf("%s:%d", bindInterface, port),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig:    NewHardenedTLSConfig(),
			Handler:      mux,
		},
		bindInterface: bindInterface,
		port:          port,
	}, mux
}

// ListenAndServeTLSRedirector starts up an unencrypted HTTP server whose only function is to redirect all
// URLs to the HTTPS server.
func (s *HardenedServer) ListenAndServeTLSRedirector(httpsHost string, httpPort int) {
	if httpPort < 1 {
		panic(fmt.Sprintf("invalid HSTS port %d specified", httpPort))
	}
	if httpsHost == "" {
		httpsHost = s.bindInterface
	}
	if s.port != 443 {
		httpsHost = fmt.Sprintf("%s:%d", httpsHost, s.port)
	}
	go func() {
		log.Warn("main (http)", "fallback HTTP server shutting down", (&http.Server{
			Addr:         fmt.Sprintf("%s:%d", s.bindInterface, httpPort),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Connection", "close")
				url := fmt.Sprintf("https://%s/%s", httpsHost, req.URL.String())
				log.Debug("main (http)", "redirect to https", url)
				http.Redirect(w, req, url, http.StatusMovedPermanently)
			}),
		}).ListenAndServe())
	}()
}

// RequireClientRoot instructs the HardenedServer to only accept connections from clients which
// present a client certificate signed by a CA during TLS handshake. If the provided rootCertFile is
// a specific (self-signed) certificate instead of a CA certificate, the behavior is basically
// certificate pinning. This is intended for use in API servers where the only clients are
// non-browser entities.
func (s *HardenedServer) RequireClientRoot(rootCertFile string) {
	rootCert, err := ioutil.ReadFile(rootCertFile)
	if err != nil {
		panic(err)
	}

	clientRoot := x509.NewCertPool()
	clientRoot.AppendCertsFromPEM(rootCert)
	s.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	s.TLSConfig.ClientCAs = clientRoot
	s.TLSConfig.BuildNameToCertificate()
}

type wrapper struct {
	cur  func(http.HandlerFunc) http.HandlerFunc
	prev *wrapper
}

// Wrapper returns a builder which can be used to assemble a client request authentication strategy
// from a selection of boilerplate building blocks. Calling the other methods on this object
// constructs a call chain of authentication operators, which can then be use to Wrap() a standard
// http.HandlerFunc. This allows request handlers to refrain from repeating common authentication
// code blocks.
//
// mux.HandleFunc(
//   "/some/path",
//   httputil.Wrapper()
//     .WithPanicHandler()
//     .WithSecretSentry()
//     .WithSessionSentry(nil)
//     .WithMethodSentry([]string{"GET", "PUT"})
//     .Wrap(somePathHandler))
func Wrapper() *wrapper {
	return &wrapper{}
}

func (w *wrapper) prep(f func(http.HandlerFunc) http.HandlerFunc) *wrapper {
	w.cur = f
	next := &wrapper{prev: w}
	return next
}

// Wrap constructs a final http.HandlerFunc out of the chain of authenticator blocks represented by
// w.
func (w *wrapper) Wrap(f http.HandlerFunc) http.HandlerFunc {
	if w.prev == nil { // first in the chain, no predecessor
		return w.cur(f)
	}
	if w.cur == nil { // last in the chain, no cur set
		return w.prev.Wrap(f)
	}
	return w.prev.Wrap(w.cur(f))
}

// WithMethodSentry adds a request method check to the chain represented by w. It compares the
// current request method against the provided list of messages, and aborts the request with an
// error if the method is not approved. This is intended to ensure that REST endpoint handlers don't
// have to deal with methods they aren't expecting.
func (w *wrapper) WithMethodSentry(methods ...string) *wrapper {
	return w.prep(func(f http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			allowed := false
			for _, method := range methods {
				if method == req.Method {
					allowed = true
					break
				}
			}
			if !allowed {
				log.Warn("methodSentry", "disallowed HTTP method", req.URL.Path, req.Method)
				SendJSON(writer, http.StatusMethodNotAllowed, struct{}{})
				return
			}
			f(writer, req)
		}
	})
}

// WithPanicHandler adds a top-level defer handler for panics. Requests that trip this handler
// return a 500 Internal Server Error response. This allows handlers to avoid cluttering their code
// with lots of `if err != nil` checks for internal issues, like database errors or filesystem errors.
func (w *wrapper) WithPanicHandler() *wrapper {
	return w.prep(func(f http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			defer func() {
				if r := recover(); r != nil {
					log.Warn("panicHandler", fmt.Sprintf("panic in handler for %s %s", req.Method, req.URL.Path), r)
					SendJSON(writer, http.StatusInternalServerError, struct{}{})
				}
			}()
			f(writer, req)
		}
	})
}

// WithSecretSentry adds a check for an API secret in the request header. The header key and value
// must match those specified in the module's Config struct. If the header is missing or invalid,
// a 403 response is returned to the client.
func (w *wrapper) WithSecretSentry(header, value string) *wrapper {
	if header == "" || value == "" {
		log.Error("WithSecretSentry", "missing header or value; check will be a no-op")
	}
	return w.prep(func(f http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			if !CheckAPISecret(req, header, value) {
				log.Warn("secretSentry", "API secret check failed", req.URL.Path, req.Method)
				SendJSON(writer, http.StatusForbidden, struct{}{})
				return
			}
			f(writer, req)
		}
	})
}

// WithSessionSentry adds a check for OAuth2 login. See the `playground/session` package for
// details.
func (w *wrapper) WithSessionSentry(body interface{}) *wrapper {
	return w.prep(func(f http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			ssn := session.GetSession(req)
			if !ssn.IsLoggedIn() {
				ssn.Update(writer)
				if body != nil {
					SendJSON(writer, http.StatusForbidden, body)
				} else {
					SendPlaintext(writer, http.StatusForbidden, "Unauthenticated")
				}
			}
			f(writer, req)
		}
	})
}
