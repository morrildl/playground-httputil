// Copyright © 2018 Playground Global, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	log.Debug("httputil.Send", "Content-Type: '"+contentType+"'")
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
		log.Warn("httputil.SendJSON", "error marshaling object to JSON", err)
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

// ExtractSegment returns the nth element in the path, as delimited by "/", or "" if it isn't set
// (or if the path doesn't have >= n segments.)
func ExtractSegment(path string, n int) string {
	chunks := strings.Split(path, "/")
	if len(chunks) > n {
		return chunks[n]
	}
	return ""
}

// PopulateFromBody attempts to unmarshal the body text stored in the provided request into the
// provided struct. Uses the usual Go JSON library and so the struct must follow the usual
// constraints. This simply handles the boilerplate of reading the string and handling errors.
func PopulateFromBody(dest interface{}, req *http.Request) error {
	TAG := "httputil.PopulateFromBody"

	if req.Body == nil {
		return errors.New("request with no body")
	}

	body, err := ioutil.ReadAll(req.Body)
	log.Debug(TAG, "raw JSON string follows")
	log.Debug(TAG, string(body))
	if err != nil {
		log.Warn(TAG, "I/O error parsing JSON from client", err)
		return err
	}
	err = json.Unmarshal(body, dest)
	if err != nil {
		log.Warn(TAG, "error parsing JSON from client", err)
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
	TAG := "httputil.CheckAPISecret"
	log.Debug(TAG, req.Header)

	if header == "" || value == "" {
		return true
	}

	provided := req.Header.Get(header)
	if provided == "" {
		log.Warn(TAG, "missing API secret", req.URL.Path)
		return false
	}

	if provided == value {
		return true
	}

	log.Warn(TAG, "bad API secret")
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
		log.Warn("HardenedServer.ListenAndServeTLSRedirector", "fallback HTTP server shutting down", (&http.Server{
			Addr:         fmt.Sprintf("%s:%d", s.bindInterface, httpPort),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Connection", "close")
				url := fmt.Sprintf("https://%s/%s", httpsHost, req.URL.String())
				log.Debug("HardenedServer.ListenAndServeTLSRedirector", "redirect to https", url)
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

// An Assertable coordinates with the WithPanicHandler() wrapper to permit callers to avoid certain
// multi-line boilerplate idioms that frequently appear in server code. Simply put, this:
//
//     if req.Method != "PUT" {
//       log.Warn("someTag", "invalid method")
//       SendJSON(writer, http.StatusMethodNotAllowed, &someStruct{})
//       return
//     }
//
// ...can become this:
//
//     badMethod := NewJSONAssertable(writer, "someTag", http.StatusMethodNotAllowed, &someStruct{})
//     badMethod.Assert(req.Method != "PUT", "invalid method from '%s'", currentUser)
//     ...
//     badMethod.Assert(req.Method == "GET" && someParam == "", "missing URL someParam in GET from '%s'", currentUser)
//
// The Assert() call will panic() if the condition check fails, but will be caught by the
// WithPanicHandler() wrapper. In this way, boilerplate lines can be reduced for readability.
type Assertable struct {
	Writer       http.ResponseWriter
	Tag          string
	ResponseCode int
	ContentType  string
	Payload      interface{}

	isJSON bool
	data   []byte
	msg    string
}

// NewJSONAssertable constructs an Assertable whose responses to the client have Content-Type:
// application/json with a body of the indicated payload.
func NewJSONAssertable(writer http.ResponseWriter, tag string, responseCode int, payload interface{}) *Assertable {
	return &Assertable{writer, tag, responseCode, "application/json", payload, true, nil, ""}
}

// NewAssertable constructs an Assertable which will, when Assert() is called with a failing test,
// respond to the client with the indicated Content-Type and payload.
func NewAssertable(writer http.ResponseWriter, tag string, responseCode int, contentType string, payload []byte) *Assertable {
	return &Assertable{writer, tag, responseCode, contentType, nil, false, payload, ""}
}

func (a *Assertable) Error() string {
	return a.msg
}

// Assert tests the `assertion` parameter, and trips if it test fails. A "trip" comprises three
// things: the provided message is logged; the client is sent the canned response (via the
// `http.ResponseWriter` provided at creation); and, the current execution stack is interrupted via
// a `panic` with the `Assertable` as the error. This panic is intended to be intercepted by the
// `WithPanicHandler()` wrapper from this package, making Wrapper/Assertable a pair.
func (a *Assertable) Assert(assertion bool, params ...interface{}) {
	if assertion {
		return
	}

	if len(params) < 1 {
		if a.isJSON {
			SendJSON(a.Writer, a.ResponseCode, a.Payload)
		} else {
			Send(a.Writer, a.ResponseCode, a.ContentType, a.data)
		}
		a.msg = "unspecified assertion error"
		log.Warn(fmt.Sprintf("httputil.Assert['%s']", a.Tag), a.msg)
		panic(a)
	}

	for i, o := range params {
		if o == nil {
			continue
		}
		if err, ok := o.(error); ok {
			params[i] = err.Error()
		}
	}

	var obj interface{}
	for len(params) > 0 {
		if msg, ok := params[0].(string); ok {
			a.msg = fmt.Sprintf(msg, params[1:]...)
			params = nil
			break
		}
		if obj != nil {
			break
		}
		obj = params[0]
		params = params[1:]
	}

	if a.msg == "" {
		a.msg = "unspecified assertion error"
	}

	if a.isJSON {
		payload := a.Payload
		if obj != nil {
			payload = obj
		}
		SendJSON(a.Writer, a.ResponseCode, payload)
		log.Warn(fmt.Sprintf("httputil.Assert['%s']", a.Tag), a.msg)
		panic(a)
	}

	b, ok := obj.([]byte)
	if !ok {
		b = a.data
	}

	Send(a.Writer, a.ResponseCode, a.ContentType, b)
	panic(a)
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
	return (&wrapper{}).withLogger(false)
}

// LoggingWrapper works exactly like Wrapper except that it logs all requests at Status log level.
// That is, if you want every request logged even when not running in Debug mode, use this.
func LoggingWrapper() *wrapper {
	return (&wrapper{}).withLogger(true)
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
				log.Warn("Wrapper.WithMethodSentry", "disallowed HTTP method", req.URL.Path, req.Method)
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
					log.Warn("Wrapper.PanicHandler", fmt.Sprintf("panic in handler for %s %s", req.Method, req.URL.Path), r)
					if _, ok := r.(*Assertable); !ok { // an Assertable will have already committed the response
						SendJSON(writer, http.StatusInternalServerError, struct{}{})
					}
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
	TAG := "Wrapper.WithSecretSentry"
	if header == "" || value == "" {
		log.Error(TAG, "missing header or value; check will be a no-op")
	}
	return w.prep(func(f http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			if !CheckAPISecret(req, header, value) {
				log.Warn(TAG, "API secret check failed", req.URL.Path, req.Method)
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

func (w *wrapper) withLogger(always bool) *wrapper {
	return w.prep(func(f http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			if always {
				log.Status("httputil.Wrapper", fmt.Sprintf("%s %s", req.Method, req.URL.Path))
			} else {
				log.Debug("httputil.Wrapper", fmt.Sprintf("%s %s", req.Method, req.URL.Path))
			}
			f(writer, req)
		}
	})
}
