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

	"playground/log"
)

// Send writes the indicated data to the client as the indicated content-type, handling
// the Content-Length header.
func Send(writer http.ResponseWriter, status int, contentType string, data []byte) {
	log.Debug("sendBytes", "Content-Type: '"+contentType+"'")
	writer.Header().Add("Content-Type", contentType)
	writer.Header().Add("Content-Length", strconv.Itoa(len(data)))
	writer.WriteHeader(status)
	writer.Write(data)
}

// sendJSON is the internal implementation called by SendJSON and SendFormattedJSON.
func sendJSON(writer http.ResponseWriter, status int, object interface{}, format bool) {
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
	writer.Header().Add("Content-Type", "text/plain")
	writer.Header().Add("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	io.WriteString(writer, body)
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

// CallAPI is a convenience wrapper specifically around API calls. It handles setting the
// shared-secret header for authentication to the remote server, automatically constructs a final
// URL using the server/scheme specified in the server's config file, etc. Returns the HTTP status
// code, or the underlying error if not nil.
func CallAPI(api string, method string, sendObj interface{}, recvObj interface{}) (int, error) {
	if client == nil {
		initHTTPSClient()
	}

	body, err := json.Marshal(sendObj)
	if err != nil {
		log.Error("httputil.CallAPI", "trivial Request failed to marshal", err)
		return -1, err
	}

	req, err := http.NewRequest(method, api, bytes.NewReader(body))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(Config.APISecretHeader, Config.APISecretValue)
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
func CheckAPISecret(req *http.Request) bool {
	log.Debug("httputil.CheckAPISecret", req.Header)

	if Config.APISecretHeader == "" || Config.APISecretValue == "" {
		return true
	}

	provided, ok := req.Header[Config.APISecretHeader]
	if !ok {
		log.Warn("httputil.CheckAPISecret", "missing API secret", req.URL.Path)
		return false
	}

	if len(provided) != 1 {
		log.Warn("httputil.CheckAPISecret", "multivalued API secret", req.URL.Path)
		return false
	}

	if provided[0] == Config.APISecretValue {
		return true
	}
	log.Warn("httputil.CheckAPISecret", "bad API secret")
	return false
}

// HandleFunc is a version of http.HandleFunc that wraps an http.HandlerFunc with some boilerplate
// checks frequently needed by handlers for API endpoints. Specifically, it checks incoming
// requests' methods against an allowed list, so that handlers don't have to repeat the same code.
// If Config.APISecretValue is set (i.e. via config.json), the wrapper optionally enforces the API
// secret.
func HandleFunc(path string, methods []string, handler http.HandlerFunc) {
	http.HandleFunc(path, func(writer http.ResponseWriter, req *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				log.Warn(path, fmt.Sprintf("panic in handler for %s %s", req.Method, req.URL.Path), r)
				SendJSON(writer, http.StatusInternalServerError, struct{}{})
			}
		}()

		if !CheckAPISecret(req) {
			log.Warn(path, "API secret check failed", req.URL.Path, req.Method)
			SendJSON(writer, http.StatusForbidden, struct{}{})
			return
		}

		allowed := false
		for _, method := range methods {
			if method == req.Method {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Warn(path, "disallowed HTTP method", req.URL.Path, req.Method)
			SendJSON(writer, http.StatusMethodNotAllowed, struct{}{})
			return
		}

		log.Status(path, fmt.Sprintf("%s %s", req.Method, req.URL.Path))
		handler(writer, req)
	})
}
