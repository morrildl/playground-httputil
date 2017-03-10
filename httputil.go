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
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"

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

// SendJSON marshals the provided struct to a JSON string and then writes it to the client using the
// HTTP response/status code provided.
func SendJSON(writer http.ResponseWriter, status int, object interface{}) {
	writer.Header().Add("Content-Type", "application/json")

	s, err := json.Marshal(object)
	if err != nil {
		log.Warn("main", "error marshaling object to JSON", err)
		writer.Header().Add("Content-Length", strconv.Itoa(2))
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte("{}"))
		return
	}

	writer.Header().Add("Content-Length", strconv.Itoa(len(s)))
	writer.WriteHeader(status)
	writer.Write(s)
}

// SendPlaintext writes a raw string to the client as text/plain, handling the Content-Length header.
func SendPlaintext(writer http.ResponseWriter, status int, body string) {
	writer.Header().Add("Content-Type", "text/plain")
	writer.Header().Add("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	io.WriteString(writer, body)
}

// URLFor safely constructs a path from the provided components. "Safely" means that it properly
// handles duplicate / characters, etc. That is, URLFor("/foo/", "bar") is equivalent to
// URLFor("/foo/", "/bar"), etc.
func URLFor(elements ...string) string {
	u, err := url.Parse(Config.MgmtURLBase)
	if err != nil {
		log.Error("certs.urlFor", "Config.MgmtURLBase is malformed: '"+Config.MgmtURLBase+"'", err)
		// this implies a config error and is accordingly unrecoverable, so panic
		panic("Config.URLBase is malformed: '" + Config.MgmtURLBase + "'")
	}
	u.Path = path.Join(append([]string{u.Path}, elements...)...)
	return u.String()
}

var client *http.Client = nil

// Generally we only want to transmit requests to the Mgmt server instance we trust, which we want
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

// CallAPI is a convenience wrapper specifically around Mgmt API calls. It handles setting the
// shared-secret header for authentication to Mgmt, automatically constructs a final URL using the
// server/scheme specified in the server's config file, etc. Returns the HTTP status code, or the
// underlying error if not nil.
func CallAPI(api string, method string, sendObj interface{}, recvObj interface{}) (int, error) {
	if client == nil {
		initHTTPSClient()
	}

	body, err := json.Marshal(sendObj)
	if err != nil {
		log.Error("http.CallAPI", "trivial Request failed to marshal", err)
		return -1, err
	}

	req, err := http.NewRequest(method, api, bytes.NewReader(body))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Mgmt-Api-Secret", Config.MgmtSecret)
	if err != nil {
		return -1, err
	}
	res, err := client.Do(req)
	if err != nil {
		return -1, err
	}

	if recvObj != nil {
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error("http.CallAPI", "low-level I/O error reading HTTP response body", err)
			return -1, err
		}
		err = json.Unmarshal(body, recvObj)
		if err != nil {
			log.Error("http.CallAPI", "parse error unmarshaling HTTP response JSON", err)
			return -1, err
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
	log.Debug("http.PopulateFromBody", "raw JSON string follows")
	log.Debug("http.PopulateFromBody", string(body))
	if err != nil {
		log.Warn("http.PopulateFromBody", "I/O error parsing JSON from client", err)
		return err
	}
	err = json.Unmarshal(body, dest)
	if err != nil {
		log.Warn("http.PopulateFromBody", "error parsing JSON from client", err)
		return err
	}
	return nil
}
