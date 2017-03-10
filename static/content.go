/* Copyright © Playground Global, LLC. All rights reserved. */

// Package httputil provides a few convenience functions for frequent operations on Go's http
// objects.
package static

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"playground/httputil"
	"playground/log"
)

// OAuthHandler is a generic function for inspecting a request and completing the final OAuth2
// redirection dance. Intended to be passed to http.HandleFunc.
func OAuthHandler(writer http.ResponseWriter, req *http.Request) {
	ssn := session.GetSession(req)
	if err := ssn.CompleteLogin(req); err != nil {
		log.Warn("OauthHandler", "error finishing login", err)
		SendPlaintext(writer, http.StatusForbidden, "Forbidden")
		return
	}
	ssn.Update(writer)
	redirTo := ssn.OriginalURL
	if redirTo == "" {
		redirTo = "/"
	}
	http.Redirect(writer, req, redirTo, http.StatusFound)
}

// StaticContent is a utility for managing access, caching, and serving of static content from
// disk. It is intended for use with the http package.
type StaticContent struct {
	Path         string
	Prefix       string
	faviconBytes []byte
	indexBytes   []byte
	preloads     map[string][]byte
}

// Handler is an http.HandleFunc that searches for and serves a file from disk (or cache, if it was
// Preload()ed.)
func (self *StaticContent) Handler(writer http.ResponseWriter, req *http.Request) {
	ssn := session.GetSession(req)
	if !ssn.IsLoggedIn() {
		ssn.Update(writer)
		log.Debug("StaticContent.Handler", "rejecting unauthenticated request for "+req.URL.Path)
		log.Debug("StaticContent.Handler", "session ID='"+ssn.ID+"'")
		SendPlaintext(writer, http.StatusUnauthorized, "Reauthentication Required")
		return
	}

	log.Debug("StaticContent.Handler", "received request for '"+req.URL.Path+"'")

	prefixLen := len(self.Prefix)
	fileBytes, err := self.loadFile(req.URL.Path[prefixLen:])
	if err != nil {
		log.Status("StaticContent.httpHandler", "failed to load file for '"+req.URL.Path+"'", err)
		SendPlaintext(writer, http.StatusNotFound, "File Not Found")
		return
	}

	// attempt to guess a content-type based on filename extension, if any
	idx := strings.LastIndex(req.URL.Path, ".")
	var ext string
	if idx > -1 {
		ext = req.URL.Path[idx:]
	}
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	log.Status("StaticContent.Handler", "serving "+req.URL.Path)
	Send(writer, http.StatusOK, contentType, fileBytes)
}

// RootHandler is an http.HandleFunc intended to handle the root path ("/") mapping. It
// searches for and serves a file called "index.html" if the request is a GET, or returns an error
// otherwise.
func (self *StaticContent) RootHandler(writer http.ResponseWriter, req *http.Request) {
	ssn := session.GetSession(req)
	if !ssn.IsLoggedIn() {
		log.Status("StaticContent.RootHandler", "redirecting expired or invalid login to OAuth")
		ssn.StartLogin(req, writer)
		return
	}

	// if it's a GET serve up index.html
	if req.Method == "GET" {
		log.Debug("StaticContent.RootHandler", "incoming request to '"+req.URL.Path+"'; serving index.html")

		indexBytes, err := self.loadFile("index.html")
		if err != nil {
			log.Error("StaticContent.RootHandler", "unable to load index.html", err)
			SendPlaintext(writer, http.StatusNotFound, "File Not Found")
			return
		}

		Send(writer, http.StatusOK, "text/html", indexBytes)
		return
	}

	// anything else is an error
	log.Debug("StaticContent.RootHandler", "incoming non-GET request to '"+req.URL.Path+"'")
	SendPlaintext(writer, http.StatusForbidden, "Forbidden")
}

// FaviconHandler is an http.HandleFunc intended to handle the root path ("/") mapping. It
// searches for and serves a file called "favicon.ico" in response to all requests.
func (self *StaticContent) FaviconHandler(writer http.ResponseWriter, req *http.Request) {
	favBytes, err := self.loadFile("favicon.ico")
	if err != nil {
		Send(writer, http.StatusOK, "image/x-icon", favBytes)
	} else {
		SendPlaintext(writer, http.StatusNotFound, "File Not Found")
	}
}

// Preload searches for and loads a file from disk, and then stores the resulting bytes. It is
// intended to be used to preload and cache common files that change very little, such as
// index.html, favicon.ico, and so on. Do NOT use this for files that can change during the lifetime
// of the server.
func (self *StaticContent) Preload(files ...string) {
	for _, filename := range files {
		fileBytes, err := self.loadFile(filename)
		if err == nil {
			self.preloads[filename] = fileBytes
		} else {
			log.Warn("StaticContent.Preload", "failed to preload file '"+filename+"'", err)
		}
	}
}

// loadFile is a private method that handles actual disk access, and is called by other methods.
func (self *StaticContent) loadFile(filename string) ([]byte, error) {
	if self.preloads == nil {
		self.preloads = make(map[string][]byte)
	}

	fileBytes, ok := self.preloads[filename]
	if ok {
		return fileBytes, nil
	}

	path := filepath.Join(self.Path, filename)
	if path, err := filepath.Abs(path); err != nil {
		log.Error("StaticContent.loadFile", "index.html file '"+path+"' does not resolve")
		return nil, err
	}
	if stat, err := os.Stat(path); err != nil || (stat != nil && stat.IsDir()) {
		log.Error("StaticContent.loadFile", "index.html file '"+path+"' does not stat or is a directory", err)
		return nil, err
	}
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("StaticContent.loadFile", "index.html file '"+path+"' failed to load", err)
		return nil, err
	}

	return fileBytes, nil
}
