/* Copyright © Playground Global, LLC. All rights reserved. */

// Package httputil provides a few convenience functions for frequent operations on Go's http
// objects.
package static

import (
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"playground/httputil"
	"playground/log"
	"playground/session"
)

// OAuthHandler is a generic function for inspecting a request and completing the final OAuth2
// redirection dance. Intended to be passed to http.HandleFunc.
func OAuthHandler(writer http.ResponseWriter, req *http.Request) {
	ssn := session.GetSession(req)
	if err := ssn.CompleteLogin(req); err != nil {
		log.Warn("OauthHandler", "error finishing login", err)
		httputil.SendPlaintext(writer, http.StatusForbidden, "Forbidden")
		return
	}
	ssn.Update(writer)
	redirTo := ssn.OriginalURL
	if redirTo == "" {
		redirTo = "/"
	}
	http.Redirect(writer, req, redirTo, http.StatusFound)
}

// Content is a utility for managing access, caching, and serving of static content from
// disk. It is intended for use with the http package.
type Content struct {
	Path         string
	Prefix       string
	faviconBytes []byte
	indexBytes   []byte
	preloads     map[string][]byte
}

// Handler is an http.HandleFunc that searches for and serves a file from disk (or cache, if it was
// Preload()ed.)
func (self *Content) Handler(writer http.ResponseWriter, req *http.Request) {
	ssn := session.GetSession(req)
	if !ssn.IsLoggedIn() {
		ssn.Update(writer)
		log.Debug("Content.Handler", "rejecting unauthenticated request for "+req.URL.Path)
		log.Debug("Content.Handler", "session ID='"+ssn.ID+"'")
		httputil.SendPlaintext(writer, http.StatusUnauthorized, "Reauthentication Required")
		return
	}

	log.Debug("Content.Handler", "received request for '"+req.URL.Path+"'")

	prefixLen := len(self.Prefix)
	fileBytes, err := self.loadFile(req.URL.Path[prefixLen:])
	if err != nil {
		log.Status("Content.httpHandler", "failed to load file for '"+req.URL.Path+"'", err)
		httputil.SendPlaintext(writer, http.StatusNotFound, "File Not Found")
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

	log.Status("Content.Handler", "serving "+req.URL.Path)
	httputil.Send(writer, http.StatusOK, contentType, fileBytes)
}

// RootHandler is an http.HandleFunc intended to handle the root path ("/") mapping. It
// searches for and serves a file called "index.html" if the request is a GET, or returns an error
// otherwise.
func (self *Content) RootHandler(writer http.ResponseWriter, req *http.Request) {
	ssn := session.GetSession(req)
	if !ssn.IsLoggedIn() {
		log.Status("Content.RootHandler", "redirecting expired or invalid login to OAuth")
		ssn.StartLogin(req, writer)
		return
	}

	// if it's a GET serve up index.html
	if req.Method == "GET" {
		log.Debug("Content.RootHandler", "incoming request to '"+req.URL.Path+"'; serving index.html")

		indexBytes, err := self.loadFile("index.html")
		if err != nil {
			log.Error("Content.RootHandler", "unable to load index.html", err)
			httputil.SendPlaintext(writer, http.StatusNotFound, "File Not Found")
			return
		}

		httputil.Send(writer, http.StatusOK, "text/html", indexBytes)
		return
	}

	// anything else is an error
	log.Debug("Content.RootHandler", "incoming non-GET request to '"+req.URL.Path+"'")
	httputil.SendPlaintext(writer, http.StatusForbidden, "Forbidden")
}

// FaviconHandler is an http.HandleFunc intended to handle favicon serving. It
// searches for and serves a file called "favicon.ico" in response to all requests.
// The basic static Handler can also handle favicons, but FaviconHandler is an optimization that
// skips path parsing and file lookups, since favicons are loaded very frequently.
func (self *Content) FaviconHandler(writer http.ResponseWriter, req *http.Request) {
	favBytes, err := self.loadFile("favicon.ico")
	if err == nil {
		httputil.Send(writer, http.StatusOK, "image/x-icon", favBytes)
	} else {
		httputil.SendPlaintext(writer, http.StatusNotFound, "File Not Found")
	}
}

// Preload searches for and loads a file from disk, and then stores the resulting bytes. It is
// intended to be used to preload and cache common files that change very little, such as
// index.html, favicon.ico, and so on. Do NOT use this for files that can change during the lifetime
// of the server.
func (self *Content) Preload(files ...string) {
	for _, filename := range files {
		fileBytes, err := self.loadFile(filename)
		if err == nil {
			self.preloads[filename] = fileBytes
		} else {
			log.Warn("Content.Preload", "failed to preload file '"+filename+"'", err)
		}
	}
}

// loadFile is a private method that handles actual disk access, and is called by other methods.
func (self *Content) loadFile(filename string) ([]byte, error) {
	if self.preloads == nil {
		self.preloads = make(map[string][]byte)
	}

	fileBytes, ok := self.preloads[filename]
	if ok {
		return fileBytes, nil
	}

	path := filepath.Join(self.Path, filename)
	if path, err := filepath.Abs(path); err != nil {
		log.Error("Content.loadFile", "index.html file '"+path+"' does not resolve")
		return nil, err
	}
	if stat, err := os.Stat(path); err != nil || (stat != nil && stat.IsDir()) {
		log.Error("Content.loadFile", "index.html file '"+path+"' does not stat or is a directory", err)
		return nil, err
	}
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Content.loadFile", "index.html file '"+path+"' failed to load", err)
		return nil, err
	}

	return fileBytes, nil
}
