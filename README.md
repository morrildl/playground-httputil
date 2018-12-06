# Package `playground/httputil`

This library is a set of utilities for building small HTTPS/REST services. It includes two things: a "hardened" HTTPS configuration, and some convenience functions for reducing boilerplate in HTTP handlers for JSON REST endpoints.

The HTTPS configuration is based on [this post from Cloudflare.](https://blog.cloudflare.com/exposing-go-on-the-internet/)

The convenience utilities comprise a set of JSON marshaling/unmarshaling helpers, as well as a wrapper scheme for adding common useful behaviors to a standard Go HTTP handler.

Special thanks to Playground Global, LLC for open-sourcing this software. See `LICENSE` for details.