/* Copyright © Playground Global, LLC. All rights reserved. */

package httputil

// ConfigType for use by the caller to populate this package's configuration
type ConfigType struct {
	ClientCertFile           string
	ClientKeyFile            string
	SelfSignedServerCertFile string
	APISecretHeader          string
	APISecretValue           string
}

// Config instance of ConfigType for use by the caller to populate this package's configuration
var Config = ConfigType{
	ClientCertFile:           "./client.crt",
	ClientKeyFile:            "./client.key",
	SelfSignedServerCertFile: "server.crt",
	APISecretHeader:          "X-Playground-Api-Secret",
	APISecretValue:           "",
}
