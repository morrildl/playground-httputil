/* Copyright © Playground Global, LLC. All rights reserved. */

package httputil

type ConfigType struct {
	MgmtURLBase              string
	MgmtSecret               string
	ClientCertFile           string
	ClientKeyFile            string
	SelfSignedServerCertFile string
}

var Config = ConfigType{
	MgmtURLBase:              "https://localhost:9000",
	MgmtSecret:               "",
	ClientCertFile:           "./client.crt",
	ClientKeyFile:            "./client.key",
	SelfSignedServerCertFile: "server.crt",
}
