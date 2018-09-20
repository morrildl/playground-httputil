/* Copyright © Playground Global, LLC. All rights reserved. */

package httputil

// ConfigType for use by the caller to populate this package's configuration
type ConfigType struct {
	EnableHSTS bool
}

// Config instance of ConfigType for use by the caller to populate this package's configuration
var Config = ConfigType{
	EnableHSTS: true,
}
