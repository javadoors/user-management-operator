/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package server

import (
	"os"
	"strconv"

	"openfuyao.com/user-management/pkg/constants"
	"openfuyao.com/user-management/pkg/tools"
)

const (
	defaultServicePort = 9175
)

// Config defines http config
type Config struct {
	// server bind address
	BindAddress string

	// insecure port number
	InsecurePort int

	// secure port number
	SecurePort int

	// tls private key file
	PrivateKeyFile string

	// tls cert file
	CertFile string

	// tls CA file
	CAFile string
}

// RunConfig encapsulates the runtime configuration of the server,
// potentially including other settings beyond the basic server configuration.
type RunConfig struct {
	Config *Config
}

// NewServer creates and initializes a Server struct with default settings:
// listens on all network interfaces, binds to port 9197 for HTTP, and disables HTTPS.
func NewServer() *Config {
	port, err := strconv.Atoi(os.Getenv("SERVICE_PORT"))
	if err != nil {
		tools.LogWarn("service port not provided, use default port: 9175")
		port = defaultServicePort
	}
	// create default server run options
	s := Config{
		BindAddress:  "0.0.0.0",
		InsecurePort: 0,
		SecurePort:   0,
	}
	if _, err := os.Stat(constants.TlsCertPath); os.IsNotExist(err) {
		s.InsecurePort = port
		tools.FormatInfo("init user-management server with non-tls config, port: %d", port)
		return &s
	} else if err != nil {
		tools.FormatError("LogError accessing file: %v", err)
		return nil
	}
	tools.FormatInfo("init user-management server with tls config, port: %d", port)
	s.SecurePort = port
	s.CertFile = constants.TlsCertPath
	s.PrivateKeyFile = constants.TlsKeyPath
	s.CAFile = constants.TlsCAPath
	return &s
}

// NewRunConfig creates a RunConfig struct with a default Server configuration.
func NewRunConfig() *RunConfig {
	return &RunConfig{
		Config: NewServer(),
	}
}
