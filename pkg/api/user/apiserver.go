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

// Package user defines the apiserver for user handlers
package user

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/apimachinery/pkg/util/runtime"

	"openfuyao.com/user-management/pkg/api/user/v1"
	"openfuyao.com/user-management/pkg/filters"
	"openfuyao.com/user-management/pkg/server"
	"openfuyao.com/user-management/pkg/tools"
)

// APIServer defines the http server core
type APIServer struct {
	Server    *http.Server
	container *restful.Container
}

// NewAPIServer initializes the http server
func NewAPIServer(cfg *server.RunConfig) (*APIServer, error) {
	apiServer := &APIServer{}
	httpServer, err := initServer(cfg)
	if err != nil {
		errorMessage := fmt.Sprintf("LogError creating a new ApiServer: %s", err)
		tools.LogError(errorMessage)
		return nil, errors.New(errorMessage)
	}
	apiServer.container = restful.NewContainer()
	apiServer.container.Router(restful.CurlyRouter{})
	// extract user from token and add it to req.Request.context
	apiServer.container.Filter(filters.RecordAccessLogs)
	apiServer.container.Filter(filters.AuthenticateOpenFuyaoUser)
	apiServer.Server = httpServer
	return apiServer, nil

}

func initServer(cfg *server.RunConfig) (*http.Server, error) {
	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.Config.InsecurePort),
	}
	// https 证书配置
	if cfg.Config.SecurePort != 0 {
		certificate, err := tls.LoadX509KeyPair(cfg.Config.CertFile, cfg.Config.PrivateKeyFile)
		if err != nil {
			tools.FormatError("error loading %s and %s , %v", cfg.Config.CertFile, cfg.Config.PrivateKeyFile, err)
			return nil, err
		}
		// load RootCA
		caCert, err := os.ReadFile(cfg.Config.CAFile)
		if err != nil {
			tools.FormatError("error read %s, err: %v", cfg.Config.CAFile, err)
			return nil, err
		}

		// create the cert pool
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS12,
			ClientCAs:    caCertPool,
		}
		httpServer.Addr = fmt.Sprintf(":%d", cfg.Config.SecurePort)
	}
	return httpServer, nil
}

// Run starts the APIServer, registering API endpoints and handling requests.
// It supports graceful shutdown on context cancellation.
func (s *APIServer) Run(ctx context.Context) error {
	s.registerAPI()
	s.Server.Handler = s.container
	shutdownCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		err := s.Server.Shutdown(shutdownCtx)
		if err != nil {
			errorMessage := fmt.Sprintf("ApiServer shutdown error: %s", err)
			tools.LogError(errorMessage)
		}
	}()

	var err error
	if s.Server.TLSConfig != nil {
		err = s.Server.ListenAndServeTLS("", "")
	} else {
		err = s.Server.ListenAndServe()
	}
	return err
}

func (s *APIServer) registerAPI() {
	runtime.Must(v1.AddLogsContainer(s.container))
}
