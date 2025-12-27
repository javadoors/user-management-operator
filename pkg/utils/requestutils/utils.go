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

// Package requestutils provide util functions for http request
package requestutils

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"openfuyao.com/user-management/pkg/api/user/v1/types"
	"openfuyao.com/user-management/pkg/constants"
	"openfuyao.com/user-management/pkg/tools"
)

// PrepareUserMgmtRequestURL returns user-management related urls
func PrepareUserMgmtRequestURL(clusterName string, suffix string) string {
	url := fmt.Sprintf("%s://%s:%d", constants.ConsoleServiceProtocol,
		constants.ConsoleServiceHost, constants.ConsoleServicePort)
	pathPrefix := strings.Replace(constants.UserMgmtPathPrefix, "{cluster}", clusterName, 1)
	return url + pathPrefix + suffix
}

// PrepareK8sResourceRequestURL returns k8s resource related urls
func PrepareK8sResourceRequestURL(clusterName string, suffix string) string {
	url := fmt.Sprintf("%s://%s:%d", constants.ConsoleServiceProtocol,
		constants.ConsoleServiceHost, constants.ConsoleServicePort)
	pathPrefix := strings.Replace(constants.K8sResourcePathPrefix, "{cluster}", clusterName, 1)
	return url + pathPrefix + suffix
}

// PrepareMultiClusterRequestURL returns url that is called across clusters
func PrepareMultiClusterRequestURL(suffix string) string {
	url := fmt.Sprintf("%s://%s:%d", constants.ConsoleServiceProtocol,
		constants.ConsoleServiceHost, constants.ConsoleServicePort)
	return url + constants.MultiClusterPathPrefix + suffix
}

// DoUserManagementRequest make user-management related requests
func DoUserManagementRequest(url string, method string, oriReq *http.Request,
	reqBodyBytes []byte) (*types.ApiResponse, error) {
	req, err := http.NewRequest(method, url, nil)
	if len(reqBodyBytes) == 0 {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(reqBodyBytes))
	}
	if err != nil {
		tools.FormatError("Error creating request: %v", err)
		return nil, err
	}

	addAuthorizationHeader(oriReq, req)

	// Create a custom HTTP client with TLS config to skip certificate verification
	tlsConfig, err := GetCustomizedHttpConfigByPath(constants.TlsCertPath, constants.TlsKeyPath, constants.TlsCAPath)
	if err != nil {
		tools.FormatWarn("create tls config failed: %v, continue with http config", tlsConfig)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		tools.FormatError("Error sending request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read and print the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tools.FormatError("Error reading response: %v", err)
		return nil, err
	}

	// unmarshal to ApiResponse
	var response types.ApiResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		tools.FormatError("Error converting to ApiResponse: %v", err)
		return nil, err
	}

	return &response, nil
}

// DoRequestWithMaxRetries make requests with max retries
func DoRequestWithMaxRetries(url string, method string, oriReq *http.Request, reqBodyBytes []byte,
	maxAttempts int) (int, []byte, error) {
	const retryInterval = 1
	req, err := http.NewRequest(method, url, nil)
	if len(reqBodyBytes) != 0 {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(reqBodyBytes))
	}
	if err != nil {
		tools.FormatError("Error creating request: %v", err)
		return http.StatusInternalServerError, nil, err
	}

	addAuthorizationHeader(oriReq, req)

	// Create a custom HTTP client with TLS config to skip certificate verification
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	var statusCode int
	var body []byte
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Send the HTTP request
		resp, err := client.Do(req)
		if err != nil {
			tools.FormatError("Error sending request: %v", err)
			return http.StatusInternalServerError, nil, err
		}
		defer resp.Body.Close()

		// Read and print the response body
		statusCode = resp.StatusCode
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			tools.FormatError("Error reading response: %v", err)
			return http.StatusInternalServerError, nil, err
		}

		if resp.StatusCode < http.StatusMultipleChoices {
			return resp.StatusCode, body, nil
		}
		if resp.StatusCode == http.StatusConflict {
			break
		}

		if attempt < maxAttempts {
			tools.FormatWarn("retrying request in %d second...", retryInterval)
			time.Sleep(retryInterval * time.Second)
		}
	}

	return statusCode, nil, fmt.Errorf("%s", string(body))
}

func addAuthorizationHeader(req *http.Request, extReq *http.Request) {
	// add authorization header
	authInfo := req.Header.Get("Authorization")
	if authInfo != "" {
		tools.LogInfo("Successfully retrieve Authorization token from request")
		extReq.Header.Set("Authorization", authInfo)
	} else {
		tools.LogError("Cannot retrieve Authorization token from request")
	}

	openFuyaoAuthInfo := req.Header.Get(constants.OpenFuyaoAuthHeaderKey)
	if openFuyaoAuthInfo != "" {
		tools.LogInfo("Successfully retrieve OpenFuyao Authorization token from request")
		extReq.Header.Set(constants.OpenFuyaoAuthHeaderKey, openFuyaoAuthInfo)
	} else {
		tools.LogError("Cannot retrieve OpenFuyao Authorization token from request")
		if authInfo != "" {
			tools.LogInfo("Use Authorization header token in OpenFuyao Authorization header")
			extReq.Header.Set(constants.OpenFuyaoAuthHeaderKey, authInfo)
		}
	}
}

// GetCustomizedHttpConfigByPath returns a TLS config with optional certs and CA
func GetCustomizedHttpConfigByPath(certPath, keyPath, caPath string) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	// load certs
	if err := loadClientCert(tlsCfg, certPath, keyPath); err != nil {
		return tlsCfg, err
	}

	// load CA
	if err := loadCA(tlsCfg, caPath); err != nil {
		return tlsCfg, err
	}

	// fallback
	if len(tlsCfg.Certificates) == 0 && tlsCfg.RootCAs == nil {
		tlsCfg.InsecureSkipVerify = true
	}
	return tlsCfg, nil
}

func loadClientCert(tlsCfg *tls.Config, certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("load cert/key: %w", err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

func loadCA(tlsCfg *tls.Config, caPath string) error {
	if caPath == "" {
		return nil
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read CA %s: %w", caPath, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("append CA %s failed", caPath)
	}
	tlsCfg.RootCAs = caCertPool
	return nil
}
