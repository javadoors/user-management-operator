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

package requestutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	hours     = 24
	days      = 365
	serialNum = 2
	keyLen    = 2048
)

func TestPrepareUserManagementRequestURL(t *testing.T) {
	// 定义测试用例
	tests := []struct {
		clusterName string
		suffix      string
		expectedURL string
	}{
		{
			clusterName: "cluster1", suffix: "/users/list",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/clusters/" +
				"cluster1/rest/user/v1/users/list",
		},
		{
			clusterName: "cluster2", suffix: "/users/details",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/clusters/" +
				"cluster2/rest/user/v1/users/details",
		},
		{
			clusterName: "prod-cluster", suffix: "/users/delete",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/clusters" +
				"/prod-cluster/rest/user/v1/users/delete",
		},
		{
			clusterName: "dev-cluster", suffix: "/roles/assign",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/clusters" +
				"/dev-cluster/rest/user/v1/roles/assign",
		},
	}

	// 遍历每个测试用例
	for _, tt := range tests {
		t.Run(fmt.Sprintf("clusterName=%s, suffix=%s", tt.clusterName, tt.suffix), func(t *testing.T) {
			// 调用被测试的函数
			resultURL := PrepareUserMgmtRequestURL(tt.clusterName, tt.suffix)

			// 使用 assert.Equal 断言实际结果与预期结果是否相同
			assert.Equal(t, tt.expectedURL, resultURL, "they should be equal")
		})
	}
}

func TestPrepareK8sResourceRequestURL(t *testing.T) {
	// 定义测试用例
	tests := []struct {
		clusterName string
		suffix      string
		expectedURL string
	}{
		{
			clusterName: "cluster1",
			suffix:      "/pods/list",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/clusters/cluster1/api/kubernetes/pods/list",
		},
		{
			clusterName: "cluster2",
			suffix:      "/deployments/details",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/clusters/cluster2/api/kubernetes/deployments/details",
		},
		{
			clusterName: "prod-cluster",
			suffix:      "/services/delete",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/clusters/prod-cluster/api/kubernetes/services/delete",
		},
	}

	// 遍历测试用例
	for _, tt := range tests {
		t.Run(fmt.Sprintf("clusterName=%s, suffix=%s", tt.clusterName, tt.suffix), func(t *testing.T) {
			// 调用被测试的函数
			resultURL := PrepareK8sResourceRequestURL(tt.clusterName, tt.suffix)

			// 使用 assert.Equal 断言实际结果与预期结果是否相同
			assert.Equal(t, tt.expectedURL, resultURL, "they should be equal")
		})
	}
}

func TestPrepareMultiClusterRequestURL(t *testing.T) {
	// 定义测试用例
	tests := []struct {
		suffix      string
		expectedURL string
	}{
		{
			suffix:      "/clusters/list",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/rest/multicluster/v1beta1/clusters/list",
		},
		{
			suffix:      "/nodes/details",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/rest/multicluster/v1beta1/nodes/details",
		},
		{
			suffix:      "/resources/delete",
			expectedURL: "https://console-service.openfuyao-system.svc.cluster.local:80/rest/multicluster/v1beta1/resources/delete",
		},
	}

	// 遍历测试用例
	for _, tt := range tests {
		t.Run(fmt.Sprintf("suffix=%s", tt.suffix), func(t *testing.T) {
			// 调用被测试的函数
			resultURL := PrepareMultiClusterRequestURL(tt.suffix)

			// 使用 assert.Equal 断言实际结果与预期结果是否相同
			assert.Equal(t, tt.expectedURL, resultURL, "they should be equal")
		})
	}
}

// 模拟的工具日志函数
var logInfoCalled bool
var logErrorCalled bool

func LogInfo(message string, args ...interface{}) {
	logInfoCalled = true
}

func LogError(message string, args ...interface{}) {
	logErrorCalled = true
}
func TestAddAuthorizationHeader(t *testing.T) {
	// 测试数据
	tests := []struct {
		name                  string
		reqHeaders            map[string]string
		expectedExtReqHeaders map[string]string
		expectLogError        bool
	}{
		{
			name: "Both Authorization and OpenFuyaoAuth headers present",
			reqHeaders: map[string]string{
				"Authorization": "Bearer test-token",
			},
			expectedExtReqHeaders: map[string]string{
				"Authorization": "Bearer test-token",
			},
			expectLogError: false,
		},
	}

	// 遍历每个测试用例
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 初始化请求和外部请求
			req := &http.Request{
				Header: make(http.Header),
			}
			extReq := &http.Request{
				Header: make(http.Header),
			}

			// 设置请求头
			for key, value := range tt.reqHeaders {
				req.Header.Set(key, value)
			}

			// 调用被测试的函数
			addAuthorizationHeader(req, extReq)

			// 验证 extReq 是否包含预期的头信息
			for key, expectedValue := range tt.expectedExtReqHeaders {
				actualValue := extReq.Header.Get(key)
				assert.Equal(t, expectedValue, actualValue, "Expected header value for %s", key)
			}

			// 验证是否调用了 LogError
			if tt.expectLogError {
				assert.True(t, logErrorCalled, "Expected LogError to be called")
			} else {
				assert.False(t, logErrorCalled, "Expected LogError not to be called")
			}

			// 重置日志标记
			logInfoCalled = false
			logErrorCalled = false
		})
	}
}

type ApiResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

func TestDoUserManagementRequest(t *testing.T) {
	// 创建模拟的 HTTP 服务器
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟返回的 API 响应
		mockResponse := ApiResponse{
			Code: 200,
			Msg:  "Success",
			Data: map[string]string{"key": "value"},
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(mockResponse)
		assert.Nil(t, err)
	}))
	defer mockServer.Close()

	// 定义测试用例
	tests := []struct {
		name          string
		method        string
		reqBodyBytes  []byte
		expectedBody  ApiResponse
		expectedError bool
	}{
		{
			name:          "GET request success",
			method:        "GET",
			reqBodyBytes:  nil,
			expectedBody:  ApiResponse{Code: 200, Msg: "Success", Data: map[string]interface{}{"key": "value"}},
			expectedError: false,
		},
		{
			name:          "POST request with body",
			method:        "POST",
			reqBodyBytes:  []byte(`{"test":"data"}`),
			expectedBody:  ApiResponse{Code: 200, Msg: "Success", Data: map[string]interface{}{"key": "value"}},
			expectedError: false,
		},
	}

	// 遍历测试用例
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建模拟的原始请求
			oriReq, err := http.NewRequest("GET", mockServer.URL, nil)
			assert.Nil(t, err)
			oriReq.Header.Set("Authorization", "Bearer test-token")

			// 调用被测试的函数
			apiResponse, err := DoUserManagementRequest(mockServer.URL, tt.method, oriReq, tt.reqBodyBytes)

			// 验证是否有预期的错误
			if tt.expectedError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			// 验证响应体内容
			assert.Equal(t, tt.expectedBody.Code, apiResponse.Code)
			assert.Equal(t, tt.expectedBody.Msg, apiResponse.Msg)
			assert.Equal(t, tt.expectedBody.Data, apiResponse.Data)
		})
	}
}

func TestDoRequestWithMaxRetries(t *testing.T) {
	// 模拟 HTTP 服务器
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟重试逻辑
		if r.Header.Get("Retry-Attempt") == "" {
			w.Header().Set("Retry-Attempt", "1")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Internal Server Error")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"key":"value"}`)
	}))
	defer mockServer.Close()

	// 定义测试用例
	tests := []struct {
		name          string
		method        string
		reqBodyBytes  []byte
		maxAttempts   int
		expectedCode  int
		expectedBody  string
		expectedError bool
	}{
		{
			name:          "Fail after max retries",
			method:        "GET",
			reqBodyBytes:  nil,
			maxAttempts:   1,
			expectedCode:  http.StatusInternalServerError,
			expectedBody:  "",
			expectedError: true,
		},
	}

	// 遍历测试用例
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建模拟的原始请求
			oriReq, err := http.NewRequest("GET", mockServer.URL, nil)
			assert.Nil(t, err)
			oriReq.Header.Set("Authorization", "Bearer test-token")

			// 调用被测试的函数
			statusCode, body, err := DoRequestWithMaxRetries(mockServer.URL, tt.method, oriReq,
				tt.reqBodyBytes, tt.maxAttempts)

			// 验证响应状态码和响应体
			assert.Equal(t, tt.expectedCode, statusCode)
			assert.Equal(t, tt.expectedBody, string(body))

			// 验证是否有预期的错误
			if tt.expectedError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestLoadClientCert(t *testing.T) {
	certs, err := generateTestCertificate()
	assert.NoError(t, err)

	certPath, err := createTempFile(certs.certPEM)
	assert.NoError(t, err)
	defer os.Remove(certPath)

	keyPath, err := createTempFile(certs.keyPEM)
	assert.NoError(t, err)
	defer os.Remove(keyPath)

	t.Run("Valid cert and key paths", func(t *testing.T) {
		tlsCfg := &tls.Config{}
		err := loadClientCert(tlsCfg, certPath, keyPath)
		assert.NoError(t, err)
		assert.Len(t, tlsCfg.Certificates, 1)
	})

	t.Run("Empty paths", func(t *testing.T) {
		tlsCfg := &tls.Config{}
		err := loadClientCert(tlsCfg, "", "")
		assert.NoError(t, err)
		assert.Len(t, tlsCfg.Certificates, 0)
	})

	t.Run("Non-existent paths", func(t *testing.T) {
		tlsCfg := &tls.Config{}
		err := loadClientCert(tlsCfg, "/nonexistent/cert", "/nonexistent/key")
		assert.NoError(t, err)
		assert.Len(t, tlsCfg.Certificates, 0)
	})
}

// Helper function to generate a self-signed certificate and CA for testing
type testCertificate struct {
	certPEM []byte
	keyPEM  []byte
	caPEM   []byte
}

func generateTestCertificate() (*testCertificate, error) {
	caPriv, caCert, err := generateCACertificate()
	if err != nil {
		return nil, err
	}

	serverCertPEM, serverKeyPEM, err := generateServerCertificate(caCert, caPriv)
	if err != nil {
		return nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	return &testCertificate{
		certPEM: serverCertPEM,
		keyPEM:  serverKeyPEM,
		caPEM:   caPEM,
	}, nil
}

func generateServerCertificate(caCert *x509.Certificate, caPriv *rsa.PrivateKey) (certPEM, keyPEM []byte, err error) {
	serverPriv, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		return nil, nil, err
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(serialNum),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * hours * days),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverDerBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDerBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPriv)})

	return certPEM, keyPEM, nil
}

func generateCACertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	caPriv, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		return nil, nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * hours * days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDerBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caDerBytes)
	if err != nil {
		return nil, nil, err
	}

	return caPriv, caCert, nil
}

// Helper function to create temporary files
func createTempFile(content []byte) (string, error) {
	file, err := os.CreateTemp("", "test")
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = file.Write(content)
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

func TestLoadCA(t *testing.T) {
	certs, err := generateTestCertificate()
	assert.NoError(t, err)

	caPath, err := createTempFile(certs.caPEM)
	assert.NoError(t, err)
	defer os.Remove(caPath)

	t.Run("Valid CA path", func(t *testing.T) {
		tlsCfg := &tls.Config{}
		err := loadCA(tlsCfg, caPath)
		assert.NoError(t, err)
		assert.NotNil(t, tlsCfg.RootCAs)
	})

	t.Run("Empty CA path", func(t *testing.T) {
		tlsCfg := &tls.Config{}
		err := loadCA(tlsCfg, "")
		assert.NoError(t, err)
		assert.Nil(t, tlsCfg.RootCAs)
	})

	t.Run("Non-existent CA path", func(t *testing.T) {
		tlsCfg := &tls.Config{}
		err := loadCA(tlsCfg, "/nonexistent/ca")
		assert.NoError(t, err)
		assert.Nil(t, tlsCfg.RootCAs)
	})

	t.Run("Invalid CA content", func(t *testing.T) {
		invalidCAPath, err := createTempFile([]byte("invalid cert"))
		assert.NoError(t, err)
		defer os.Remove(invalidCAPath)

		tlsCfg := &tls.Config{}
		err = loadCA(tlsCfg, invalidCAPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "append CA")
	})
}

func TestGetCustomizedHttpConfigByPath(t *testing.T) {
	certs, err := generateTestCertificate()
	assert.NoError(t, err)

	certPath, err := createTempFile(certs.certPEM)
	assert.NoError(t, err)
	defer os.Remove(certPath)

	keyPath, err := createTempFile(certs.keyPEM)
	assert.NoError(t, err)
	defer os.Remove(keyPath)

	t.Run("Empty cert and key paths", func(t *testing.T) {
		tlsCfg, err := GetCustomizedHttpConfigByPath("", "", "")
		assert.NoError(t, err)
		assert.NotNil(t, tlsCfg)
		assert.True(t, tlsCfg.InsecureSkipVerify)
	})

	t.Run("Non-existent cert path", func(t *testing.T) {
		tlsCfg, err := GetCustomizedHttpConfigByPath("/nonexistent/cert", "/nonexistent/key", "")
		assert.NoError(t, err)
		assert.NotNil(t, tlsCfg)
	})
}
