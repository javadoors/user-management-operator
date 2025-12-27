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
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	"openfuyao.com/user-management/pkg/constants"
)

func TestNewServer(t *testing.T) {
	// 调用被测试的函数
	serverConfig := NewServer()

	// 验证 BindAddress 是否正确
	assert.Equal(t, "0.0.0.0", serverConfig.BindAddress, "BindAddress should be '0.0.0.0'")

	// 验证 InsecurePort 是否正确
	assert.Equal(t, 9175, serverConfig.InsecurePort, "InsecurePort should be 9175")

	// 验证 SecurePort 是否正确
	assert.Equal(t, 0, serverConfig.SecurePort, "SecurePort should be 0")
}

func TestNewServerWithTLS(t *testing.T) {
	err := os.Setenv("SERVICE_PORT", "12345")
	defer func() {
		err := os.Unsetenv("SERVICE_PORT")
		if err != nil {
			t.Fatalf("failed to unset environment variable: %v", err)
		}
	}()
	if err != nil {
		t.Fatalf("failed to set environment variable: %v", err)
	}

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	// mock os.Stat：始终返回一个假的 FileInfo，不返回 error
	patches.ApplyFunc(os.Stat, func(name string) (os.FileInfo, error) {
		return nil, nil
	})

	cfg := NewServer()

	const securePort = 12345
	assert.NotNil(t, cfg)
	assert.Equal(t, securePort, cfg.SecurePort)
	assert.Equal(t, constants.TlsCertPath, cfg.CertFile)
	assert.Equal(t, constants.TlsKeyPath, cfg.PrivateKeyFile)
	assert.Equal(t, constants.TlsCAPath, cfg.CAFile)
	assert.Equal(t, 0, cfg.InsecurePort)
}

func TestNewRunConfig(t *testing.T) {
	// 调用被测试的函数
	runConfig := NewRunConfig()

	// 验证 RunConfig 是否不为 nil
	assert.NotNil(t, runConfig, "RunConfig should not be nil")

	// 验证 RunConfig.Config 是否不为 nil
	assert.NotNil(t, runConfig.Config, "RunConfig.Config should not be nil")

	// 验证 RunConfig.Config 的字段是否正确
	assert.Equal(t, "0.0.0.0", runConfig.Config.BindAddress, "BindAddress should be '0.0.0.0'")
	assert.Equal(t, 9175, runConfig.Config.InsecurePort, "InsecurePort should be 9175")
	assert.Equal(t, 0, runConfig.Config.SecurePort, "SecurePort should be 0")
}
