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

package controller

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testLockDuration             = 300
	testMaxAttempts              = 5
	testInvalidNumber            = "invalid"
	testLockDurationKey          = "LOCK_DURATION"
	testMaxAttemptsKey           = "MAX_ATTEMPTS"
	testErrorLockDurationNotSet  = "LOCK_DURATION not set"
	testErrorMaxAttemptsNotSet   = "MAX_ATTEMPTS not set"
	testErrorInvalidLockDuration = "invalid LOCK_ATTEMPTS format: "
	testErrorInvalidMaxAttempts  = "invalid MAX_ATTEMPTS format: "
)

func setupTestEnv(key, value string) error {
	return os.Setenv(key, value)
}

func cleanupTestEnv(key, originalValue string) {
	if originalValue != "" {
		err := os.Setenv(key, originalValue)
		if err != nil {
			return
		}
	} else {
		err := os.Unsetenv(key)
		if err != nil {
			return
		}
	}
}

func TestLoadConfigurationSuccess(t *testing.T) {
	// 保存原始环境变量
	originalLockDuration := os.Getenv(testLockDurationKey)
	originalMaxAttempts := os.Getenv(testMaxAttemptsKey)

	// 设置测试环境变量
	err := setupTestEnv(testLockDurationKey, fmt.Sprintf("%d", testLockDuration))
	if err != nil {
		t.Fatalf("Failed to set LOCK_DURATION: %v", err)
	}
	err = setupTestEnv(testMaxAttemptsKey, fmt.Sprintf("%d", testMaxAttempts))
	if err != nil {
		t.Fatalf("Failed to set MAX_ATTEMPTS: %v", err)
	}

	// 恢复原始环境变量
	defer cleanupTestEnv(testLockDurationKey, originalLockDuration)
	defer cleanupTestEnv(testMaxAttemptsKey, originalMaxAttempts)

	// 调用被测试的函数
	lockDuration, maxAttempts, err := loadConfiguration()

	// 验证结果
	assert.NoError(t, err)
	assert.Equal(t, testLockDuration, lockDuration)
	assert.Equal(t, testMaxAttempts, maxAttempts)
}

func TestLoadConfigurationLockDurationNotSet(t *testing.T) {
	// 保存原始环境变量
	originalLockDuration := os.Getenv(testLockDurationKey)
	originalMaxAttempts := os.Getenv(testMaxAttemptsKey)

	// 清除 LOCK_DURATION 环境变量
	err := os.Unsetenv(testLockDurationKey)
	if err != nil {
		t.Fatalf("Failed to unset LOCK_DURATION: %v", err)
	}
	err = setupTestEnv(testMaxAttemptsKey, fmt.Sprintf("%d", testMaxAttempts))
	if err != nil {
		t.Fatalf("Failed to set MAX_ATTEMPTS: %v", err)
	}

	// 恢复原始环境变量
	defer cleanupTestEnv(testLockDurationKey, originalLockDuration)
	defer cleanupTestEnv(testMaxAttemptsKey, originalMaxAttempts)

	// 调用被测试的函数
	lockDuration, maxAttempts, err := loadConfiguration()

	// 验证结果
	assert.Error(t, err)
	assert.Equal(t, 0, lockDuration)
	assert.Equal(t, 0, maxAttempts)
	assert.Equal(t, testErrorLockDurationNotSet, err.Error())
}

func TestLoadConfigurationMaxAttemptsNotSet(t *testing.T) {
	// 保存原始环境变量
	originalLockDuration := os.Getenv(testLockDurationKey)
	originalMaxAttempts := os.Getenv(testMaxAttemptsKey)

	// 设置 LOCK_DURATION 但清除 MAX_ATTEMPTS 环境变量
	err := setupTestEnv(testLockDurationKey, fmt.Sprintf("%d", testLockDuration))
	if err != nil {
		t.Fatalf("Failed to set LOCK_DURATION: %v", err)
	}
	err = os.Unsetenv(testMaxAttemptsKey)
	if err != nil {
		t.Fatalf("Failed to unset MAX_ATTEMPTS: %v", err)
	}

	// 恢复原始环境变量
	defer cleanupTestEnv(testLockDurationKey, originalLockDuration)
	defer cleanupTestEnv(testMaxAttemptsKey, originalMaxAttempts)

	// 调用被测试的函数
	lockDuration, maxAttempts, err := loadConfiguration()

	// 验证结果
	assert.Error(t, err)
	assert.Equal(t, 0, lockDuration)
	assert.Equal(t, 0, maxAttempts)
	assert.Equal(t, testErrorMaxAttemptsNotSet, err.Error())
}

func TestLoadConfigurationInvalidLockDurationFormat(t *testing.T) {
	// 保存原始环境变量
	originalLockDuration := os.Getenv(testLockDurationKey)
	originalMaxAttempts := os.Getenv(testMaxAttemptsKey)

	// 设置无效的 LOCK_DURATION 格式
	err := setupTestEnv(testLockDurationKey, testInvalidNumber)
	if err != nil {
		t.Fatalf("Failed to set LOCK_DURATION: %v", err)
	}
	err = setupTestEnv(testMaxAttemptsKey, fmt.Sprintf("%d", testMaxAttempts))
	if err != nil {
		t.Fatalf("Fail to set MAX_ATTEMPTS: %v", err)
	}

	// 恢复原始环境变量
	defer cleanupTestEnv(testMaxAttemptsKey, originalMaxAttempts)
	defer cleanupTestEnv(testLockDurationKey, originalLockDuration)

	// 调用被测试的函数
	lockDuration, maxAttempts, err := loadConfiguration()

	// 验证结果
	assert.Error(t, err)
	assert.Equal(t, 0, maxAttempts)
	assert.Equal(t, 0, lockDuration)
	assert.Contains(t, err.Error(), testErrorInvalidLockDuration)
}

func TestLoadConfigurationInvalidMaxAttemptsFormat(t *testing.T) {
	// 保存原始环境变量
	originalLockDuration := os.Getenv(testLockDurationKey)
	originalMaxAttempts := os.Getenv(testMaxAttemptsKey)

	// 设置无效的 MAX_ATTEMPTS 格式
	err := setupTestEnv(testLockDurationKey, fmt.Sprintf("%d", testLockDuration))
	if err != nil {
		t.Fatalf("Failed to set LOCK_DURATION: %v", err)
	}
	err = setupTestEnv(testMaxAttemptsKey, testInvalidNumber)
	if err != nil {
		t.Fatalf("Failed to set MAX_ATTEMPTS: %v", err)
	}

	// 恢复原始环境变量
	defer cleanupTestEnv(testLockDurationKey, originalLockDuration)
	defer cleanupTestEnv(testMaxAttemptsKey, originalMaxAttempts)

	// 调用被测试的函数
	lockDuration, maxAttempts, err := loadConfiguration()

	// 验证结果
	assert.Error(t, err)
	assert.Equal(t, 0, lockDuration)
	assert.Equal(t, 0, maxAttempts)
	assert.Contains(t, err.Error(), testErrorInvalidMaxAttempts)
}

func TestLoadConfigurationBothNotSet(t *testing.T) {
	// 保存原始环境变量
	originalLockDuration := os.Getenv(testLockDurationKey)
	originalMaxAttempts := os.Getenv(testMaxAttemptsKey)

	// 清除所有相关环境变量
	err := os.Unsetenv(testLockDurationKey)
	if err != nil {
		t.Fatalf("Failed to unset LOCK_DURATION: %v", err)
	}
	err = os.Unsetenv(testMaxAttemptsKey)
	if err != nil {
		t.Fatalf("Failed to unset MAX_ATTEMPTS: %v", err)
	}

	// 恢复原始环境变量
	defer cleanupTestEnv(testMaxAttemptsKey, originalMaxAttempts)
	defer cleanupTestEnv(testLockDurationKey, originalLockDuration)

	// 调用被测试的函数
	lockDuration, maxAttempts, err := loadConfiguration()

	// 验证结果
	assert.Error(t, err)
	assert.Equal(t, 0, lockDuration)
	assert.Equal(t, 0, maxAttempts)
	assert.Equal(t, testErrorLockDurationNotSet, err.Error())
}
