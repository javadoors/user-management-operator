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

package passwordutils

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/pbkdf2"
)

func Test_reverseString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "Regular string",
			s:    "hello",
			want: "olleh",
		},
		{
			name: "Empty string",
			s:    "",
			want: "",
		},
		{
			name: "Single character",
			s:    "a",
			want: "a",
		},
		{
			name: "String with spaces",
			s:    "hello world",
			want: "dlrow olleh",
		},
		{
			name: "Palindrome string",
			s:    "madam",
			want: "madam",
		},
		{
			name: "String with special characters",
			s:    "123!@#",
			want: "#@!321",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverseString(tt.s); got != tt.want {
				t.Errorf("reverseString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isByteSameAsString(t *testing.T) {
	tests := []struct {
		name     string
		passwd   []byte
		username string
		want     bool
	}{
		{
			name:     "Same byte array and string",
			passwd:   []byte("testuser"),
			username: "testuser",
			want:     true,
		},
		{
			name:     "Different byte array and string",
			passwd:   []byte("testuser"),
			username: "differentuser",
			want:     false,
		},
		{
			name:     "Empty byte array and empty string",
			passwd:   []byte(""),
			username: "",
			want:     true,
		},
		{
			name:     "Empty byte array and non-empty string",
			passwd:   []byte(""),
			username: "testuser",
			want:     false,
		},
		{
			name:     "Non-empty byte array and empty string",
			passwd:   []byte("testuser"),
			username: "",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isByteSameAsString(tt.passwd, tt.username); got != tt.want {
				t.Errorf("isByteSameAsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkPasswordComplexity(t *testing.T) {
	tests := []struct {
		name     string
		username string
		passwd   []byte
		want     bool
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Password too short",
			username: "testuser",
			passwd:   []byte("12345"),
			want:     false,
			wantErr:  true,
			errMsg:   "the password length should lie between 8 and 32",
		},
		{
			name:     "Password too long",
			username: "testuser",
			passwd:   []byte("aVeryLongPasswordThatExceedsTheMaxLength1234567890!"),
			want:     false,
			wantErr:  true,
			errMsg:   "the password length should lie between 8 and 32",
		},
		{
			name:     "Password missing special character",
			username: "testuser",
			passwd:   []byte("Password123"),
			want:     false,
			wantErr:  true,
			errMsg:   "password must contain at least one lowercase letter or one uppercase letter, one number, and one special character",
		},
		{
			name:     "Valid password",
			username: "testuser",
			passwd:   []byte("ValidPassw0rd!"),
			want:     true,
			wantErr:  false,
			errMsg:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPasswordComplexity(tt.username, tt.passwd)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkPasswordComplexity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && err.Error() != tt.errMsg {
				t.Errorf("checkPasswordComplexity() error message = %v, wantErrMsg %v", err.Error(), tt.errMsg)
			}
			if got != tt.want {
				t.Errorf("checkPasswordComplexity() = %v, want %v", got, tt.want)
			}
		})
	}
}

const (
	SaltLength     = 16     // 盐的长度
	Iterations     = 100000 // 迭代次数
	KeyLength      = 64     // 生成的密钥长度（以字节为单位）
	PasswordMinLen = 8
	PasswordMaxLen = 32
)

func TestEncryptPassword(t *testing.T) {
	// 测试数据
	rawPassword := []byte("testPassword123!")

	// 调用被测试的函数
	encryptedPassword, err := EncryptPassword(rawPassword)

	// 检查是否发生错误
	assert.Nil(t, err)
	assert.NotNil(t, encryptedPassword)

	// 解码 Base64 编码的数据
	decodedData, err := base64.StdEncoding.DecodeString(string(encryptedPassword))
	assert.Nil(t, err)

	// 验证解码后的数据长度是否符合预期
	expectedLength := SaltLength + KeyLength
	assert.Equal(t, expectedLength, len(decodedData), "The combined salt and encrypted password length should be equal to SaltLength + KeyLength")

	// 验证生成的盐值部分和密文部分
	salt := decodedData[:SaltLength]
	encryptedPart := decodedData[SaltLength:]

	// 确保盐值和加密的部分长度符合预期
	assert.Equal(t, SaltLength, len(salt), "Salt length should be equal to constants.SaltLength")
	assert.Equal(t, KeyLength, len(encryptedPart), "Encrypted part length should be equal to constants.KeyLength")

	// 验证使用相同盐和密码生成的密文与解码后的密文是否一致
	reEncryptedPassword := pbkdf2.Key(rawPassword, salt, Iterations, KeyLength, sha256.New)
	assert.Equal(t, reEncryptedPassword, encryptedPart, "Re-encrypted password should match the original encrypted part")
}
