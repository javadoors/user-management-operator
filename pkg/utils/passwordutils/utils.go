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

// Package passwordutils provide util functions for password encryption and verification
package passwordutils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"

	"golang.org/x/crypto/pbkdf2"

	"openfuyao.com/user-management/pkg/constants"
)

func reverseString(s string) string {
	var reversed string
	for _, char := range s {
		reversed = string(char) + reversed
	}
	return reversed
}

// CheckPasswordComplexity checks whether the password complexity
func CheckPasswordComplexity(username string, passwd []byte) (bool, error) {
	// check password length
	if len(passwd) < constants.PasswordMinLen || len(passwd) > constants.PasswordMaxLen {
		return false, fmt.Errorf("the password length should lie between 8 and 32")
	}

	// check that the password at least contains one lowercase/uppercase letter, one number and one special character
	reUpperCase := regexp.MustCompile(`[A-Z]`)
	reLowerCase := regexp.MustCompile(`[a-z]`)
	reDigit := regexp.MustCompile(`[0-9]`)
	reSpecialChar := regexp.MustCompile(`[\x60!\"#$%&'()*+,-./:;<=>?@[\\^\]_{|}~ ]`)

	if (!reUpperCase.Match(passwd) && !reLowerCase.Match(passwd)) || !reDigit.Match(passwd) ||
		!reSpecialChar.Match(passwd) {
		return false, fmt.Errorf("password must contain at least one lowercase letter or one uppercase letter, " +
			"one number, and one special character")
	}

	// check whether the password is contained in username / reversed username
	if isByteSameAsString(passwd, username) || isByteSameAsString(passwd, reverseString(username)) {
		return false, fmt.Errorf("password cannot be the same as the account number or the reverse account number")

	}

	return true, nil
}

func isByteSameAsString(passwd []byte, username string) bool {
	byteUserName := []byte(username)
	return bytes.Equal(passwd, byteUserName)
}

// EncryptPassword encrypts the byte password
func EncryptPassword(rawPassword []byte) ([]byte, error) {
	// 生成随机的盐值
	salt := make([]byte, constants.SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// 使用 PBKDF2 算法生成密文
	encryptedPassword := pbkdf2.Key(rawPassword, salt, constants.Iterations, constants.KeyLength, sha256.New)

	// 将盐值和密文合并并编码为 Base64 字符串
	encryptedData := append(salt, encryptedPassword...)
	encryptedData = []byte(base64.StdEncoding.EncodeToString(encryptedData))

	// 返回加密后的密码
	return encryptedData, nil
}
