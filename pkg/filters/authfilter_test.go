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

package filters

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"

	"openfuyao.com/user-management/pkg/constants"
)

func TestExtractUserFromJWT(t *testing.T) {
	// 创建一个有效的模拟 JWT 令牌
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject: "testuser",
	})
	tokenString, _ := token.SignedString([]byte("testsecret"))

	// 调用被测试的函数
	userInfo, err := ExtractUserFromJWT(tokenString)

	// 验证没有错误
	assert.NoError(t, err)

	// 验证提取出的用户信息
	assert.Equal(t, "testuser", userInfo.GetName(),
		"The extracted user's name should be 'testuser'")
}

func TestExtractUserFromJWTFail(t *testing.T) {
	tokenString := "jwt-fail"

	// 调用被测试的函数
	_, err := ExtractUserFromJWT(tokenString)

	// 验证没有错误
	assert.Contains(t, err.Error(), "token contains an invalid number of segments")
}

func TestAuthenticateOpenFuyaoUserValidToken(t *testing.T) {
	// 创建模拟的 restful 请求和响应
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(constants.OpenFuyaoAuthHeaderKey, "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjb25zb2xlIiwiZXhwIjoxNzU5MjE1OTQ3LCJzdWIiOiJhZG1pbiJ9.IVzsV6csR_XY5mrv7lK83B4cjhD_rZl-IbDgxv7LbyLY3oBpjhOVv7QwS7BLQqHUogDibIbRyOmqfVUVHHf36Q")

	restReq := restful.NewRequest(req)
	recorder := httptest.NewRecorder()
	resp := restful.NewResponse(recorder)

	// 模拟过滤器链
	chain := &restful.FilterChain{
		Filters: []restful.FilterFunction{
			func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
				resp.WriteHeader(http.StatusOK)
			},
		},
	}

	// 调用被测试的函数
	AuthenticateOpenFuyaoUser(restReq, resp, chain)
	if status := recorder.Result().StatusCode; status != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, status)
	}
}

func TestAuthenticateOpenFuyaoUserValidTokenFail(t *testing.T) {
	// 创建模拟的 restful 请求和响应
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(constants.OpenFuyaoAuthHeaderKey, "Invalid eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ"+
		"jb25zb2xlIiwiZXhwIjoxNzU5MjE1OTQ3LCJzdWIiOiJhZG1pbiJ9.IVzsV6csR_XY5mrv7lK83B4cjhD_rZl-IbDgxv7LbyLY3oBpjhOVv"+
		"7QwS7BLQqHUogDibIbRyOmqfVUVHHf36Q")

	restReq := restful.NewRequest(req)
	recorder := httptest.NewRecorder()
	resp := restful.NewResponse(recorder)

	// 模拟过滤器链
	chain := &restful.FilterChain{
		Filters: []restful.FilterFunction{
			func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
				resp.WriteHeader(http.StatusInternalServerError)
			},
		},
	}

	// 调用被测试的函数
	AuthenticateOpenFuyaoUser(restReq, resp, chain)
	if status := recorder.Result().StatusCode; status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}
