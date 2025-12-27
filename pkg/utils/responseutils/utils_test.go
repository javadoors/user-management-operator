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

package responseutils

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emicklei/go-restful/v3"
	"github.com/stretchr/testify/assert"
)

type ApiResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

const (
	testApiCodeSuccess    = 200
	testApiCodeBadRequest = 400
)

func TestWriteSuccessResponse(t *testing.T) {
	// 创建一个 httptest.ResponseRecorder 以捕获响应
	recorder := httptest.NewRecorder()

	// 使用 restful.NewResponse 创建一个模拟的 restful.Response
	resp := restful.NewResponse(recorder)
	resp.SetRequestAccepts("application/json")

	// 测试数据
	testData := map[string]string{"key": "value"}

	// 调用 WriteSuccessResponse
	WriteSuccessResponse("Success", testData, resp)

	// 检查是否正确设置了状态码
	assert.Equal(t, http.StatusOK, recorder.Code)

	// 验证 Content-Type 头
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	// 验证响应体
	var apiResponse ApiResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &apiResponse)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, apiResponse.Code)
	assert.Equal(t, "Success", apiResponse.Msg)
}

func TestWriteRawSuccessResponse(t *testing.T) {
	// 创建一个 httptest.ResponseRecorder 以捕获响应
	recorder := httptest.NewRecorder()

	// 使用 restful.NewResponse 创建一个模拟的 restful.Response
	resp := restful.NewResponse(recorder)
	resp.SetRequestAccepts("application/json")

	// 测试数据
	testData := map[string]string{"key": "value"}

	// 调用 WriteRawSuccessResponse
	WriteRawSuccessResponse(testData, resp)

	// 检查是否正确设置了状态码
	assert.Equal(t, http.StatusOK, recorder.Code)

	// 验证 Content-Type 头
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	// 验证响应体
	var responseData map[string]string
	err := json.Unmarshal(recorder.Body.Bytes(), &responseData)
	assert.NoError(t, err)
	assert.Equal(t, testData, responseData)
}

func TestHandleNotAuthorized(t *testing.T) {
	// 创建一个 httptest.ResponseRecorder 以捕获响应
	recorder := httptest.NewRecorder()

	// 使用 restful.NewResponse 创建一个模拟的 restful.Response
	resp := restful.NewResponse(recorder)
	resp.SetRequestAccepts("application/json")

	// 调用 HandleNotAuthorized
	testError := errors.New("unauthorized error")
	HandleNotAuthorized(resp, "Unauthorized", testError)

	// 检查是否正确设置了状态码
	assert.Equal(t, http.StatusForbidden, recorder.Code)

	// 验证 Content-Type 头
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	// 验证响应体
	var apiResponse ApiResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &apiResponse)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, apiResponse.Code)
}

func TestHandleErrorSuccess(t *testing.T) {
	// 创建一个 httptest.ResponseRecorder 以捕获响应
	recorder := httptest.NewRecorder()

	// 使用 restful.NewResponse 创建一个模拟的 restful.Response
	resp := restful.NewResponse(recorder)
	resp.SetRequestAccepts("application/json")

	// 调用 HandleError
	testError := errors.New("test error")
	HandleError(resp, "Test message", testError)

	// 检查是否正确设置了状态码
	assert.Equal(t, http.StatusBadRequest, recorder.Code)

	// 验证 WriteEntity 的响应体
	var apiResponse ApiResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &apiResponse)
	if err != nil {
		return
	}
	assert.Equal(t, http.StatusBadRequest, apiResponse.Code)

}
