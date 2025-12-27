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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/stretchr/testify/assert"
)

func TestLogResponse(t *testing.T) {
	// 模拟请求
	mockRequest := &restful.Request{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/test"},
			Proto:  "HTTP/1.1",
		},
	}

	// 模拟响应
	mockResponse := &restful.Response{
		ResponseWriter: httptest.NewRecorder(),
	}
	mockResponse.WriteHeader(200)                              // 设置状态码
	mockResponse.ResponseWriter.Write([]byte("response body")) // 模拟写入响应体

	// 捕获日志输出的变量
	var loggedMessage string

	// 定义一个模拟的 logFunc
	mockLogFunc := func(format string, args ...interface{}) {
		loggedMessage = fmt.Sprintf(format, args...)
	}

	// 调用被测试的函数
	startTime := time.Now()
	LogResponse(mockRequest, mockResponse, startTime, mockLogFunc)

	// 验证 logFunc 是否正确被调用以及日志内容是否符合预期
	expectedLog := fmt.Sprintf("HTTP request details: method=%s, url=%s, proto=%s, status=%d, length=%d, duration=%dms",
		"GET",
		"/test",
		"HTTP/1.1",
		200,
		mockResponse.ContentLength(),
		time.Since(startTime).Milliseconds(),
	)

	assert.Equal(t, expectedLog, loggedMessage)
}

var loggedMessage string

func TestRecordAccessLogs(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		expectedLogMsg string
	}{
		{
			name:           "Test success request with 200 status code",
			statusCode:     http.StatusOK,
			expectedLogMsg: "",
		},
		{
			name:           "Test error request with 500 status code",
			statusCode:     http.StatusInternalServerError,
			expectedLogMsg: "",
		},
		{
			name:           "Test bad request with 400 status code",
			statusCode:     http.StatusBadRequest,
			expectedLogMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 重置日志记录
			loggedMessage = ""

			// 模拟请求
			mockRequest := &restful.Request{
				Request: &http.Request{
					Method: "GET",
					URL:    &url.URL{Path: "/test"},
				},
			}

			// 模拟响应
			recorder := httptest.NewRecorder()
			mockResponse := restful.NewResponse(recorder)
			mockResponse.WriteHeader(tt.statusCode)

			// 模拟过滤器链
			mockChain := &restful.FilterChain{
				Filters: []restful.FilterFunction{
					func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
						// Do nothing, simulate a pass-through filter
					},
				},
			}

			// 调用被测试的函数
			RecordAccessLogs(mockRequest, mockResponse, mockChain)

			// 验证日志内容
			assert.Contains(t, loggedMessage, tt.expectedLogMsg, "Logged message should match")
		})
	}
}
