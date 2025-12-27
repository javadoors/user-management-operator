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
	"time"

	"github.com/emicklei/go-restful/v3"

	"openfuyao.com/user-management/pkg/tools"
)

// LogFunction defines the log function interface
type LogFunction func(format string, args ...interface{})

// LogResponse defines the actual log function
func LogResponse(req *restful.Request, resp *restful.Response, start time.Time, logFunc LogFunction) {
	logFunc("HTTP request details: method=%s, url=%s, proto=%s, status=%d, length=%d, duration=%dms",
		req.Request.Method,
		req.Request.URL,
		req.Request.Proto,
		resp.StatusCode(),
		resp.ContentLength(),
		time.Since(start).Milliseconds(),
	)
}

// RecordAccessLogs is the filter function to access log
func RecordAccessLogs(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	start := time.Now()
	chain.ProcessFilter(req, resp)
	// StatusBadRequest错误码是400，大于400的StatusCode都是各种不同的http错误
	if resp.StatusCode() > http.StatusBadRequest {
		LogResponse(req, resp, start, tools.FormatWarn)
	} else {
		LogResponse(req, resp, start, tools.FormatInfo)
	}
}
