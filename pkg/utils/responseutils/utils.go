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

// Package responseutils provide packed funcs when responding to the frontend
package responseutils

import (
	"net/http"

	"github.com/emicklei/go-restful/v3"

	"openfuyao.com/user-management/pkg/api/user/v1/types"
	"openfuyao.com/user-management/pkg/tools"
)

// WriteSuccessResponse returns message and data with 200 status code
func WriteSuccessResponse(message string, data interface{}, response *restful.Response) {
	apiResponse := types.ApiResponse{
		Code: 200,
		Msg:  message,
		Data: data,
	}
	response.AddHeader("Content-Type", "application/json")
	err := response.WriteEntity(apiResponse)
	if err != nil {
		HandleError(response, "Entity writing error", err)
		return
	}
}

// WriteRawSuccessResponse returns raw data with 200 status code
func WriteRawSuccessResponse(data interface{}, response *restful.Response) {
	response.AddHeader("Content-Type", "application/json")
	err := response.WriteEntity(data)
	if err != nil {
		HandleError(response, "Entity writing error", err)
		return
	}
}

// HandleError responds with 400 and err message
func HandleError(response *restful.Response, message string, err error) {
	apiResponse := types.ApiResponse{
		Code: 400,
		Msg:  message,
		Data: err,
	}
	response.AddHeader("Content-Type", "application/json")
	writeErr := response.WriteHeaderAndEntity(http.StatusBadRequest, apiResponse)
	if writeErr != nil {
		tools.FormatError("Error Write Entity: %v", writeErr)
	}
}

// HandleNotAuthorized responds with 403 and unauthorized
func HandleNotAuthorized(response *restful.Response, message string, err error) {
	apiResponse := types.ApiResponse{
		Code: http.StatusForbidden,
		Msg:  message,
		Data: err,
	}
	response.AddHeader("Content-Type", "application/json")
	writeErr := response.WriteHeaderAndEntity(http.StatusForbidden, apiResponse)
	if writeErr != nil {
		tools.FormatError("Error Write Entity, %v", writeErr)
	}
}
