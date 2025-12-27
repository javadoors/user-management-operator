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
	"fmt"
	"strings"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// apiRootPath defines the base path for all API endpoints.
	apiRootPath = "/rest"
)

// GetAPIBasePath returns the full base path for a given GroupVersion.
func GetAPIBasePath(gv schema.GroupVersion) string {
	return strings.TrimRight(fmt.Sprintf("%s/%s", apiRootPath, gv.String()), "/")
}

// NewWebService creates a new RESTful web service for the specified API group and version.
func NewWebService(gv schema.GroupVersion) *restful.WebService {
	ws := new(restful.WebService)
	ws.Path(GetAPIBasePath(gv)).
		Produces(restful.MIME_JSON)
	return ws
}

// GetQueryParamOrDefault extracts the value of a specified query parameter from a request.
// If the parameter is not present or its value is empty, a provided default value is returned.
func GetQueryParamOrDefault(r *restful.Request, param, defaultValue string) string {
	value := r.Request.URL.Query().Get(param)
	if value == "" {
		return defaultValue
	}
	return value
}
