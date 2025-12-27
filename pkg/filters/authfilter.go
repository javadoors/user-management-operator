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

// Package filters do pre-requisite checks before passing requests to webservices
package filters

import (
	"context"
	"strings"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	"k8s.io/apiserver/pkg/authentication/user"

	"openfuyao.com/user-management/pkg/constants"
	"openfuyao.com/user-management/pkg/tools"
)

// JWTAccessClaims structure
type JWTAccessClaims struct {
	jwt.StandardClaims
}

// ExtractUserFromJWT extracts userinfo from jwt
func ExtractUserFromJWT(token string) (user.Info, error) {
	var claims = JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{},
	}
	_, _, err := jwt.NewParser().ParseUnverified(token, &claims)
	if err != nil {
		tools.FormatError("Fail to parse tokenJWT: %v", err)
		return nil, err
	}

	var extractedUser user.DefaultInfo
	extractedUser.Name = claims.Subject

	return &extractedUser, nil
}

// AuthenticateOpenFuyaoUser authenticates whether the requested user is from openfuyao
func AuthenticateOpenFuyaoUser(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	// get access token
	token := req.HeaderParameter(constants.OpenFuyaoAuthHeaderKey)
	if !strings.HasPrefix(token, "Bearer ") {
		tools.FormatWarn("the request does not have openFuyao token, reqURL: %s", req.Request.URL.Path)
		chain.ProcessFilter(req, resp)
		return
	}

	// decode the token info
	token = strings.TrimPrefix(token, "Bearer ")
	extractedUser, err := ExtractUserFromJWT(token)
	if err != nil {
		return
	}

	// add user to child context
	ctx := context.WithValue(req.Request.Context(), constants.UserKey, extractedUser)
	req.Request = req.Request.WithContext(ctx)
	tools.FormatInfo("add current user %s to req.context", extractedUser.GetName())

	chain.ProcessFilter(req, resp)

	return
}
