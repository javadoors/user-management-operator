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

// Package stringutils provide packed funcs for string manipulation
package stringutils

import (
	"strings"

	"k8s.io/api/rbac/v1"

	"openfuyao.com/user-management/pkg/constants"
)

// TrimOpenFuyaoRolePrefix trim openfuyao- before return to frontend
func TrimOpenFuyaoRolePrefix(name string) string {
	return strings.TrimPrefix(name, constants.OpenFuyaoRolePrefix)
}

// AddOpenFuyaoRolePrefix add openfuyao- before saving to k8s
func AddOpenFuyaoRolePrefix(name string) string {
	return constants.OpenFuyaoRolePrefix + name
}

// TrimOpenFuyaoRoleListPrefix trim openfuyao- of CRBS before return to frontend
func TrimOpenFuyaoRoleListPrefix(clusterRoleList []v1.ClusterRole) []v1.ClusterRole {
	var retClusterRoleList []v1.ClusterRole
	for _, cr := range clusterRoleList {
		var copyCR *v1.ClusterRole
		copyCR = cr.DeepCopy()
		copyCR.Name = TrimOpenFuyaoRolePrefix(copyCR.Name)
		retClusterRoleList = append(retClusterRoleList, *copyCR)
	}

	return retClusterRoleList
}

// CaseInsensitiveContains check whether is in the slice, case-insensitive
func CaseInsensitiveContains(slice []string, item string) bool {
	for _, each := range slice {
		if strings.EqualFold(each, item) {
			return true
		}
	}
	return false
}

// CaseInsensitiveNotContains check whether is off the slice, case-insensitive
func CaseInsensitiveNotContains(slice []string, item string) bool {
	for _, each := range slice {
		if strings.EqualFold(each, item) {
			return false
		}
	}
	return true
}

// StringInSlice check whether the target string is in the list
func StringInSlice(target string, list []string) bool {
	for _, str := range list {
		if str == target {
			return true
		}
	}
	return false
}

// RemoveStringFromList remove target string from list
func RemoveStringFromList(target string, list []string) []string {
	var newList []string
	for _, item := range list {
		if item != target {
			newList = append(newList, item)
		}
	}
	return newList
}
