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

// Package authorizers provider authorization functions for different request paths
package authorizers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	usersv1alpha1 "openfuyao.com/user-management/api/v1alpha1"
	"openfuyao.com/user-management/pkg/constants"
	"openfuyao.com/user-management/pkg/tools"
	"openfuyao.com/user-management/pkg/utils/requestutils"
	"openfuyao.com/user-management/pkg/utils/stringutils"
)

var platformRoles = []string{"platform-admin", "platform-regular"}
var clusterRoles = []string{"cluster-admin", "cluster-viewer", "cluster-editor"}

// AuthorizeByAdmittedRoles authorizes the user by its corresponding clusterrole
func AuthorizeByAdmittedRoles(req *http.Request, clusterName string,
	admittedRoles []string, k8sClient kubernetes.Interface) bool {
	userinfo, ok := req.Context().Value(constants.UserKey).(user.Info)
	if !ok {
		tools.LogError("cannot get userinfo from req.context")
		return false
	}

	// fetch clusterrolebinding
	username := userinfo.GetName()
	crbs, err := getOpenFuyaoClusterRoleBindings(username, clusterName, k8sClient, req)
	if err != nil {
		tools.FormatError("cannot get crb for %s", userinfo.GetName())
		return false
	}

	// check its platform admin
	for _, crb := range crbs {
		role := getOpenFuyaoClusterRoleType(crb)
		if openFuyaoRoleContains(admittedRoles, role) {
			tools.FormatInfo("get openfuyao cluterrole/platformrole type from %s", crb.Name)
			return true
		}
	}

	tools.FormatError("cannot get openfuyao clusterrole or platformrole")
	return false
}

func getOpenFuyaoClusterRoleBindings(userName, clusterName string, k8sClient kubernetes.Interface,
	req *http.Request) ([]*rbacv1.ClusterRoleBinding, error) {
	var crbList rbacv1.ClusterRoleBindingList
	if clusterName != "" {
		url := requestutils.PrepareK8sResourceRequestURL(clusterName,
			"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
		statusCode, respBody, err := requestutils.DoRequestWithMaxRetries(url, "GET", req, nil, 1)
		if err != nil || statusCode != http.StatusOK {
			tools.FormatError("cant get CRB for user %s on cluster %s when authz err: %v", userName, clusterName, err)
			return nil, err
		}
		err = json.Unmarshal(respBody, &crbList)
		if err != nil {
			tools.FormatError("cannot unmarshal CRB list, err: %v", err)
			return nil, err
		}

	} else {
		crbListPointer, err := k8sClient.RbacV1().ClusterRoleBindings().List(context.Background(),
			v1.ListOptions{LabelSelector: constants.OpenFuyaoRoleLabel})
		crbList = *crbListPointer
		if err != nil {
			tools.FormatError("cannot list clusterrolebinding, err: %v", err)
			return nil, err
		}
	}

	crbs := make([]*rbacv1.ClusterRoleBinding, 0)
	for _, crb := range crbList.Items {
		for _, subj := range crb.Subjects {
			if subj.Name == userName {
				tools.FormatInfo("find clusterrolebinding %s", crb.Name)
				crbs = append(crbs, crb.DeepCopy())
			}
		}
	}

	if len(crbs) == 0 {
		errString := fmt.Sprintf("no matched clusterrolebinding for user %s", userName)
		return nil, errors.New(errString)
	}

	return crbs, nil
}

func getOpenFuyaoClusterRoleType(crb *rbacv1.ClusterRoleBinding) string {
	// get role-type value
	roleType := crb.Labels[constants.OpenFuyaoRoleLabel]
	roleName := crb.RoleRef.Name
	if roleType == "platform-role" {
		if openFuyaoRoleContains(platformRoles, roleName) {
			return roleName
		}
	} else if roleType == "cluster-role" {
		if openFuyaoRoleContains(clusterRoles, roleName) {
			return roleName
		}
	} else {
		return ""
	}

	return ""
}

func openFuyaoRoleContains(list []string, query string) bool {
	for _, item := range list {
		if stringutils.TrimOpenFuyaoRolePrefix(query) == item {
			return true
		}
	}
	return false
}

// CheckDangerousOperation avoid self modification/deletion or admin modification/deletion
func CheckDangerousOperation(req *http.Request, username string) bool {
	return checkSelfOperation(req, username) || checkAdminOperation(username)
}

// HorizontalAuthorizationCheck return self operation on platform-regular user
func HorizontalAuthorizationCheck(req *http.Request, username string, client client.Client) bool {
	return !checkSelfOperation(req, username) && getUserPlatformRole(req, client) == "platform-regular"
}

func getUserPlatformRole(req *http.Request, client client.Client) string { // fetch userinfo
	userinfo, ok := req.Context().Value(constants.UserKey).(user.Info)
	if !ok {
		tools.LogError("cannot get userinfo from req.context")
		return ""
	}
	user := &usersv1alpha1.User{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: userinfo.GetName()}, user); err != nil {
		return ""
	}
	return user.Spec.PlatformRole
}

func checkSelfOperation(req *http.Request, username string) bool {
	// fetch userinfo
	userinfo, ok := req.Context().Value(constants.UserKey).(user.Info)
	if !ok {
		tools.LogError("cannot get userinfo from req.context")
		return false
	}
	if userinfo.GetName() == username {
		return true
	}

	return false
}

func checkAdminOperation(username string) bool {
	return username == "admin"
}
