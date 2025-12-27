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

package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/emicklei/go-restful/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"openfuyao.com/user-management/api/v1alpha1"
	"openfuyao.com/user-management/pkg/api/user/v1/types"
	"openfuyao.com/user-management/pkg/constants"
	"openfuyao.com/user-management/pkg/tools"
	"openfuyao.com/user-management/pkg/utils/requestutils"
	"openfuyao.com/user-management/pkg/utils/stringutils"
)

func prepareUserInstance(userReq types.UserCreateRequest, encryptedPassword []byte,
	platformRole string) *v1alpha1.User {
	user := &v1alpha1.User{
		TypeMeta: metav1.TypeMeta{
			Kind:       "User",
			APIVersion: "users.openfuyao.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: userReq.Username,
		},
		Spec: v1alpha1.UserSpec{
			Username:          userReq.Username,
			EncryptedPassword: encryptedPassword,
			Description:       userReq.Description,
			PlatformRole:      platformRole,
			FirstLogin:        true,
		},
	}
	return user
}

func searchUsersByKeyword(users interface{}, keyword string) interface{} {
	var filteredUsers []interface{}

	switch u := users.(type) {
	case []types.UserReturnListPlatform:
		for _, user := range u {
			if strings.Contains(strings.ToLower(user.Username), strings.ToLower(keyword)) {
				filteredUsers = append(filteredUsers, user)
			}
		}
	case []types.UserReturnListCluster:
		for _, user := range u {
			if strings.Contains(strings.ToLower(user.Username), strings.ToLower(keyword)) {
				filteredUsers = append(filteredUsers, user)
			}
		}
	default:
		fmt.Println("Unsupported type")
		return nil
	}

	return filteredUsers
}

func filterUserSpec(spec v1alpha1.UserSpec) types.UserSpecFiltered {
	return types.UserSpecFiltered{
		Username:              spec.Username,
		Description:           spec.Description,
		InvitedByClustersList: spec.InvitedByClustersList,
		PlatformRole:          spec.PlatformRole,
	}
}

func filterUserSpecForDescription(spec v1alpha1.UserSpec) types.UserDescription {
	return types.UserDescription{
		Username:    spec.Username,
		Description: spec.Description,
	}
}

func extractUserInfoCollections(userList *v1alpha1.UserList) *types.IdentityCollection {
	collection := &types.IdentityCollection{
		UserInfo: make(map[string]*types.IdentityDescriptor),
	}
	for _, user := range userList.Items {
		var platformBool bool
		if user.Spec.PlatformRole == "platform-admin" {
			platformBool = true
		} else {
			platformBool = false
		}
		descriptor := &types.IdentityDescriptor{
			IdentityName:   user.Spec.Username,
			ApiGroup:       "users.openfuyao.com",
			PlatformAdmin:  platformBool,
			MemberClusters: user.Spec.InvitedByClustersList,
		}
		collection.UserInfo[user.Name] = descriptor
	}
	return collection
}

func getClusterRoleByConsoleService(req *http.Request, clusterName string, username string) (string, error) {
	url := requestutils.PrepareUserMgmtRequestURL(clusterName,
		fmt.Sprintf("/cluster-rolebindings?user=%s", username))
	resp, err := requestutils.DoUserManagementRequest(url, "GET", req, nil)
	if err != nil {
		tools.FormatError("cannot make request: GET %s, err: %v", url, err)
		return "", err
	}

	// parse response
	if resp.Code != http.StatusOK {
		tools.FormatError("request GET %s failed with msg: %v", url, resp.Msg)
		return "", fmt.Errorf("%s", resp.Msg)
	}
	jsonData, err := json.Marshal(resp.Data)
	if err != nil {
		tools.FormatError("cannot marshal http response to json bytes")
		return "", fmt.Errorf("cannot marshal http response to json bytes")
	}
	var crb rbacv1.ClusterRoleBinding
	err = json.Unmarshal(jsonData, &crb)
	if err != nil {
		tools.LogError("cannot convert the response to clusterrolebinding")
		return "", fmt.Errorf("cannot convert the response to clusterrolebinding")
	}

	// get crName from crb
	return crb.RoleRef.Name, nil
}

func prepareClusterRoleBinding(userName, roleName, roleType string) *rbacv1.ClusterRoleBinding {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: userName + "-" + roleName,
			Labels: map[string]string{
				constants.UserRefLabel:        userName,
				constants.ClusterRoleRefLabel: roleName,
				constants.OpenFuyaoRoleLabel:  roleType,
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: userName,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     stringutils.AddOpenFuyaoRolePrefix(roleName),
			APIGroup: rbacv1.GroupName,
		},
	}
	return clusterRoleBinding
}

func deletePlatformCRBAccrossClusters(request *restful.Request, userName, clusterName, roleName string) {
	crbName := fmt.Sprintf("%s-%s", userName, roleName)
	url := requestutils.PrepareK8sResourceRequestURL(clusterName,
		fmt.Sprintf("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/%s", crbName))
	tools.FormatInfo("the request url is %s", url)
	_, _, err := requestutils.DoRequestWithMaxRetries(url, "DELETE", request.Request, nil, 1)
	if err != nil {
		tools.FormatError("delete PRB on %s when unjoining cluster %s errored, err: %v", userName, clusterName, err)
	} else {
		tools.FormatInfo("delete platform admin binding succed, user: %s, cluster: %s", userName, clusterName)
	}
}

func createPlatfromCRBByClusters(request *restful.Request, response *restful.Response, clusterList []string,
	user *v1alpha1.User) bool {
	// send safelyCreateInstructions one by one
	for _, clusterName := range clusterList {
		if clusterName == "host" {
			continue
		}
		if !createPlatformCRBAccrossClusters(request, response, user.Name, clusterName, user.Spec.PlatformRole) {
			tools.FormatError("Broadcast platform-admin to all clusters failed, cannot create crb on other clusters")
			return false
		}
	}
	return true
}

func createPlatformCRBAccrossClusters(request *restful.Request, response *restful.Response,
	userName, clusterName, roleName string) bool {
	newCRB := prepareClusterRoleBinding(userName, roleName, "platform-role")
	crbJson, err := json.Marshal(newCRB)
	if err != nil {
		return false
	}
	url := requestutils.PrepareK8sResourceRequestURL(clusterName,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
	const maxAttempts = 5
	statusCode, _, err := requestutils.DoRequestWithMaxRetries(url, "POST", request.Request, crbJson, maxAttempts)
	if err != nil && statusCode != http.StatusConflict {
		tools.FormatError("cant call invite-users on %s when joining cluster %s, err: %v", userName, clusterName, err)
		return false
	}
	tools.FormatInfo("create platform admin binding succed, user: %s, cluster: %s", userName, clusterName)
	return true
}

func getAllAvailableClusters(request *restful.Request) ([]string, error) {
	url := requestutils.PrepareMultiClusterRequestURL("/resources/clusters")
	statusCode, body, err := requestutils.DoRequestWithMaxRetries(url, "GET", request.Request, nil, 1)
	if statusCode != http.StatusOK || err != nil {
		tools.FormatError("cannot get all cluster lists, err: %v", err)
		return nil, err
	}

	var clusterInfoList types.ClusterList
	err = json.Unmarshal(body, &clusterInfoList)
	if err != nil {
		tools.FormatError("cannot unmarshal multicluser reponse to clusterlist, err: %v", err)
		return nil, err
	}

	var clusterNameList []string
	for clusterName, _ := range clusterInfoList.Info {
		clusterNameList = append(clusterNameList, clusterName)
	}
	return clusterNameList, nil
}

func sendUserListToMulticlusterService(userList types.IdentityCollection) error {
	// 将 userList 转换为 JSON
	jsonData, err := json.Marshal(userList)
	if err != nil {
		return fmt.Errorf("failed to marshal userList: %v", err)
	}
	// 设置目标服务的 URL
	// 使用服务的 DNS 名称进行调用 (这里默认命名空间是 default)
	url := fmt.Sprintf("%s://%s:%d%s/userinfo", constants.MultiClusterProtocol, constants.MultiClusterHost,
		constants.MultiClusterServicePort, constants.MultiClusterPathPrefix)
	// 创建一个 POST 请求，设置请求体为 JSON 数据
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// 设置请求头，表明内容类型为 JSON
	req.Header.Set("Content-Type", "application/json")
	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response: %s", body)
	}
	tools.FormatInfo("successfully send user list:\n %s", string(jsonData))
	return nil
}

func validateUserName(username string) bool {
	if len(username) > constants.MetaNameLength {
		return false
	}
	match, err := regexp.MatchString(constants.MetaNamePattern, username)
	if err != nil {
		tools.LogError(err)
	}
	return match
}
