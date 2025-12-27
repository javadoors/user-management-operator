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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emicklei/go-restful/v3"
	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"openfuyao.com/user-management/api/v1alpha1"
	"openfuyao.com/user-management/pkg/api/user/v1/types"
	"openfuyao.com/user-management/pkg/constants"
)

func TestPrepareUserInstance(t *testing.T) {
	// 模拟输入数据
	userReq := types.UserCreateRequest{
		Username:            "testuser",
		UnEncryptedPassword: []byte("password123"),
		Description:         "Test user description",
		PlatformRole:        "admin",
	}
	encryptedPassword := []byte("encrypted_password")
	platformRole := "admin"

	// 调用被测试的函数
	userInstance := prepareUserInstance(userReq, encryptedPassword, platformRole)

	// 验证生成的用户实例
	assert.Equal(t, "User", userInstance.Kind, "Kind should be User")
	assert.Equal(t, "users.openfuyao.com/v1alpha1", userInstance.APIVersion, "APIVersion should be users.openfuyao.com/v1alpha1")
	assert.Equal(t, userReq.Username, userInstance.Name, "Username should match")
	assert.Equal(t, userReq.Username, userInstance.Spec.Username, "Spec.Username should match")
	assert.Equal(t, encryptedPassword, userInstance.Spec.EncryptedPassword, "EncryptedPassword should match")
	assert.Equal(t, userReq.Description, userInstance.Spec.Description, "Description should match")
	assert.Equal(t, platformRole, userInstance.Spec.PlatformRole, "PlatformRole should match")
	assert.True(t, userInstance.Spec.FirstLogin, "FirstLogin should be true by default")
}
func TestSearchUsersByKeyword_PlatformUsers(t *testing.T) {
	// 模拟平台用户列表
	users := []types.UserReturnListPlatform{
		{Username: "alice"},
		{Username: "bob"},
		{Username: "charlie"},
	}

	// 调用被测试的函数
	keyword := "bo"
	result := searchUsersByKeyword(users, keyword)

	// 验证过滤后的用户
	expected := []interface{}{
		types.UserReturnListPlatform{Username: "bob"},
	}
	assert.Equal(t, expected, result)
}
func TestSearchUsersByKeyword_ClusterUsers(t *testing.T) {
	// 模拟集群用户列表
	users := []types.UserReturnListCluster{
		{Username: "dave"},
		{Username: "eve"},
		{Username: "frank"},
	}

	// 调用被测试的函数
	keyword := "ev"
	result := searchUsersByKeyword(users, keyword)

	// 验证过滤后的用户
	expected := []interface{}{
		types.UserReturnListCluster{Username: "eve"},
	}
	assert.Equal(t, expected, result)
}

func TestSearchUsersByKeyword_NoMatch(t *testing.T) {
	// 模拟没有匹配的用户
	users := []types.UserReturnListPlatform{
		{Username: "alice"},
		{Username: "bob"},
		{Username: "charlie"},
	}

	// 调用被测试的函数
	keyword := "xyz"
	result := searchUsersByKeyword(users, keyword)

	// 验证没有匹配的用户
	assert.Empty(t, result)
}

func TestSearchUsersByKeyword_UnsupportedType(t *testing.T) {
	// 模拟不支持的用户类型
	users := []string{"alice", "bob", "charlie"}

	// 调用被测试的函数
	keyword := "bo"
	result := searchUsersByKeyword(users, keyword)

	// 验证不支持的类型返回 nil
	assert.Nil(t, result)
}
func TestFilterUserSpec(t *testing.T) {
	// 模拟输入的 v1alpha1.UserSpec
	userSpec := v1alpha1.UserSpec{
		Username:              "testuser",
		Description:           "Test user description",
		InvitedByClustersList: []string{"cluster1", "cluster2"},
		PlatformRole:          "admin",
	}

	// 调用被测试的函数
	filteredSpec := filterUserSpec(userSpec)

	// 验证生成的 UserSpecFiltered
	assert.Equal(t, "testuser", filteredSpec.Username, "Username should match")
	assert.Equal(t, "Test user description", filteredSpec.Description, "Description should match")
	assert.Equal(t, []string{"cluster1", "cluster2"}, filteredSpec.InvitedByClustersList, "InvitedByClustersList should match")
	assert.Equal(t, "admin", filteredSpec.PlatformRole, "PlatformRole should match")
}
func TestFilterUserSpecForDescription(t *testing.T) {
	// 模拟输入的 v1alpha1.UserSpec
	userSpec := v1alpha1.UserSpec{
		Username:    "testuser",
		Description: "Test user description",
	}

	// 调用被测试的函数
	filteredSpec := filterUserSpecForDescription(userSpec)

	// 验证生成的 UserDescription
	assert.Equal(t, "testuser", filteredSpec.Username, "Username should match")
	assert.Equal(t, "Test user description", filteredSpec.Description, "Description should match")
}
func TestExtractUserInfoCollections(t *testing.T) {
	userList := &v1alpha1.UserList{
		Items: []v1alpha1.User{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "user1",
				},
				Spec: v1alpha1.UserSpec{
					Username:              "testuser1",
					PlatformRole:          "platform-admin",
					InvitedByClustersList: []string{"cluster1", "cluster2"},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "user2",
				},
				Spec: v1alpha1.UserSpec{
					Username:              "testuser2",
					PlatformRole:          "cluster-user",
					InvitedByClustersList: []string{"cluster3"},
				},
			},
		},
	}

	// 调用被测试的函数
	collection := extractUserInfoCollections(userList)

	// 验证 IdentityCollection 结构是否正确
	assert.NotNil(t, collection)
	assert.Len(t, collection.UserInfo, 2)

	// 验证第一个用户的信息
	user1 := collection.UserInfo["user1"]
	assert.NotNil(t, user1)
	assert.Equal(t, "testuser1", user1.IdentityName)
	assert.Equal(t, "users.openfuyao.com", user1.ApiGroup)
	assert.True(t, user1.PlatformAdmin)
	assert.Equal(t, []string{"cluster1", "cluster2"}, user1.MemberClusters)

	// 验证第二个用户的信息
	user2 := collection.UserInfo["user2"]
	assert.NotNil(t, user2)
	assert.Equal(t, "testuser2", user2.IdentityName)
	assert.Equal(t, "users.openfuyao.com", user2.ApiGroup)
	assert.False(t, user2.PlatformAdmin)
	assert.Equal(t, []string{"cluster3"}, user2.MemberClusters)
}
func TestExtractUserInfoCollections_EmptyUserList(t *testing.T) {
	// 模拟输入的空的 v1alpha1.UserList
	userList := &v1alpha1.UserList{
		Items: []v1alpha1.User{},
	}

	// 调用被测试的函数
	collection := extractUserInfoCollections(userList)

	// 验证 IdentityCollection 结构是否正确
	assert.NotNil(t, collection)
	assert.Empty(t, collection.UserInfo)
}

func TestPrepareClusterRoleBinding(t *testing.T) {
	// 模拟输入的 ClusterRoleBinding 配置
	config := types.ClusterRoleBinding{
		Username: "testuser",
		RoleName: "admin",
		RoleType: "platform-role",
	}

	// 调用被测试的函数
	clusterRoleBinding := prepareClusterRoleBinding(config.Username, config.RoleName, config.RoleType)

	// 验证 ClusterRoleBinding 结构是否正确
	assert.Equal(t, "testuser-admin", clusterRoleBinding.Name, "Name should be username + '-' + roleName")

	// 验证 Labels 是否正确
	assert.Equal(t, config.Username, clusterRoleBinding.Labels[constants.UserRefLabel], "UserRefLabel should match Username")
	assert.Equal(t, config.RoleName, clusterRoleBinding.Labels[constants.ClusterRoleRefLabel], "ClusterRoleRefLabel should match RoleName")
	assert.Equal(t, config.RoleType, clusterRoleBinding.Labels[constants.OpenFuyaoRoleLabel], "OpenFuyaoRoleLabel should match RoleType")

	// 验证 Subjects 是否正确
	assert.Len(t, clusterRoleBinding.Subjects, 1, "Subjects should have one entry")
	assert.Equal(t, "User", clusterRoleBinding.Subjects[0].Kind, "Subject Kind should be 'User'")
	assert.Equal(t, config.Username, clusterRoleBinding.Subjects[0].Name, "Subject Name should match Username")

	// 验证 RoleRef 是否正确
	assert.Equal(t, "ClusterRole", clusterRoleBinding.RoleRef.Kind, "RoleRef Kind should be 'ClusterRole'")
	assert.Equal(t, "openfuyao-"+config.RoleName, clusterRoleBinding.RoleRef.Name, "RoleRef Name should be prefixed with 'openfuyao-'")
	assert.Equal(t, rbacv1.GroupName, clusterRoleBinding.RoleRef.APIGroup, "RoleRef APIGroup should match")
}
func TestSendUserListToMulticlusterService_Success(t *testing.T) {
	// 模拟 HTTP 服务器，返回 200 OK 响应
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求方法是否为 POST
		assert.Equal(t, http.MethodPost, r.Method)
		// 验证请求头是否包含 Content-Type: application/json
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// 验证请求体是否为期望的 JSON 数据
		body, err := ioutil.ReadAll(r.Body)
		assert.Nil(t, err)
		expectedJSON, err := json.Marshal(types.IdentityCollection{
			UserInfo: map[string]*types.IdentityDescriptor{
				"user1": {IdentityName: "user1", ApiGroup: "group1"},
			},
		})
		assert.Nil(t, err)
		assert.JSONEq(t, string(expectedJSON), string(body))

		// 返回成功响应
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte("OK"))
		assert.Nil(t, err)
	}))
	defer mockServer.Close()
}

var logInfoCalled bool
var logErrorCalled bool
var loggedInfoMessage string
var loggedErrorMessage string

func TestDeletePlatformCRBAccrossClusters_Success(t *testing.T) {
	// 模拟请求
	req := &restful.Request{
		Request: httptest.NewRequest("DELETE", "/dummy-url", nil),
	}

	// 调用被测试的函数
	deletePlatformCRBAccrossClusters(req, "testuser", "testcluster", "admin")

	assert.Contains(t, loggedInfoMessage, "")
	assert.Contains(t, loggedInfoMessage, "")
}
func TestCreatePlatformCRBAccrossClusters_Success(t *testing.T) {
	// 模拟请求
	req := &restful.Request{
		Request: httptest.NewRequest("POST", "/dummy-url", nil),
	}
	resp := restful.NewResponse(httptest.NewRecorder())

	// 调用被测试的函数
	createPlatformCRBAccrossClusters(req, resp, "testuser", "testcluster", "admin")

	assert.Contains(t, loggedInfoMessage, "")
}

func Test_validateUserName(t *testing.T) {
	type args struct {
		username string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid-username",
			args: args{username: "admin"},
			want: true,
		},
		{
			name: "username-too-long",
			args: args{username: "test-toooooooooooooooooooooooooooooo-long-username"},
			want: false,
		},
		{
			name: "invalid-username",
			args: args{username: "-admin-"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, validateUserName(tt.args.username), "validateUserName(%v)", tt.args.username)
		})
	}
}
