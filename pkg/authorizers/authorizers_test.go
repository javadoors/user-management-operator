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

package authorizers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"openfuyao.com/user-management/pkg/constants"
	"openfuyao.com/user-management/pkg/tools"
	"openfuyao.com/user-management/pkg/utils/requestutils"
)

const (
	testClusterName            = "test-cluster"
	testUsername               = "test-user"
	testClusterRoleBindingName = "test-crb"
	testAdmittedRole           = "platform-admin"
	testNonAdmittedRole        = "platform-guest"
	testClusterRoleType        = "platform-admin"
)

func TestAuthorizeByAdmittedRolesSuccess(t *testing.T) {
	// 创建测试请求和上下文
	req := httptest.NewRequest("GET", "/", nil)

	// 创建用户信息
	testUser := &user.DefaultInfo{Name: testUsername}
	ctx := context.WithValue(req.Context(), constants.UserKey, testUser)
	req = req.WithContext(ctx)

	// 创建模拟的 Kubernetes 客户端
	k8sClient := fake.NewSimpleClientset()

	// 准备 admitted roles
	admittedRoles := []string{testAdmittedRole, "cluster-admin"}

	// 使用 gomonkey mock getOpenFuyaoClusterRoleBindings 函数
	patches := gomonkey.ApplyFunc(getOpenFuyaoClusterRoleBindings, func(username, clusterName string,
		k8sClient kubernetes.Interface, req *http.Request) ([]*rbacv1.ClusterRoleBinding, error) {
		return []*rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:   testClusterRoleBindingName,
					Labels: map[string]string{constants.OpenFuyaoRoleLabel: "platform-role"},
				},
			},
		}, nil
	})

	// mock getOpenFuyaoClusterRoleType 函数
	patches.ApplyFunc(getOpenFuyaoClusterRoleType, func(crb *rbacv1.ClusterRoleBinding) string {
		return testClusterRoleType
	})

	defer patches.Reset()

	// 调用被测试的函数
	result := AuthorizeByAdmittedRoles(req, testClusterName, admittedRoles, k8sClient)

	// 验证结果
	assert.True(t, result)
}

func TestAuthorizeByAdmittedRolesNoUserinfo(t *testing.T) {
	// 创建测试请求，不包含用户信息
	req := httptest.NewRequest("GET", "/", nil)

	// 创建模拟的 Kubernetes 客户端
	k8sClient := fake.NewSimpleClientset()

	// 准备 admitted roles
	admittedRoles := []string{testAdmittedRole}

	// 调用被测试的函数
	result := AuthorizeByAdmittedRoles(req, testClusterName, admittedRoles, k8sClient)

	// 验证结果
	assert.False(t, result)
}

func TestAuthorizeByAdmittedRolesGetCRBError(t *testing.T) {
	// 创建测试请求和上下文
	req := httptest.NewRequest("GET", "/", nil)

	// 创建用户信息
	testUser := &user.DefaultInfo{Name: testUsername}
	ctx := context.WithValue(req.Context(), constants.UserKey, testUser)
	req = req.WithContext(ctx)

	// 创建模拟的 Kubernetes 客户端
	k8sClient := fake.NewSimpleClientset()

	// 准备 admitted roles
	admittedRoles := []string{testAdmittedRole}

	// 使用 gomonkey mock getOpenFuyaoClusterRoleBindings 函数返回错误
	patches := gomonkey.ApplyFunc(getOpenFuyaoClusterRoleBindings, func(username, clusterName string,
		k8sClient kubernetes.Interface, req *http.Request) ([]rbacv1.ClusterRoleBinding, error) {
		return nil, assert.AnError
	})

	// mock tools.FormatError 函数
	logErrorPatch := gomonkey.ApplyFunc(tools.FormatError, func(format string, args ...interface{}) {
		expectedMsg := "cannot get crb for %s"
		actualMsg := format
		assert.Equal(t, expectedMsg, actualMsg)
	})
	defer logErrorPatch.Reset()

	defer patches.Reset()

	// 调用被测试的函数
	result := AuthorizeByAdmittedRoles(req, testClusterName, admittedRoles, k8sClient)

	// 验证结果
	assert.False(t, result)
}

func TestAuthorizeByAdmittedRolesNoMatchingRole(t *testing.T) {
	// 创建测试请求和上下文
	req := httptest.NewRequest("GET", "/", nil)

	// 创建用户信息
	testUser := &user.DefaultInfo{Name: testUsername}
	ctx := context.WithValue(req.Context(), constants.UserKey, testUser)
	req = req.WithContext(ctx)

	// 创建模拟的 Kubernetes 客户端
	k8sClient := fake.NewSimpleClientset()

	// 准备 admitted roles
	admittedRoles := []string{testNonAdmittedRole}

	// 使用 gomonkey mock 函数
	patches := gomonkey.ApplyFunc(getOpenFuyaoClusterRoleBindings, func(username, clusterName string,
		k8sClient kubernetes.Interface, req *http.Request) ([]*rbacv1.ClusterRoleBinding, error) {
		return []*rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:   testClusterRoleBindingName,
					Labels: map[string]string{constants.OpenFuyaoRoleLabel: "any-role"},
				},
				RoleRef: rbacv1.RoleRef{Name: "any-role"},
			},
		}, nil
	})

	// mock getOpenFuyaoClusterRoleType 函数
	patches.ApplyFunc(getOpenFuyaoClusterRoleType, func(crb *rbacv1.ClusterRoleBinding) string {
		return testClusterRoleType
	})

	// mock openFuyaoRoleContains 函数返回 false
	patches.ApplyFunc(openFuyaoRoleContains, func(roles []string, role string) bool {
		return false
	})

	defer patches.Reset()

	// 调用被测试的函数
	result := AuthorizeByAdmittedRoles(req, testClusterName, admittedRoles, k8sClient)

	// 验证结果
	assert.False(t, result)
}

func TestAuthorizeByAdmittedRolesEmptyCRBs(t *testing.T) {
	// 创建测试请求和上下文
	req := httptest.NewRequest("GET", "/", nil)

	// 创建用户信息
	testUser := &user.DefaultInfo{Name: testUsername}
	ctx := context.WithValue(req.Context(), constants.UserKey, testUser)
	req = req.WithContext(ctx)

	// 创建模拟的 Kubernetes 客户端
	k8sClient := fake.NewSimpleClientset()

	// 准备 admitted roles
	admittedRoles := []string{testAdmittedRole}

	// 使用 gomonkey mock getOpenFuyaoClusterRoleBindings 函数返回空列表
	patches := gomonkey.ApplyFunc(getOpenFuyaoClusterRoleBindings, func(username, clusterName string,
		k8sClient kubernetes.Interface, req *http.Request) ([]rbacv1.ClusterRoleBinding, error) {
		return []rbacv1.ClusterRoleBinding{}, nil
	})

	defer patches.Reset()

	// 调用被测试的函数
	result := AuthorizeByAdmittedRoles(req, testClusterName, admittedRoles, k8sClient)

	// 验证结果
	assert.False(t, result)
}

func TestGetOpenFuyaoClusterRoleType(t *testing.T) {
	tests := []struct {
		name         string
		crb          *rbacv1.ClusterRoleBinding
		expectedRole string
	}{
		{
			name: "invalid role type",
			crb: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{ // Use ObjectMeta for labels
					Labels: map[string]string{constants.OpenFuyaoRoleLabel: "platform-role"},
				},
				RoleRef: rbacv1.RoleRef{Name: "any-role"},
			},
			expectedRole: "",
		},
		{
			name: "role not in platform roles",
			crb: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{ // Use ObjectMeta for labels
					Labels: map[string]string{constants.OpenFuyaoRoleLabel: "platform-role"},
				},
				RoleRef: rbacv1.RoleRef{Name: "invalid-platform-role"},
			},
			expectedRole: "",
		},
		{
			name: "role in platform roles",
			crb: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{ // Use ObjectMeta for labels
					Labels: map[string]string{constants.OpenFuyaoRoleLabel: "platform-role"},
				},
				RoleRef: rbacv1.RoleRef{Name: "platform-admin"},
			},
			expectedRole: "platform-admin",
		},
		{
			name: "role not in cluster roles",
			crb: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{ // Use ObjectMeta for labels
					Labels: map[string]string{constants.OpenFuyaoRoleLabel: "cluster-role"},
				},
				RoleRef: rbacv1.RoleRef{Name: "invalid-cluster-role"},
			},
			expectedRole: "",
		},
	}

	// Assuming platformRoles and clusterRoles are defined as globals or constants
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getOpenFuyaoClusterRoleType(tt.crb)
			assert.Equal(t, tt.expectedRole, result)
		})
	}
}

func TestCheckDangerousOperation(t *testing.T) {
	// 模拟用户信息
	userInfo := &user.DefaultInfo{
		Name:   "testuser",
		Groups: []string{"group1"},
	}

	// 定义测试用例
	tests := []struct {
		name      string
		username  string
		userInCtx user.Info
		expected  bool
		isAdmin   bool
	}{
		{
			name:      "Self modification",
			username:  "testuser",
			userInCtx: userInfo,
			expected:  true,
			isAdmin:   false,
		},
		{
			name:      "Admin modification",
			username:  "admin",
			userInCtx: userInfo,
			expected:  true,
			isAdmin:   true,
		},
		{
			name:      "Other user modification",
			username:  "otheruser",
			userInCtx: userInfo,
			expected:  false,
			isAdmin:   false,
		},
		{
			name:      "No user in context",
			username:  "testuser",
			userInCtx: nil,
			expected:  false,
			isAdmin:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建模拟请求
			req := httptest.NewRequest("GET", "http://example.com", nil)

			// 如果有 userInfo，加入上下文
			if tt.userInCtx != nil {
				ctx := context.WithValue(req.Context(), constants.UserKey, tt.userInCtx)
				req = req.WithContext(ctx)
			}

			// 调用 CheckDangerousOperation 函数
			result := CheckDangerousOperation(req, tt.username)

			// 断言结果是否符合预期
			assert.Equal(t, tt.expected, result)
		})
	}
}

func patchDoRequestWithMockCRB(userName string) *gomonkey.Patches {
	return gomonkey.ApplyFunc(requestutils.DoRequestWithMaxRetries, func(url, method string,
		req *http.Request, body []byte, retries int) (int, []byte, error) {
		// 模拟返回
		crbList := rbacv1.ClusterRoleBindingList{
			Items: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-crb",
						Labels: map[string]string{
							constants.OpenFuyaoRoleLabel: "platform-role",
						},
					},
					Subjects: []rbacv1.Subject{
						{
							Name: userName,
						},
					},
				},
			},
		}
		respBody, err := json.Marshal(crbList)
		if err != nil {
			return http.StatusInternalServerError, nil, err
		}
		return http.StatusOK, respBody, nil
	})
}

func TestGetOpenFuyaoClusterRoleBindings(t *testing.T) {
	userName := "testuser"

	fakeK8sClient := fake.NewSimpleClientset(&rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "test-crb", Labels: map[string]string{
			constants.OpenFuyaoRoleLabel: "platform-role"}},
		Subjects: []rbacv1.Subject{{Name: userName}}})

	tests := []struct {
		name         string
		userName     string
		clusterName  string
		expectError  bool
		setupRequest func() *http.Request
		usePatch     bool
	}{
		{
			name:         "Fetch CRB from specific cluster via HTTP",
			userName:     userName,
			clusterName:  "testcluster",
			expectError:  false,
			setupRequest: func() *http.Request { return httptest.NewRequest("GET", "http://example.com", nil) },
			usePatch:     true,
		},
		{
			name:         "Fetch CRB directly from Kubernetes client",
			userName:     userName,
			clusterName:  "",
			expectError:  false,
			setupRequest: func() *http.Request { return httptest.NewRequest("GET", "http://example.com", nil) },
			usePatch:     false,
		},
		{
			name:         "No CRB found for user",
			userName:     "none-existed-user",
			clusterName:  "",
			expectError:  true,
			setupRequest: func() *http.Request { return httptest.NewRequest("GET", "http://example.com", nil) },
			usePatch:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var patches *gomonkey.Patches
			if tt.usePatch {
				patches = patchDoRequestWithMockCRB(tt.userName)
				defer patches.Reset()
			}

			req := tt.setupRequest()
			crbs, err := getOpenFuyaoClusterRoleBindings(tt.userName, tt.clusterName, fakeK8sClient, req)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, crbs)
				assert.Greater(t, len(crbs), 0)
				assert.Equal(t, tt.userName, crbs[0].Subjects[0].Name)
			}
		})
	}
}
