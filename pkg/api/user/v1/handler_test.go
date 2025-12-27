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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	usersv1alpha1 "openfuyao.com/user-management/api/v1alpha1"
	"openfuyao.com/user-management/pkg/api/user/v1/types"
	"openfuyao.com/user-management/pkg/authorizers"
)

func TestHandler_safelyCreateCRBByClientGo(t *testing.T) {
	tests := []struct {
		name        string
		existingCRB *rbacv1.ClusterRoleBinding // If the CRB exists in the fake client
		newCRB      *rbacv1.ClusterRoleBinding // The new CRB to be created or updated
		want        bool                       // Expected return value for CRB creation
		wantErr     bool                       // Whether an error is expected
	}{
		{
			name: "CRB exists, update required",
			existingCRB: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "test-crb",
					ResourceVersion: "1",
				},
			},
			newCRB: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-crb",
				},
			},
			want:    true, // CRB already exists, so it should be updated, not created
			wantErr: false,
		},
		{
			name:        "CRB does not exist, create required",
			existingCRB: nil, // No existing CRB
			newCRB: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "new-crb",
				},
			},
			want:    true, // CRB does not exist, so it should be created
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake Kubernetes client
			k8sClient := fake.NewSimpleClientset()

			// If the test case has an existing CRB, add it to the fake client
			if tt.existingCRB != nil {
				k8sClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), tt.existingCRB, metav1.CreateOptions{})
			}

			// Create the handler with the fake client
			h := &Handler{
				K8sClient: k8sClient,
			}

			// Call the method and check the result
			succeed, err := h.safelyCreateCRBByClientGo(tt.newCRB)

			// Check if an error was expected or not
			if (err != nil) != tt.wantErr {
				t.Errorf("safelyCreateCRBByClientGo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check if the CRB was expected to be created
			assert.Equal(t, tt.want, succeed)
		})
	}
}

func TestHandler_isServiceAvailable(t *testing.T) {
	tests := []struct {
		name          string
		serviceName   string
		namespace     string
		serviceExists bool
		clusterIP     string
		wantAvailable bool
	}{
		{
			name:          "Service exists with valid ClusterIP",
			serviceName:   "test-service",
			namespace:     "default",
			serviceExists: true,
			clusterIP:     "10.0.0.1",
			wantAvailable: true,
		},
		{
			name:          "Service exists without ClusterIP",
			serviceName:   "test-service",
			namespace:     "default",
			serviceExists: true,
			clusterIP:     "",
			wantAvailable: false,
		},
		{
			name:          "Service exists with ClusterIP set to None",
			serviceName:   "test-service",
			namespace:     "default",
			serviceExists: true,
			clusterIP:     "None",
			wantAvailable: false,
		},
		{
			name:          "Service does not exist",
			serviceName:   "non-existent-service",
			namespace:     "default",
			serviceExists: false,
			wantAvailable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake Kubernetes client
			k8sClient := fake.NewSimpleClientset()

			// Create a service if the test case requires it
			if tt.serviceExists {
				svc := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tt.serviceName,
						Namespace: tt.namespace,
					},
					Spec: corev1.ServiceSpec{
						ClusterIP: tt.clusterIP,
					},
				}
				k8sClient.CoreV1().Services(tt.namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
			}

			// Create the handler with the fake client
			h := &Handler{
				K8sClient: k8sClient,
			}

			// Call the method and check the result
			got := h.isServiceAvailable(tt.serviceName, tt.namespace)
			assert.Equal(t, tt.wantAvailable, got)
		})
	}
}

func TestHandler_userListPostAPI(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = usersv1alpha1.AddToScheme(scheme) // Register the scheme for UserList

	// Create a fake client with test data
	fakeClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a fake UserList to return from the client
	userList := &usersv1alpha1.UserList{
		Items: []usersv1alpha1.User{
			{
				Spec: usersv1alpha1.UserSpec{
					Username:     "test-user",
					PlatformRole: "platform-admin",
				},
			},
		},
	}

	// Pre-populate the fake client with userList
	_ = fakeClient.Create(context.Background(), &userList.Items[0])

	// Create an instance of Handler with the fake client
	h := &Handler{
		UserClient: fakeClient,
	}

	// Mock the sendUserListToMulticlusterService function
	patches := gomonkey.ApplyFunc(sendUserListToMulticlusterService, func(userList types.IdentityCollection) error {
		return nil // 模拟调用成功
	})
	defer patches.Reset()

	// Call the function being tested
	err := h.userListPostAPI()

	// Assert no error
	assert.NoError(t, err)
}

func TestHandler_checkUserMainPageAccessPermission(t *testing.T) {
	type args struct {
		request  *restful.Request
		response *restful.Response
	}
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	tests := []struct {
		name       string
		username   string
		args       args
		setupFunc  func(client.Client) // A setup function to initialize test data
		wantStatus int                 // Expected HTTP status
		wantBody   string              // Expected response body
	}{
		{
			name:     "User is platform-admin, has permission",
			username: "admin",
			setupFunc: func(userClient client.Client) {
				user := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "admin"},
					Spec: usersv1alpha1.UserSpec{
						Username:     "admin",
						PlatformRole: "platform-admin",
					},
				}
				userClient.Create(context.Background(), user)
			},
			wantStatus: http.StatusOK,
			wantBody:   "user has permission to access main page",
		},
		{
			name:     "User is platform-regular with cluster invites, has permission",
			username: "regularUser",
			setupFunc: func(userClient client.Client) {
				user := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "regularUser"},
					Spec: usersv1alpha1.UserSpec{
						Username:              "regularUser",
						PlatformRole:          "platform-regular",
						InvitedByClustersList: []string{"cluster1"},
					},
				}
				userClient.Create(context.Background(), user)
			},
			wantStatus: http.StatusOK,
			wantBody:   "user has permission to access main page",
		},
		{
			name:     "User is platform-regular with no invites, no permission",
			username: "regularUser",
			setupFunc: func(userClient client.Client) {
				user := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "regularUser"},
					Spec: usersv1alpha1.UserSpec{
						Username:              "regularUser",
						PlatformRole:          "platform-regular",
						InvitedByClustersList: []string{},
					},
				}
				userClient.Create(context.Background(), user)
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "user is not authorized to access main page",
		},
		{
			name:     "User does not exist",
			username: "regularUser",
			setupFunc: func(userClient client.Client) {
				// Do nothing, the user doesn't exist in this case
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "The user does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize fake clients and setup request/response
			fakeClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
			req := restful.NewRequest(httptest.NewRequest("GET", "/users/"+tt.username, nil))
			req.Request.Header.Set("Accept", "application/json")
			req.PathParameters()["user-name"] = tt.username
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fake.NewSimpleClientset(),
			}

			if tt.setupFunc != nil {
				tt.setupFunc(fakeClient) // Run setup to prepare the test data
			}

			h.checkUserMainPageAccessPermission(req, resp)

			// Check expected status and response body
			if resp.StatusCode() != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode())
			}

			respBody := recorder.Body.String()
			if !strings.Contains(respBody, tt.wantBody) {
				t.Errorf("expected body %s, got %s", tt.wantBody, respBody)
			}
		})
	}
}

func TestHandler_preCreateSteps(t *testing.T) {
	type args struct {
		userReq  types.UserCreateRequest
		response *restful.Response
	}

	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	tests := []struct {
		name      string
		args      args
		setupFunc func(client.Client) // A setup function to initialize test data
		want      []byte
	}{
		{
			name: "pre-create-succeed",
			args: args{
				userReq: types.UserCreateRequest{
					Username:            "admin",
					UnEncryptedPassword: []byte("test@1234"),
				},
			},
			want: []byte("random-bytes"),
		},
		{
			name: "no-user-name",
			args: args{
				userReq: types.UserCreateRequest{
					Username:            "",
					UnEncryptedPassword: []byte("test@1234"),
				},
			},
			want: nil,
		},
		{
			name: "user-name-invalid",
			args: args{
				userReq: types.UserCreateRequest{
					Username:            "?admin",
					UnEncryptedPassword: []byte("test@1234"),
				},
			},
			want: nil,
		},
		{
			name: "user-already-exists",
			args: args{
				userReq: types.UserCreateRequest{
					Username:            "admin",
					UnEncryptedPassword: []byte("test@1234"),
				},
			},
			setupFunc: func(userClient client.Client) {
				user := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "admin"},
					Spec: usersv1alpha1.UserSpec{
						Username:     "admin",
						PlatformRole: "platform-regular",
					},
				}
				userClient.Create(context.Background(), user)
			},
			want: nil,
		},
		{
			name: "password-complexity-fail",
			args: args{
				userReq: types.UserCreateRequest{
					Username:            "admin",
					UnEncryptedPassword: []byte("test1234"),
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")
			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fake.NewSimpleClientset(),
			}
			if tt.setupFunc != nil {
				tt.setupFunc(fakeClient) // Run setup to prepare the test data
			}
			if tt.want == nil {
				assert.Equalf(t, tt.want, h.preCreateSteps(tt.args.userReq, resp), "preCreateSteps(%v, %v)", tt.args.userReq, resp)
			} else {
				assert.NotNil(t, h.preCreateSteps(tt.args.userReq, resp), "preCreateSteps(%v, %v)", tt.args.userReq, resp)
			}
		})
	}
}

func TestHandler_findRoleBindingForSpecificUser(t *testing.T) {
	type args struct {
		username  string
		roleLabel string
	}

	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	tests := []struct {
		name      string
		args      args
		setupFunc func() kubernetes.Interface
		want      *rbacv1.ClusterRoleBinding
		wantErr   assert.ErrorAssertionFunc
	}{
		{
			name: "User has role binding",
			setupFunc: func() kubernetes.Interface {
				return fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "test-rolebinding",
							Labels: map[string]string{"role-type": "test-role"},
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "test-user",
							},
						},
					},
				)
			},
			args: args{
				username:  "test-user",
				roleLabel: "test-role",
			},
			want: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rolebinding",
					Labels: map[string]string{
						"role-type": "test-role",
					},
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "User not found in role bindings",
			setupFunc: func() kubernetes.Interface {
				return fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "some-other-rolebinding",
							Labels: map[string]string{"role-type": "test-role"},
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "other-user",
							},
						},
					},
				)
			},
			args: args{
				username:  "nonexistent-user",
				roleLabel: "test-role",
			},
			want:    nil,
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeK8sClient kubernetes.Interface
			if tt.setupFunc != nil {
				fakeK8sClient = tt.setupFunc() // Run setup to prepare the test data
			}

			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fakeK8sClient,
			}
			got, err := h.findRoleBindingForSpecificUser(tt.args.username, tt.args.roleLabel)
			if !tt.wantErr(t, err, fmt.Sprintf("findRoleBindingForSpecificUser(%v, %v)", tt.args.username, tt.args.roleLabel)) {
				return
			}
			assert.Equalf(t, tt.want, got, "findRoleBindingForSpecificUser(%v, %v)", tt.args.username, tt.args.roleLabel)
		})
	}
}

func TestHandler_listPlatformUser(t *testing.T) {
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patch := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(req *http.Request, clusterName string,
		admittedRoles []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patch.Reset()

	tests := []struct {
		name      string
		setupFunc func() (client.Client, *restful.Request)
		wantCode  int
		wantBody  string
	}{
		{
			name: "Successfully list platform users without keyword",
			setupFunc: func() (client.Client, *restful.Request) {
				req := httptest.NewRequest("GET", "/users", nil)
				restReq := restful.NewRequest(req)
				userClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
				user1 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser1"},
					Spec: usersv1alpha1.UserSpec{
						Username:     "testuser1",
						PlatformRole: "platform-admin",
						Description:  "A platform user",
					},
				}
				user2 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser2"},
					Spec: usersv1alpha1.UserSpec{
						Username:     "testuser2",
						PlatformRole: "platform-admin",
						Description:  "Another user",
					},
				}
				userClient.Create(context.Background(), user1)
				userClient.Create(context.Background(), user2)
				return userClient, restReq
			},
			wantCode: http.StatusOK,
			wantBody: "Platform users listed successfully",
		},
		{
			name: "Successfully list platform users with keyword filter",
			setupFunc: func() (client.Client, *restful.Request) {
				req := httptest.NewRequest("GET", "/users?user=admin", nil)
				restReq := restful.NewRequest(req)
				userClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
				user1 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser1"},
					Spec: usersv1alpha1.UserSpec{
						Username:     "testuser1",
						PlatformRole: "platform-admin",
						Description:  "A platform user",
					},
				}
				user2 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser2"},
					Spec: usersv1alpha1.UserSpec{
						Username:     "testuser2",
						PlatformRole: "platform-admin",
						Description:  "Another user",
					},
				}
				userClient.Create(context.Background(), user1)
				userClient.Create(context.Background(), user2)
				// Mock UserClient.List
				return userClient, restReq
			},
			wantCode: http.StatusOK,
			wantBody: "Platform users listed successfully",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fakeClient client.Client
			var restReq *restful.Request
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			if tt.setupFunc != nil {
				fakeClient, restReq = tt.setupFunc() // Run setup to prepare the test data
			}

			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fake.NewSimpleClientset(),
			}

			h.listPlatformUser(restReq, resp)

			// Check response status code
			assert.Equal(t, tt.wantCode, recorder.Code)

			// Check response body for specific keywords
			assert.Contains(t, recorder.Body.String(), tt.wantBody)
		})
	}
}

func TestHandler_editRoleBinding(t *testing.T) {
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patch1 := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(req *http.Request, clusterName string,
		admittedRoles []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patch1.Reset()

	tests := []struct {
		name           string
		userName       string
		clusterRole    string
		setupFunc      func() (*restful.Request, kubernetes.Interface)
		expectedStatus int
	}{
		{
			name:        "create-rolebinding-succeeds",
			userName:    "admin",
			clusterRole: "cluster-editor",
			setupFunc: func() (*restful.Request, kubernetes.Interface) {
				fakeK8sClient := fake.NewSimpleClientset()
				req := httptest.NewRequest("PATCH", "/cluster-rolebindings/{user-name}/{cluster-role}", nil)
				restReq := restful.NewRequest(req)
				restReq.PathParameters()["user-name"] = "admin"
				restReq.PathParameters()["cluster-role"] = "cluster-editor"

				return restReq, fakeK8sClient
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "edit-rolebinding-succeeds",
			userName:    "admin",
			clusterRole: "cluster-editor",
			setupFunc: func() (*restful.Request, kubernetes.Interface) {
				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "admin-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "admin",
							},
						},
					},
				)

				req := httptest.NewRequest("PATCH", "/cluster-rolebindings/{user-name}/{cluster-role}", nil)
				restReq := restful.NewRequest(req)
				restReq.PathParameters()["user-name"] = "admin"
				restReq.PathParameters()["cluster-role"] = "cluster-editor"

				return restReq, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "no-need-to-edit-rolebinding",
			userName:    "admin",
			clusterRole: "cluster-admin",
			setupFunc: func() (*restful.Request, kubernetes.Interface) {
				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "admin-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "admin",
							},
						},
					},
				)

				req := httptest.NewRequest("PATCH", "/cluster-rolebindings/{user-name}/{cluster-role}", nil)
				restReq := restful.NewRequest(req)
				restReq.PathParameters()["user-name"] = "admin"
				restReq.PathParameters()["cluster-role"] = "cluster-admin"

				return restReq, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			fakeClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeK8sClient kubernetes.Interface
			if tt.setupFunc != nil {
				restReq, fakeK8sClient = tt.setupFunc() // Run setup to prepare the test data
			}

			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fakeK8sClient,
			}
			h.editRoleBinding(restReq, resp)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
		})
	}
}

func TestHandler_listClusterUser(t *testing.T) {
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patch1 := gomonkey.ApplyFunc(getClusterRoleByConsoleService, func(req *http.Request, clusterName string,
		username string) (string, error) {
		return "openfuyao-cluster-admin", nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(req *http.Request, clusterName string,
		admittedRoles []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patch2.Reset()

	tests := []struct {
		name           string
		userParam      string
		clusterParam   string
		setupFunc      func() (*restful.Request, client.Client, kubernetes.Interface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:         "list-cluster-members-without-username-param-successfully",
			userParam:    "",
			clusterParam: "host",
			setupFunc: func() (*restful.Request, client.Client, kubernetes.Interface) {
				req := httptest.NewRequest("GET", "/cluster-members?cluster-name=host", nil)
				restReq := restful.NewRequest(req)

				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testuser1-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "testuser1",
							},
						},
					},
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testuser2-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "testuser2",
							},
						},
					},
				)

				userClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
				user1 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser1"},
					Spec: usersv1alpha1.UserSpec{
						Username:              "testuser1",
						PlatformRole:          "platform-admin",
						Description:           "A platform user",
						InvitedByClustersList: []string{"host"},
					},
				}
				user2 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser2"},
					Spec: usersv1alpha1.UserSpec{
						Username:              "testuser2",
						PlatformRole:          "platform-admin",
						Description:           "Another user",
						InvitedByClustersList: []string{"host"},
					},
				}
				userClient.Create(context.Background(), user1)
				userClient.Create(context.Background(), user2)

				return restReq, userClient, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Cluster-members fetched successfully",
		},
		{
			name:         "list-cluster-members-with-username-param-successfully",
			userParam:    "",
			clusterParam: "host",
			setupFunc: func() (*restful.Request, client.Client, kubernetes.Interface) {
				req := httptest.NewRequest("GET", "/cluster-members?cluster-name=host&user=admin", nil)
				restReq := restful.NewRequest(req)

				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testuser1-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "testuser1",
							},
						},
					},
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testuser2-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "testuser2",
							},
						},
					},
				)

				userClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
				user1 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser1"},
					Spec: usersv1alpha1.UserSpec{
						Username:              "testuser1",
						PlatformRole:          "platform-admin",
						Description:           "A platform user",
						InvitedByClustersList: []string{"host"},
					},
				}
				user2 := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{Name: "testuser2"},
					Spec: usersv1alpha1.UserSpec{
						Username:              "testuser2",
						PlatformRole:          "platform-admin",
						Description:           "Another user",
						InvitedByClustersList: []string{"host"},
					},
				}
				userClient.Create(context.Background(), user1)
				userClient.Create(context.Background(), user2)

				return restReq, userClient, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Cluster-members fetched successfully",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			var fakeClient client.Client
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeK8sClient kubernetes.Interface
			if tt.setupFunc != nil {
				restReq, fakeClient, fakeK8sClient = tt.setupFunc() // Run setup to prepare the test data
			}

			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fakeK8sClient,
			}
			h.listClusterUser(restReq, resp)

			// Check response status code
			assert.Equal(t, tt.expectedStatus, recorder.Code)

			// Check response body for specific keywords
			assert.Contains(t, recorder.Body.String(), tt.expectedBody)
		})
	}
}

func TestHandler_getClusterRoleBindingsForUser(t *testing.T) {
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patches := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(req *http.Request, clusterName string,
		admittedRoles []string, client kubernetes.Interface) bool {
		return true
	})
	defer patches.Reset()

	tests := []struct {
		name           string
		userParam      string
		setupFunc      func() (*restful.Request, client.Client, kubernetes.Interface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:      "clusterrolebinding-not-fonud",
			userParam: "admin",
			setupFunc: func() (*restful.Request, client.Client, kubernetes.Interface) {
				req := httptest.NewRequest("GET", "/cluster-rolebindings?user=admin", nil)
				restReq := restful.NewRequest(req)

				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testuser1-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "testuser1",
							},
						},
					},
				)

				userClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()

				return restReq, userClient, fakeK8sClient
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Could not find ClusterRoleBinding for this user",
		},
		{
			name:      "clusterrolebinding-successfully-fetched",
			userParam: "admin",
			setupFunc: func() (*restful.Request, client.Client, kubernetes.Interface) {
				req := httptest.NewRequest("GET", "/cluster-rolebindings?user=admin", nil)
				restReq := restful.NewRequest(req)

				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "admin-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
						RoleRef: rbacv1.RoleRef{
							Name: "openfuyao-cluster-admin",
						},
						Subjects: []rbacv1.Subject{
							{
								Kind: "User",
								Name: "admin",
							},
						},
					},
				)

				userClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()

				return restReq, userClient, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Clusterrolebinding fetched successfully",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			var fakeClient client.Client
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeK8sClient kubernetes.Interface
			if tt.setupFunc != nil {
				restReq, fakeClient, fakeK8sClient = tt.setupFunc() // Run setup to prepare the test data
			}

			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fakeK8sClient,
			}

			h.getClusterRoleBindingsForUser(restReq, resp)
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			assert.Contains(t, recorder.Body.String(), tt.expectedBody)
		})
	}
}

func TestHandler_getUserDetail(t *testing.T) {
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme) // 将 User CRD 添加到 Scheme
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patch1 := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(req *http.Request, clusterName string,
		admittedRoles []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(getClusterRoleByConsoleService, func(req *http.Request, clusterName string,
		username string) (string, error) {
		return "openfuyao-cluster-admin", nil
	})
	defer patch2.Reset()

	tests := []struct {
		name           string
		userName       string
		setupFunc      func() (*restful.Request, client.Client, kubernetes.Interface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:     "user-not-found",
			userName: "test-user",
			setupFunc: func() (*restful.Request, client.Client, kubernetes.Interface) {
				restReq := restful.NewRequest(httptest.NewRequest("GET", "/users/test-user", nil))
				restReq.Request.Header.Set("Accept", "application/json")
				restReq.PathParameters()["user-name"] = "test-user"
				// 使用假客户端，不返回任何用户数据
				userClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
				fakeK8sClient := fake.NewSimpleClientset()
				return restReq, userClient, fakeK8sClient
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Get operation failed. User client internal error",
		},
		{
			name:     "successfully-fetched-user-detail",
			userName: "test-user",
			setupFunc: func() (*restful.Request, client.Client, kubernetes.Interface) {
				// 创建一个包含用户详细信息的模拟请求
				restReq := restful.NewRequest(httptest.NewRequest("GET", "/users/test-user", nil))
				restReq.Request.Header.Set("Accept", "application/json")
				restReq.PathParameters()["user-name"] = "test-user"

				// 使用带有测试用户的假客户端
				testUser := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user",
					},
					Spec: usersv1alpha1.UserSpec{
						Username:              "test-user",
						Description:           "Test description",
						PlatformRole:          "platform-admin",
						InvitedByClustersList: []string{"cluster1"},
					},
				}

				// 创建带有该用户数据的客户端
				userClient := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(testUser).Build()
				fakeK8sClient := fake.NewSimpleClientset()

				return restReq, userClient, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "User detail get sucessfully",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			var fakeClient client.Client
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeK8sClient kubernetes.Interface
			if tt.setupFunc != nil {
				restReq, fakeClient, fakeK8sClient = tt.setupFunc() // Run setup to prepare the test data
			}

			h := &Handler{
				UserClient: fakeClient,
				K8sClient:  fakeK8sClient,
			}
			h.getUserDetail(restReq, resp)

			// 检查响应状态码
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			// 检查响应内容是否包含预期结果
			assert.Contains(t, recorder.Body.String(), tt.expectedBody)
		})
	}
}

func TestHandler_listPlatformRoles(t *testing.T) {
	// 初始化 Scheme
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patch := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(request *http.Request, clusterName string,
		admittedRoles []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patch.Reset()

	tests := []struct {
		name           string
		setupFunc      func() (*restful.Request, kubernetes.Interface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "platform-roles-fetch-error",
			setupFunc: func() (*restful.Request, kubernetes.Interface) {
				// 模拟请求
				req := httptest.NewRequest("GET", "/platform-roles", nil)
				restReq := restful.NewRequest(req)

				// 使用带有错误返回的假客户端
				fakeK8sClient := fake.NewSimpleClientset()
				fakeK8sClient.PrependReactor("list", "clusterroles", func(action clientgotesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("internel error")
				})

				return restReq, fakeK8sClient
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Error occurs in fetching cluster role resource",
		},
		{
			name: "successfully-fetched-platform-roles",
			setupFunc: func() (*restful.Request, kubernetes.Interface) {
				// 模拟请求
				req := httptest.NewRequest("GET", "/platform-roles", nil)
				restReq := restful.NewRequest(req)

				// 创建带有测试数据的假客户端
				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "platform-admin",
							Labels: map[string]string{"role-type": "platform-role"},
						},
					},
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "platform-regular",
							Labels: map[string]string{"role-type": "platform-role"},
						},
					},
				)

				return restReq, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Platform-Roles fetched successfully",
		},
	}

	// 遍历所有测试用例
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeK8sClient kubernetes.Interface
			if tt.setupFunc != nil {
				restReq, fakeK8sClient = tt.setupFunc() // 设置测试环境
			}

			h := &Handler{
				K8sClient: fakeK8sClient,
			}

			// 调用被测试的函数
			h.listPlatformRoles(restReq, resp)

			// 检查响应状态码
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			// 检查响应内容是否包含预期结果
			assert.Contains(t, recorder.Body.String(), tt.expectedBody)
		})
	}
}

func TestHandler_listClusterRoles(t *testing.T) {
	// 初始化 Scheme
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patches := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(req *http.Request, cluster string,
		admittedRoles []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patches.Reset()

	tests := []struct {
		name           string
		setupFunc      func() (*restful.Request, kubernetes.Interface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "cluster-roles-fetch-error",
			setupFunc: func() (*restful.Request, kubernetes.Interface) {
				// 模拟请求
				req := httptest.NewRequest("GET", "/cluster-roles", nil)
				restReq := restful.NewRequest(req)

				// 使用带有错误返回的假客户端
				fakeK8sClient := fake.NewSimpleClientset()
				fakeK8sClient.PrependReactor("list", "clusterroles", func(action clientgotesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("internel error")
				})

				return restReq, fakeK8sClient
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Error occurs in fetching cluster role resource",
		},
		{
			name: "successfully-fetched-cluster-roles",
			setupFunc: func() (*restful.Request, kubernetes.Interface) {
				// 模拟请求
				req := httptest.NewRequest("GET", "/cluster-roles", nil)
				restReq := restful.NewRequest(req)

				// 创建带有测试数据的假客户端
				fakeK8sClient := fake.NewSimpleClientset(
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "openfuyao-cluster-admin",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
					},
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "openfuyao-cluster-editor",
							Labels: map[string]string{"role-type": "cluster-role"},
						},
					},
				)

				return restReq, fakeK8sClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Cluster-Roles fetched successfully",
		},
	}

	// 遍历所有测试用例
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeK8sClient kubernetes.Interface
			if tt.setupFunc != nil {
				restReq, fakeK8sClient = tt.setupFunc() // 设置测试环境
			}

			h := &Handler{
				K8sClient: fakeK8sClient,
			}

			// 调用被测试的函数
			h.listClusterRoles(restReq, resp)

			// 检查响应状态码
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			// 检查响应内容是否包含预期结果
			assert.Contains(t, recorder.Body.String(), tt.expectedBody)
		})
	}
}

func TestHandler_getUserDescription(t *testing.T) {
	// 初始化 Scheme
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patches := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(req *http.Request, clusterName string,
		admitted []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patches.Reset()

	tests := []struct {
		name           string
		setupFunc      func() (*restful.Request, client.Client)
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "user-get-failed",
			setupFunc: func() (*restful.Request, client.Client) {
				// 模拟请求
				req := httptest.NewRequest("GET", "/users/test-user", nil)
				restReq := restful.NewRequest(req)
				restReq.PathParameters()["user-name"] = "test-user"

				// 创建假用户客户端并返回错误
				fakeUserClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()

				return restReq, fakeUserClient
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Get operation failed. User client internal error",
		},
		{
			name: "user-description-fetched-successfully",
			setupFunc: func() (*restful.Request, client.Client) {
				// 模拟请求
				req := httptest.NewRequest("GET", "/users/test-user", nil)
				restReq := restful.NewRequest(req)
				restReq.PathParameters()["user-name"] = "test-user"

				// 模拟用户数据
				user := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user",
					},
					Spec: usersv1alpha1.UserSpec{
						Description: "Test user description",
					},
				}

				// 创建假用户客户端并返回成功数据
				fakeUserClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
				fakeUserClient.Create(context.Background(), user)

				return restReq, fakeUserClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Get user description succeeds",
		},
	}

	// 遍历所有测试用例
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeUserClient client.Client
			if tt.setupFunc != nil {
				restReq, fakeUserClient = tt.setupFunc() // 设置测试环境
			}

			h := &Handler{
				UserClient: fakeUserClient,
			}

			// 调用被测试的函数
			h.getUserDescription(restReq, resp)

			// 检查响应状态码
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			// 检查响应内容是否包含预期结果
			assert.Contains(t, recorder.Body.String(), tt.expectedBody)
		})
	}
}

func TestHandler_editUserDescription(t *testing.T) {
	// Initialize Scheme
	scheme := runtime.NewScheme()
	err := usersv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Mock the authorizers.AuthorizeByAdmittedRoles function
	patches := gomonkey.ApplyFunc(authorizers.AuthorizeByAdmittedRoles, func(request *http.Request, cluster string,
		admittedRoles []string, k8sClient kubernetes.Interface) bool {
		return true
	})
	defer patches.Reset()

	tests := []struct {
		setupFunc      func() (*restful.Request, client.Client)
		name           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "edit-user-description-entity-reading-error",
			setupFunc: func() (*restful.Request, client.Client) {
				// Simulate request
				req := httptest.NewRequest("PUT", "/users/test-user/user-descriptions", strings.NewReader("invalid-json"))
				restReq := restful.NewRequest(req)
				restReq.PathParameters()["user-name"] = "test-user"

				// Fake client setup
				fakeUserClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()

				return restReq, fakeUserClient
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Entity reading error",
		},
		{
			name: "edit-user-description-get-error",
			setupFunc: func() (*restful.Request, client.Client) {
				// Simulate request with correct data
				reqBody := `{"Username": "test-user", "Description": "Updated description"}`
				req := httptest.NewRequest("PUT", "/users/test-user/user-descriptions", strings.NewReader(reqBody))
				restReq := restful.NewRequest(req)
				restReq.Request.Header.Set("Accept", "application/json")
				restReq.Request.Header.Set("Content-Type", "application/json")
				restReq.PathParameters()["user-name"] = "test-user"

				// Fake client with get error
				fakeUserClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()

				return restReq, fakeUserClient
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Get operation failed. User client internal error",
		},
		{
			name: "edit-user-description-success",
			setupFunc: func() (*restful.Request, client.Client) {
				// Simulate request with correct data
				reqBody := `{"Username": "test-user", "Description": "Updated description"}`
				req := httptest.NewRequest("PUT", "/users/test-user", strings.NewReader(reqBody))
				restReq := restful.NewRequest(req)
				restReq.Request.Header.Set("Accept", "application/json")
				restReq.Request.Header.Set("Content-Type", "application/json")
				restReq.PathParameters()["user-name"] = "test-user"

				// Create user object and fake client
				user := &usersv1alpha1.User{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user",
					},
					Spec: usersv1alpha1.UserSpec{
						Username:    "test-user",
						Description: "Old description",
					},
				}

				fakeUserClient := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(user).Build()

				return restReq, fakeUserClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Edit user description succeeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restReq *restful.Request
			recorder := httptest.NewRecorder()
			resp := restful.NewResponse(recorder)
			resp.SetRequestAccepts("application/json")

			var fakeUserClient client.Client
			if tt.setupFunc != nil {
				restReq, fakeUserClient = tt.setupFunc()
			}

			h := &Handler{
				UserClient: fakeUserClient,
			}

			// Call the function being tested
			h.editUserDescription(restReq, resp)

			// Check response status code
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			// Check response body
			assert.Contains(t, recorder.Body.String(), tt.expectedBody)
		})
	}
}
