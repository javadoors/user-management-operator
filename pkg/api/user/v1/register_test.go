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
	"testing"

	"github.com/emicklei/go-restful/v3"
	"github.com/stretchr/testify/assert"

	"openfuyao.com/user-management/pkg/server"
)

func TestCreateUserRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	createUserRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/users", route.Path, "The route path should be /users")

	// 验证 HTTP 方法是否为 POST
	assert.Equal(t, "POST", route.Method, "The route method should be POST")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Return total file name list", route.Doc, "The route documentation should match")

	// 验证请求体的类型是否为 UserCreateRequest

}

func TestListPlatformUserRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	listPlatformUserRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/users", route.Path, "The route path should be /users")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Return total user list on platform", route.Doc, "The route documentation should match")

	// 验证查询参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 1, "There should be one query parameter")
	assert.Equal(t, server.UserKeyword, params[0].Data().Name, "The query parameter name should be 'keyword'")
	assert.Equal(t, server.KeywordNameDescription, params[0].Data().Description, "The query parameter description should match")

}

func TestListClusterUserRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	listClusterUserRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/cluster-members", route.Path, "The route path should be /cluster-members")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Return total user list on specific cluster", route.Doc, "The route documentation should match")

	// 验证查询参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 2, "There should be two query parameters")

	// 验证第一个查询参数
	assert.Equal(t, server.ClusterName, params[0].Data().Name, "The first query parameter name should be 'cluster-name'")
	assert.Equal(t, server.ClusterNameDescription, params[0].Data().Description, "The first query parameter description should match")

	// 验证第二个查询参数
	assert.Equal(t, server.UserKeyword, params[1].Data().Name, "The second query parameter name should be 'keyword'")
	assert.Equal(t, server.KeywordNameDescription, params[1].Data().Description, "The second query parameter description should match")

}

func TestGetClusterRoleBindingsForUserRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	getClusterRoleBindingsForUserRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/cluster-rolebindings", route.Path, "The route path should be /cluster-rolebindings")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Return specific role binding for user", route.Doc, "The route documentation should match")

}

func TestGetUserDetailRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	getUserDetailRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/users/{user-name}", route.Path, "The route path should be /users/{user-name}")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Return total user list on platform", route.Doc, "The route documentation should match")

	// 验证路径参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 1, "There should be one path parameter")

	// 验证路径参数的名称和描述
	assert.Equal(t, "user-name", params[0].Data().Name, "The path parameter name should be 'user-name'")
	assert.Equal(t, "Name of user detail to get", params[0].Data().Description, "The path parameter description should match")

}

func TestInviteUserListRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	inviteUserListRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/invite-users", route.Path, "The route path should be /invite-users")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Invitable user list of a cluster", route.Doc, "The route documentation should match")

	// 验证查询参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 1, "There should be one query parameter")

	// 验证查询参数的名称和描述
	assert.Equal(t, server.ClusterName, params[0].Data().Name, "The query parameter name should be 'cluster-name'")
	assert.Equal(t, server.ClusterNameDescription, params[0].Data().Description, "The query parameter description should match")

}

func TestDeleteUserRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	deleteUserRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/users/{user-name}", route.Path, "The route path should be /users/{user-name}")

	// 验证 HTTP 方法是否为 DELETE
	assert.Equal(t, "DELETE", route.Method, "The route method should be DELETE")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Delete a specific user", route.Doc, "The route documentation should match")

	// 验证路径参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 1, "There should be one path parameter")

	// 验证路径参数的名称和描述
	assert.Equal(t, "user-name", params[0].Data().Name, "The path parameter name should be 'user-name'")
	assert.Equal(t, "Name of the user to delete", params[0].Data().Description, "The path parameter description should match")

}

func TestListPlatformRolesRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	listPlatformRolesRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/platform-roles", route.Path, "The route path should be /platform-roles")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "List platform roles in system", route.Doc, "The route documentation should match")

}

func TestListClusterRolesRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	listClusterRolesRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/cluster-roles", route.Path, "The route path should be /cluster-roles")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "List cluster roles in system", route.Doc, "The route documentation should match")

}

func TestEditClusterRoleBindingRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	editClusterRoleBindingRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/cluster-rolebindings/{user-name}/{cluster-role}", route.Path, "The route path should be /cluster-rolebindings/{user-name}/{cluster-role}")

	// 验证 HTTP 方法是否为 PATCH
	assert.Equal(t, "PATCH", route.Method, "The route method should be PATCH")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Edit the cluster roles bindings based on user input", route.Doc, "The route documentation should match")

	// 验证路径参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 2, "There should be two path parameters")

	// 验证路径参数的名称和描述
	assert.Equal(t, "user-name", params[0].Data().Name, "The first path parameter name should be 'user-name'")
	assert.Equal(t, "Name of the user to be invited", params[0].Data().Description, "The first path parameter description should match")
	assert.Equal(t, "cluster-role", params[1].Data().Name, "The second path parameter name should be 'cluster-role'")
	assert.Equal(t, "Name of the user to mark", params[1].Data().Description, "The second path parameter description should match")

}

func TestInviteUserToCluster(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	inviteUserToCluster(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/invite-users/{user-name}/{cluster-name}/{cluster-role}", route.Path, "The route path should be /invite-users/{user-name}/{cluster-name}/{cluster-role}")

	// 验证 HTTP 方法是否为 PUT
	assert.Equal(t, "PUT", route.Method, "The route method should be PUT")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Invite user to specific cluster", route.Doc, "The route documentation should match")

	// 验证路径参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 3, "There should be three path parameters")

	// 验证路径参数的名称和描述
	assert.Equal(t, "user-name", params[0].Data().Name, "The first path parameter name should be 'user-name'")
	assert.Equal(t, "Name of the user to be invited", params[0].Data().Description, "The first path parameter description should match")
	assert.Equal(t, "cluster-name", params[1].Data().Name, "The second path parameter name should be 'cluster-name'")
	assert.Equal(t, "Invite user to which cluster", params[1].Data().Description, "The second path parameter description should match")
	assert.Equal(t, "cluster-role", params[2].Data().Name, "The third path parameter name should be 'cluster-role'")
	assert.Equal(t, "Name of the user to mark", params[2].Data().Description, "The third path parameter description should match")

}

func TestInviteUserCreateCRBRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	inviteUserCreateCRB(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/invite-user-crb/{user-name}/{cluster-role}", route.Path, "The route path should be /invite-user-crb/{user-name}/{cluster-role}")

	// 验证 HTTP 方法是否为 POST
	assert.Equal(t, "POST", route.Method, "The route method should be POST")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Invite user to specific cluster", route.Doc, "The route documentation should match")

	// 验证路径参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 2, "There should be two path parameters")

	// 验证路径参数的名称和描述
	assert.Equal(t, "user-name", params[0].Data().Name, "The first path parameter name should be 'user-name'")
	assert.Equal(t, "Name of the user to be invited", params[0].Data().Description, "The first path parameter description should match")
	assert.Equal(t, "cluster-role", params[1].Data().Name, "The second path parameter name should be 'cluster-role'")
	assert.Equal(t, "Name of the user to mark", params[1].Data().Description, "The second path parameter description should match")

}

func TestRemoveUserFromClusterRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	removeUserFromCluster(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/remove-users/{user-name}/{cluster-name}", route.Path, "The route path should be /remove-users/{user-name}/{cluster-name}")

	// 验证 HTTP 方法是否为 DELETE
	assert.Equal(t, "DELETE", route.Method, "The route method should be DELETE")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Remove a user from a specific cluster", route.Doc, "The route documentation should match")

	// 验证路径参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 2, "There should be two path parameters")

	// 验证路径参数的名称和描述
	assert.Equal(t, "user-name", params[0].Data().Name, "The first path parameter name should be 'user-name'")
	assert.Equal(t, "Name of the user to be removed", params[0].Data().Description, "The first path parameter description should match")
	assert.Equal(t, "cluster-name", params[1].Data().Name, "The second path parameter name should be 'cluster-name'")
	assert.Equal(t, "Remove user from which cluster", params[1].Data().Description, "The second path parameter description should match")

}

func TestDeleteClusterCRBRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	deleteClusterCRB(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/remove-user-crb/{user-name}", route.Path, "The route path should be /remove-user-crb/{user-name}")

	// 验证 HTTP 方法是否为 DELETE
	assert.Equal(t, "DELETE", route.Method, "The route method should be DELETE")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Remove a user from a specific cluster", route.Doc, "The route documentation should match")

	// 验证路径参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 1, "There should be one path parameter")

	// 验证路径参数的名称和描述
	assert.Equal(t, "user-name", params[0].Data().Name, "The path parameter name should be 'user-name'")
	assert.Equal(t, "Name of the user to be removed", params[0].Data().Description, "The path parameter description should match")

}

func TestEditUserDetailRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	editUserDetail(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/users/{user-name}", route.Path, "The route path should be /users/{user-name}")

	// 验证 HTTP 方法是否为 PATCH
	assert.Equal(t, "PATCH", route.Method, "The route method should be PATCH")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Edit an user information,description and platform role", route.Doc, "The route documentation should match")

}

func TestGetUserDescriptionRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	getUserDescription(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/users/{user-name}/user-descriptions", route.Path, "The route path should be /users/{user-name}/user-descriptions")

	// 验证 HTTP 方法是否为 GET
	assert.Equal(t, "GET", route.Method, "The route method should be GET")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Get an user description", route.Doc, "The route documentation should match")

}

func TestEditUserDescriptionRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	editUserDescription(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/users/{user-name}/user-descriptions", route.Path, "The route path should be /users/{user-name}/user-descriptions")

	// 验证 HTTP 方法是否为 PATCH
	assert.Equal(t, "PATCH", route.Method, "The route method should be PATCH")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "Edit an user description", route.Doc, "The route documentation should match")

}

func TestPassMessageRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	passMessage(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/request-userList", route.Path, "The route path should be /request-userList")

	// 验证 HTTP 方法是否为 POST
	assert.Equal(t, "POST", route.Method, "The route method should be POST")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "This API returns a user list info", route.Doc, "The route documentation should match")

}

func TestBroadcastRoute(t *testing.T) {
	// 模拟一个 restful.WebService
	ws := new(restful.WebService)

	// 创建一个模拟的 Handler
	handler := &Handler{}

	// 调用被测试的函数
	broadcastRoute(ws, handler)

	// 验证是否有正确注册的路由
	routes := ws.Routes()
	assert.Len(t, routes, 1, "There should be exactly one route registered")

	// 验证路径是否正确
	route := routes[0]
	assert.Equal(t, "/broadcast-users", route.Path, "The route path should be /broadcast-users")

	// 验证 HTTP 方法是否为 POST
	assert.Equal(t, "POST", route.Method, "The route method should be POST")

	// 验证是否指向了正确的处理函数
	assert.NotNil(t, route.Function, "The route handler function should not be nil")

	// 验证文档说明是否正确
	assert.Equal(t, "This API returns a user list info", route.Doc, "The route documentation should match")

	// 验证查询参数是否正确
	params := route.ParameterDocs
	assert.Len(t, params, 2, "There should be two query parameters")

	// 验证查询参数的名称和描述
	assert.Equal(t, server.Method, params[0].Data().Name, "The first query parameter name should be 'method'")
	assert.Equal(t, server.ClusterNameDescription, params[0].Data().Description, "The first query parameter description should match")
	assert.Equal(t, server.ClusterName, params[1].Data().Name, "The second query parameter name should be 'cluster-name'")
	assert.Equal(t, server.ClusterNameDescription, params[1].Data().Description, "The second query parameter description should match")

}

func TestAddLogsContainer(t *testing.T) {
	// 创建一个模拟的 restful.Container
	container := restful.NewContainer()

	// 调用被测试的函数
	err := AddLogsContainer(container)

	// 验证没有错误返回
	assert.NoError(t, err, "AddLogsContainer should not return an error")

	// 验证是否添加了 WebService 到容器中
	assert.Len(t, container.RegisteredWebServices(), 1, "There should be exactly one WebService registered")

	// 获取注册的 WebService
	webservice := container.RegisteredWebServices()[0]

	// 验证路由数量
	expectedRoutes := 20 // 确保你把所有的路由都列出来
	assert.Len(t, webservice.Routes(), expectedRoutes, "The WebService should have the correct number of routes registered")

}
