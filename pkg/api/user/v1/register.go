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
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"openfuyao.com/user-management/pkg/api/user/v1/types"
	"openfuyao.com/user-management/pkg/server"
)

const (
	groupName = "user"
)

// GroupVersion defines the API group and version for the logging service.
var groupVersion = schema.GroupVersion{Group: groupName, Version: "v1"}

// 创建平台用户，平台行为
func createUserRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.POST("/users").
		To(handler.createUser).
		Deprecate().
		Doc("Return total file name list").
		Reads(types.UserCreateRequest{}).
		Returns(http.StatusOK, "User created successfully", nil).
		Returns(http.StatusBadRequest, "Invalid user parameters", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 列出全部的平台用户，平台行为
func listPlatformUserRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/users").
		To(handler.listPlatformUser).
		Deprecate().
		Doc("Return total user list on platform").
		Param(webservice.QueryParameter(server.UserKeyword, server.KeywordNameDescription)).
		Returns(http.StatusOK, "User listed successfully", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 列出某个集群上的全部用户，平台接口，根据user cr获取某个集群上的已邀请的用户列表
func listClusterUserRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/cluster-members").
		To(handler.listClusterUser).
		Deprecate().
		Doc("Return total user list on specific cluster").
		Param(webservice.QueryParameter(server.ClusterName, server.ClusterNameDescription)).
		Param(webservice.QueryParameter(server.UserKeyword, server.KeywordNameDescription)).
		Returns(http.StatusOK, "User listed successfully", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 通过username获取其对应的clusterrolebinding
func getClusterRoleBindingsForUserRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/cluster-rolebindings").
		To(handler.getClusterRoleBindingsForUser).
		Deprecate().
		Reads(types.UserClusterRoleList{}).
		Doc("Return specific role binding for user").
		Param(webservice.QueryParameter(server.UserKeyword, server.KeywordNameDescription)).
		Returns(http.StatusOK, "Clusterrolebinding get successfully", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 获取用户详情
func getUserDetailRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/users/{user-name}").
		To(handler.getUserDetail).
		Deprecate().
		Doc("Return total user list on platform").
		Param(webservice.PathParameter("user-name", "Name of user detail to get")).
		Returns(http.StatusOK, "User details read successfully", nil).
		Returns(http.StatusBadRequest, "Invalid user name", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 列出当前可以被邀请到某个集群的用户列表（即，目前没有被邀请到当前集群的全部用户）
func inviteUserListRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/invite-users").
		To(handler.inviteUserList).
		Deprecate().
		Doc("Invitable user list of a cluster").
		Param(webservice.QueryParameter(server.ClusterName, server.ClusterNameDescription)).
		Returns(http.StatusOK, "User listed successfully", nil).
		Returns(http.StatusBadRequest, "Invalid user name", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 平台删除用户时返回InvitedByCluster列表，然后前台依次前往各个集群删除ClusterRoleBinding
// 调用平台该接口之后，前台根据返回的列表前往各个集群中调用deleteClusterCRB接口
func deleteUserRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.DELETE("/users/{user-name}").
		To(handler.deleteUser).
		Deprecate().
		Doc("Delete a specific user").
		Param(webservice.PathParameter("user-name", "Name of the user to delete")).
		Returns(http.StatusOK, "User deleted successfully", nil).
		Returns(http.StatusBadRequest, "Invalid user name", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 列出全部平台角色接口
func listPlatformRolesRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/platform-roles").
		To(handler.listPlatformRoles).
		Deprecate().
		Doc("List platform roles in system").
		Returns(http.StatusOK, "Roles listed successfully", nil).
		Returns(http.StatusBadRequest, "Invalid role type", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 列出全部集群角色接口
func listClusterRolesRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/cluster-roles").
		To(handler.listClusterRoles).
		Deprecate().
		Doc("List cluster roles in system").
		Returns(http.StatusOK, "Roles listed successfully", nil).
		Returns(http.StatusBadRequest, "Invalid role type", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 修改集群上某个用户的CRB接口，集群侧操作
func editClusterRoleBindingRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.PATCH("/cluster-rolebindings/{user-name}/{cluster-role}").
		To(handler.editRoleBinding).
		Deprecate().
		Doc("Edit the cluster roles bindings based on user input").
		Param(webservice.PathParameter("user-name", "Name of the user to be invited")).
		Param(webservice.PathParameter("cluster-role", "Name of the user to mark")).
		Returns(http.StatusOK, "Role binding modified successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input body parameters ", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))

}

// 邀请用户到集群
func inviteUserToCluster(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.PUT("/invite-users/{user-name}/{cluster-name}/{cluster-role}").
		To(handler.inviteUser).
		Deprecate().
		Doc("Invite user to specific cluster").
		Param(webservice.PathParameter("user-name", "Name of the user to be invited")).
		Param(webservice.PathParameter("cluster-name", "Invite user to which cluster")).
		Param(webservice.PathParameter("cluster-role", "Name of the user to mark")).
		Returns(http.StatusOK, "User invited successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input parameter format", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))

}

// 邀请用户到集群，集群侧操作，创建用户CRB
func inviteUserCreateCRB(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.POST("/invite-user-crb/{user-name}/{cluster-role}").
		To(handler.createClusterCRB).
		Deprecate().
		Doc("Invite user to specific cluster").
		Param(webservice.PathParameter("user-name", "Name of the user to be invited")).
		Param(webservice.PathParameter("cluster-role", "Name of the user to mark")).
		Returns(http.StatusOK, "User invited successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input parameter format", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 移除集群中用户接口
func removeUserFromCluster(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.DELETE("/remove-users/{user-name}/{cluster-name}").
		To(handler.removeUser).
		Deprecate().
		Doc("Remove a user from a specific cluster").
		Param(webservice.PathParameter("user-name", "Name of the user to be removed")).
		Param(webservice.PathParameter("cluster-name", "Remove user from which cluster")).
		Returns(http.StatusOK, "User removed successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input parameter format", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 移除集群中用户接口，集群侧操作，删除用户CRB
func deleteClusterCRB(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.DELETE("/remove-user-crb/{user-name}").
		To(handler.deleteClusterCRB).
		Deprecate().
		Doc("Remove a user from a specific cluster").
		Param(webservice.PathParameter("user-name", "Name of the user to be removed")).
		Returns(http.StatusOK, "User removed successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input parameter format", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// 修改用户详情以及平台角色绑定，平台侧操作
func editUserDetail(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.PATCH("/users/{user-name}").
		To(handler.editUserDetail).
		Deprecate().
		Doc("Edit an user information,description and platform role").
		Reads(types.UserEdition{}).
		Returns(http.StatusOK, "User description modified successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input body parameters ", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

func getUserDescription(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/users/{user-name}/user-descriptions").
		To(handler.getUserDescription).
		Deprecate().
		Doc("Get an user description").
		Returns(http.StatusOK, "User description modified successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input body parameters ", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

func editUserDescription(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.PATCH("/users/{user-name}/user-descriptions").
		To(handler.editUserDescription).
		Deprecate().
		Doc("Edit an user description").
		Reads(types.UserDescription{}).
		Returns(http.StatusOK, "User description modified successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input body parameters ", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

func passMessage(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.POST("/request-userList").
		To(handler.passUserMessage).
		Deprecate().
		Doc("This API returns a user list info").
		Returns(http.StatusOK, "User message pass successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input body parameters ", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

func broadcastRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.POST("/broadcast-users").
		To(handler.broadcastToAllPlatformAdmins).
		Deprecate().
		Doc("This API returns a user list info").
		Param(webservice.QueryParameter(server.Method, server.ClusterNameDescription)).
		Param(webservice.QueryParameter(server.ClusterName, server.ClusterNameDescription)).
		Returns(http.StatusOK, "Broadcasting users successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input body parameters ", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

func checkUserAccessPermissionJRoute(webservice *restful.WebService, handler *Handler) {
	webservice.Route(webservice.GET("/users/{user-name}/check-permission").
		To(handler.checkUserMainPageAccessPermission).
		Deprecate().
		Doc("This API returns a whether user has permission to access main page").
		Returns(http.StatusOK, "Check user permission successfully", nil).
		Returns(http.StatusBadRequest, "Invalid input body parameters ", nil).
		Returns(http.StatusInternalServerError, "Internal server error", nil))
}

// AddLogsContainer registers all handler to webservice
func AddLogsContainer(c *restful.Container) error {
	webservice := server.NewWebService(groupVersion)
	handler := New()
	createUserRoute(webservice, handler)        // tested platform-admin
	getUserDetailRoute(webservice, handler)     // tested regular
	editUserDetail(webservice, handler)         // tested? platform-admin
	listPlatformUserRoute(webservice, handler)  // tested platform-admin
	listClusterUserRoute(webservice, handler)   // tested
	deleteUserRoute(webservice, handler)        // tested platform-admin
	listPlatformRolesRoute(webservice, handler) // tested platform-admin

	listClusterRolesRoute(webservice, handler)       // tested regular
	inviteUserListRoute(webservice, handler)         // tested platform-admin
	editClusterRoleBindingRoute(webservice, handler) // tested cluster-admin
	inviteUserToCluster(webservice, handler)         // tested platform-admin
	removeUserFromCluster(webservice, handler)       // tested platform-admin

	inviteUserCreateCRB(webservice, handler)                // tested cluster-admin
	deleteClusterCRB(webservice, handler)                   // tested cluster-admin
	getClusterRoleBindingsForUserRoute(webservice, handler) // tested regular

	getUserDescription(webservice, handler)  // regular
	editUserDescription(webservice, handler) // regular
	passMessage(webservice, handler)
	broadcastRoute(webservice, handler)
	checkUserAccessPermissionJRoute(webservice, handler)
	c.Add(webservice)
	return nil
}
