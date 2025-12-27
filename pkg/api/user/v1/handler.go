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

// Package v1 defines all user-management handlers and register them to webservices
package v1

import (
	"context"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	usersv1alpha1 "openfuyao.com/user-management/api/v1alpha1"
	usertypes "openfuyao.com/user-management/pkg/api/user/v1/types"
	"openfuyao.com/user-management/pkg/authorizers"
	"openfuyao.com/user-management/pkg/constants"
	"openfuyao.com/user-management/pkg/server"
	"openfuyao.com/user-management/pkg/tools"
	"openfuyao.com/user-management/pkg/utils/passwordutils"
	"openfuyao.com/user-management/pkg/utils/requestutils"
	"openfuyao.com/user-management/pkg/utils/responseutils"
	"openfuyao.com/user-management/pkg/utils/stringutils"
)

var openFuyaoPlatformRoles = []string{"platform-admin", "platform-regular"}

// Handler defines the main handler function
type Handler struct {
	UserClient client.Client
	K8sClient  kubernetes.Interface
}

// New initializes the handler
func New() *Handler {
	k8sClient, userClient, err := newKubernetesAPI()
	if err != nil {
		fmt.Printf("Error")
	}
	handler := &Handler{
		UserClient: userClient,
		K8sClient:  k8sClient,
	}
	return handler
}

func newKubernetesAPI() (kubernetes.Interface, client.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		fmt.Printf("Failed to get Kubernetes config: %v\n", err)
		return nil, nil, err
	}
	// 添加 User CRD 到 scheme
	usersv1alpha1.AddToScheme(scheme.Scheme)
	// 创建 controller-runtime 客户端
	userClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		fmt.Printf("Failed to create User-CR client: %v\n", err)
		return nil, nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Printf("Failed to create Kubernetes client: %v\n", err)
		return nil, nil, err
	}
	return clientset, userClient, nil
}

func (h *Handler) editRoleBinding(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to edit cluster rolebindings", nil)
		return
	}
	userName := request.PathParameter("user-name")
	clusterRole := request.PathParameter("cluster-role")
	tgtCRB, err := h.findRoleBindingForSpecificUser(userName, "cluster-role")
	if err != nil {
		responseutils.HandleError(response, "Get clusterRoleBinding failed. User client internal error", err)
		return
	}
	if tgtCRB != nil {
		if stringutils.TrimOpenFuyaoRolePrefix(tgtCRB.RoleRef.Name) == clusterRole {
			responseutils.WriteSuccessResponse("No changes needed, CRB is already set correctly", tgtCRB, response)
			return
		}
		// 删除当前的 ClusterRoleBinding
		err = h.K8sClient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), tgtCRB.Name, metav1.DeleteOptions{})
		if err != nil {
			responseutils.HandleError(response, "The original roleBinding deletion is failed", err)
			return
		}
	}
	newCRB := prepareClusterRoleBinding(userName, clusterRole, "cluster-role")
	succeed, err := h.safelyCreateCRBByClientGo(newCRB)
	if !succeed {
		responseutils.HandleError(response, "Error occurs in creating new roleBinding", err)
		return
	}
	responseutils.WriteSuccessResponse("Edit successes", newCRB, response)
}

func (h *Handler) createUser(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to create users", nil)
		return
	}
	var userReq usertypes.UserCreateRequest
	if err := request.ReadEntity(&userReq); err != nil {
		responseutils.HandleError(response, "Entity reading error", err)
		return
	}
	encryptedPassword := h.preCreateSteps(userReq, response)
	if encryptedPassword == nil {
		return
	}
	if stringutils.StringInSlice(userReq.PlatformRole, openFuyaoPlatformRoles) {
		newCRB := prepareClusterRoleBinding(userReq.Username, userReq.PlatformRole, "platform-role")
		succeed, err := h.safelyCreateCRBByClientGo(newCRB)
		if !succeed {
			responseutils.HandleError(response, "Error occurs in creating new roleBinding. K8s internal error", err)
			return
		}
		tools.LogInfo("Platform-admin bound to user: ", userReq.Username)
	} else {
		responseutils.HandleError(response, "Wrong platform role input", fmt.Errorf("wrong parameter input"))
		return
	}
	user := prepareUserInstance(userReq, encryptedPassword, userReq.PlatformRole)

	// broadcast to all other clusters
	// first get all clusters
	clusterNameList, err := getAllAvailableClusters(request)
	if err != nil {
		tools.FormatError("Broadcast platform-admin to all clusters failed, %v", err)
	}
	if !createPlatfromCRBByClusters(request, response, clusterNameList, user) {
		responseutils.HandleError(response, "Create CRB on member clusters failed", nil)
		return
	}
	err = h.UserClient.Create(context.Background(), user)
	if err != nil {
		responseutils.HandleError(response, "Create operation failed. User client internal error", err)
		return
	}

	if h.isServiceAvailable(constants.MultiClusterService, constants.MultiClusterNamespace) {
		err = h.userListPostAPI()
		if err != nil {
			responseutils.HandleError(response, "POST info to multi-cluster service failed.", err)
			return
		}
	}
	visibleResult := filterUserSpec(user.Spec)
	responseutils.WriteSuccessResponse("User created successfully", visibleResult, response)
}

func (h *Handler) preCreateSteps(userReq usertypes.UserCreateRequest, response *restful.Response) []byte {
	if userReq.Username == "" {
		responseutils.HandleError(response, "Please enter a valid username", nil)
		return nil
	}
	if !validateUserName(userReq.Username) {
		responseutils.HandleError(response, "用户名不符合规范", nil)
		return nil
	}
	reqUser := &usersv1alpha1.User{}
	err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: userReq.Username}, reqUser)
	if err == nil {
		responseutils.HandleError(response, "该用户名已存在", err)
		return nil
	}
	passwordCheck, err := passwordutils.CheckPasswordComplexity(userReq.Username, userReq.UnEncryptedPassword)
	if !passwordCheck {
		responseutils.HandleError(response, "Invalid input password format", err)
		return nil
	}
	encryptedPassword, err := passwordutils.EncryptPassword(userReq.UnEncryptedPassword)
	if err != nil {
		responseutils.HandleError(response, "Error occurred in Encrypting password", nil)
		return nil
	}
	return encryptedPassword
}

func (h *Handler) listPlatformUser(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to list platform users", nil)
		return
	}
	userList := &usersv1alpha1.UserList{}
	keyword := server.GetQueryParamOrDefault(request, server.UserKeyword, "")
	if err := h.UserClient.List(context.Background(), userList, &client.ListOptions{}); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	var platformUsers []usertypes.UserReturnListPlatform
	for _, user := range userList.Items {
		simplifiedUser := usertypes.UserReturnListPlatform{
			Username:     user.Spec.Username,
			PlatformRole: user.Spec.PlatformRole,
			Description:  user.Spec.Description,
		}
		platformUsers = append(platformUsers, simplifiedUser)
	}
	if keyword != "" {
		filteredResult := searchUsersByKeyword(platformUsers, keyword)
		responseutils.WriteSuccessResponse("Platform users listed successfully", filteredResult, response)
		return
	}
	responseutils.WriteSuccessResponse("Platform users listed successfully", platformUsers, response)
}

func (h *Handler) findRoleBindingForSpecificUser(username string,
	roleLabel string) (*rbacv1.ClusterRoleBinding, error) {
	listOptions := metav1.ListOptions{LabelSelector: fmt.Sprintf("role-type=%s", roleLabel)}
	clusterRoles, err := h.K8sClient.RbacV1().ClusterRoleBindings().List(context.TODO(), listOptions)

	if err != nil {
		return nil, fmt.Errorf("can not get clusterRoleBindings")
	}
	var existingRoleBinding *rbacv1.ClusterRoleBinding
	for _, rb := range clusterRoles.Items {
		for _, subject := range rb.Subjects {
			if subject.Kind == "User" && subject.Name == username {
				existingRoleBinding = rb.DeepCopy()
				return existingRoleBinding, nil
			}
		}
	}
	return nil, fmt.Errorf("user %s has no role in cluster", username)
}

func (h *Handler) listClusterUser(request *restful.Request, response *restful.Response) {
	userParam := server.GetQueryParamOrDefault(request, server.UserKeyword, "")
	clusterParam := server.GetQueryParamOrDefault(request, server.ClusterName, "host")
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, clusterParam, admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to list cluster members", nil)
		return
	}

	userList := &usersv1alpha1.UserList{}
	if err := h.UserClient.List(context.Background(), userList, &client.ListOptions{}); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	var clusterUsers []usertypes.UserReturnListCluster
	for _, user := range userList.Items {
		if stringutils.CaseInsensitiveContains(user.Spec.InvitedByClustersList, clusterParam) {
			cr, err := getClusterRoleByConsoleService(request.Request, clusterParam, user.Name)
			if err != nil {
				cr = ""
			}
			simplifiedUser := usertypes.UserReturnListCluster{
				Username:    user.Spec.Username,
				ClusterRole: stringutils.TrimOpenFuyaoRolePrefix(cr),
			}
			clusterUsers = append(clusterUsers, simplifiedUser)
		}
	}
	if userParam != "" {
		filteredResult := searchUsersByKeyword(clusterUsers, userParam)
		responseutils.WriteSuccessResponse("Cluster-members fetched successfully", filteredResult, response)
		return
	}
	responseutils.WriteSuccessResponse("Cluster-members fetched successfully", clusterUsers, response)
}

func (h *Handler) getClusterRoleBindingsForUser(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin", "cluster-editor", "cluster-viewer", "platform-regular"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to get clusterrole for user", nil)
		return
	}
	userParam := server.GetQueryParamOrDefault(request, server.UserKeyword, "")
	crb, err := h.findRoleBindingForSpecificUser(userParam, "cluster-role")
	if err != nil {
		tools.FormatError("get crb failed, err: %v", err)
		responseutils.HandleError(response, "Could not find ClusterRoleBinding for this user", err)
		return
	}
	responseutils.WriteSuccessResponse("Clusterrolebinding fetched successfully", crb, response)
}

func (h *Handler) getUserDetail(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin", "cluster-editor", "cluster-viewer", "platform-regular"}
	userName := request.PathParameter("user-name")
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) ||
		authorizers.HorizontalAuthorizationCheck(request.Request, userName, h.UserClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to get user details", nil)
		return
	}
	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	userDetail := usertypes.UserDetailResponse{
		Username:     user.Spec.Username,
		Description:  user.Spec.Description,
		PlatformRole: user.Spec.PlatformRole,
	}
	// get clusterrolemap for each user
	clusterToRoleMap := make(map[string]string)
	for _, cluster := range user.Spec.InvitedByClustersList {
		cr, err := getClusterRoleByConsoleService(request.Request, cluster, userName)
		if err != nil {
			cr = ""
		}
		if cr != "" {
			clusterToRoleMap[cluster] = stringutils.TrimOpenFuyaoRolePrefix(cr)
		}
	}
	userDetail.InvitedByClustersMap = clusterToRoleMap
	responseutils.WriteSuccessResponse("User detail get sucessfully", userDetail, response)
}

func (h *Handler) broadcastToAllPlatformAdmins(request *restful.Request, response *restful.Response) {
	clusterName := server.GetQueryParamOrDefault(request, server.ClusterName, "host")
	method := server.GetQueryParamOrDefault(request, server.Method, "")
	if method != "join" && method != "unjoin" {
		responseutils.HandleError(response, "Unable to read input method", fmt.Errorf("invalid input parameter"))
		return
	}
	userList := &usersv1alpha1.UserList{}
	if err := h.UserClient.List(context.TODO(), userList, &client.ListOptions{}); err != nil {
		responseutils.HandleError(response, "Failed to list User instances", err)
		return
	}
	if method == "join" {
		// handle join logic
		collection := extractUserInfoCollections(userList)
		responseutils.WriteRawSuccessResponse(collection, response)
		return
	}
	// handle unjoin logic
	// remove cluster-rolebinding
	for _, user := range userList.Items {
		newUser := user.DeepCopy()
		if !stringutils.CaseInsensitiveContains(newUser.Spec.InvitedByClustersList, clusterName) {
			continue
		}
		url := requestutils.PrepareUserMgmtRequestURL(clusterName, fmt.Sprintf("/remove-user-crb/%s", newUser.Name))
		_, err := requestutils.DoUserManagementRequest(url, "DELETE", request.Request, nil)
		if err != nil {
			responseutils.HandleError(response, "The original CRB deletion fail", fmt.Errorf("rbac client error"))
			return
		}
		newClusterList := stringutils.RemoveStringFromList(clusterName, newUser.Spec.InvitedByClustersList)
		newUser.Spec.InvitedByClustersList = newClusterList
		if err := h.UserClient.Update(context.Background(), newUser); err != nil {
			responseutils.HandleError(response, fmt.Sprintf("Failed to update user: %s", newUser.Name), err)
			return
		}
		tools.FormatInfo("broadcast delete CRB for user %s on %s when unjoin succeed", newUser.Name, clusterName)
	}
	if err := h.UserClient.List(context.TODO(), userList, &client.ListOptions{}); err != nil {
		responseutils.HandleError(response, "Failed to list User instances", err)
		return
	}
	if h.isServiceAvailable(constants.MultiClusterService, constants.MultiClusterNamespace) {
		err := h.userListPostAPI()
		if err != nil {
			responseutils.HandleError(response, "POST information to multi-cluster service failed.", err)
			return
		}
	}
	collection := extractUserInfoCollections(userList)
	responseutils.WriteRawSuccessResponse(collection, response)
}

func (h *Handler) inviteUserList(request *restful.Request, response *restful.Response) {
	clusterParam := server.GetQueryParamOrDefault(request, server.ClusterName, "host")
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, clusterParam, admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response,
			"current user is unauthorized to list uninvited users for this cluster", nil)
		return
	}
	userList := &usersv1alpha1.UserList{}
	if err := h.UserClient.List(context.Background(), userList, &client.ListOptions{}); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	var simplifiedUsers []usertypes.UserInvitedListSimplified
	for _, user := range userList.Items {
		if stringutils.CaseInsensitiveNotContains(user.Spec.InvitedByClustersList, clusterParam) {
			simplifiedUser := usertypes.UserInvitedListSimplified{
				Username:    user.Spec.Username,
				Description: user.Spec.Description,
			}
			simplifiedUsers = append(simplifiedUsers, simplifiedUser)
		}
	}
	responseutils.WriteSuccessResponse("User invites list get successful", simplifiedUsers, response)
}

func (h *Handler) deleteUser(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin"}
	userName := request.PathParameter("user-name")
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) ||
		authorizers.CheckDangerousOperation(request.Request, userName) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to delete users", nil)
		return
	}
	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	oldRB, err := h.findRoleBindingForSpecificUser(user.Spec.Username, "platform-role")
	if err != nil {
		tools.FormatError("Cannot find the related platform-role to delete, continue deleting the user")
	} else {
		err = h.K8sClient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), oldRB.Name, metav1.DeleteOptions{})
		if err != nil {
			tools.FormatError("The original roleBinding deletion is failed, continue deleting the user, err: %v", err)
		}
	}

	for _, cluster := range user.Spec.InvitedByClustersList {
		url := requestutils.PrepareUserMgmtRequestURL(cluster, fmt.Sprintf("/remove-user-crb/%s", userName))
		_, err := requestutils.DoUserManagementRequest(url, "DELETE", request.Request, nil)
		if err != nil {
			responseutils.HandleError(response, fmt.Sprintf("Del CRB fail on %s fail for %s", cluster, userName), err)
			return
		}
	}
	// broadcast to all other clusters
	// first get all clusters
	clusterNameList, err := getAllAvailableClusters(request)
	if err != nil {
		tools.FormatError("Broadcast platform-admin to all clusters failed, %v", err)
	}
	// send safelyCreateInstructions one by one
	for _, clusterName := range clusterNameList {
		deletePlatformCRBAccrossClusters(request, user.Name, clusterName, user.Spec.PlatformRole)
	}
	if err := h.UserClient.Delete(context.Background(), user); err != nil {
		responseutils.HandleError(response, "Failed to delete user: "+userName, err)
		return
	}
	if h.isServiceAvailable(constants.MultiClusterService, constants.MultiClusterNamespace) {
		err := h.userListPostAPI()
		if err != nil {
			responseutils.HandleError(response, "POST information to multi-cluster service failed.", err)
			return
		}
	}
	filtered := filterUserSpec(user.Spec)
	responseutils.WriteSuccessResponse("Delete user and its CRB on its clusters succeed", filtered, response)
}

func (h *Handler) listPlatformRoles(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to list platform roles", nil)
		return
	}
	listOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("role-type=platform-role"),
	}
	clusterRoles, err := h.K8sClient.RbacV1().ClusterRoles().List(context.TODO(), listOptions)
	if err != nil {
		responseutils.HandleError(response, "Error occurs in fetching cluster role resource",
			fmt.Errorf("internel error"))
		return
	}
	clusterRoleList := stringutils.TrimOpenFuyaoRoleListPrefix(clusterRoles.Items)
	responseutils.WriteSuccessResponse("Platform-Roles fetched successfully", clusterRoleList, response)
}

func (h *Handler) listClusterRoles(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin", "cluster-editor", "cluster-viewer", "platform-regular"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to get list cluster roles", nil)
		return
	}
	listOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("role-type=cluster-role"),
	}
	clusterRoles, err := h.K8sClient.RbacV1().ClusterRoles().List(context.TODO(), listOptions)
	if err != nil {
		responseutils.HandleError(response, "Error occurs in fetching cluster role resource",
			fmt.Errorf("internel error"))
		return
	}
	clusterRoleList := stringutils.TrimOpenFuyaoRoleListPrefix(clusterRoles.Items)
	responseutils.WriteSuccessResponse("Cluster-Roles fetched successfully", clusterRoleList, response)
}

func (h *Handler) getUserDescription(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin", "cluster-editor", "cluster-viewer", "platform-regular"}
	userName := request.PathParameter("user-name")
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) ||
		authorizers.HorizontalAuthorizationCheck(request.Request, userName, h.UserClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to get user descriptions", nil)
		return
	}
	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	visibleResult := filterUserSpecForDescription(user.Spec)
	responseutils.WriteSuccessResponse("Get user description succeeds", visibleResult, response)
}

func (h *Handler) editUserDescription(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin", "cluster-editor", "cluster-viewer", "platform-regular"}
	userName := request.PathParameter("user-name")
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) ||
		authorizers.HorizontalAuthorizationCheck(request.Request, userName, h.UserClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to edit user descriptions", nil)
		return
	}
	var editReq usertypes.UserDescription
	if err := request.ReadEntity(&editReq); err != nil {
		responseutils.HandleError(response, "Entity reading error", err)
		return
	}
	if userName != editReq.Username {
		tools.FormatWarn("path-user %s and struct-user %s doesn't match, use struct-user", userName, editReq.Username)
	}
	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: editReq.Username}, user); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	user.Spec.Description = editReq.Description
	if err := h.UserClient.Update(context.Background(), user); err != nil {
		responseutils.HandleError(response, fmt.Sprintf("Failed to update user: %s", user.Spec.Username), err)
		return
	}
	visibleResult := filterUserSpecForDescription(user.Spec)
	responseutils.WriteSuccessResponse("Edit user description succeeds", visibleResult, response)
}

func (h *Handler) editUserDetail(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to edit user details", nil)
		return
	}
	var editReq usertypes.UserEdition
	userName := request.PathParameter("user-name")
	if err := request.ReadEntity(&editReq); err != nil {
		responseutils.HandleError(response, "Entity reading error", err)
		return
	}
	if userName != editReq.Username {
		tools.FormatWarn("path-user %s and patched struct-user %s does not match, use struct-user",
			userName, editReq.Username)
	}
	if authorizers.CheckDangerousOperation(request.Request, userName) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to edit user", nil)
		return
	}
	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: editReq.Username}, user); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	if editReq.PlatformRole != user.Spec.PlatformRole {
		err := h.modifyPlatformRoleBinding(request, response, user, editReq)
		if err != nil {
			responseutils.HandleError(response, err.Error(), err)
			return
		}
	}
	user.Spec.Description = editReq.Description
	if err := h.UserClient.Update(context.Background(), user); err != nil {
		responseutils.HandleError(response, fmt.Sprintf("Failed to update user: %s", user.Spec.Username), err)
		return
	}
	if h.isServiceAvailable(constants.MultiClusterService, constants.MultiClusterNamespace) {
		err := h.userListPostAPI()
		if err != nil {
			responseutils.HandleError(response, "POST information to multi-cluster service failed.", err)
			return
		}
	}
	visibleResult := filterUserSpec(user.Spec)
	responseutils.WriteSuccessResponse("Edit successes", visibleResult, response)
}

func (h *Handler) modifyPlatformRoleBinding(request *restful.Request, response *restful.Response,
	user *usersv1alpha1.User, editReq usertypes.UserEdition) error {
	oldRB, err := h.findRoleBindingForSpecificUser(user.Spec.Username, "platform-role")
	if err != nil {
		tools.FormatWarn("Cannot find the related platform-role, skip deleting the platform-role and " +
			"continue creating the new platform-role")
	} else {
		err = h.K8sClient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), oldRB.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("cannot delete old CRB when modify platformRB")
		}

	}
	newCRB := prepareClusterRoleBinding(editReq.Username, editReq.PlatformRole, "platform-role")
	succeed, err := h.safelyCreateCRBByClientGo(newCRB)
	if !succeed {
		return fmt.Errorf("error occurs in creating new roleBinding")
	}
	// update platform crb in all other clusters
	clusterList, err := getAllAvailableClusters(request)
	if err != nil {
		tools.FormatError("Broadcast platform-admin to all clusters failed, %v", err)
	}
	// send safelyCreateInstructions one by one
	for _, clusterName := range clusterList {
		if clusterName == "host" {
			continue
		}
		deletePlatformCRBAccrossClusters(request, user.Name, clusterName, user.Spec.PlatformRole)
		if !createPlatformCRBAccrossClusters(request, response, user.Name, clusterName, editReq.PlatformRole) {
			tools.FormatError("Broadcast platform-role to all clusters fail, cannot create crb on other clusters")
		}
	}
	user.Spec.PlatformRole = editReq.PlatformRole
	return nil
}

func (h *Handler) inviteUser(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter("user-name")
	clusterName := request.PathParameter("cluster-name")
	clusterRole := request.PathParameter("cluster-role")
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, clusterName, admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to invite user to cluster", nil)
		return
	}

	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	if stringutils.StringInSlice(clusterName, user.Spec.InvitedByClustersList) {
		responseutils.HandleError(response, "The user is already invited in given cluster",
			fmt.Errorf("wrong input parameter"))
		return
	}

	// modify the clusterrolebinding in the target cluster
	url := requestutils.PrepareUserMgmtRequestURL(clusterName,
		fmt.Sprintf("/invite-user-crb/%s/%s", userName, clusterRole))
	resp, err := requestutils.DoUserManagementRequest(url, "POST", request.Request, nil)
	if err != nil || resp.Code == http.StatusNotFound {
		responseutils.HandleError(response, fmt.Sprintf("cannot create CRB on cluster %s", clusterName), err)
		return
	}

	user.Spec.InvitedByClustersList = append(user.Spec.InvitedByClustersList, clusterName)
	if err := h.UserClient.Update(context.Background(), user); err != nil {
		responseutils.HandleError(response, fmt.Sprintf("Fail to update user: %s", user.Spec.Username), err)
		return
	}
	if h.isServiceAvailable(constants.MultiClusterService, constants.MultiClusterNamespace) {
		err = h.userListPostAPI()
		if err != nil {
			responseutils.HandleError(response, "POST information to multi-cluster service failed.", err)
			return
		}
	}
	visibleResult := filterUserSpec(user.Spec)
	responseutils.WriteSuccessResponse("Invited successes", visibleResult, response)
}

func (h *Handler) createClusterCRB(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to create CRBs", nil)
		return
	}
	userName := request.PathParameter("user-name")
	clusterRole := request.PathParameter("cluster-role")
	newCRB := prepareClusterRoleBinding(userName, clusterRole, "cluster-role")
	succeed, err := h.safelyCreateCRBByClientGo(newCRB)
	if !succeed {
		responseutils.HandleError(response, "Error occurs in creating new roleBinding", err)
		return
	}
	responseutils.WriteSuccessResponse("Create invited CRB succeeds", newCRB, response)
}

func (h *Handler) safelyCreateCRBByClientGo(newCRB *rbacv1.ClusterRoleBinding) (bool, error) {
	if oriCRB, err := h.K8sClient.RbacV1().ClusterRoleBindings().Get(
		context.Background(), newCRB.Name, metav1.GetOptions{}); err == nil {
		newCRB.ResourceVersion = oriCRB.ResourceVersion
		if _, err = h.K8sClient.RbacV1().ClusterRoleBindings().Update(
			context.Background(), newCRB, metav1.UpdateOptions{}); err == nil {
			return true, nil
		} else {
			return false, err
		}
	}
	_, err := h.K8sClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), newCRB, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (h *Handler) removeUser(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter("user-name")
	clusterName := request.PathParameter("cluster-name")
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, clusterName, admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to remove user from cluster", nil)
		return
	}
	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	if !stringutils.StringInSlice(clusterName, user.Spec.InvitedByClustersList) {
		responseutils.HandleError(response, "The user is not invited in given cluster",
			fmt.Errorf("wrong input parameter"))
		return
	}

	// proxy to member cluster to delete cluster-rolebinding
	url := requestutils.PrepareUserMgmtRequestURL(clusterName, fmt.Sprintf("/remove-user-crb/%s", userName))
	_, err := requestutils.DoUserManagementRequest(url, "DELETE", request.Request, nil)
	if err != nil {
		responseutils.HandleError(response, "The original roleBinding deletion is failed",
			fmt.Errorf("rbac client error"))
		return
	}

	var newClusterList []string
	for _, cluster := range user.Spec.InvitedByClustersList {
		if cluster != clusterName {
			newClusterList = append(newClusterList, cluster)
		}
	}
	user.Spec.InvitedByClustersList = newClusterList
	if err := h.UserClient.Update(context.Background(), user); err != nil {
		responseutils.HandleError(response, fmt.Sprintf("Failed to update user: %s", user.Spec.Username), err)
		return
	}
	if h.isServiceAvailable(constants.MultiClusterService, constants.MultiClusterNamespace) {
		err = h.userListPostAPI()
		if err != nil {
			responseutils.HandleError(response, "POST information to multi-cluster service fail.", err)
			return
		}
	}
	visibleResult := filterUserSpec(user.Spec)
	responseutils.WriteSuccessResponse("Remove user from cluster succeeds", visibleResult, response)
}

func (h *Handler) deleteClusterCRB(request *restful.Request, response *restful.Response) {
	admittedRoles := []string{"platform-admin", "cluster-admin"}
	if !authorizers.AuthorizeByAdmittedRoles(request.Request, "", admittedRoles, h.K8sClient) {
		responseutils.HandleNotAuthorized(response, "current user is unauthorized to delete CRBs", nil)
		return
	}
	userName := request.PathParameter("user-name")
	targetClusterRoleBinding, err := h.findRoleBindingForSpecificUser(userName, "cluster-role")
	if err != nil {
		responseutils.HandleError(response, "Get clusterRoleBinding failed. User client internal error", err)
		return
	}
	err = h.K8sClient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), targetClusterRoleBinding.Name,
		metav1.DeleteOptions{})
	if err != nil {
		responseutils.HandleError(response, "The original roleBinding deletion is failed",
			fmt.Errorf("rbac client error"))
		return
	}
	responseutils.WriteSuccessResponse("Delete cluster CRB succeeds", nil, response)
}

func (h *Handler) passUserMessage(request *restful.Request, response *restful.Response) {
	userList := &usersv1alpha1.UserList{}
	if err := h.UserClient.List(context.Background(), userList, &client.ListOptions{}); err != nil {
		responseutils.HandleError(response, "Get operation failed. User client internal error", err)
		return
	}
	collection := extractUserInfoCollections(userList)
	err := sendUserListToMulticlusterService(*collection)
	if err != nil {
		tools.LogError("send POST request failed", err)
		responseutils.HandleError(response, "send POST request failed", err)
		return
	}
	tools.FormatInfo("in passUserMessage successfully send collections %v to multicluster-service", *collection)
	responseutils.WriteSuccessResponse("Pass user message successes", collection, response)
}

// service name: multicluster-service. namespace name default
func (h *Handler) isServiceAvailable(serviceName, namespace string) bool {
	svc, err := h.K8sClient.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		tools.FormatInfo("Service %s in namespace %s is not available: %v", serviceName, namespace, err)
		return false
	}
	// 检查服务是否有至少一个可用的端点
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		tools.FormatInfo("Service %s in namespace %s does not have a valid ClusterIP", serviceName, namespace)
		return false
	}

	tools.FormatInfo("Service %s in namespace %s is available", serviceName, namespace)
	return true
}

func (h *Handler) userListPostAPI() error {
	userList := &usersv1alpha1.UserList{}
	if err := h.UserClient.List(context.Background(), userList, &client.ListOptions{}); err != nil {
		tools.FormatError("Get operation failed. User client internal error, err: %v", err)
		return err
	}
	collection := extractUserInfoCollections(userList)
	err := sendUserListToMulticlusterService(*collection)
	if err != nil {
		tools.FormatError("send POST request failed, err: %v", err)
		return err
	}
	return nil
}

func (h *Handler) checkUserMainPageAccessPermission(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter("user-name")
	user := &usersv1alpha1.User{}
	if err := h.UserClient.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
		responseutils.HandleError(response, "The user does not exist", err)
		return
	}
	if user.Spec.PlatformRole == "platform-admin" {
		responseutils.WriteSuccessResponse("user has permission to access main page", "succeed", response)
		return
	}
	if user.Spec.PlatformRole == "platform-regular" && len(user.Spec.InvitedByClustersList) > 0 {
		responseutils.WriteSuccessResponse("user has permission to access main page", "succeed", response)
		return
	}
	responseutils.HandleNotAuthorized(response, "user is not authorized to access main page", nil)
	return
}
