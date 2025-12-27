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

// Package types defines user types used in user-management apis
package types

import (
	"hash"
)

// UserCreateRequest defines user create request schema
type UserCreateRequest struct {
	Username            string `json:"Username" binding:"required"`
	UnEncryptedPassword []byte `json:"UnEncryptedPassword" binding:"required"`
	Description         string `json:"Description,omitempty"`
	PlatformRole        string `json:"PlatformRole,omitempty"`
}

// EditRoleBindingStruct defines edit role binding schema
type EditRoleBindingStruct struct {
	Username    string `json:"Username" binding:"required"`
	ClusterName string `json:"ClusterName,omitempty"`
	ClusterRole string `json:"ClusterRole,omitempty"`
}

// ApiResponse defines schema for apiResponse
type ApiResponse struct {
	Code int         `json:"Code"`
	Msg  string      `json:"Msg"`
	Data interface{} `json:"Data"`
}

// UserReturnListPlatform defines schema for user return list
type UserReturnListPlatform struct {
	Username     string `json:"Username"`
	PlatformRole string `json:"PlatformRole,omitempty"`
	Description  string `json:"Description,omitempty"`
}

// UserReturnListCluster defines user return list schema
type UserReturnListCluster struct {
	Username    string `json:"Username"`
	ClusterRole string `json:"ClusterRole,omitempty"`
}

// UserInvitedListSimplified defines simplified user invited list schema
type UserInvitedListSimplified struct {
	Username    string `json:"username"`
	Description string `json:"Description"`
}

// UserDetailResponse defines user detail response schema
type UserDetailResponse struct {
	Username             string            `json:"Username"`
	Description          string            `json:"Description"`
	PlatformRole         string            `json:"PlatformRole"`
	InvitedByClustersMap map[string]string `json:"InvitedByClustersMap"`
}

// PBKDF2Encryptor defines encryptor schema
type PBKDF2Encryptor struct {
	SaltLength    int
	Iterations    int
	KeyLength     int
	EncryptMethod func() hash.Hash
}

// ClusterRoleBinding defines schema for clusterrolebinding
type ClusterRoleBinding struct {
	RoleType string
	Username string
	RoleName string
}

// UserEdition defines user edition schema
type UserEdition struct {
	Username     string `json:"Username" binding:"required"`
	Description  string `json:"Description,omitempty"`
	PlatformRole string `json:"PlatformRole,omitempty"`
}

// UserDescription defines user description schema
type UserDescription struct {
	Username    string `json:"Username" binding:"required"`
	Description string `json:"Description,omitempty"`
}

// UserClusterRoleList defines user clusterrole list
type UserClusterRoleList struct {
	Data []UserReturnListCluster `json:"Data"`
}

// UserSpecFiltered defines filtered user spec
type UserSpecFiltered struct {
	Username              string   `json:"Username,omitempty"`
	Description           string   `json:"Description,omitempty"`
	InvitedByClustersList []string `json:"InvitedByClustersList,omitempty"`
	PlatformRole          string   `json:"PlatformRole,omitempty"`
}

// IdentityCollection defines map for all valid users
type IdentityCollection struct {
	UserInfo map[string]*IdentityDescriptor `json:"userInfo,omitempty"`
}

// IdentityDescriptor 存储单个用户的身份信息
type IdentityDescriptor struct {
	IdentityName   string   `json:"identityName,omitempty"`
	ApiGroup       string   `json:"apiGroup,omitempty"`
	PlatformAdmin  bool     `json:"platformAdmin"`
	MemberClusters []string `json:"memberClusters"`
}

// ClusterList defines a structure for holding information about cluster objects.
type ClusterList struct {
	Info map[string]*ClustersInformation `json:"info,omitempty"` // Info holds cluster information.
}

// ClustersInformation contains detailed information about a specified cluster,
// including name, labels and resource usage details.
type ClustersInformation struct {
	ClusterName string `json:"clustername,omitempty"` // ClusterName
}
