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

package v1alpha1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterList represents a list of clusters that a user is invited to.
type ClusterList struct {
	ClusterName string `json:"ClusterName,omitempty"`
}

// UserSpec represents the desired configuration for system users
// +kubebuilder:validation:Required
type UserSpec struct {
	// Username is the name of the user.
	// +kubebuilder:validation:Required
	Username string `json:"Username,omitempty"`
	// EncryptedPassword is the user's encrypted password.
	// +kubebuilder:validation:Required
	EncryptedPassword []byte `json:"EncryptedPassword,omitempty"`
	// Description is an optional description of the user.
	Description string `json:"Description,omitempty"`
	// InvitedByClustersList contains the list of cluster names the user is invited to.
	InvitedByClustersList []string `json:"InvitedByClustersList,omitempty"`
	// PlatformRole defines the role of the user within the platform.
	// +kubebuilder:validation:Required
	PlatformRole string `json:"PlatformRole,omitempty"`
	// FailedLoginRecords is a list of timestamps for each failed login attempt.
	FailedLoginRecords []v1.Time `json:"failedLoginRecords,omitempty"`
	// FirstLogin indicates whether this is the user's first login.
	// +kubebuilder:validation:Required
	FirstLogin bool `json:"FirstLogin,omitempty"`
}

// UserStatus reflects current operational state
type UserStatus struct {
	// LockStatus indicates whether the user is locked or unlocked.
	LockStatus string `json:"lockStatus,omitempty"`
	// LockedTimestamp is the timestamp when the user was locked.
	LockedTimestamp *v1.Time `json:"lockedTimestamp,omitempty"`
	// RemainAttempts is the number of remaining login attempts before the user gets locked.
	RemainAttempts int `json:"RemainAttempts,omitempty"`
}

// User represents the core user resource schema
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.lockStatus"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp",description="Creation timestamp"
// +kubebuilder:printcolumn:name="RemainAttempts",type="integer",JSONPath="..status.RemainAttempts"
// +kubebuilder:resource:shortName=ur
// +kubebuilder:resource:scope=Cluster
type User struct {
	v1.TypeMeta   `json:",inline"`
	v1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserSpec   `json:"spec,omitempty"`
	Status UserStatus `json:"status,omitempty"`
}

// UserList contains collections of User resources
// +kubebuilder:object:root=true
type UserList struct {
	v1.TypeMeta `json:",inline"`
	v1.ListMeta `json:"metadata,omitempty"`
	Items       []User `json:"items"`
}

func init() {
	SchemeBuilder.Register(&User{}, &UserList{})
}
