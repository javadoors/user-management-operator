/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 *
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package v1alpha1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestClusterListDeepCopy(t *testing.T) {
	// Test ClusterList DeepCopy
	original := &ClusterList{
		ClusterName: "test-cluster",
	}

	copied := original.DeepCopy()
	assert.NotNil(t, copied)
	assert.Equal(t, original.ClusterName, copied.ClusterName)

	// Verify it's a copy by modifying original
	original.ClusterName = "new-cluster"
	assert.Equal(t, "test-cluster", copied.ClusterName)
	assert.Equal(t, "new-cluster", original.ClusterName)
}

func TestUserSpecDeepCopy(t *testing.T) {
	// Test UserSpec DeepCopy
	now := v1.Now()

	original := &UserSpec{
		Username:          "testuser",
		EncryptedPassword: []byte("encrypted-password"),
		Description:       "Test user",
		InvitedByClustersList: []string{
			"cluster-1",
			"cluster-2",
		},
		PlatformRole: "platform-admin",
		FailedLoginRecords: []v1.Time{
			now,
		},
		FirstLogin: true,
	}

	copied := original.DeepCopy()
	assert.NotNil(t, copied)
	assert.Equal(t, original.Username, copied.Username)
	assert.Equal(t, original.Description, copied.Description)
	assert.Equal(t, original.FirstLogin, copied.FirstLogin)
	assert.Equal(t, original.PlatformRole, copied.PlatformRole)
	assert.Equal(t, len(original.EncryptedPassword), len(copied.EncryptedPassword))
	assert.Equal(t, len(original.InvitedByClustersList), len(copied.InvitedByClustersList))
	assert.Equal(t, len(original.FailedLoginRecords), len(copied.FailedLoginRecords))

	// Verify deep copy by modifying original
	original.Username = "newuser"
	assert.Equal(t, "testuser", copied.Username)
	assert.Equal(t, "newuser", original.Username)

	// Verify slice deep copy
	original.InvitedByClustersList[0] = "new-cluster"
	assert.Equal(t, "cluster-1", copied.InvitedByClustersList[0])
	assert.Equal(t, "new-cluster", original.InvitedByClustersList[0])
}

func TestUserSpecDeepCopyEmptyFields(t *testing.T) {
	// Test UserSpec DeepCopy with empty fields
	original := &UserSpec{
		Username:              "testuser",
		EncryptedPassword:     nil,
		InvitedByClustersList: nil,
		FailedLoginRecords:    nil,
	}

	copied := original.DeepCopy()
	assert.NotNil(t, copied)
	assert.Equal(t, original.Username, copied.Username)
	assert.Nil(t, copied.EncryptedPassword)
	assert.Nil(t, copied.FailedLoginRecords)
	assert.Nil(t, copied.InvitedByClustersList)
}

func TestUserStatusDeepCopy(t *testing.T) {
	// Test UserStatus DeepCopy
	now := v1.Now()
	lockedTime := &now

	original := &UserStatus{
		LockStatus:      "locked",
		LockedTimestamp: lockedTime,
		RemainAttempts:  3,
	}

	copied := original.DeepCopy()
	assert.NotNil(t, copied)
	assert.Equal(t, original.LockStatus, copied.LockStatus)
	assert.Equal(t, original.RemainAttempts, copied.RemainAttempts)
	assert.NotNil(t, copied.LockedTimestamp)
	assert.Equal(t, original.LockedTimestamp.Unix(), copied.LockedTimestamp.Unix())

	// Verify it's a deep copy
	time.Sleep(time.Second)
	newTime := v1.Now()
	original.LockedTimestamp = &newTime
	assert.NotEqual(t, original.LockedTimestamp.Unix(), copied.LockedTimestamp.Unix())
}

func TestUserStatusDeepCopyEmptyFields(t *testing.T) {
	// Test UserStatus DeepCopy with nil LockedTimestamp
	original := &UserStatus{
		LockedTimestamp: nil,
		LockStatus:      "unlocked",
		RemainAttempts:  5,
	}

	copied := original.DeepCopy()
	assert.NotNil(t, copied)
	assert.Equal(t, original.LockStatus, copied.LockStatus)
	assert.Equal(t, original.RemainAttempts, copied.RemainAttempts)
	assert.Nil(t, copied.LockedTimestamp)
}

func TestUserDeepCopy(t *testing.T) {
	// Test User DeepCopy
	now := v1.Now()
	lockedTime := v1.Now()

	original := &User{
		TypeMeta: v1.TypeMeta{
			Kind:       "User",
			APIVersion: "openfuyao.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-user",
			Namespace: "default",
			Labels: map[string]string{
				"environment": "test",
			},
		},
		Spec: UserSpec{
			Username:          "testuser",
			EncryptedPassword: []byte("encrypted-password"),
			Description:       "Test user",
			InvitedByClustersList: []string{
				"cluster-1",
			},
			PlatformRole: "platform-admin",
			FailedLoginRecords: []v1.Time{
				now,
			},
			FirstLogin: true,
		},
		Status: UserStatus{
			LockStatus:      "unlocked",
			LockedTimestamp: &lockedTime,
			RemainAttempts:  5,
		},
	}

	copied := original.DeepCopy()
	assert.NotNil(t, copied)
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Namespace, copied.Namespace)
	assert.Equal(t, original.Kind, copied.Kind)
	assert.Equal(t, original.APIVersion, copied.APIVersion)

	// Verify deep copy by modifying original
	original.ObjectMeta.Labels["environment"] = "production"
	assert.Equal(t, "test", copied.ObjectMeta.Labels["environment"])
	assert.Equal(t, "production", original.ObjectMeta.Labels["environment"])

	// Verify spec fields
	assert.Equal(t, original.Spec.Username, copied.Spec.Username)
	assert.Equal(t, original.Spec.Description, copied.Spec.Description)
	assert.Equal(t, len(original.Spec.InvitedByClustersList), len(copied.Spec.InvitedByClustersList))

	// Verify status fields
	assert.Equal(t, original.Status.LockStatus, copied.Status.LockStatus)
	assert.Equal(t, original.Status.RemainAttempts, copied.Status.RemainAttempts)
	assert.Equal(t, original.Status.LockedTimestamp.Unix(), copied.Status.LockedTimestamp.Unix())
}

func TestUserDeepCopyInto(t *testing.T) {
	// Test User DeepCopyInto
	original := &User{
		TypeMeta: v1.TypeMeta{
			Kind:       "User",
			APIVersion: "openfuyao.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-user",
			Namespace: "default",
		},
		Spec: UserSpec{
			Username:          "testuser",
			EncryptedPassword: []byte("encrypted-password"),
			Description:       "Test user",
			InvitedByClustersList: []string{
				"cluster-1",
			},
			PlatformRole: "platform-admin",
		},
		Status: UserStatus{
			LockStatus:     "unlocked",
			RemainAttempts: 5,
		},
	}

	copied := &User{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Namespace, copied.Namespace)
	assert.Equal(t, original.Kind, copied.Kind)
	assert.Equal(t, original.APIVersion, copied.APIVersion)
	assert.Equal(t, original.Spec.Username, copied.Spec.Username)
	assert.Equal(t, original.Spec.Description, copied.Spec.Description)
	assert.Equal(t, len(original.Spec.InvitedByClustersList), len(copied.Spec.InvitedByClustersList))
	assert.Equal(t, original.Status.LockStatus, copied.Status.LockStatus)
	assert.Equal(t, original.Status.RemainAttempts, copied.Status.RemainAttempts)
}

func TestUserDeepCopyObject(t *testing.T) {
	// Test User DeepCopyObject
	original := &User{
		TypeMeta: v1.TypeMeta{
			Kind:       "User",
			APIVersion: "openfuyao.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "test-user",
		},
		Spec: UserSpec{
			Username: "testuser",
		},
		Status: UserStatus{
			LockStatus: "unlocked",
		},
	}

	obj := original.DeepCopyObject()
	assert.NotNil(t, obj)

	// Cast back to User
	copied, ok := obj.(*User)
	assert.True(t, ok)
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Spec.Username, copied.Spec.Username)
	assert.Equal(t, original.Status.LockStatus, copied.Status.LockStatus)
}

func TestUserListDeepCopy(t *testing.T) {
	// Test UserList DeepCopy
	now := v1.Now()
	lockedTime := v1.Now()

	original := &UserList{
		TypeMeta: v1.TypeMeta{
			APIVersion: "openfuyao.io/v1alpha1",
			Kind:       "UserList",
		},
		ListMeta: v1.ListMeta{
			ResourceVersion: "1",
		},
		Items: []User{
			{
				ObjectMeta: v1.ObjectMeta{
					Name: "user-1",
				},
				Spec: UserSpec{
					Username: "user1",
				},
				Status: UserStatus{
					LockStatus: "unlocked",
				},
			},
			{
				ObjectMeta: v1.ObjectMeta{
					Name: "user-2",
				},
				Spec: UserSpec{
					Username: "user2",
					FailedLoginRecords: []v1.Time{
						now,
					},
				},
				Status: UserStatus{
					LockStatus:      "locked",
					LockedTimestamp: &lockedTime,
				},
			},
		},
	}

	copied := original.DeepCopy()
	assert.NotNil(t, copied)
	assert.Equal(t, original.Kind, copied.Kind)
	assert.Equal(t, original.APIVersion, copied.APIVersion)
	assert.Equal(t, len(original.Items), len(copied.Items))
	assert.Equal(t, original.Items[0].Name, copied.Items[0].Name)
	assert.Equal(t, original.Items[1].Name, copied.Items[1].Name)

	// Verify deep copy by modifying original
	original.Items[0].Spec.Username = "newuser1"
	assert.Equal(t, "user1", copied.Items[0].Spec.Username)
	assert.Equal(t, "newuser1", original.Items[0].Spec.Username)
}

func TestUserListDeepCopyInto(t *testing.T) {
	// Test UserList DeepCopyInto
	original := &UserList{
		TypeMeta: v1.TypeMeta{
			Kind:       "UserList",
			APIVersion: "openfuyao.io/v1alpha1",
		},
		ListMeta: v1.ListMeta{
			ResourceVersion: "2",
		},
		Items: []User{
			{
				Spec: UserSpec{
					Username: "user1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "user-1",
				},
				Status: UserStatus{
					LockStatus: "unlocked",
				},
			},
		},
	}

	copied := &UserList{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.Kind, copied.Kind)
	assert.Equal(t, original.APIVersion, copied.APIVersion)
	assert.Equal(t, len(original.Items), len(copied.Items))
	assert.Equal(t, original.Items[0].Name, copied.Items[0].Name)
	assert.Equal(t, original.Items[0].Spec.Username, copied.Items[0].Spec.Username)
	assert.Equal(t, original.Items[0].Status.LockStatus, copied.Items[0].Status.LockStatus)
}

func TestUserListDeepCopyObject(t *testing.T) {
	// Test UserList DeepCopyObject
	original := &UserList{
		TypeMeta: v1.TypeMeta{
			Kind:       "UserList",
			APIVersion: "openfuyao.io/v1alpha1",
		},
		ListMeta: v1.ListMeta{
			ResourceVersion: "3",
		},
		Items: []User{
			{
				ObjectMeta: v1.ObjectMeta{
					Name: "user-1",
				},
				Spec: UserSpec{
					Username: "user1",
				},
			},
		},
	}

	obj := original.DeepCopyObject()
	assert.NotNil(t, obj)

	// Cast back to UserList
	copied, ok := obj.(*UserList)
	assert.True(t, ok)
	assert.Equal(t, original.Kind, copied.Kind)
	assert.Equal(t, original.APIVersion, copied.APIVersion)
	assert.Equal(t, len(original.Items), len(copied.Items))
}
