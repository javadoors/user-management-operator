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

// Package controller defines controller reconcile logics
package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	usersv1alpha1 "openfuyao.com/user-management/api/v1alpha1"
)

// UserReconciler reconciles a User object
type UserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=users.openfuyao.com,resources=users,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=users.openfuyao.com,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=users.openfuyao.com,resources=users/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// Modify the Reconcile function to compare the state specified by
// the User object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.0/pkg/reconcile
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	lockDurationInt, maxAttempts, err := loadConfiguration()
	if err != nil {
		return ctrl.Result{}, err
	}

	logger := log.FromContext(ctx)
	user := &usersv1alpha1.User{}
	if err := r.Get(ctx, req.NamespacedName, user); err != nil {
		if errors.IsNotFound(err) {
			// 资源已经被删除
			return ctrl.Result{}, nil
		}
	}

	// 检查 CR 是否有 deletionTimestamp
	if !user.ObjectMeta.DeletionTimestamp.IsZero() {
		// 资源正在被删除，当前没有写删除的controller逻辑
		return ctrl.Result{}, nil
	}

	if user.Status.LockStatus == "" {
		r.initializeUserStatusIfNeeded(ctx, user, maxAttempts)
	}

	if user.Status.LockStatus == "Active" {
		if r.lockUserIfNeeded(ctx, user, lockDurationInt, maxAttempts) {
			if err := r.Status().Update(ctx, user); err != nil {
				logger.Error(err, "Status update fails")
			}
			lockDuration := time.Duration(lockDurationInt) * time.Minute // 锁定持续时间为5分钟
			unlockTime := user.Status.LockedTimestamp.Add(lockDuration)  // 计算解锁时间
			return ctrl.Result{RequeueAfter: time.Until(unlockTime)}, nil
		} else {
			if err := r.Status().Update(ctx, user); err != nil {
				logger.Error(err, "Status update fails")
			}
			return ctrl.Result{}, nil
		}
	} else {
		if r.unlockUserIfNeeded(ctx, user, lockDurationInt) {
			user.Spec.FailedLoginRecords = []v1.Time{}
			if err := r.Update(ctx, user); err != nil {
				logger.Error(err, "Failed to update User status to locked")
			}
			user.Status.LockStatus = "Active"
			user.Status.RemainAttempts = maxAttempts
			if err := r.Status().Update(ctx, user); err != nil {
				logger.Error(err, "Status update fails")
			}
		}
		return ctrl.Result{}, nil
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&usersv1alpha1.User{}).
		Complete(r)
}

func (r *UserReconciler) lockUserIfNeeded(ctx context.Context, user *usersv1alpha1.User,
	lockDuration, maxAttempts int) bool {
	logger := log.FromContext(ctx)
	now := v1.Now()
	recentFailures := 0
	for _, failedTime := range user.Spec.FailedLoginRecords {
		if now.Sub(failedTime.Time) <= (time.Minute * time.Duration(lockDuration)) {
			recentFailures++
		}
	}
	logger.Info("Recent login failures", "count", recentFailures)
	if recentFailures >= maxAttempts {
		logger.Info("User has too many failed login attempts, locking user", "username", user.Name)
		user.Status.RemainAttempts = 0
		logger.Info("User locked due to excessive failed login attempts", "username", user.Spec.Username)
		user.Status.LockStatus = "Locked"
		user.Status.LockedTimestamp = &now
		return true
	} else {
		user.Status.RemainAttempts = maxAttempts - recentFailures
		logger.Info("Remaining attempts", "remain attempts", user.Status.RemainAttempts)
	}
	return false
}

func (r *UserReconciler) unlockUserIfNeeded(ctx context.Context, user *usersv1alpha1.User, lockDuration int) bool {
	logger := log.FromContext(ctx)
	if user.Status.LockedTimestamp != nil {
		lockDuration := time.Duration(lockDuration) * time.Minute // 锁定持续时间为 5 分钟
		unlockTime := user.Status.LockedTimestamp.Add(lockDuration)
		if time.Now().After(unlockTime) {
			// 解锁用户
			user.Status.LockStatus = "Active"
			logger.Info("User unlocked after lock duration exceeded", "username", user.Spec.Username)
			return true
		}
	}

	return false
}

func (r *UserReconciler) setDefaultUserStatusIfNeeded(ctx context.Context, user *usersv1alpha1.User) error {
	logger := log.FromContext(ctx)

	if user.Status.LockStatus == "" {
		user.Status.LockStatus = "Active"
		if err := r.Status().Update(ctx, user); err != nil {
			logger.Error(err, "Failed to set default User status to unlocked")
			return err
		}
		logger.Info("User status set to default unlocked", "username", user.Spec.Username)
	}
	return nil
}
func (r *UserReconciler) initializeUserStatusIfNeeded(ctx context.Context, user *usersv1alpha1.User, remainTimes int) {
	logger := log.FromContext(ctx)

	// 初始化 LockStatus
	if user.Status.LockStatus == "" {
		user.Status.LockStatus = "Active"
		user.Status.RemainAttempts = remainTimes
	}

	// 更新 User 状态
	if err := r.Status().Update(ctx, user); err != nil {
		logger.Error(err, "Failed to initialize User status fields")
		return
	}
	logger.Info("Initialized User status fields", "username", user.Spec.Username)
	return
}

func loadConfiguration() (int, int, error) {
	lockDurationStr := os.Getenv("LOCK_DURATION")
	if lockDurationStr == "" {
		return 0, 0, fmt.Errorf("LOCK_DURATION not set")
	}

	lockDurationInt, err := strconv.Atoi(lockDurationStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid LOCK_ATTEMPTS format: %v", err)
	}

	maxAttemptsStr := os.Getenv("MAX_ATTEMPTS")
	if maxAttemptsStr == "" {
		return 0, 0, fmt.Errorf("MAX_ATTEMPTS not set")
	}
	maxAttempts, err := strconv.Atoi(maxAttemptsStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid MAX_ATTEMPTS format: %v", err)
	}

	return lockDurationInt, maxAttempts, nil
}
