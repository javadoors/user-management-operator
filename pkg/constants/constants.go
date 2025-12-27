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

// Package constants defines the constants
package constants

// Constants for authn
const (
	OpenFuyaoAuthHeaderKey = "X-OpenFuyao-Authorization"
	UserKey                = "user"
)

// Constants for fuyao roles
const (
	OpenFuyaoRoleLabel  = "role-type"
	OpenFuyaoRolePrefix = "openfuyao-"
	UserRefLabel        = "openfuyao.com/user-ref"
	ClusterRoleRefLabel = "openfuyao.com/clusterrole-ref"
)

// Constants for fuyao services configs
const (
	ConsoleServiceProtocol = "https"
	ConsoleServiceHost     = "console-service.openfuyao-system.svc.cluster.local"
	ConsoleServicePort     = 80
	UserMgmtPathPrefix     = "/clusters/{cluster}/rest/user/v1"
	K8sResourcePathPrefix  = "/clusters/{cluster}/api/kubernetes"

	MultiClusterProtocol    = "http"
	MultiClusterNamespace   = "karmada-system" // "karmada-system"
	MultiClusterService     = "multicluster-service"
	MultiClusterHost        = MultiClusterService + "." + MultiClusterNamespace + ".svc.cluster.local"
	MultiClusterServicePort = 9022
	MultiClusterPathPrefix  = "/rest/multicluster/v1beta1"
)

// Constants for password configs
const (
	SaltLength     = 16     // 盐的长度
	Iterations     = 100000 // 迭代次数
	KeyLength      = 64     // 生成的密钥长度（以字节为单位）
	PasswordMinLen = 8
	PasswordMaxLen = 32
)

// Constants for regex
const (
	MetaNamePattern = `^[a-z0-9]+([-a-z0-9]*[a-z0-9])?$`
	MetaNameLength  = 32
)

// Constants for tls file
const (
	TlsCAPath   = "/ssl/ca.pem"
	TlsCertPath = "/ssl/server.crt"
	TlsKeyPath  = "/ssl/server.key"
)
