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

package server

import (
	"net/http"
	"testing"

	"github.com/emicklei/go-restful/v3"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestGetQueryParamOrDefault(t *testing.T) {
	// 创建一个包含查询参数的请求
	reqWithParam, err := http.NewRequest("GET", "/test?param=value", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 创建一个不包含查询参数的请求
	reqWithoutParam, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 使用 restful 包创建请求对象
	reqWithParamRestful := restful.NewRequest(reqWithParam)
	reqWithoutParamRestful := restful.NewRequest(reqWithoutParam)

	// 进行有查询参数的测试
	result := GetQueryParamOrDefault(reqWithParamRestful, "param", "default")
	assert.Equal(t, "value", result)

	// 进行无查询参数的测试
	result = GetQueryParamOrDefault(reqWithoutParamRestful, "param", "default")
	assert.Equal(t, "default", result)

	// 进行查询参数为空的测试
	reqEmptyParam, err := http.NewRequest("GET", "/test?param=", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqEmptyParamRestful := restful.NewRequest(reqEmptyParam)

	result = GetQueryParamOrDefault(reqEmptyParamRestful, "param", "default")
	assert.Equal(t, "default", result)
}

// 模拟 schema.GroupVersion 结构体
type GroupVersion struct {
	Group   string
	Version string
}

// String 方法返回 GroupVersion 的字符串表示
func (gv GroupVersion) String() string {
	return gv.Group + "/" + gv.Version
}
func TestNewWebService(t *testing.T) {
	// 创建一个 GroupVersion 实例
	gv := schema.GroupVersion{
		Group:   "testgroup",
		Version: "v1",
	}

	// 调用被测试的函数
	webservice := NewWebService(gv)

	// 验证 Path 是否正确
	expectedPath := "/rest/testgroup/v1"
	assert.Equal(t, expectedPath, webservice.RootPath(), "WebService path should match the expected path")
}
