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

package stringutils

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_stringInSlice(t *testing.T) {
	tests := []struct {
		name   string
		target string
		list   []string
		want   bool
	}{
		{
			name:   "Target string is in the list",
			target: "apple",
			list:   []string{"apple", "banana", "cherry"},
			want:   true,
		},
		{
			name:   "Target string is not in the list",
			target: "orange",
			list:   []string{"apple", "banana", "cherry"},
			want:   false,
		},
		{
			name:   "Empty list",
			target: "apple",
			list:   []string{},
			want:   false,
		},
		{
			name:   "Target string appears multiple times",
			target: "banana",
			list:   []string{"banana", "banana", "cherry"},
			want:   true,
		},
		{
			name:   "List contains similar but not equal strings",
			target: "apple",
			list:   []string{"Apple", "Banana", "Cherry"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StringInSlice(tt.target, tt.list); got != tt.want {
				t.Errorf("stringInSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestCaseInsensitiveNotContains(t *testing.T) {
	// 测试列表中不包含元素
	t.Run("ItemNotInSlice", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := "grape"
		if !CaseInsensitiveNotContains(slice, item) {
			t.Errorf("expected %v not to be in slice, but got false", item)
		}
	})

	// 测试列表中包含元素，大小写不同
	t.Run("ItemInSliceDifferentCase", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := "APPLE"
		if CaseInsensitiveNotContains(slice, item) {
			t.Errorf("expected %v to be in slice (case-insensitive), but got true", item)
		}
	})

	// 测试列表中包含元素，大小写相同
	t.Run("ItemInSliceSameCase", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := "banana"
		if CaseInsensitiveNotContains(slice, item) {
			t.Errorf("expected %v to be in slice, but got true", item)
		}
	})

	// 测试空列表
	t.Run("EmptySlice", func(t *testing.T) {
		var slice []string
		item := "apple"
		if !CaseInsensitiveNotContains(slice, item) {
			t.Errorf("expected %v not to be in an empty slice, but got false", item)
		}
	})

	// 测试空字符串作为元素
	t.Run("EmptyStringItem", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := ""
		if !CaseInsensitiveNotContains(slice, item) {
			t.Errorf("expected empty string not to be in slice, but got false")
		}
	})

	// 测试空字符串在列表中
	t.Run("EmptyStringInSlice", func(t *testing.T) {
		slice := []string{"apple", "banana", ""}
		item := ""
		if CaseInsensitiveNotContains(slice, item) {
			t.Errorf("expected empty string to be in slice, but got true")
		}
	})
}

func TestCaseInsensitiveContains(t *testing.T) {
	// 测试列表中包含元素，大小写不同
	t.Run("ItemInSliceDifferentCase", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := "APPLE"
		if !CaseInsensitiveContains(slice, item) {
			t.Errorf("expected %v to be in slice (case-insensitive), but got false", item)
		}
	})

	// 测试列表中包含元素，大小写相同
	t.Run("ItemInSliceSameCase", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := "banana"
		if !CaseInsensitiveContains(slice, item) {
			t.Errorf("expected %v to be in slice, but got false", item)
		}
	})

	// 测试列表中不包含元素
	t.Run("ItemNotInSlice", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := "grape"
		if CaseInsensitiveContains(slice, item) {
			t.Errorf("expected %v not to be in slice, but got true", item)
		}
	})

	// 测试空列表
	t.Run("EmptySlice", func(t *testing.T) {
		var slice []string
		item := "apple"
		if CaseInsensitiveContains(slice, item) {
			t.Errorf("expected %v not to be in an empty slice, but got true", item)
		}
	})

	// 测试空字符串作为元素
	t.Run("EmptyStringItem", func(t *testing.T) {
		slice := []string{"apple", "banana", "orange"}
		item := ""
		if CaseInsensitiveContains(slice, item) {
			t.Errorf("expected empty string not to be in slice, but got true")
		}
	})

	// 测试空字符串在列表中
	t.Run("EmptyStringInSlice", func(t *testing.T) {
		slice := []string{"apple", "banana", ""}
		item := ""
		if !CaseInsensitiveContains(slice, item) {
			t.Errorf("expected empty string to be in slice, but got false")
		}
	})
}

func TestTrimOpenFuyaoRolePrefix(t *testing.T) {
	// 测试带有前缀的名称
	t.Run("WithPrefix", func(t *testing.T) {
		name := "openfuyao-cluster-admin"
		expected := "cluster-admin"
		if result := TrimOpenFuyaoRolePrefix(name); result != expected {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	// 测试没有前缀的名称
	t.Run("WithoutPrefix", func(t *testing.T) {
		name := "cluster-admin"
		expected := "cluster-admin"
		if result := TrimOpenFuyaoRolePrefix(name); result != expected {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}

// Test AddOpenFuyaoRolePrefix function
func TestAddOpenFuyaoRolePrefix(t *testing.T) {
	// 测试添加前缀
	t.Run("AddPrefix", func(t *testing.T) {
		name := "cluster-admin"
		expected := "openfuyao-cluster-admin"
		if result := AddOpenFuyaoRolePrefix(name); result != expected {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	// 测试已经有前缀的名称
	t.Run("AlreadyHasPrefix", func(t *testing.T) {
		name := "openfuyao-cluster-admin"
		expected := "openfuyao-openfuyao-cluster-admin"
		if result := AddOpenFuyaoRolePrefix(name); result != expected {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}

// Test TrimOpenFuyaoRoleListPrefix function
func TestTrimOpenFuyaoRoleListPrefix(t *testing.T) {
	// 构建 ClusterRole 列表
	clusterRoles := []v1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "openfuyao-cluster-admin",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cluster-viewer",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "openfuyao-cluster-editor",
			},
		},
	}

	// 期望的结果
	expected := []string{"cluster-admin", "cluster-viewer", "cluster-editor"}

	// 调用函数
	result := TrimOpenFuyaoRoleListPrefix(clusterRoles)

	// 验证结果
	for i, cr := range result {
		if i < len(expected) && cr.Name != expected[i] {
			t.Errorf("expected %v, got %v at index %d", expected[i], cr.Name, i)
		}
	}
}

func TestRemoveStringFromList(t *testing.T) {
	type args struct {
		target string
		list   []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "successfully-remove",
			args: args{
				target: "a",
				list:   []string{"a", "b", "c"},
			},
			want: []string{"b", "c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveStringFromList(tt.args.target, tt.args.list); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveStringFromList() = %v, want %v", got, tt.want)
			}
		})
	}
}
