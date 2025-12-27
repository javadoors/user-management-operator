# user-management-operator

## 特性介绍

本项目是openFuyao容器平台中用户管理组件，为容器平台提供了一整套灵活的用户和角色管理功能。该系统支持用户的增删改查以及角色的分配，查看与解除绑定等。

管理员可以为平台用户分配合适的角色，实现精细的权限控制。
支持集群成员的邀请、移除和集群角色的绑定，管理员能够为不同集群中的用户设置不同的权限。
支持平台级和集群级的角色分配，确保用户在多集群场景下操作时拥有正确的权限，满足多集群环境下的访问控制需求。
openFuyao容器平台通过该系统能够提升用户管理的效率和安全性，保证资源的合理分配与使用。

所属sig: [sig-container-platform](https://gitcode.com/openFuyao/sig-container-platform)

## 本地构建

### 镜像构建

#### 构建参数

- `GOPRIVATE`：配置Go语言私有仓库，相当于`GOPRIVATE`环境变量
- `COMMIT`：当前git commit的哈希值
- `VERSION`：组件版本
- `SOURCE_DATE_EPOCH`：镜像rootfs的时间戳

#### 构建命令

- 构建并推送到指定OCI仓库

  <details open>
  <summary>使用<code>docker</code></summary>

  ```bash
  docker buildx build . -f <path/to/dockerfile> \
      -o type=image,name=<oci/repository>:<tag>,oci-mediatypes=true,rewrite-timestamp=true,push=true \
      --platform=linux/amd64,linux/arm64 \
      --provenance=false \
      --build-arg=GOPRIVATE=gopkg.openfuyao.cn \
      --build-arg=COMMIT=$(git rev-parse HEAD) \
      --build-arg=VERSION=0.0.0-latest \
      --build-arg=SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
  ```

  </details>
  <details>
  <summary>使用<code>nerdctl</code></summary>

  ```bash
  nerdctl build . -f <path/to/dockerfile> \
      -o type=image,name=<oci/repository>:<tag>,oci-mediatypes=true,rewrite-timestamp=true,push=true \
      --platform=linux/amd64,linux/arm64 \
      --provenance=false \
      --build-arg=GOPRIVATE=gopkg.openfuyao.cn \
      --build-arg=COMMIT=$(git rev-parse HEAD) \
      --build-arg=VERSION=0.0.0-latest \
      --build-arg=SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
  ```

  </details>

  其中，`<path/to/dockerfile>`为Dockerfile路径`./build/Dockerfile`，`<oci/repository>`为镜像地址，`<tag>`为镜像tag

- 构建并导出OCI Layout到本地tarball

  <details open>
  <summary>使用<code>docker</code></summary>

  ```bash
  docker buildx build . -f <path/to/dockerfile> \
      -o type=oci,name=<oci/repository>:<tag>,dest=<path/to/oci-layout.tar>,rewrite-timestamp=true \
      --platform=linux/amd64,linux/arm64 \
      --provenance=false \
      --build-arg=GOPRIVATE=gopkg.openfuyao.cn \
      --build-arg=COMMIT=$(git rev-parse HEAD) \
      --build-arg=VERSION=0.0.0-latest \
      --build-arg=SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
  ```

  </details>
  <details>
  <summary>使用<code>nerdctl</code></summary>

  ```bash
  nerdctl build . -f <path/to/dockerfile> \
      -o type=oci,name=<oci/repository>:<tag>,dest=<path/to/oci-layout.tar>,rewrite-timestamp=true \
      --platform=linux/amd64,linux/arm64 \
      --provenance=false \
      --build-arg=GOPRIVATE=gopkg.openfuyao.cn \
      --build-arg=COMMIT=$(git rev-parse HEAD) \
      --build-arg=VERSION=0.0.0-latest \
      --build-arg=SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
  ```

  </details>

  其中，`<path/to/dockerfile>`为Dockerfile路径`./build/Dockerfile`，`<oci/repository>`为镜像地址，`<tag>`为镜像tag，`path/to/oci-layout.tar`为tar包路径

- 构建并导出镜像rootfs到本地目录

  <details open>
  <summary>使用<code>docker</code></summary>

  ```bash
  docker buildx build . -f <path/to/dockerfile> \
      -o type=local,dest=<path/to/output>,platform-split=true \
      --platform=linux/amd64,linux/arm64 \
      --provenance=false \
      --build-arg=GOPRIVATE=gopkg.openfuyao.cn \
      --build-arg=COMMIT=$(git rev-parse HEAD) \
      --build-arg=VERSION=0.0.0-latest
  ```

  </details>
  <details>
  <summary>使用<code>nerdctl</code></summary>

  ```bash
  nerdctl build . -f <path/to/dockerfile> \
      -o type=local,dest=<path/to/output>,platform-split=true \
      --platform=linux/amd64,linux/arm64 \
      --provenance=false \
      --build-arg=GOPRIVATE=gopkg.openfuyao.cn \
      --build-arg=COMMIT=$(git rev-parse HEAD) \
      --build-arg=VERSION=0.0.0-latest
  ```

  </details>

  其中，`<path/to/dockerfile>`为Dockerfile路径`./build/Dockerfile`，`path/to/output`为本地目录路径

### Helm Chart构建

- 打包Helm Chart

  ```bash
  helm package <path/to/chart> -u \
      --version=0.0.0-latest \
      --app-version=openFuyao-v25.09
  ```

  其中，`<path/to/chart>`为Chart文件夹路径

- 推送Chart包到指定OCI仓库

  ```bash
  helm push <path/to/chart.tgz> oci://<oci/repository>:<tag>
  ```

  其中，`<path/to/chart.tgz>`为Chart包路径，`<oci/repository>`为Chart包推送地址，`<tag>`为Chart包tag

## 安装说明

该组件为openFuyao容器平台的核心组件，请依据openFuyao容器平台的安装方式进行统一安装(参见[安装指南](https://docs.openfuyao.cn/docs/%E5%AE%89%E8%A3%85%E6%8C%87%E5%AF%BC/Cluster%20API%E5%AE%89%E8%A3%85/%E5%9C%A8%E7%BA%BF%E5%AE%89%E8%A3%85%E5%BC%95%E5%AF%BC%E9%9B%86%E7%BE%A4))。

## 使用说明

详细使用说明请参考[用户指南](https://docs.openfuyao.cn/docs/%E7%94%A8%E6%88%B7%E6%8C%87%E5%8D%97/%E7%94%A8%E6%88%B7%E7%AE%A1%E7%90%86)