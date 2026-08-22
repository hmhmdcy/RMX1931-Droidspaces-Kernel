# 容器内核定制说明（rootless Podman 支持）

本分支（`feat/container-networking`）在 realme SM8150 4.14 CAF 内核上为
**rootless 容器（podman + crun + fuse-overlayfs）** 所做的定制改动汇总。

## 背景

- 设备：Realme X2 Pro（SM8150 / msmnile），Android + DroidSpaces 容器内跑 Debian
- 目标：`podman run`（rootless，userns）跑通：`userns → 挂 /proc → 挂 /sys → 存储层(fuse-overlayfs) → 起容器`
- 约束：**软件全部使用官方源**（crun/podman 不补丁），内核改动面最小，一次刷机到位
- 内核版本锁死 4.14（高通平台策略：SM8150 = 4.14），主线新能力（5.x）无法整体跟进

## 改动总览

| commit | 文件 | 类型 | 内容 |
|---|---|---|---|
| `8a1dcad1d` | fs/proc/root.c | **[backport]** | 恢复 `ns_capable(ns->user_ns, CAP_SYS_ADMIN)` + `sget_userns(ns->user_ns)`（upstream mount_ns 语义，CAF 分支改动导致的回归） |
| `8a1dcad1d` | fs/proc/inode.c | **[backport]** | `s_iflags |= SB_I_NOEXEC`（upstream v5.4 修复：userns 挂 proc 无条件 EPERM） |
| `8a1dcad1d` | fs/namespace.c | **[relax]** | `mnt_already_visible` 放行文件型锁定子挂载 |
| `1695c442a` | fs/fuse/inode.c | **[backport]** | `fuse_fs_type.fs_flags |= FS_USERNS_MOUNT` + fill_super fd userns 检查改 `sb->s_user_ns`（upstream v4.18） |
| `8cbeef92d` | fs/namespace.c | **[relax]**（中间态，已被 f3df8b7b6 取代） | 放行 ro/异类子挂载——proc 部分有效；对 sysfs 的归因后来证明错误（见下） |
| `f3df8b7b6` | fs/namespace.c | **[relax]** | `mnt_already_visible` 完全移除锁定子挂载检查 |
| `f3df8b7b6` | kernel/cgroup/cgroup.c | **[restrict]** | cgroup 挂载检查 `ns_capable(ns->user_ns)` → `capable()`（仅 init userns；userns 挂 cgroup 一律 EPERM → crun 官方 fallback bind 触发） |
| `24298cf8c` | net/core/net-sysfs.c | **[relax]** | `net_current_may_mount` 放行挂载者当前 netns（sysfs 直挂） |
| `886338239` | fs/namespace.c | **[relax]** | `mnt_already_visible` 删除 readonly 不匹配拒绝（Android 宿主 /sys 为 ro，userns 挂 rw sysfs 被误拒）；不传播 `MNT_LOCK_READONLY` |
| `9759bd08d` | fs/fuse/* | **[backport]** | 补齐 FUSE 的 `fc->user_ns` / `sb->s_user_ns` UID/GID 映射机制（upstream v4.18），彻底解决 rootless `fuse-overlayfs` 根目录变 nobody/EPERM 问题 |

类型说明：
- **[backport]**：主线早已修复的 bug 原样搬回，与 upstream 语义一致，无安全差异
- **[relax]**：主动放宽 upstream 安全检查（见安全边界）
- **[restrict]**：比 upstream 更严格（安全收紧）

## 各放宽点的安全边界

总体依据：**userns root 不是宿主 uid 0**。VFS 权限位（root 属主 0644/0200 文件
只给 other 位）和写回调内的 `capable(CAP_SYS_ADMIN)`（init userns 语义）双重
限制，userns root 对 proc/sysfs 新实例只有读权限。放宽不新增任何写能力。

1. **锁定子挂载检查（fs/namespace.c）**：Android/DroidSpaces 在 `/proc` 下锁了
   `/proc/sys`（ro）、`/proc/irq`（ro）、`/proc/uptime`（tmpfs 伪装）等，
   `/sys` 下有 `/sys/devices/virtual/net`（rw）。`copy_tree(CL_UNPRIVILEGED)`
   复制时全部 `MNT_LOCKED` → `mount_too_revealing`（CVE-2018-18955 修复）拒绝
   userns 挂载。放行理由：锁定挂载覆盖的路径在新 proc/sysfs 实例中依然存在
   （内容全局或由新 pid ns 生成），tmpfs 伪装在新实例中无内容；写被 VFS 挡住。
2. **netns 检查（net/core/net-sysfs.c）**：`sysfs_mount()` 的
   `kobj_ns_current_may_mount(KOBJ_NS_TYPE_NET)` 要求 `ns_capable(net->user_ns, CAP_SYS_ADMIN)`。
   rootless 容器的 netns 由 slirp4netns（init userns）创建 → userns 挂载者必被拒。
   **注意：upstream 的 rootless crun 挂 sysfs 同样失败**（同款检查），upstream 靠
   open_tree(2) 的 bind fallback（5.2+）；4.14 无 open_tree 且 backport 需 fs_context
   框架（不可行），故让 sysfs 直挂成功。放行条件：挂载者当前 netns
   （`net == current->nsproxy->net_ns`）——`sysfs_mount` 用 `kobj_ns_grab_current`
   把新 sb 绑定挂载者当前 netns，只暴露自己 netns 的接口（本来就可见）；
   其它 netns 的 owner-capability 要求保留。
3. **cgroup（kernel/cgroup/cgroup.c）**：`cgroup_mount` 的检查改为 init userns
   `capable()`——userns 挂 cgroup 一律 EPERM。cgroup 层级全局（cgroup ns 只虚拟化
   路径），crun 的官方 fallback（EPERM 时 bind 当前 cgroup）正常工作。rootful
   （init userns root）不受影响。
4. **readonly 不匹配（fs/namespace.c，`886338239`）**：Android 宿主 `/sys` 是 ro
   挂载（`sb_rdonly` → 伪 `MNT_LOCK_READONLY`），`mnt_already_visible` 的
   readonly 分支会拒绝 userns 挂载 rw sysfs——尽管新实例是绑挂载者当前 netns 的
   全新 superblock，不揭示任何宿主内容。删除该拒绝并停止向新实例传播
   `MNT_LOCK_READONLY`（atime 锁仍保留）。写权限仍被 VFS mode 位 + 属性写回调的
   `capable(CAP_SYS_ADMIN)` 双重挡住。**实测**：`unshare -Urm` 挂 rw sysfs 从
   `EPERM`（24298cf8c）变为 `EXIT=0`（886338239）。

## 已知取舍

- rootless 容器必须 `--cgroups=disabled`：DroidSpaces 宿主 cgroup2 布局
  （`user.slice/user-1000.slice/...`）**没有 `pids` controller**（Android 系统
  cgroup 配置限制），crun 管理 cgroup 时直接报
  `controller 'pids' is not available`。`--cgroups=disabled` 绕过（crun 官方
  fallback）。
- **overlay 存储（fuse-overlayfs）已打通**：通过补齐内核 FUSE 模块中的 `fc->user_ns` UID/GID 转换机制（upstream 4.18），`fuse-overlayfs` 在 userns 下返回的 UID 0 可正确映射为容器 root 用户，根目录不再退化为 `nobody`，支持在 `~/.config/containers/storage.conf` 中开启 `driver = "overlay"`。
- **镜像加速**：手机网络下 `registry-1.docker.io` DNS 被污染（解析到
  `100.49.158.130`，connection reset）。已配置 `~/.config/containers/registries.conf`
  镜像：`docker.m.daocloud.io`（HTTP/2 401 = 正常 registry 响应）。
- 放宽后本内核不适合"多租户 userns 互不信任隔离"场景；单用户设备场景无实际风险面

## 运维注意（DroidSpaces 本体，非内核）

- **Magisk 模块禁用即全链路故障**：`/data/adb/modules/droidspaces/disable` 存在时
  post-fs-data 不执行 → daemon 不自启 + `droidspacesd` SELinux 域规则不注入 →
  手动启动 daemon 后 console/PTY 通道异常 → 容器 init 卡在 `n_tty_write`
  （wchan=`wait_woken`，PTY master 无人读）。症状：app 面板终端连不上、
  `podman run` 正常但 SSH 不通。恢复：删 disable → 重启。
- **开机后 1 分钟内启动容器必失败**（系统服务未就绪 → init exit 1）；开机
  6 分钟以上再启动稳定成功。

## 验证方法

```bash
# 1. 内核身份
uname -a                        # 应含最新编译时间

# 2. userns 挂 proc（8a1dcad1d 后应 OK）
python3 -u -c "
import os, ctypes
libc = ctypes.CDLL(None, use_errno=True)
os.unshare(os.CLONE_NEWUSER)
open('/proc/self/setgroups','w').write('deny')
open('/proc/self/uid_map','w').write('0 1000 1\n')
open('/proc/self/gid_map','w').write('0 1000 1\n')
os.unshare(os.CLONE_NEWPID | os.CLONE_NEWNS)
pid = os.fork()
if pid == 0:
    os.makedirs('/tmp/pt', exist_ok=True)
    r = libc.mount(b'proc', b'/tmp/pt', b'proc', 0, b'')
    print('PROC:', 'OK' if r==0 else 'errno %d' % ctypes.get_errno())
    os._exit(0)
os.waitpid(pid, 0)
"

# 3. FUSE（1695c442a 后应 OK）
podman unshare sh -c 'mkdir -p /tmp/fo && fuse-overlayfs -o lowerdir=/tmp/fo -o upperdir=/tmp/fo -o workdir=/tmp/fo /tmp/fo && echo FUSE-OK && fusermount -u /tmp/fo'

# 4. 全链路（24298cf8c 后应 OK）
podman run --rm --cgroups=disabled alpine echo hi

# 5. rw sysfs 挂载（886338239 后应 EXIT=0；此前 EPERM）
unshare -Urm sh -c 'mkdir -p /tmp/mnttest && mount -t sysfs sysfs /tmp/mnttest; echo EXIT=$?'

# 6. 容器内挂载完整性（24298cf8c netns 绑定）
podman run --rm --cgroups=disabled alpine ls /sys/class/net/   # 应显示 eth0（容器 veth）
```

## 红线（勿动）

- `CONFIG_NET_L3_MASTER_DEV`、`CONFIG_VLAN_8021Q` 绝不能开（wlan.ko ABI，bootloop）
