# Vireo

Vireo 是使用 C11 编写、面向 Linux 的事件驱动对象存储与虚拟文件服务项目。

当前可运行入口是 `vireo-auth-server`：提供 TLS 1.3 下的 REGISTER、LOGIN、LOGOUT、SESSION_RESUME、NODE_ROOT、NODE_STAT 和 NODE_LIST，使用 MySQL 保存身份和目录元数据。LIST 支持带分页 token 的目录遍历；上传、下载和完整客户端尚未完成。

认证后先用 NODE_ROOT 获取真实根 ID，再以显式目录 ID 和每页 1～64 项调用 NODE_LIST。响应带 MORE 时，用新的请求 sequence 和返回的 96 字节 token 获取下一页；token 绑定用户、持久会话、目录和页大小，整条分页链有效期为 10 分钟。同一持久会话通过 RESUME 恢复后可继续，新 LOGIN 或服务重启会使旧 token 失效。

分页按节点 ID 递增，每页重新授权，不提供跨页快照或总数。翻页期间目录发生变化可能影响后续页；节点 ID 和 token 都不是授权凭据。

## 构建与测试

需要 C11 编译器、CMake 3.20+、pthread、OpenSSL 3.x、pkg-config、libargon2（20190702+）和 MySQL 客户端开发库。启用测试还需要 Python 3、`mysqld` 和 `mysql`；数据库集成测试会自动创建独立本地实例。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON -DVIREO_ENABLE_ASAN=ON -DVIREO_ENABLE_UBSAN=ON
cmake --build build -j 4
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build --output-on-failure
```

构建默认启用严格警告。真实 MySQL 测试需要足够的临时目录空间，夹具保留诊断和数据库数据；可用 `TMPDIR` 指定所在文件系统。

## 运行当前服务端

```text
vireo-auth-server ADDRESS PORT CERT_FILE KEY_FILE MYSQL_SOCKET MYSQL_USER PASSWORD_FILE DATABASE SESSION_LIFETIME_MS
```

例如，将证书、私钥及数据库密码文件准备好后：

```sh
./build/vireo-auth-server 127.0.0.1 8443 cert.pem key.pem \
  /run/mysqld/mysqld.sock vireo db-password.txt vireo 3600000
```

`ADDRESS` 是 IPv4 地址，`SESSION_LIFETIME_MS` 是正毫秒数。密码通过文件读取；MySQL 账户须能执行启动时的 schema migration 和运行时业务。服务打印 `vireo-auth-server ready` 后开始处理请求，SIGINT/SIGTERM 触发有序关闭。客户端须使用 Vireo 二进制协议和 TLS 1.3。

当前生产装配最多接入 32 个连接，并显式启用以下策略：

| 阶段 | 时限 | 续期条件 |
|---|---:|---|
| TLS 握手 | 5 秒 | 固定总期限 |
| TLS 建立后未认证 | 30 秒 | 成功 LOGIN/RESUME 后切换为空闲期限 |
| 单帧收齐 | 10 秒 | 首字节开始，后续字节不延长 |
| 已认证空闲 | 60 秒 | 成功绑定身份或完整合法请求移交 worker |

连接期限使用单调时钟；时间轮刻度为 100 毫秒，实际释放还需有限调度和清理轮次。会话过期或本地撤销后重新进入未认证期。超时关闭不会强制中止已开始的数据库操作，迟到结果仍按完整连接代次核验；业务任务另有 10 秒软期限。

这些值目前由生产装配显式设置，CLI 尚无调整参数；库调用者可在接客前通过 `auth_service_deadline.h` 的显式接口配置。未启用该接口的旧服务调用者继续负责连接超时管理。
