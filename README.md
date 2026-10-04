# 卫星载荷镜像 Overlay 审计服务

归档工程师在载荷镜像入库前，用本服务确认多层交付物按 OCI 白化（whiteout）
规则叠加后，不会保留已撤销的校准文件或错误继承下层内容。

调用方以审计标识向 `POST /audits` 提交 **1–6 层**（自底向上排列）的
`base64(gzip(tar))` 数据；服务逐层严格校验后在内存中构建联合文件树，
冻结最终裁决。`GET /audits/{id}` 返回冻结的最终路径清单、每条路径的
来源层以及删除证据；`GET /audits/{id}/history?path=<路径>` 按规范路径
返回创建、覆盖、白化、opaque 清除与重建的完整演变。任一层失败，整个
审计被拒绝，不留下部分裁决。

## 运行（Docker Compose）

```bash
docker compose build
docker compose up --abort-on-container-exit --exit-code-from verify
echo "verify exit code: $?"
```

* `app`：审计服务。宿主端口可配置：`AUDIT_HOST_PORT=9000 docker compose up app`
  （默认 `8080`）。Compose 健康检查打 `/healthz`。
* `verify`：依赖 `app` 健康后启动，**先**运行白化规则单元测试与构建检查
  （`compileall` 字节编译），**再**提交含 opaque 清除、目录替换与重建的
  审计并读回最终结果，随后对一条路径读取完整演变（`…/history`）做 HTTP
  冒烟，最后以退出码结束（0 = 全部通过）。

无 Docker 时本地等价流程：

```bash
python3 -m unittest discover -s tests -t . -v   # 白化规则测试
python3 -m compileall -q app tests              # 构建检查
PORT=8080 python3 -m app.server &               # 启动服务
APP_ADDR=http://127.0.0.1:8080 python3 -m app.smoke
```

## API

### `POST /audits`

```json
{
  "id": "run-2026-10-03-a",
  "layers": ["H4sIAAAAAAAC/...", "..."]
}
```

* `id`：审计标识，`[A-Za-z0-9._-]`，1–128 字符；冻结后不可复用（重复 `409`）。
* `layers`：1–6 个元素，`layers[0]` 为最底层。
* 成功：`201` + 冻结结果；校验失败：`400 {"error": "layer N: ..."}`，不存任何状态。

### `GET /audits/{id}`

```json
{
  "id": "run-2026-10-03-a",
  "layerCount": 3,
  "paths": [
    {"path": "payload/calib/gain.txt", "type": "file", "layer": 2},
    {"path": "payload/calib/gain.link", "type": "file", "layer": 2,
     "link": "payload/calib/gain.txt"}
  ],
  "deletions": [
    {"path": "payload/calib/gain.txt", "layer": 0, "kind": "whiteout",
     "byLayer": 1, "via": "payload/calib/.wh.gain.txt"}
  ]
}
```

* `paths[].layer`：路径来源层（0 = 最底层）；硬链接条目附 `link` 目标。
* `deletions[]`：删除证据。`kind` ∈ `whiteout`（`.wh.<name>` 删除）、
  `opaque`（`.wh..wh..opq` 清空下层子项）、`replaced`（文件/目录替换，
  目录被替换时其整棵子树逐条记录）；`byLayer` 为执行删除的层，`via`
  为触发该删除的条目路径。
* 另有 `GET /audits`（列出已冻结 id）与 `GET /healthz`。

### `GET /audits/{id}/history?path=<path>`

按**规范相对路径**读取一条路径自底向上的完整演变，供复核工程师追查最终
路径为何存在或为何消失：

```json
{
  "id": "run-2026-10-03-a",
  "path": "payload/calib/gain.txt",
  "status": "present",
  "final": {"type": "file", "layer": 2},
  "history": [
    {"action": "create", "layer": 0, "via": "payload/calib/gain.txt",
     "beforeType": null, "afterType": "file"},
    {"action": "whiteout", "layer": 1,
     "via": "payload/calib/.wh.gain.txt",
     "beforeType": "file", "afterType": null},
    {"action": "recreate", "layer": 2, "via": "payload/calib/gain.txt",
     "beforeType": null, "afterType": "file"}
  ]
}
```

* 事件严格按层顺序排列，`action` ∈ `create`（创建）、`overwrite`（覆盖，
  含文件↔目录类型替换）、`whiteout`（白化删除）、`opaque`（opaque 清除）、
  `recreate`（删除后重新创建）。每个事件保留：`layer`（执行动作的来源层）、
  `via`（触发该动作的 TAR 条目路径）、`beforeType`/`afterType`
  （动作前后的 `file`/`dir`/`null`）。
* 目录被文件替换或被白化/opaque 清除时，其后代路径同样返回解释消失的
  **祖先动作**（`via` 指向祖先条目，`afterType: null`）；后代在后续层重新
  创建时历史保持连续，`final.layer` 与 `GET /audits/{id}` 的最终来源一致。
* `status`：`present`（最终存在，附 `final`）或 `deleted`（已消失且未重建，
  `final: null`）。路径合法但从未在任何层出现过，返回 200
  `{"status": "untracked", "history": []}`；非法路径（绝对路径、`..`、
  空/`.` 分量、尾斜杠）或缺少 `path` 参数返回 `400`；审计 id 不存在返回
  `404`，且不泄露任何历史片段（未冻结的审计不存任何状态）。

## 层校验规则（`app/tarparse.py`）

每层必须是**恰好一个被完整消费的 gzip 成员**，解压出**恰好一个 TAR 归档**：

* 512 字节块对齐；ustar 头校验和逐块核验；数字字段必须是八进制
  （拒绝 base-256）；文件数据后零填充；两个零块结束标记，之后只允许零填充；
  gzip 成员之后有任何字节（含第二个成员）即拒绝。
* 只接受目录、普通文件、硬链接；符号链接、设备、FIFO、PAX/GNU 扩展头一律拒绝。
* 路径必须相对且规范：拒绝绝对路径、`..` 穿越、`.`/空分量、文件尾斜杠。
* 层内重复规范路径拒绝；硬链接目标必须在本层先前出现且当前仍存在
  （悬空链接拒绝）。

## 白化裁决规则（`app/engine.py`）

* `.wh.<name>`：删除同目录下 `<name>` 及其子树；白化条目本身不进结果。
* `.wh..wh..opq`：所在目录对下层不透明——清除该目录所有来自下层的子项，
  本层新增子项保留，目录本身保留下层来源层。
* 普通条目覆盖下层不同类型条目（文件↔目录）；目录被替换时删除其整棵子树；
  同层后层文件取代前层文件记为 `replaced` 证据；重复声明目录不改变其来源层。
* 被白化删除的路径可在后续层重新创建，来源层记为新层。
* 裁决同时冻结每条出现过的路径的演变事件流（创建/覆盖/白化/opaque/重建），
  供 `…/history` 按路径追查；目录被替换时其后代继承祖先动作。
* 所有层在私有树上裁决，任一失败整体抛弃——审计是原子的。

## 资源限制

请求体 ≤ 64 MiB；单层压缩后 ≤ 16 MiB、解压后 ≤ 64 MiB；单层条目 ≤ 4096；
单文件 ≤ 32 MiB；层数 1–6。
