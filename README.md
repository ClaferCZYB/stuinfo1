# 在籍在读学生信息核查系统

学生输入**本人身份证号后 6 位**，即可在线查验自己在《在籍在读学生信息表》中所在行的完整信息。
纯静态页面，可直接部署到 **GitHub Pages**（也可用 Vercel / EdgeOne 等任意静态托管）。

## 安全设计（务必先读）

GitHub Pages 是**公开网站**，任何人都能下载页面文件。因此本系统**不是**"明文数据 + 口令比对"，
而是真正的加密查询：

| 措施 | 说明 |
|------|------|
| 全量加密 | `data.js` 中只有密文，**不存在任何明文**姓名 / 身份证号 / 电话 |
| 密钥派生 | `PBKDF2-HMAC-SHA256`（默认 5 万次迭代），口令 = 学生本人身份证后 6 位 + 构建 PEPPER |
| 逐条独立 | 每条记录独立盐值与密钥，破解一条不影响其他记录 |
| 完整性校验 | HMAC-SHA256 认证标签，密文被篡改时拒绝展示 |
| 防在线枚举 | 连错 5 次锁定 3 分钟；离开页面 5 分钟自动锁定 |
| 默认打码 | 身份证号、电话默认打码显示，需手动点击才展开 |

**风险边界（必须知晓）**：纯静态站点无法做到绝对安全。理论上攻击者可离线暴力枚举
10⁶ 种后六位组合——5 万次 PBKDF2 迭代下，单条记录枚举约需数小时至数天。
若需更强保护，可把 `--iter` 提高到 20 万（代价：核验等待时间变长），
或改用带服务端（如 Cloudflare Workers）的方案。

## 目录结构

```
student-info-check/
├── index.html              # 页面入口
├── assets/
│   ├── style.css           # 样式
│   ├── app.js              # 核验逻辑（WebCrypto，全部本地计算）
│   ├── data.js             # ★ 加密数据（构建脚本生成）
│   └── pepper.js           # ★ 构建密钥（构建脚本生成，勿外传完整项目）
├── tools/
│   ├── build_data.py       # ★ 数据构建脚本（xlsx → data.js）
│   └── selfcheck.py        # 自检脚本（验证加密/解密一致性）
└── README.md
```

## 部署到 GitHub Pages

1. 在 GitHub 新建仓库（如 `class-check`），把本目录除 `tools/` 外的文件推上去：
   ```bash
   cd student-info-check
   git init
   git add index.html assets/ README.md
   git commit -m "init: 学生信息核查系统"
   git branch -M main
   git remote add origin https://github.com/<你的用户名>/class-check.git
   git push -u origin main
   ```
2. 仓库 **Settings → Pages → Build and deployment → Source** 选
   `Deploy from a branch`，分支选 `main`，目录 `/ (root)`，保存。
3. 约 1 分钟后访问 `https://<你的用户名>.github.io/class-check/`。
   手机扫码即可使用（可将链接生成二维码贴在教室）。

> ⚠️ `assets/pepper.js` 会一并公开，这是设计内的（安全性主要来自 PBKDF2 迭代成本）。
> 但 `tools/.test_tails.json`（自检口令缓存）**绝不能上传**，`.gitignore` 已排除。

## 更新学生数据

表格数据变化后，重新运行构建脚本并推送即可：

```bash
python tools/build_data.py "D:/Days in Tong‘Nan/教育工作/在籍在读学生信息表（班主任版）.xlsx"
git add assets/data.js index.html
git commit -m "update: 更新学生数据"
git push
```

- 构建脚本会自动更新 `index.html` 里 `data.js` 的版本号，避免浏览器缓存旧数据。
- 默认读取 Sheet1、跳过姓名和身份证都为空的行；工作表不同时加 `--sheet 表名`。
- 若某两个学生身份证后六位重复，构建时会打印警告——需人工处理（一般不会发生）。
- 生成后建议跑一次自检：`python tools/selfcheck.py`。

## 常见问题

| 现象 | 原因与处理 |
|------|-----------|
| 提示"不支持安全加密模块" | WebCrypto 需要 HTTPS 或 localhost；确认通过 `https://` 访问 |
| 核验很慢（数秒） | 正常现象：56 条记录 × 5 万次 PBKDF2。手机约 1~3 秒 |
| 学生说"未找到匹配记录" | 核对是否输错（末位 X 需大写）；或该生信息未录入本次表格 |
| 想更换全体口令体系 | 删除 `assets/pepper.js` 后重新构建，所有记录将使用新 PEPPER 重新加密 |
