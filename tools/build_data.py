# -*- coding: utf-8 -*-
"""
在籍在读学生信息核查系统 —— 数据构建脚本
==========================================
用途：从「在籍在读学生信息表（班主任版）.xlsx」生成前端可用的加密数据文件 assets/data.js

安全设计（重要）
----------------
1. data.js 中不存在任何明文的姓名 / 身份证号 / 电话号码，只有密文与盐值。
2. 密钥派生：master = PBKDF2-HMAC-SHA256(PEPPER + 身份证后六位, salt_i, ITER)
   - PEPPER 是构建时随机生成的常量，保存在 assets/pepper.js（与 data.js 分离）
   - salt_i 每条记录独立随机
3. 记录定位：idx = HMAC-SHA256(master, "idx")[:4]，避免直接存口令索引被反查。
4. 数据加密：HMAC-SHA256-CTR 流加密 + HMAC-SHA256 认证标签（Encrypt-then-MAC）。
5. 因此：拿到 data.js 的人，必须对每个后六位组合跑 5 万次 PBKDF2 才能试出一条记录，
   暴力枚举全班约需数天～数月（取决于设备），且可通过提高 ITER 继续加码。

用法
----
    python build_data.py                          # 使用默认 xlsx 路径
    python build_data.py "D:/path/to/表.xlsx"      # 指定文件
    python build_data.py --iter 50000             # 提高迭代次数（更安全，但更慢）
"""

import os
import re
import sys
import json
import hmac
import base64
import hashlib
import datetime
import argparse

try:
    import openpyxl
except ImportError:
    sys.exit("缺少依赖 openpyxl，请先安装：pip install openpyxl")

# ----------------------------------------------------------------------------
# 配置
# ----------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(ROOT, "assets")
DATA_JS = os.path.join(ASSETS, "data.js")
PEPPER_JS = os.path.join(ASSETS, "pepper.js")

DEFAULT_XLSX = r"D:/Days in Tong‘Nan/教育工作/在籍在读学生信息表（班主任版）.xlsx"
DEFAULT_SHEET = "Sheet1"
HEADER_ROW = 4          # 表头占前 4 行（0-based index 0..3），数据从第 5 行开始
DEFAULT_ITER = 50000    # PBKDF2 迭代次数
DATA_START_ROW = 5      # Excel 中的行号（1-based）

# 列索引（0-based），对应 Sheet1 的 X0~X18
C_SEQ, C_SCHCODE, C_SCHNAME, C_STAGE, C_NAME, C_ID, C_CLASS, C_STATUS, \
    C_BOARD, C_HJ_AREA, C_HJ_TOWN, C_HJ_VILL, C_FNAME, C_FID, C_MNAME, \
    C_MID, C_TEL, C_TEL2 = range(18)

# 公开字段（全班一致，无个人隐私风险，明文存放）
PUB_FIELDS = [
    {"key": "seq", "label": "序号"},
    {"key": "schCode", "label": "学校代码"},
    {"key": "schName", "label": "规范简称"},
    {"key": "stage", "label": "学段"},
    {"key": "className", "label": "年级班级"},
    {"key": "status", "label": "就读状态"},
]

# 私密字段（加密存放），sensitive=True 的默认打码展示
PRIV_FIELDS = [
    {"key": "name", "label": "姓名"},
    {"key": "idCard", "label": "身份证号码", "sensitive": True},
    {"key": "boarding", "label": "是否住校"},
    {"key": "hjArea", "label": "户籍所在区域"},
    {"key": "hjTown", "label": "区内户籍所属镇街"},
    {"key": "hjVillage", "label": "区内户籍所属村居"},
    {"key": "fatherName", "label": "学生父亲姓名"},
    {"key": "fatherId", "label": "父亲身份证号码", "sensitive": True},
    {"key": "motherName", "label": "学生母亲姓名"},
    {"key": "motherId", "label": "母亲身份证号码", "sensitive": True},
    {"key": "phone", "label": "监护人联系电话", "sensitive": True},
    {"key": "phone2", "label": "备用联系电话", "sensitive": True},
    {"key": "note", "label": "特殊情况备注"},
]

PRIV_KEYS = [f["key"] for f in PRIV_FIELDS]


# ----------------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------------
def clean(v):
    """把单元格值清洗成字符串：去空格换行、处理 float 尾巴。"""
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = str(v)
    s = s.replace("\u00a0", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = re.sub(r"\s+", " ", s).strip()
    if s in ("None", "nan", "/", "-", "无"):
        return ""
    return s


def clean_id(v):
    """身份证号：去空格、X 大写。"""
    s = clean(v).replace(" ", "").upper()
    if s.endswith(".0"):
        s = s[:-2]
    return s


def clean_phone(v):
    """电话：单元格里可能有多个号码（换行/空格分隔），统一用 / 连接。"""
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    raw = str(v)
    parts = [p.strip() for p in re.split(r"[\r\n\t,，;；、/|]+", raw) if p.strip()]
    parts = [re.sub(r"\s+", "", p) if re.search(r"\d", p) else p for p in parts]
    return " / ".join(parts)


def looks_like_phone(s):
    """判断内容是否像电话号码（用于区分「备用电话」与「备注」）。"""
    if not s:
        return False
    digits = re.sub(r"\D", "", s)
    return len(digits) >= 7 and len(digits) <= 20 and len(digits) / max(len(s), 1) > 0.6


def b64(b):
    return base64.b64encode(b).decode("ascii")


def pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int = 32):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hmac_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 生成 keystream 的 CTR 模式流加密（加解密同函数）。"""
    out = bytearray()
    counter = 0
    pos = 0
    while pos < len(data):
        block = hmac_sha256(key, nonce + counter.to_bytes(4, "big"))
        chunk = data[pos:pos + len(block)]
        out.extend(a ^ b for a, b in zip(chunk, block))
        pos += len(block)
        counter += 1
    return bytes(out)


def encrypt_record(pepper: bytes, tail6: str, salt: bytes, nonce: bytes,
                   iterations: int, plaintext: bytes):
    """派生密钥并加密一条记录，返回 (idx_hex, ciphertext, tag)。"""
    master = pbkdf2(pepper + tail6.encode("utf-8"), salt, iterations)
    idx = hmac_sha256(master, b"idx")[:4].hex()
    enc_key = hmac_sha256(master, b"enc")
    mac_key = hmac_sha256(master, b"mac")
    ct = hmac_ctr_crypt(enc_key, nonce, plaintext)
    tag = hmac_sha256(mac_key, nonce + ct)
    return idx, ct, tag


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
def load_or_create_pepper():
    """读取已有的 pepper；不存在则随机生成 32 字节。"""
    if os.path.exists(PEPPER_JS):
        m = re.search(r'PEPPER_B64\s*=\s*"([^"]+)"', open(PEPPER_JS, encoding="utf-8").read())
        if m:
            return base64.b64decode(m.group(1))
    pepper = os.urandom(32)
    os.makedirs(ASSETS, exist_ok=True)
    with open(PEPPER_JS, "w", encoding="utf-8") as f:
        f.write(
            "// 自动生成，请勿手工修改。\n"
            "// 该文件与 data.js 分离存放，重建数据时若此文件存在则会自动复用。\n"
            "// 若怀疑此密钥泄露，删除本文件后重新运行 build_data.py 即可全部重新加密。\n"
            'window.SIC_PEPPER_B64 = "%s";\n' % b64(pepper)
        )
    return pepper


def read_rows(xlsx_path, sheet_name):
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb[sheet_name] if sheet_name in wb.sheetnames else wb.worksheets[0]
    rows = []
    for r in ws.iter_rows(min_row=DATA_START_ROW, max_row=ws.max_row, values_only=True):
        vals = [clean(x) for x in r[:18]]
        if not vals[C_NAME] and not vals[C_ID]:
            continue  # 空行跳过
        rows.append(vals)
    return rows


def build(xlsx_path, sheet_name, iterations):
    pepper = load_or_create_pepper()
    raw_rows = read_rows(xlsx_path, sheet_name)
    if not raw_rows:
        sys.exit("未读取到任何学生数据，请检查 xlsx 路径与工作表名。")

    records = []
    warnings = []
    tail_map = {}

    for vals in raw_rows:
        idcard = clean_id(vals[C_ID])
        if len(idcard) < 6:
            warnings.append("序号 %s（%s）身份证号长度不足，已跳过" % (vals[C_SEQ], vals[C_NAME]))
            continue
        tail6 = idcard[-6:].upper()

        # 后六位冲突检测
        if tail6 in tail_map:
            warnings.append(
                "警告：身份证后六位 %s 重复（%s 与 %s），两人中只能有一人被正常检索到"
                % (tail6, tail_map[tail6], vals[C_NAME])
            )
        tail_map[tail6] = vals[C_NAME]

        tel2 = clean_phone(vals[C_TEL2])
        if tel2 and not looks_like_phone(tel2):
            note, phone2 = tel2, ""      # 不像电话 -> 归到备注
        else:
            note, phone2 = "", tel2

        priv = {
            "name": vals[C_NAME],
            "idCard": idcard,
            "boarding": vals[C_BOARD],
            "hjArea": vals[C_HJ_AREA],
            "hjTown": vals[C_HJ_TOWN],
            "hjVillage": vals[C_HJ_VILL],
            "fatherName": vals[C_FNAME],
            "fatherId": clean_id(vals[C_FID]),
            "motherName": vals[C_MNAME],
            "motherId": clean_id(vals[C_MID]),
            "phone": clean_phone(vals[C_TEL]),
            "phone2": phone2,
            "note": note,
        }
        pub = {
            "seq": vals[C_SEQ],
            "schCode": vals[C_SCHCODE],
            "schName": vals[C_SCHNAME],
            "stage": vals[C_STAGE],
            "className": vals[C_CLASS],
            "status": vals[C_STATUS],
        }

        plaintext = json.dumps({k: priv[k] for k in PRIV_KEYS}, ensure_ascii=False).encode("utf-8")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        idx, ct, tag = encrypt_record(pepper, tail6, salt, nonce, iterations, plaintext)

        records.append({
            "idx": idx,
            "salt": b64(salt),
            "nonce": b64(nonce),
            "tag": b64(tag),
            "ct": b64(ct),
            "pub": pub,
        })

    # 班级名取出现最多的
    classes = [r["pub"]["className"] for r in records if r["pub"]["className"]]
    class_name = max(set(classes), key=classes.count) if classes else ""
    schools = [r["pub"]["schName"] for r in records if r["pub"]["schName"]]
    school_name = max(set(schools), key=schools.count) if schools else ""

    data = {
        "meta": {
            "title": "在籍在读学生信息核查",
            "school": school_name,
            "className": class_name,
            "count": len(records),
            "updated": datetime.date.today().isoformat(),
            "iter": iterations,
            "algo": "PBKDF2-HMAC-SHA256 + HMAC-SHA256-CTR + HMAC-SHA256 tag",
        },
        "pubFields": PUB_FIELDS,
        "privFields": PRIV_FIELDS,
        "records": records,
    }

    os.makedirs(ASSETS, exist_ok=True)
    with open(DATA_JS, "w", encoding="utf-8") as f:
        f.write("// 自动生成，请勿手工修改。重新生成请运行 tools/build_data.py\n")
        f.write("// 本文件不含任何明文个人信息，全部字段均已加密。\n")
        f.write("window.SIC_DATA = ")
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        f.write(";\n")

    # 更新 index.html 中 data.js 的版本参数，避免浏览器缓存旧数据
    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    idx_path = os.path.join(ROOT, "index.html")
    if os.path.exists(idx_path):
        html = open(idx_path, encoding="utf-8").read()
        new_html = re.sub(r'(assets/data\.js\?v=)[^"\']+', r"\g<1>" + stamp, html)
        if new_html != html:
            with open(idx_path, "w", encoding="utf-8") as f:
                f.write(new_html)
            print("已更新 index.html 中 data.js 版本号 -> %s" % stamp)

    print("=" * 60)
    print("生成完成：%s" % DATA_JS)
    print("  学生记录数：%d" % len(records))
    print("  学校 / 班级：%s  %s" % (school_name, class_name))
    print("  PBKDF2 迭代：%d 次" % iterations)
    print("  文件大小：%.1f KB" % (os.path.getsize(DATA_JS) / 1024.0))
    if warnings:
        print("-" * 60)
        for w in warnings:
            print("  ! " + w)
    print("=" * 60)


def main():
    ap = argparse.ArgumentParser(description="生成学生信息核查系统的加密数据文件")
    ap.add_argument("xlsx", nargs="?", default=DEFAULT_XLSX, help="xlsx 源文件路径")
    ap.add_argument("--sheet", default=DEFAULT_SHEET, help="工作表名，默认 Sheet1")
    ap.add_argument("--iter", type=int, default=DEFAULT_ITER, help="PBKDF2 迭代次数，默认 50000")
    args = ap.parse_args()
    build(args.xlsx, args.sheet, args.iter)


if __name__ == "__main__":
    main()
