# -*- coding: utf-8 -*-
"""
自检脚本：验证 data.js 能被正确解密，且错误口令无法命中。
模拟前端 app.js 的同样流程（PBKDF2 -> HMAC idx -> HMAC-CTR -> 校验 tag）。

用法： python selfcheck.py
"""
import os
import re
import json
import hmac
import base64
import hashlib
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(ROOT, "assets")

sys.path.insert(0, HERE)
from build_data import pbkdf2, hmac_sha256, hmac_ctr_crypt  # noqa: E402


def load_js(path, varname):
    src = open(path, encoding="utf-8").read()
    m = re.search(r"%s\s*=\s*(.+?);\s*$" % varname, src, re.S)
    return json.loads(m.group(1)) if varname.endswith("DATA") else m.group(1).strip('"')


def main():
    data = load_js(os.path.join(ASSETS, "data.js"), "window.SIC_DATA")
    pepper = base64.b64decode(load_js(os.path.join(ASSETS, "pepper.js"), "window.SIC_PEPPER_B64"))
    recs = data["records"]
    it = data["meta"]["iter"]

    print("记录数：%d    迭代次数：%d" % (len(recs), it))

    # ---- 1. 全量正确口令解密测试 ----
    ok = 0
    for r in recs:
        rec_pw = None
        # 从 data.js 无法得知正确口令，这里由调用方提供测试口令表
        rec_pw = TEST_TAILS.get(r["idx"])
        if rec_pw is None:
            continue
        master = pbkdf2(pepper + rec_pw.encode(), base64.b64decode(r["salt"]), it)
        idx = hmac_sha256(master, b"idx")[:4].hex()
        if idx != r["idx"]:
            print("  ✗ 口令 %s 索引不匹配" % rec_pw)
            continue
        enc_key = hmac_sha256(master, b"enc")
        mac_key = hmac_sha256(master, b"mac")
        nonce = base64.b64decode(r["nonce"])
        ct = base64.b64decode(r["ct"])
        if hmac_sha256(mac_key, nonce + ct) != base64.b64decode(r["tag"]):
            print("  ✗ 口令 %s 完整性校验失败" % rec_pw)
            continue
        pt = json.loads(hmac_ctr_crypt(enc_key, nonce, ct).decode("utf-8"))
        ok += 1
        print("  ✓ %-6s -> %-6s  身份证 %s" % (rec_pw, pt["name"], pt["idCard"][:6] + "****" + pt["idCard"][-4:]))

    # ---- 2. 错误口令不得命中 ----
    found = 0
    for wrong in ["000000", "123456", "99999X", "12345X"]:
        for r in recs:
            master = pbkdf2(pepper + wrong.encode(), base64.b64decode(r["salt"]), it)
            if hmac_sha256(master, b"idx")[:4].hex() == r["idx"]:
                found += 1
    print("错误口令误命中次数：%d （应为 0）" % found)

    print("-" * 50)
    print("结果：%s" % ("全部通过 ✅" if found == 0 and ok == len(TEST_TAILS) else "存在问题 ❌"))


# 测试用：idx -> 正确后六位（由 build 时打印，或从 xlsx 现算）
def build_test_tails():
    import openpyxl
    sys.path.insert(0, HERE)
    from build_data import (DEFAULT_XLSX, DEFAULT_SHEET, DATA_START_ROW, C_ID, C_NAME,
                            load_or_create_pepper, read_rows, clean_id)

    pepper = load_or_create_pepper()
    wb_rows = read_rows(DEFAULT_XLSX, DEFAULT_SHEET)
    data = load_js(os.path.join(ASSETS, "data.js"), "window.SIC_DATA")
    it = data["meta"]["iter"]
    out = {}
    for vals in wb_rows:
        idc = clean_id(vals[C_ID])
        if len(idc) < 6:
            continue
        tail = idc[-6:].upper()
        master = pbkdf2(pepper + tail.encode(), b"", it)  # 占位，下面用真实 salt
        for r in data["records"]:
            m = pbkdf2(pepper + tail.encode(), base64.b64decode(r["salt"]), it)
            if hmac_sha256(m, b"idx")[:4].hex() == r["idx"]:
                out[r["idx"]] = tail
                break
    return out


if __name__ == "__main__":
    try:
        TEST_TAILS_PATH = os.path.join(HERE, ".test_tails.json")
        if os.path.exists(TEST_TAILS_PATH):
            TEST_TAILS = json.load(open(TEST_TAILS_PATH, encoding="utf-8"))
        else:
            print("首次运行，正在从 xlsx 生成测试口令表…")
            TEST_TAILS = build_test_tails()
            json.dump(TEST_TAILS, open(TEST_TAILS_PATH, "w", encoding="utf-8"), ensure_ascii=False)
            print("（已缓存到 tools/.test_tails.json，含明文口令，请勿上传仓库）")
    except Exception as e:
        print("无法生成测试口令表：%s" % e)
        sys.exit(1)
    main()
