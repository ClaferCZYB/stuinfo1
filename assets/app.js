/* 在籍在读学生信息核查系统 —— 前端核心逻辑
 * ---------------------------------------------------------------
 * 口令 = 学生本人身份证号后 6 位
 *   master = PBKDF2-HMAC-SHA256(PEPPER + 口令, salt_i, iter)
 *   idx    = HMAC-SHA256(master, "idx")[0:4]   -> 定位记录（不含口令信息）
 *   encKey = HMAC-SHA256(master, "enc")        -> HMAC-CTR 流加密密钥
 *   macKey = HMAC-SHA256(master, "mac")        -> 完整性校验
 * 全部计算在浏览器本地完成，不发送任何网络请求。
 */
(function () {
  'use strict';

  var DATA = window.SIC_DATA;
  var PEPPER_B64 = window.SIC_PEPPER_B64 || '';
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  var MAX_TRIES = 5;          // 连续失败上限
  var LOCK_MS = 3 * 60 * 1000; // 锁定时长
  var AUTO_LOCK_MS = 5 * 60 * 1000; // 无操作自动锁定
  var BATCH = 8;              // 并行派生批次

  var LS_FAIL = 'sic_fail_v1';
  var LS_LOCK = 'sic_lock_v1';
  var LS_OK = 'sic_confirmed_v1';

  var state = { rec: null, priv: null, revealed: false, timer: null };

  // ---------------------------------------------------------------- DOM
  var $ = function (id) { return document.getElementById(id); };
  var gateView = $('gateView'), resultView = $('resultView');
  var tailInput = $('tailInput'), verifyBtn = $('verifyBtn'), clearBtn = $('clearBtn');
  var errBox = $('errBox'), triesBox = $('triesBox'), groups = $('groups');
  var spinner = document.querySelector('#verifyBtn .spinner');
  var btnText = document.querySelector('#verifyBtn .btn-text');

  // ---------------------------------------------------------------- 初始化
  function init() {
    if (!window.crypto || !window.crypto.subtle) {
      $('insecureTip').hidden = false;
      verifyBtn.disabled = true;
      tailInput.disabled = true;
      return;
    }
    if (!DATA || !DATA.records || !DATA.records.length) {
      showError('数据未加载，请检查 assets/data.js 是否存在。');
      verifyBtn.disabled = true;
      return;
    }
    var m = DATA.meta || {};
    $('sysTitle').textContent = m.title || '在籍在读学生信息核查';
    $('sysSub').textContent = [m.school, m.className].filter(Boolean).join(' · ');
    $('sysMeta').innerHTML = [
      '登记人数 ' + m.count + ' 人',
      '数据更新 ' + (m.updated || '-'),
      '加密强度 PBKDF2 × ' + (m.iter || 0)
    ].map(function (t) { return '<span>' + esc(t) + '</span>'; }).join('');
    $('footMeta').textContent = '加密算法：' + (m.algo || '-');

    bindEvents();
    refreshLockState();
    tailInput.focus();
  }

  function bindEvents() {
    tailInput.addEventListener('input', function () {
      var v = tailInput.value.toUpperCase().replace(/[^0-9X]/g, '').slice(0, 6);
      if (v !== tailInput.value) tailInput.value = v;
      clearBtn.hidden = !v;
      hideError();
    });
    tailInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); doVerify(); }
    });
    clearBtn.addEventListener('click', function () {
      tailInput.value = ''; clearBtn.hidden = true; hideError(); tailInput.focus();
    });
    verifyBtn.addEventListener('click', doVerify);

    $('toggleMaskBtn').addEventListener('click', function () {
      state.revealed = !state.revealed;
      renderGroups();
      $('toggleMaskBtn').textContent = state.revealed ? '隐藏完整号码' : '显示完整号码';
      resetAutoLock();
    });
    $('lockBtn').addEventListener('click', lockNow);

    $('okBtn').addEventListener('click', function () {
      var key = LS_OK + '_' + (state.rec ? state.rec.idx : '');
      var t = new Date().toLocaleString('zh-CN', { hour12: false });
      try { localStorage.setItem(key, t); } catch (e) {}
      var n = $('confirmNote');
      n.hidden = false;
      n.textContent = '✓ 已记录：你于 ' + t + ' 确认信息核对无误。如需再次核对请重新核验。';
      toast('已标记为核对无误');
    });

    $('fixBtn').addEventListener('click', openFixModal);
    $('copyBtn').addEventListener('click', copyFixText);
    Array.prototype.forEach.call(document.querySelectorAll('[data-close]'), function (el) {
      el.addEventListener('click', function () { $('modal').hidden = true; });
    });
    $('modal').addEventListener('click', function (e) {
      if (e.target.hasAttribute('data-close')) $('modal').hidden = true;
    });

    document.addEventListener('visibilitychange', function () {
      if (document.hidden && state.rec) lockNow();
    });
  }

  // ---------------------------------------------------------------- 尝试次数 / 锁定
  function getFail() { try { return parseInt(localStorage.getItem(LS_FAIL) || '0', 10) || 0; } catch (e) { return 0; } }
  function setFail(n) { try { localStorage.setItem(LS_FAIL, String(n)); } catch (e) {} }
  function getLockUntil() { try { return parseInt(localStorage.getItem(LS_LOCK) || '0', 10) || 0; } catch (e) { return 0; } }
  function setLockUntil(t) { try { localStorage.setItem(LS_LOCK, String(t)); } catch (e) {} }

  function refreshLockState() {
    var left = getLockUntil() - Date.now();
    if (left > 0) {
      lockUI(left);
      return;
    }
    setLockUntil(0);
    if (getFail() > 0) {
      triesBox.hidden = false;
      triesBox.textContent = '已连续输错 ' + getFail() + ' 次，剩余 ' + (MAX_TRIES - getFail()) + ' 次机会';
    } else {
      triesBox.hidden = true;
    }
  }

  function lockUI(ms) {
    verifyBtn.disabled = true;
    tailInput.disabled = true;
    triesBox.hidden = false;
    var sec = Math.ceil(ms / 1000);
    triesBox.textContent = '尝试次数过多，请 ' + sec + ' 秒后重试';
    setTimeout(function () {
      var left = getLockUntil() - Date.now();
      if (left > 0) { lockUI(left); }
      else {
        verifyBtn.disabled = false; tailInput.disabled = false;
        setFail(0); triesBox.hidden = true; tailInput.focus();
      }
    }, 1000);
  }

  // ---------------------------------------------------------------- 核验主流程
  function doVerify() {
    var tail = tailInput.value.trim().toUpperCase();
    hideError();

    if (getLockUntil() > Date.now()) { refreshLockState(); return; }
    if (!/^[0-9]{5}[0-9X]$/.test(tail)) {
      showError('请输入 6 位号码：前 5 位为数字，末位为数字或字母 X。');
      flashError();
      return;
    }

    setLoading(true);
    var t0 = performance.now();

    lookup(tail).then(function (res) {
      // 防止过快响应暴露时序信息，最少展示 260ms 加载态
      var wait = Math.max(0, 260 - (performance.now() - t0));
      return new Promise(function (r) { setTimeout(function () { r(res); }, wait); });
    }).then(function (res) {
      setLoading(false);
      if (!res) {
        var n = getFail() + 1;
        setFail(n);
        if (n >= MAX_TRIES) {
          setLockUntil(Date.now() + LOCK_MS);
          setFail(0);
          showError('连续 ' + MAX_TRIES + ' 次核验失败，已临时锁定 3 分钟。');
        } else {
          showError('未找到匹配记录。请核对身份证号码后 6 位，或联系班主任确认登记信息。');
        }
        flashError();
        refreshLockState();
        return;
      }
      setFail(0);
      triesBox.hidden = true;
      state.rec = res.rec;
      state.priv = res.priv;
      state.revealed = false;
      $('toggleMaskBtn').textContent = '显示完整号码';
      showResult();
    }).catch(function (err) {
      setLoading(false);
      console.error(err);
      showError('核验过程出错：' + (err && err.message ? err.message : err) + '（请刷新页面重试）');
    });
  }

  function setLoading(on) {
    verifyBtn.disabled = on;
    tailInput.disabled = on;
    spinner.hidden = !on;
    btnText.textContent = on ? '正在核验…' : '核 验 并 查 看';
  }

  /** 遍历全部记录派生密钥并比对 idx，命中则解密 */
  function lookup(tail) {
    var recs = DATA.records;
    var iter = DATA.meta.iter;
    var pepper = b64ToBytes(PEPPER_B64);
    var pwBytes = concat(pepper, enc.encode(tail));

    return crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits'])
      .then(function (baseKey) {
        var chain = Promise.resolve(null);
        var i = 0;
        while (i < recs.length) {
          (function (slice) {
            chain = chain.then(function (hit) {
              if (hit) return hit;
              return Promise.all(slice.map(function (r) {
                return crypto.subtle.deriveBits(
                  { name: 'PBKDF2', salt: b64ToBytes(r.salt), iterations: iter, hash: 'SHA-256' },
                  baseKey, 256
                ).then(function (bits) { return new Uint8Array(bits); });
              })).then(function (masters) {
                var inner = Promise.resolve(null);
                slice.forEach(function (r, j) {
                  inner = inner.then(function (hit) {
                    if (hit) return hit;
                    return hmac(masters[j], enc.encode('idx')).then(function (h) {
                      if (toHex(h.slice(0, 4)) !== r.idx) return null;
                      return decrypt(masters[j], r);
                    });
                  });
                });
                return inner;
              });
            });
          })(recs.slice(i, i + BATCH));
          i += BATCH;
        }
        return chain;
      });
  }

  function decrypt(master, rec) {
    var nonce = b64ToBytes(rec.nonce);
    var ct = b64ToBytes(rec.ct);
    return Promise.all([
      hmac(master, enc.encode('enc')),
      hmac(master, enc.encode('mac'))
    ]).then(function (keys) {
      return hmac(keys[1], concat(nonce, ct)).then(function (tag) {
        if (toHex(tag) !== toHex(b64ToBytes(rec.tag))) {
          throw new Error('数据完整性校验失败');
        }
        return hmacCtr(keys[0], nonce, ct);
      });
    }).then(function (pt) {
      return { rec: rec, priv: JSON.parse(dec.decode(pt)) };
    });
  }

  // ---------------------------------------------------------------- 加密原语
  function hmac(keyBytes, msg) {
    return crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign('HMAC', k, msg); })
      .then(function (sig) { return new Uint8Array(sig); });
  }

  /** HMAC-SHA256 生成 keystream 的 CTR 流加密（加解密同函数） */
  function hmacCtr(keyBytes, nonce, data) {
    var out = new Uint8Array(data.length);
    var pos = 0, counter = 0;
    function step() {
      if (pos >= data.length) return Promise.resolve(out);
      return hmac(keyBytes, concat(nonce, u32(counter))).then(function (block) {
        var n = Math.min(block.length, data.length - pos);
        for (var k = 0; k < n; k++) out[pos + k] = data[pos + k] ^ block[k];
        pos += n; counter++;
        return step();
      });
    }
    return step();
  }

  function u32(n) {
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  }

  function concat(a, b) {
    var r = new Uint8Array(a.length + b.length);
    r.set(a, 0); r.set(b, a.length);
    return r;
  }

  function b64ToBytes(b64) {
    var bin = atob(b64), r = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) r[i] = bin.charCodeAt(i);
    return r;
  }

  function toHex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += ('0' + u8[i].toString(16)).slice(-2);
    return s;
  }

  // ---------------------------------------------------------------- 结果渲染
  var GROUPS = [
    {
      title: '基本信息',
      keys: ['name', 'idCard', 'className', 'status', 'boarding']
    },
    {
      title: '户籍信息',
      keys: ['hjArea', 'hjTown', 'hjVillage']
    },
    {
      title: '监护人信息',
      keys: ['fatherName', 'fatherId', 'motherName', 'motherId']
    },
    {
      title: '联系方式',
      keys: ['phone', 'phone2', 'note']
    },
    {
      title: '学籍登记信息',
      keys: ['seq', 'schCode', 'schName', 'stage']
    }
  ];

  function fieldDef(key) {
    var all = (DATA.privFields || []).concat(DATA.pubFields || []);
    for (var i = 0; i < all.length; i++) if (all[i].key === key) return all[i];
    return { key: key, label: key };
  }

  function valueOf(key) {
    var p = state.priv, pub = state.rec ? state.rec.pub : {};
    if (p && Object.prototype.hasOwnProperty.call(p, key)) return p[key];
    return pub[key] || '';
  }

  function maskValue(key, val) {
    if (state.revealed) return val;
    var def = fieldDef(key);
    if (!def.sensitive) return val;
    if (key === 'phone' || key === 'phone2') {
      return String(val).split('/').map(function (p) {
        p = p.trim();
        var d = p.replace(/\D/g, '');
        if (d.length >= 7) {
          var head = d.slice(0, 3), tail = d.slice(-4);
          return head + '****' + tail;
        }
        return p;
      }).join(' / ');
    }
    if (key === 'idCard' || key === 'fatherId' || key === 'motherId') {
      var s = String(val);
      if (s.length >= 10) return s.slice(0, 6) + '********' + s.slice(-4);
      return s.replace(/./g, '*');
    }
    return val;
  }

  function renderGroups() {
    var html = '';
    GROUPS.forEach(function (g) {
      var rows = '';
      g.keys.forEach(function (key) {
        var raw = valueOf(key);
        var def = fieldDef(key);
        var shown = maskValue(key, raw);
        var cls = 'row-value' + (raw ? '' : ' empty');
        var content;
        if (!raw) {
          content = '<span class="' + cls + '">未登记</span>';
        } else {
          var isMasked = def.sensitive && !state.revealed;
          content = '<span class="' + cls + '"><span class="mono">' + esc(shown) + '</span>' +
            (isMasked ? '<button class="eye" data-eye="' + key + '">显示</button>' : '') + '</span>';
        }
        rows += '<div class="row"><div class="row-label">' + esc(def.label) + '</div>' +
          '<div class="row-value-wrap">' + content + '</div></div>';
      });
      html += '<div class="group"><div class="group-title">' + g.title + '</div>' + rows + '</div>';
    });
    groups.innerHTML = html;

    Array.prototype.forEach.call(groups.querySelectorAll('[data-eye]'), function (btn) {
      btn.addEventListener('click', function () {
        state.revealed = true;
        renderGroups();
        $('toggleMaskBtn').textContent = '隐藏完整号码';
        resetAutoLock();
      });
    });
  }

  function showResult() {
    var p = state.priv, pub = state.rec.pub;
    var name = p.name || '同学';
    $('resAvatar').textContent = name.charAt(0);
    $('resName').textContent = name;
    $('resClass').textContent = [pub.schName, pub.className].filter(Boolean).join(' · ');
    $('resStatus').textContent = pub.status || '在籍在读';

    renderGroups();

    var confirmed = '';
    try { confirmed = localStorage.getItem(LS_OK + '_' + state.rec.idx) || ''; } catch (e) {}
    var n = $('confirmNote');
    if (confirmed) {
      n.hidden = false;
      n.textContent = '✓ 你曾于 ' + confirmed + ' 确认信息核对无误。';
    } else {
      n.hidden = true;
    }

    gateView.hidden = true;
    resultView.hidden = false;
    window.scrollTo(0, 0);
    resetAutoLock();
  }

  function resetAutoLock() {
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(function () {
      if (state.rec) { lockNow(); toast('长时间未操作，已自动锁定'); }
    }, AUTO_LOCK_MS);
  }

  function lockNow() {
    if (state.timer) clearTimeout(state.timer);
    state.rec = null; state.priv = null; state.revealed = false;
    groups.innerHTML = '';
    resultView.hidden = true;
    gateView.hidden = false;
    tailInput.value = '';
    clearBtn.hidden = true;
    hideError();
    tailInput.focus();
  }

  // ---------------------------------------------------------------- 更正申请
  function openFixModal() {
    var p = state.priv, pub = state.rec.pub;
    var lines = [];
    lines.push('【学生信息更正申请】');
    lines.push('班级：' + (pub.className || ''));
    lines.push('姓名：' + (p.name || ''));
    lines.push('核对时间：' + new Date().toLocaleString('zh-CN', { hour12: false }));
    lines.push('');
    lines.push('以下项目中，需要更正的请保留并在后面写出正确内容，其余请删除：');
    lines.push('');
    var n = 1;
    GROUPS.forEach(function (g) {
      g.keys.forEach(function (key) {
        var v = valueOf(key);
        if (!v) return;
        lines.push(n + '. ' + fieldDef(key).label + '：' + v + '　→ 正确内容为：');
        n++;
      });
    });
    lines.push('');
    lines.push('（更正依据：户口本 / 身份证 / 其他）');
    $('fixText').value = lines.join('\n');
    $('modal').hidden = false;
    resetAutoLock();
  }

  function copyFixText() {
    var ta = $('fixText');
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) {}
    if (!ok && navigator.clipboard) {
      navigator.clipboard.writeText(ta.value).then(function () { toast('已复制到剪贴板'); });
      return;
    }
    toast(ok ? '已复制到剪贴板' : '复制失败，请长按选中后手动复制');
  }

  // ---------------------------------------------------------------- 小工具
  function showError(msg) { errBox.hidden = false; errBox.textContent = msg; }
  function hideError() { errBox.hidden = true; }
  function flashError() { tailInput.classList.add('is-error'); setTimeout(function () { tailInput.classList.remove('is-error'); }, 900); }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  var toastTimer = null;
  function toast(msg) {
    var t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 2200);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
