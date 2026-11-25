#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""aiNote / aiTextControl API 客户端（hyperos_sec_common 签名链）

鉴权链（从 notes APK 逆向还原，全部源码钉死）：
1. passport serviceLogin?sid=hyperos_sec_common → serviceToken:securityKey
2. 业务参数值 AES/CBC/PKCS5Padding 加密（key=Base64.decode(securityKey), IV="0102030405060708"）
3. signature=Base64(SHA1(METHOD & path & sorted_encrypted_params & securityKey))
4. POST: params 做 form-urlencoded body
5. 响应 AES/CBC 解密（同一 key/IV）
6. SSE 流式：每个 data: chunk 独立 Base64 decode + AES decrypt
"""
import base64, hashlib, json, os, time, urllib.parse, urllib.request
from urllib.error import HTTPError

HERE = os.path.dirname(os.path.abspath(__file__))
AUTH_FILE = os.path.join(HERE, ".runtime", "mi_auth.json")
ACCOUNT_HOST = "https://account.xiaomi.com"
AI_ENGINE = "https://ai.engine.miui.com"
SID = "hyperos_sec_common"
AES_IV = b"0102030405060708"
PC_UA = "APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f Chrome/144.0.7559.111"

# token 缓存（避免每次都走 passport 两步）
_token_cache = {"token": None, "cuser_id": None, "ts": 0}
TOKEN_TTL = 3600  # 1小时


def _load_auth():
    with open(AUTH_FILE, encoding="utf-8") as f:
        return json.load(f)


def _strip(s):
    return s.split("&&&START&&&", 1)[-1] if "&&&START&&&" in s else s


def _cookies(headers):
    out = {}
    try:
        raw = headers.get_all("Set-Cookie") or []
    except Exception:
        raw = []
    for item in raw:
        head = item.split(";")[0].strip()
        if "=" in head:
            k, v = head.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _http_get(url, cookie=None, timeout=30):
    hdrs = {"User-Agent": PC_UA, "Accept": "*/*"}
    if cookie:
        hdrs["Cookie"] = cookie
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None
    op = urllib.request.build_opener(NoRedirect)
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except Exception as e:
        return 0, f"<{type(e).__name__}: {e}>", {}


def aes_encrypt(plaintext, security_key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    key = base64.b64decode(security_key)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(AES_IV))
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(ct).decode("ascii")


def aes_decrypt(ciphertext_b64, security_key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    key = base64.b64decode(security_key)
    ct = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(AES_IV))
    dec = cipher.decryptor()
    data = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(data) + unpadder.finalize()
    return plaintext.decode("utf-8", "replace")


def get_token():
    """获取 hyperos_sec_common serviceToken（带缓存）"""
    now = time.time()
    if _token_cache["token"] and (now - _token_cache["ts"]) < TOKEN_TTL:
        return _token_cache["token"], _token_cache["cuser_id"]

    auth = _load_auth()
    pt = auth.get("passToken", "")
    uid = auth.get("userId", "")
    cid = auth.get("cUserId", "")
    devid = auth.get("deviceId", "pc_5b441f841b04d031e54fcba518aff353")
    if not pt:
        raise RuntimeError("no passToken in mi_auth.json")

    parts = [f"passToken={pt}", f"userId={uid}"]
    if cid:
        parts.append(f"cUserId={cid}")
    parts.append(f"deviceId={devid}")
    parts.append(f"uDevId={base64.b64encode(hashlib.sha1(f'{uid}{devid}'.encode()).digest()).decode()}")
    parts.append("uLocale=zh_CN")
    parts.append("pass_ua=pc")
    cookie = "; ".join(parts)

    url1 = f"{ACCOUNT_HOST}/pass/serviceLogin?_locale=zh_CN&_snsNone=true&sid={SID}&_json=true"
    st1, body1, hdrs1 = _http_get(url1, cookie=cookie, timeout=30)
    if st1 != 200:
        raise RuntimeError(f"Phase1 HTTP {st1}")
    j1 = json.loads(_strip(body1))
    if j1.get("code", -1) != 0:
        raise RuntimeError(f"Phase1 code={j1.get('code')}")

    loc = j1.get("location", "")
    ssec = j1.get("ssecurity", "")
    nonce = str(j1.get("nonce", ""))
    sc1 = _cookies(hdrs1)
    if not cid:
        cid = sc1.get("cUserId", auth.get("cUserId", ""))

    raw_sign = f"nonce={nonce}" + (f"&{ssec}" if ssec else "")
    cs = base64.b64encode(hashlib.sha1(raw_sign.encode()).digest()).decode()
    sep = "&" if "?" in loc else "?"
    url2 = f"{loc.replace(chr(92)+'/', '/')}{sep}clientSign={urllib.parse.quote(cs, safe='')}"
    st2, body2, hdrs2 = _http_get(url2, cookie=None, timeout=15)
    sc2 = _cookies(hdrs2)
    stok = sc2.get("serviceToken", "") or sc2.get(f"{SID}_serviceToken", "")
    if not cid:
        cid = sc2.get("cUserId", "")
    if not stok:
        raise RuntimeError(f"no serviceToken, got: {list(sc2.keys())}")
    if ":" in stok:
        stok_val, sec_key = stok.split(":", 1)
    else:
        stok_val = stok
        sec_key = ssec

    _token_cache["token"] = (stok_val, sec_key)
    _token_cache["cuser_id"] = cid
    _token_cache["ts"] = now
    return (stok_val, sec_key), cid


def _make_signature(method, url_path, params, security_key):
    parts = [method.upper(), url_path]
    for k in sorted(params.keys()):
        parts.append(f"{k}={params[k]}")
    parts.append(security_key)
    raw = "&".join(parts)
    return base64.b64encode(hashlib.sha1(raw.encode("utf-8")).digest()).decode("ascii")


def _do_post(url_path, biz_params, stream=False):
    """POST 请求，返回解密后的结果列表"""
    (stok, sec_key), cuser_id = get_token()

    processed = {}
    for k, v in biz_params.items():
        if k.startswith("_"):
            processed[k] = v
        else:
            processed[k] = aes_encrypt(str(v), sec_key)
    processed["_apkversion"] = "6.8.0.21"
    processed["_apkversioncode"] = "68021"
    processed["_backend"] = "false"
    processed["_delta"] = "0"
    processed["_count"] = "1"
    sig = _make_signature("POST", url_path, processed, sec_key)
    processed["signature"] = sig

    cookie = f"serviceToken={stok}"
    if cuser_id:
        cookie += f"; cUserId={cuser_id}"
    headers = {
        "User-Agent": PC_UA,
        "Accept": "*/*",
        "Cookie": cookie,
        "Content-Type": "application/x-www-form-urlencoded",
        "apk-version": "6.8.0.21",
        "apk-version-code": "68021",
        "backend": "false",
    }
    body = urllib.parse.urlencode(processed).encode("utf-8")
    url = f"{AI_ENGINE}{url_path}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode("utf-8", "replace")
    except HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return [{"error": f"HTTP {e.code}", "body": raw[:300]}]

    # 解析 SSE 或单块
    chunks = []
    for line in raw.split("\n"):
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload:
                chunks.append(payload)
    if not chunks:
        chunks = [raw.strip()]

    results = []
    for c in chunks:
        try:
            pt = aes_decrypt(c, sec_key)
            results.append(json.loads(pt))
        except json.JSONDecodeError:
            results.append({"raw_text": pt})
        except Exception as e:
            results.append({"decrypt_error": str(e)[:100], "chunk_len": len(c)})

    if stream:
        return results
    else:
        return results  # 单块也是列表，方便统一处理


def _do_get(url_path, params=None):
    """GET 请求，返回解密后的结果"""
    (stok, sec_key), cuser_id = get_token()
    processed = {}
    if params:
        for k, v in params.items():
            if k.startswith("_"):
                processed[k] = v
            else:
                processed[k] = aes_encrypt(str(v), sec_key)
    processed["_apkversion"] = "6.8.0.21"
    processed["_apkversioncode"] = "68021"
    processed["_backend"] = "false"
    processed["_delta"] = "0"
    processed["_count"] = "1"
    sig = _make_signature("GET", url_path, processed, sec_key)
    processed["signature"] = sig

    cookie = f"serviceToken={stok}"
    if cuser_id:
        cookie += f"; cUserId={cuser_id}"
    headers = {
        "User-Agent": PC_UA,
        "Accept": "*/*",
        "Cookie": cookie,
        "apk-version": "6.8.0.21",
        "apk-version-code": "68021",
        "backend": "false",
    }
    qs = urllib.parse.urlencode(processed)
    url = f"{AI_ENGINE}{url_path}?{qs}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
            pt = aes_decrypt(raw.strip(), sec_key)
            return json.loads(pt)
    except HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return {"error": f"HTTP {e.code}", "body": raw[:300]}
    except Exception as e:
        return {"error": repr(e)[:200]}


# ===================== 公开 API =====================

def get_supported_languages():
    return _do_get("/api/aiNote/getSupportedLanguageList")


def summarize_text(text, stream=False):
    params = {"bizCode": "AiNote", "inputText": text, "stream": "true" if stream else "false"}
    return _do_post("/api/aiNote/summarizeText", params, stream=stream)


def translate_text(text, src_lang="auto", target_lang="zh"):
    params = {"inputText": text, "srcLangCode": src_lang, "targetLangCode": target_lang, "bizCode": "AiNote"}
    return _do_post("/api/aiNote/translateText", params, stream=False)


def correct_errors(text, tag_type="0", stream=False):
    params = {"inputText": text, "bizCode": "AiNote", "tagType": tag_type, "stream": "true" if stream else "false"}
    return _do_post("/api/aiNote/correctErrors", params, stream=stream)


def format_text(text, stream=False):
    params = {"inputText": text, "bizCode": "AiNote", "stream": "true" if stream else "false"}
    return _do_post("/api/aiNote/formatText", params, stream=stream)


def get_recommends(package_name="com.miui.notes", lang_code="zh-CN"):
    params = {"packageName": package_name, "langCode": lang_code}
    return _do_post("/api/aiTextControl/getRecommends", params, stream=False)


def generate_text(input_text, user_prompt, enable_depth=False, stream=False):
    params = {
        "inputText": input_text,
        "userPrompt": user_prompt,
        "bizCode": "AiTextControl",
        "stream": "true" if stream else "false",
        "enableDepth": "true" if enable_depth else "false",
    }
    return _do_post("/api/aiTextControl/generationText", params, stream=stream)


def polish_text(text, polish_style=0, stream=False):
    params = {
        "inputText": text,
        "bizCode": "AiTextControl",
        "polishStyle": str(polish_style),
        "stream": "true" if stream else "false",
    }
    return _do_post("/api/aiTextControl/polishText", params, stream=stream)


def expand_text(text, stream=False):
    params = {"inputText": text, "bizCode": "AiTextControl", "stream": "true" if stream else "false"}
    return _do_post("/api/aiTextControl/expandText", params, stream=stream)


# ===================== aiRecord 录音摘要 =====================

def record_summarize(text, lang_code="zh-CN"):
    """录音转写文本 → 普通摘要（theme + resultContent + needToDeals）"""
    params = {"inputText": text, "bizCode": "AIRecord", "langCode": lang_code}
    return _do_post("/api/aiRecord/summarizeText", params, stream=False)


def record_key_points(text, lang_code="zh-CN"):
    """录音转写文本 → 要点提取（结构化 HTML + summaryContent + aiAsks）"""
    params = {"inputText": text, "bizCode": "AIRecord", "langCode": lang_code}
    return _do_post("/api/aiRecord/summarizeKeyPoints", params, stream=False)


# ===================== P78 ASR rpcproxy（DAA-TOKEN-V1 匿名鉴权链） =====================
# 从 notes APK C2842a.java (AnonymousProvider) + libaivs_jni.so 逆向还原
#
# 鉴权链：
# 1. POST account-preview.xiaomixiaoai.com/anonymous/app/auth/token → access_token
# 2. 调用 rpcproxy 时 Authorization: DAA-TOKEN-V1 client_id:...,api_key:...,access_token:...,signature:...
# 3. md5_sign/sha256_sign 必须带冒号（m6024a 格式）
# 4. native AES: key/IV 硬编码, padding=space(0x20) 非 PKCS7

import random, string, struct

_DAA_CLIENT_ID = "1353384676173025280"
_DAA_API_KEY = "TF4dBTngGtrbaFja6C02hYc2pL1pqt11q9ZeD2kgVeU"
_DAA_SIGN_SECRET = "Db7mmwEUl78yZGKR5PwtrHKHDJXdHSq8_wzcAhdAKUkPyrF68nSeL4jVGxvR2GvHd_vMAjDa7d-WNJAZYk47ng"
_DAA_MD5_SIGN = "70:14:78:a1:e3:b4:b7:e3:97:8e:a6:94:69:41:0f:13"
_DAA_SHA256_SIGN = "c9:00:9d:01:eb:f9:f5:d0:30:2b:c7:1b:2f:e9:aa:9a:47:a4:32:bb:a1:73:08:a3:11:1b:75:d7:b2:14:90:25"
_DAA_PACKAGE_NAME = "com.miui.notes"
_DAA_TOKEN_URL = "https://account-preview.xiaomixiaoai.com/anonymous/app/auth/token"
_DAA_REFRESH_URL = "https://account-preview.xiaomixiaoai.com/anonymous/app/refresh/token"

# native AES 硬编码 key/IV（libaivs_jni.so rodata）
_NATIVE_AES_KEY = bytes.fromhex("ffff000056817a4c8881caa1781feea2")
_NATIVE_AES_IV = bytes.fromhex("ffffff00aeea7c36008791cabb6ebf00")

_daa_token_cache = {"access_token": None, "refresh_token": None, "expire_at": 0}


def _native_aes_encrypt(data: bytes) -> bytes:
    """native AES-128-CBC, padding=space(0x20) 非 PKCS7（libaivs_jni.so m6017a）"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    # space-pad to 16-byte boundary
    target_len = ((len(data) - 1) // 16 + 1) * 16 if data else 16
    padded = data + b"\x20" * (target_len - len(data))
    cipher = Cipher(algorithms.AES(_NATIVE_AES_KEY), modes.CBC(_NATIVE_AES_IV))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def _rand_hex(n: int) -> str:
    """随机 n 位 hex（SecureRandom 等效，无冒号）"""
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _sha1_colon_hex(data: bytes) -> str:
    """SHA1 digest → 冒号分隔小写 hex（m6024a 格式）"""
    h = hashlib.sha1(data).digest()
    return ":".join(f"{b:02x}" for b in h)


def _sha1_no_colon(data: bytes) -> str:
    """SHA1 digest → 无冒号小写 hex"""
    return hashlib.sha1(data).hexdigest()


def _adler32_hex8(s: str) -> str:
    """Adler-32 (b<<16)|a as %08x（m6022a）"""
    b = 1
    a = 0
    for ch in s.encode("utf-8"):
        a = (a + ch) % 65521
        b = (b + a) % 65521
    return f"{(b << 16) | a:08x}"


def _daa_api_key_encrypted() -> str:
    """api_key = Base64_urlsafe_nopad(AES_spacepad(nonce8 + API_KEY))"""
    nonce = _rand_hex(8)
    raw = (nonce + _DAA_API_KEY).encode("utf-8")
    ct = _native_aes_encrypt(raw)
    return base64.urlsafe_b64encode(ct).decode("ascii").rstrip("=")


def _daa_header_signature(nonce: str) -> str:
    """header signature = (rand3+nonce+rand5+SHA1_colon(nonce+clientId+apiKey)+rand2+rand3).lower().replace(':','')"""
    sha1_colon = _sha1_colon_hex((nonce + _DAA_CLIENT_ID + _DAA_API_KEY).encode("utf-8"))
    raw = _rand_hex(3) + nonce + _rand_hex(5) + sha1_colon + _rand_hex(2) + _rand_hex(3)
    return raw.lower().replace(":", "")


def _daa_body_signature(nonce: str, device_id: str) -> str:
    """body signature = (rand3+nonce+rand5+SHA1_colon(nonce+clientId+apiKey+deviceId+signSecret)+rand2+adler32hex8(nonce+deviceId)+rand3).lower().replace(':','')"""
    sha1_colon = _sha1_colon_hex((nonce + _DAA_CLIENT_ID + _DAA_API_KEY + device_id + _DAA_SIGN_SECRET).encode("utf-8"))
    adler = _adler32_hex8(nonce + device_id)
    raw = _rand_hex(3) + nonce + _rand_hex(5) + sha1_colon + _rand_hex(2) + adler + _rand_hex(3)
    return raw.lower().replace(":", "")


def _daa_get_token(force=False):
    """获取匿名 DAA-TOKEN（带缓存）"""
    now = time.time()
    if not force and _daa_token_cache["access_token"] and now < _daa_token_cache["expire_at"]:
        return _daa_token_cache["access_token"]

    devid = "pc_5b441f841b04d031e54fcba518aff353"
    nonce = _rand_hex(8)
    api_key_enc = _daa_api_key_encrypted()
    sig = _daa_body_signature(nonce, devid)

    body = urllib.parse.urlencode({
        "grant_type": "app_token",
        "client_id": _DAA_CLIENT_ID,
        "api_key": api_key_enc,
        "device_id": devid,
        "package_name": _DAA_PACKAGE_NAME,
        "md5_sign": _DAA_MD5_SIGN,
        "sha256_sign": _DAA_SHA256_SIGN,
        "signature": sig,
    }).encode("utf-8")

    import email.utils
    date_str = email.utils.formatdate(usegmt=True)
    req = urllib.request.Request(_DAA_TOKEN_URL, data=body, method="POST", headers={
        "Date": date_str,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": PC_UA,
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
    except HTTPError as e:
        raise RuntimeError(f"DAA token HTTP {e.code}: {e.read().decode('utf-8','replace')[:200]}")

    j = json.loads(raw)
    if j.get("code") != 0:
        raise RuntimeError(f"DAA token code={j.get('code')}: {raw[:200]}")
    result = j.get("result", {})
    access_token = result.get("access_token", "")
    refresh_token = result.get("refresh_token", "")
    expires_in = result.get("expires_in", 3600)
    if not access_token:
        raise RuntimeError(f"DAA token empty: {raw[:200]}")

    _daa_token_cache["access_token"] = access_token
    _daa_token_cache["refresh_token"] = refresh_token
    _daa_token_cache["expire_at"] = now + expires_in - 60
    return access_token


def _daa_auth_header() -> str:
    """构造 DAA-TOKEN-V1 Authorization header"""
    token = _daa_get_token()
    nonce = _rand_hex(8)
    api_key_enc = _daa_api_key_encrypted()
    sig = _daa_header_signature(nonce)
    return f"DAA-TOKEN-V1 client_id:{_DAA_CLIENT_ID},api_key:{api_key_enc},access_token:{token},signature:{sig}"


def _daa_get(url_path, params=None):
    """GET 请求（DAA-TOKEN-V1 鉴权）"""
    auth = _daa_auth_header()
    qs = ""
    if params:
        qs = "?" + urllib.parse.urlencode(params)
    url = f"{AI_ENGINE}{url_path}{qs}"
    req = urllib.request.Request(url, headers={
        "Authorization": auth,
        "User-Agent": PC_UA,
        "Accept": "*/*",
    }, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return json.loads(raw)
            except Exception:
                return {"raw_text": raw}
    except HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode("utf-8", "replace")[:300]}


def _daa_post(url_path, json_body=None, form_body=None):
    """POST 请求（DAA-TOKEN-V1 鉴权）"""
    auth = _daa_auth_header()
    url = f"{AI_ENGINE}{url_path}"
    if json_body is not None:
        body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        ct = "application/json"
    else:
        body = urllib.parse.urlencode(form_body or {}).encode("utf-8")
        ct = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": auth,
        "User-Agent": PC_UA,
        "Accept": "*/*",
        "Content-Type": ct,
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return json.loads(raw)
            except Exception:
                return {"raw_text": raw}
    except HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode("utf-8", "replace")[:300]}


# ===================== P78 rpcproxy 6 端点 =====================

def rpc_llm_polish(transcribe_result_json: str):
    """AI 润色转写结果（llmPolish）。
    transcribe_result_json: JSON 字符串，含 durationMilliseconds + phrases[].text/sentences/words
    返回 task_id，需用 rpc_asr_polish_result 查询结果。"""
    try:
        result_obj = json.loads(transcribe_result_json)
    except Exception:
        result_obj = {"durationMilliseconds": 5000, "phrases": [{"text": transcribe_result_json, "sentences": [{"text": transcribe_result_json, "words": [{"text": transcribe_result_json, "offsetMilliseconds": 0, "durationMilliseconds": 5000}], "offsetMilliseconds": 0, "durationMilliseconds": 5000}], "offsetMilliseconds": 0, "durationMilliseconds": 5000}]}
    return _daa_post("/api/rpcproxy/llmPolish", json_body={"result": json.dumps(result_obj, ensure_ascii=False)})


def rpc_asr_polish_result(task_id: str):
    """查询 AI 润色结果（asrPolishResult）"""
    return _daa_get("/api/rpcproxy/asrPolishResult", params={"task_id": task_id})


def rpc_fetch_transcribe_result(task_id: str):
    """获取转写结果（fetchtranscriberesult）"""
    return _daa_get("/api/rpcproxy/fetchtranscriberesult", params={"task_id": task_id})


def rpc_share_link(transcribe_text: str, summary_text: str, file_id: str):
    """生成分享链接（shareLink）"""
    return _daa_post("/api/rpcproxy/shareLink", json_body={
        "transcribe_text": transcribe_text,
        "summary_text": summary_text,
        "file_id": file_id,
    })


def rpc_fast_transcribe(audio_path: str, language: str = "zh"):
    """快速转写音频（fasttranscribe, multipart）"""
    return _daa_post_multipart("/api/rpcproxy/fasttranscribe", audio_path, language)


def rpc_fast_transcribe_v2(audio_path: str, language: str = "zh"):
    """快速转写音频 V2（fasttranscribeV2, multipart）"""
    return _daa_post_multipart("/api/rpcproxy/fasttranscribeV2", audio_path, language)


def _daa_post_multipart(url_path, audio_path, language="zh"):
    """POST multipart（DAA-TOKEN-V1 鉴权）"""
    import uuid
    auth = _daa_auth_header()
    url = f"{AI_ENGINE}{url_path}"
    boundary = uuid.uuid4().hex
    filename = os.path.basename(audio_path) or "audio.wav"
    with open(audio_path, "rb") as f:
        audio_data = f.read()
    parts = []
    for name, val in [("language", language)]:
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{val}\r\n".encode())
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"audio\"; filename=\"{filename}\"\r\nContent-Type: audio/wav\r\n\r\n".encode())
    parts.append(audio_data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(parts)
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": auth,
        "User-Agent": PC_UA,
        "Accept": "*/*",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return json.loads(raw)
            except Exception:
                return {"raw_text": raw}
    except HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode("utf-8", "replace")[:300]}
