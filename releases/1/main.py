# -*- coding: utf-8 -*-
r"""
Tool Survey - Engineering Tool Hub App
포트 8113. Python 표준 라이브러리만 사용 (Hub 내장 런타임으로 바로 실행).

  runtime\python.exe apps\ToolSurvey\releases\1\main.py

Hub 연동:
  - /go/toolsurvey 로 들어오는 hub_user/hub_ts/hub_sig 를 HMAC 검증 후 세션 쿠키 발급
  - GET /health  ->  {"status":"ok","app":"ToolSurvey","version":"1.0"}

데이터:
  - apps\ToolSurvey\data\toolsurvey.db (SQLite/WAL) — releases 번호를 올려도 유지됨

문항은 코드가 아니라 설문마다 들고 있는 schema(JSON)에 들어 있다. 관리 화면에서
툴 목록과 문항을 고치면 되고, 새 문항 유형을 추가할 때만 코드를 건드린다.
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import mimetypes
import os
import secrets
import socket
import sqlite3
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

APP_ID = "toolsurvey"
APP_NAME = "ToolSurvey"
APP_VERSION = "1.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # ...\releases\1
APP_DIR = os.path.dirname(os.path.dirname(BASE_DIR))           # ...\apps\ToolSurvey
HUB_DIR = os.path.dirname(os.path.dirname(APP_DIR))            # ...\EngineeringHub
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(APP_DIR, "data")
DB_FILE = os.path.join(DATA_DIR, "toolsurvey.db")
SESSION_KEY_FILE = os.path.join(DATA_DIR, "session.key")
HUB_SECRET_FILE = os.path.join(HUB_DIR, "portal", "data", "secret.key")
HUB_DB_FILE = os.path.join(HUB_DIR, "portal", "data", "hub.db")
LOG_FILE = os.path.join(HUB_DIR, "logs", "toolsurvey.log")

PORT = int(os.environ.get("TOOLSURVEY_PORT", "8113"))
SESSION_HOURS = 12
SIG_MAX_AGE = 600
SOCKET_TIMEOUT = 120
MAX_BODY = 4 * 1024 * 1024
# 서버 밖(각자 PC)에서 Hub 로그인 없이 화면을 확인할 때만 쓴다. 배포 시에는 비워 둔다.
DEV_USER = os.environ.get("TOOLSURVEY_DEV_USER", "").strip()

SKEY = ""


def log(msg):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("%s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


# ============================================================== 기본 문항 구성
# 첫 실행 때 이 내용으로 설문 1개가 만들어진다. 이후에는 관리 화면에서 고친다.
DEFAULT_TOOLS = [
    {"id": "vpstatus", "name": "VP Status Dashboard", "cat": "Project Work", "kind": "WEB", "icon": "chart", "desc": "VP Status List 업로드 / MR별 승인율 · 변경 추적 / 주간보고 Excel"},
    {"id": "tclhub", "name": "TCL Hub", "cat": "Project Work", "kind": "WEB", "abbr": "TH", "color": "#3b82e0", "desc": "Technical Clarification List 관리 — 항목별 영구 ID / 리비전 관리 / Word 양방향 동기화(3-way) / 과거 TCL 지식 검색"},
    {"id": "q8c54qj", "name": "L&G Hub", "cat": "Project Work", "kind": "HTML", "abbr": "LH", "color": "#8b7fe0", "desc": "루브리컨트(Lubricant), 그리스(Grease) DB"},
    {"id": "qquw678", "name": "Equipment Item DB", "cat": "Project Work", "kind": "MSI", "abbr": "EI", "color": "#d24f80", "desc": "Equipment Item 데이터베이스 — ECS, SES, ECM 수행 프로젝트 item을 쉽게 찾아 reference로 활용"},
    {"id": "designcriteria", "name": "Design Criteria Builder", "cat": "Document Tools", "kind": "HTML", "abbr": "DC", "color": "#14891f", "desc": "회전기기 Design Criteria 작성 도구 — 항목 구성 후 Word(.docx)로 내보내기, 작업 내용은 JSON으로 저장/불러오기"},
    {"id": "qyel51y", "name": "Design Plan Builder", "cat": "Document Tools", "kind": "HTML", "abbr": "DP", "color": "#e0675f", "desc": "기계 설계업무 수행 계획서(Design Plan) 작성 도구 — 조직·업무범위·기계규모(합계 자동) 입력 후 Word(.docx)로 내보내기, 작업 내용은 JSON으로 저장/불러오기"},
    {"id": "qwie97q", "name": "DocComparePro", "cat": "Auto Tools", "kind": "EXE", "abbr": "DV", "color": "#e0692c", "desc": "PDF 도면 비교 Tool"},
    {"id": "docuscanpro", "name": "DocuScanPro", "cat": "Auto Tools", "kind": "EXE", "icon": "scan", "desc": "내 PC 문서 통합 검색 — PDF/DOCX/XLSX/PPTX/HWP/DWG 본문·파일명 검색, 키워드 패키지, 이미지 OCR"},
    {"id": "qgf18hy", "name": "Excel2Markup(Rotating)", "cat": "Auto Tools", "kind": "EXE", "abbr": "EX", "color": "#1f9a5b", "desc": "Excel에 있는 keyword를 PDF에 하이라이트 하는 tool"},
    {"id": "qeqehef", "name": "FileRename", "cat": "Auto Tools", "kind": "EXE", "abbr": "FR", "color": "#22a06b", "desc": "폴더 내 파일 이름 일괄 변경 도구"},
    {"id": "q994d1o", "name": "DocMergeStudio", "cat": "Auto Tools", "kind": "EXE", "abbr": "DM", "color": "#8c84e6", "desc": "PDF, Docx, Excel을 pdf로 합치는 도구"},
    {"id": "qdt0udg", "name": "PSTMailExplorer", "cat": "Auto Tools", "kind": "EXE", "abbr": "PS", "color": "#e06c6c", "desc": "Outlook을 닫고 PST파일에서 msg 형태의 본문만 검색하는 tool"},
    {"id": "conveyorcalc", "name": "MHSConveyorCalc", "cat": "Calculator", "kind": "WEB", "icon": "dle", "desc": "컨베이어 설계 파워 계산"},
    {"id": "worklog", "name": "Worklog Hub", "cat": "일정관리", "kind": "WEB", "abbr": "WH", "color": "#14891f", "desc": "팀 공용 일정관리 Tool (업무일지 작성/집계)"},
    {"id": "q2v77ma", "name": "Outlook Extractor", "cat": "일정관리", "kind": "EXE", "abbr": "OE", "color": "#d24f80", "desc": "아웃룩 일정을 Worklog에 올리기 위한 추출 도구"},
    {"id": "weeklyreport", "name": "Weekly Report Automater", "cat": "일정관리", "kind": "EXE", "icon": "wra", "desc": "아웃룩 일정을 그대로 Weekly Report로 출력하는 도구"},
]

SCALE_EASE = ["매우 편하다", "편하다", "보통이다", "불편하다", "매우 불편하다"]
SCALE_HELP = ["업무에 매우 도움이 된다", "도움이 된다", "보통이다",
              "별로 도움이 안 된다", "전혀 도움이 안 된다"]

DEFAULT_USED_QUESTIONS = [
    {"id": "ease", "type": "single", "label": "사용하기에 편한가요?", "options": ["매우 편하다", "편하다", "보통이다", "불편하다", "매우 불편하다"], "required": True},
    {"id": "help", "type": "single", "label": "업무에 도움(생산성 향상)이 되나요?", "options": ["업무에 매우 도움이 된다", "도움이 된다", "보통이다", "별로 도움이 안 된다", "전혀 도움이 안 된다"], "required": True},
    {"id": "prod", "type": "single", "label": "도움이 된다면, 일주일(Week)에 업무 시간을 어느 정도 줄여주나요?", "options": ["약 10분", "약 30분", "약 1시간", "약 2시간 이상"], "required": False, "requireShown": True, "when": {"q": "help", "in": ["업무에 매우 도움이 된다", "도움이 된다", "보통이다"]}},
    {"id": "pain", "type": "multi", "label": "불편한 점이 있다면 골라주세요 (여러 개 선택 가능)", "options": ["속도가 느리다", "화면이 복잡하다", "원하는 기능을 찾기 어렵다", "결과가 부정확하거나 믿기 어렵다", "오류·멈춤이 잦다", "설명서/안내가 부족하다", "엑셀 등 기존 방식이 더 편하다", "특별히 불편한 점은 없다"], "required": False},
    {"id": "improve", "type": "textarea", "label": "개선되면 좋겠다고 생각하는 사항", "placeholder": "예) 담당자별로 필터를 걸고 싶다 / 엑셀로 내보낼 때 서식이 깨진다", "required": False},
]

DEFAULT_UNUSED_QUESTIONS = [
    {"id": "why", "type": "multi", "label": "쓰지 않는 이유는 무엇인가요? (여러 개 선택 가능)", "options": ["이런 툴이 있는지 몰랐다", "내 업무와 관련이 없다", "사용법을 몰라서", "접속 방법을 몰라서", "기존 방식(엑셀 등)이 편해서", "써봤는데 불편해서", "그냥 기회가 없었다"], "required": False},
    {"id": "want", "type": "single", "label": "설명을 들으면 써보실 생각이 있나요?", "options": ["설명을 들으면 써보고 싶다", "아직 필요하지 않다", "잘 모르겠다"], "required": False},
]

DEFAULT_COMMON_QUESTIONS = [
    {"id": "freq", "type": "single", "label": "Engineering Hub 에 얼마나 들어오시나요?",
     "options": ["하루에 여러 번", "하루 1번 정도", "주 2~3회", "주 1회 정도",
                 "월 1~2회", "거의 들어가지 않는다"], "required": True},
    {"id": "hub_ease", "type": "single",
     "label": "Hub 포털 자체(로그인·툴 찾기·접속)는 쓰기 편한가요?",
     "options": SCALE_EASE, "required": False},
    {"id": "best", "type": "toolpick", "label": "가장 유용하다고 생각하는 툴 하나를 골라주세요",
     "required": False},
    {"id": "new_tool", "type": "textarea",
     "label": "새로 만들어졌으면 하는 툴, 또는 자동화하고 싶은 반복 업무가 있나요?",
     "placeholder": "지금 사람이 손으로 하고 있는 일 중에 '이건 컴퓨터가 해도 되는데' 싶은 것",
     "required": False},
    {"id": "manual_work", "type": "textarea",
     "label": "수작업으로 하느라 시간이 가장 많이 걸리는 업무는 무엇인가요?",
     "required": False},
    {"id": "etc", "type": "textarea", "label": "그 밖에 하고 싶은 말씀 (자유)",
     "required": False},
]

AWARENESS_OPTIONS = [
    {"value": "often", "label": "자주 쓴다", "used": True},
    {"value": "tried", "label": "몇 번 써봤다", "used": True},
    {"value": "heard", "label": "들어는 봤지만 안 써봤다", "used": False},
    {"value": "unknown", "label": "처음 들어본다", "used": False},
]
USED_VALUES = {"often", "tried"}


def default_schema():
    return {
        "tools": [dict(t) for t in DEFAULT_TOOLS],
        "awarenessLabel": "사용해 본(사용 중인) 툴을 모두 선택해 주세요",
        "awarenessHelp": "Hub 화면과 같은 카드입니다. 한 번이라도 써본 툴의 카드를 눌러 체크해 주세요. 체크한 툴은 다음 단계에서 하나씩 평가하고, 체크하지 않은 툴은 그 뒤에 짧게 묻습니다.",
        "usedQuestions": [dict(q) for q in DEFAULT_USED_QUESTIONS],
        "unusedQuestions": [dict(q) for q in DEFAULT_UNUSED_QUESTIONS],
        "commonQuestions": [dict(q) for q in DEFAULT_COMMON_QUESTIONS],
    }


DEFAULT_INTRO = (
    "기계설계팀 공용 툴(Engineering Hub)에 대한 의견을 묻는 설문입니다.\n"
    "써본 툴이 업무 생산성에 얼마나 도움이 되는지를 중심으로 묻고, 결과는 어떤 툴을 손보고 무엇을 새로 만들지 정하는 데 그대로 쓰입니다.\n"
    "① 써본 툴 선택 → ② 써본 툴 평가 → ③ 안 써본 툴 → ④ Hub 전반 순서로 진행되며 5~10분 정도 걸립니다. 중간에 나가도 자동 저장됩니다."
)


# ======================================================================= DB
def connect():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS surveys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            intro TEXT DEFAULT '',
            status TEXT DEFAULT 'draft',       -- draft | open | closed
            anonymous INTEGER DEFAULT 0,       -- 1이면 대시보드에서 이름을 가린다
            show_results INTEGER DEFAULT 1,    -- 1이면 일반 팀원도 집계를 볼 수 있다
            schema TEXT NOT NULL,
            created_at REAL, created_by TEXT, updated_at REAL);
        CREATE TABLE IF NOT EXISTS responses(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            display TEXT DEFAULT '',
            answers TEXT NOT NULL,
            submitted INTEGER DEFAULT 0,
            created_at REAL, updated_at REAL,
            UNIQUE(survey_id, username));
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, username TEXT, action TEXT, detail TEXT);
    """)
    n = conn.execute("SELECT COUNT(*) c FROM surveys").fetchone()["c"]
    if not n:
        now = time.time()
        conn.execute(
            "INSERT INTO surveys(title,intro,status,anonymous,show_results,schema,"
            "created_at,created_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("팀 공용 툴 사용 현황 및 개선 의견 조사", DEFAULT_INTRO, "draft", 0, 1,
             json.dumps(default_schema(), ensure_ascii=False), now, "", now))
        log("기본 설문 1건 생성")
    conn.commit()
    conn.close()


def audit(conn, user, action, detail=""):
    conn.execute("INSERT INTO audit(ts,username,action,detail) VALUES(?,?,?,?)",
                 (time.time(), (user or {}).get("username", ""), action, detail))


# ===================================================================== 인증
def session_key():
    if not os.path.exists(SESSION_KEY_FILE):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SESSION_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(32))
    return _read(SESSION_KEY_FILE)


def verify_hub(username, ts, sig):
    secret = _read(HUB_SECRET_FILE)
    if not (secret and username and ts and sig):
        return False
    try:
        if abs(time.time() - float(ts)) > SIG_MAX_AGE:
            return False
    except ValueError:
        return False
    expect = hmac.new(secret.encode(), ("%s|%s" % (username, ts)).encode(),
                      hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, sig)


def make_session(username, display):
    payload = base64.urlsafe_b64encode(json.dumps(
        {"u": username, "n": display, "e": int(time.time()) + SESSION_HOURS * 3600},
        ensure_ascii=False).encode("utf-8")).decode("ascii")
    sig = hmac.new(SKEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return payload + "." + sig


def read_session(raw):
    if not raw or "." not in raw:
        return None
    payload, sig = raw.rsplit(".", 1)
    expect = hmac.new(SKEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(expect, sig):
        return None
    try:
        d = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    if d.get("e", 0) < time.time():
        return None
    return {"username": d.get("u", ""), "display": d.get("n", "") or d.get("u", "")}


_users_cache = {"ts": 0.0, "rows": []}


def hub_users():
    if time.time() - _users_cache["ts"] < 30:
        return _users_cache["rows"]
    rows = []
    if os.path.exists(HUB_DB_FILE):
        try:
            c = sqlite3.connect(HUB_DB_FILE, timeout=5)
            c.row_factory = sqlite3.Row
            rows = [{"username": r["username"], "display": r["display_name"],
                     "role": r["role"]}
                    for r in c.execute("SELECT username, display_name, role FROM users"
                                       " ORDER BY display_name")]
            c.close()
        except Exception as e:
            log("hub.db 사용자 목록 읽기 실패: %s" % e)
            rows = []
    _users_cache["ts"] = time.time()
    _users_cache["rows"] = rows
    return rows


def is_hub_admin(username):
    for u in hub_users():
        if u["username"] == username:
            return u["role"] == "admin"
    # Hub DB를 못 읽는 단독 실행(개발) 상황에서는 DEV 사용자를 관리자로 본다
    return bool(DEV_USER) and username == DEV_USER


# =============================================================== 집계 유틸
def _opt_labels(q):
    return list(q.get("options") or [])


def aggregate(schema, rows):
    """제출된 응답들을 문항별 개수로 접는다. (그래프 없이 표로 뿌릴 수 있는 형태)"""
    tools = schema.get("tools") or []
    aw_counts = {t["id"]: {o["value"]: 0 for o in AWARENESS_OPTIONS} for t in tools}
    per_tool = {}
    for t in tools:
        per_tool[t["id"]] = {"used": {}, "unused": {}, "texts": {}}
        for grp, qs in (("used", schema.get("usedQuestions") or []),
                        ("unused", schema.get("unusedQuestions") or [])):
            for q in qs:
                if q["type"] in ("single", "multi"):
                    per_tool[t["id"]][grp][q["id"]] = {o: 0 for o in _opt_labels(q)}
                else:
                    per_tool[t["id"]]["texts"].setdefault(q["id"], [])
    common = {}
    for q in schema.get("commonQuestions") or []:
        if q["type"] in ("single", "multi"):
            common[q["id"]] = {o: 0 for o in _opt_labels(q)}
        elif q["type"] == "toolpick":
            common[q["id"]] = {t["name"]: 0 for t in tools}
        else:
            common[q["id"]] = []

    tool_name = {t["id"]: t["name"] for t in tools}
    for r in rows:
        try:
            a = json.loads(r["answers"])
        except Exception:
            continue
        who = "(익명)" if schema.get("_hide_names") else (r["display"] or r["username"])
        aw = a.get("awareness") or {}
        for tid, val in aw.items():
            if tid in aw_counts and val in aw_counts[tid]:
                aw_counts[tid][val] += 1
        for tid, ans in (a.get("tools") or {}).items():
            if tid not in per_tool:
                continue
            grp = "used" if aw.get(tid) in USED_VALUES else "unused"
            qs = schema.get("usedQuestions" if grp == "used" else "unusedQuestions") or []
            for q in qs:
                v = ans.get(q["id"])
                if v in (None, "", []):
                    continue
                if q["type"] == "single":
                    if v in per_tool[tid][grp].get(q["id"], {}):
                        per_tool[tid][grp][q["id"]][v] += 1
                elif q["type"] == "multi":
                    for one in (v if isinstance(v, list) else [v]):
                        if one in per_tool[tid][grp].get(q["id"], {}):
                            per_tool[tid][grp][q["id"]][one] += 1
                else:
                    per_tool[tid]["texts"].setdefault(q["id"], []).append(
                        {"who": who, "text": str(v)})
        for q in schema.get("commonQuestions") or []:
            v = (a.get("common") or {}).get(q["id"])
            if v in (None, "", []):
                continue
            if q["type"] == "single":
                if v in common[q["id"]]:
                    common[q["id"]][v] += 1
            elif q["type"] == "multi":
                for one in (v if isinstance(v, list) else [v]):
                    if one in common[q["id"]]:
                        common[q["id"]][one] += 1
            elif q["type"] == "toolpick":
                nm = tool_name.get(v, v)
                common[q["id"]][nm] = common[q["id"]].get(nm, 0) + 1
            else:
                common[q["id"]].append({"who": who, "text": str(v)})
    return {"awareness": aw_counts, "tools": per_tool, "common": common,
            "total": len(rows)}


def csv_bytes(schema, rows, hide_names):
    tools = schema.get("tools") or []
    used_qs = schema.get("usedQuestions") or []
    unused_qs = schema.get("unusedQuestions") or []
    common_qs = schema.get("commonQuestions") or []
    head = ["응답자", "아이디", "제출시각"]
    for t in tools:
        head.append("[%s] 인지도" % t["name"])
        for q in used_qs:
            head.append("[%s] %s" % (t["name"], q["label"]))
        for q in unused_qs:
            head.append("[%s] %s" % (t["name"], q["label"]))
    for q in common_qs:
        head.append(q["label"])

    aw_label = {o["value"]: o["label"] for o in AWARENESS_OPTIONS}
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(head)
    for r in rows:
        try:
            a = json.loads(r["answers"])
        except Exception:
            continue
        line = ["(익명)" if hide_names else (r["display"] or r["username"]),
                "" if hide_names else r["username"],
                time.strftime("%Y-%m-%d %H:%M", time.localtime(r["updated_at"] or 0))]
        aw = a.get("awareness") or {}
        tl = a.get("tools") or {}
        for t in tools:
            line.append(aw_label.get(aw.get(t["id"], ""), ""))
            ans = tl.get(t["id"]) or {}
            for q in used_qs + unused_qs:
                v = ans.get(q["id"])
                line.append(", ".join(v) if isinstance(v, list) else ("" if v is None else str(v)))
        for q in common_qs:
            v = (a.get("common") or {}).get(q["id"])
            if q["type"] == "toolpick":
                v = {t["id"]: t["name"] for t in tools}.get(v, v)
            line.append(", ".join(v) if isinstance(v, list) else ("" if v is None else str(v)))
        w.writerow(line)
    return ("﻿" + buf.getvalue()).encode("utf-8")


# ===================================================================== HTTP
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ToolSurvey/" + APP_VERSION
    timeout = SOCKET_TIMEOUT

    def log_message(self, fmt, *args):
        pass

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except socket.timeout:
            self.close_connection = True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    # ------------------------------------------------------------------ io
    def _raw(self, code, data, ctype, extra=None):
        extra = dict(extra or {})
        if len(data) > 2048 and "gzip" in (self.headers.get("Accept-Encoding") or ""):
            co = zlib.compressobj(6, zlib.DEFLATED, 31)
            data = co.compress(data) + co.flush()
            extra["Content-Encoding"] = "gzip"
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                socket.timeout, OSError):
            self.close_connection = True

    def _json(self, code, obj, extra=None):
        self._raw(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                  "application/json; charset=utf-8", extra)

    def _file(self, path):
        if not os.path.isfile(path):
            return self._raw(404, b"not found", "text/plain; charset=utf-8")
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",
                                                  "application/json"):
            ctype += "; charset=utf-8"
        with open(path, "rb") as f:
            return self._raw(200, f.read(), ctype)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        if n > MAX_BODY:
            raise ValueError("본문이 너무 큽니다.")
        return json.loads(self.rfile.read(n).decode("utf-8"))

    def _user(self):
        if DEV_USER:
            return {"username": DEV_USER, "display": DEV_USER + "(개발)"}
        raw = ""
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ts_session":
                raw = v
        return read_session(raw)

    # -------------------------------------------------------------- methods
    def do_GET(self):
        self._route("GET")

    def do_HEAD(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    # --------------------------------------------------------------- router
    def _route(self, method):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            if path == "/health":
                return self._json(200, {"status": "ok", "app": APP_NAME,
                                        "version": APP_VERSION})

            if path in ("/", "/index.html"):
                hu = (query.get("hub_user") or [""])[0]
                if hu and verify_hub(hu, (query.get("hub_ts") or [""])[0],
                                     (query.get("hub_sig") or [""])[0]):
                    disp = (query.get("hub_name") or [hu])[0]
                    cookie = ("ts_session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                              % (make_session(hu, disp), SESSION_HOURS * 3600))
                    return self._raw(302, b"", "text/plain",
                                     {"Location": "/", "Set-Cookie": cookie})
                return self._file(os.path.join(STATIC_DIR, "index.html"))

            if not path.startswith("/api/"):
                safe = os.path.normpath(os.path.join(STATIC_DIR, path.lstrip("/")))
                if not safe.startswith(STATIC_DIR):
                    return self._raw(403, b"forbidden", "text/plain; charset=utf-8")
                return self._file(safe)

            user = self._user()
            if not user:
                return self._json(401, {"error": "login_required"})
            admin = is_hub_admin(user["username"])
            return self._api(method, path, query, user, admin)
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            log("ERROR %s %s -> %r" % (method, self.path, e))
            return self._json(500, {"error": "서버 오류: %s" % e})

    # ------------------------------------------------------------------ api
    def _api(self, method, path, query, user, admin):
        conn = connect()
        try:
            if path == "/api/me":
                return self._json(200, {"username": user["username"],
                                        "display": user["display"], "admin": admin})

            if path == "/api/users":
                if not admin:
                    return self._json(403, {"error": "forbidden"})
                return self._json(200, {"users": hub_users()})

            # ---------------------------------------------------- 설문 목록
            if path == "/api/surveys" and method == "GET":
                out = []
                for s in conn.execute("SELECT * FROM surveys ORDER BY id DESC"):
                    if s["status"] == "draft" and not admin:
                        continue
                    mine = conn.execute(
                        "SELECT submitted FROM responses WHERE survey_id=? AND username=?",
                        (s["id"], user["username"])).fetchone()
                    out.append({
                        "id": s["id"], "title": s["title"], "status": s["status"],
                        "anonymous": bool(s["anonymous"]),
                        "showResults": bool(s["show_results"]),
                        "responses": conn.execute(
                            "SELECT COUNT(*) c FROM responses WHERE survey_id=? AND submitted=1",
                            (s["id"],)).fetchone()["c"],
                        "myState": ("submitted" if mine and mine["submitted"]
                                    else "draft" if mine else "none"),
                        "updatedAt": s["updated_at"]})
                return self._json(200, {"surveys": out, "hubUsers": len(hub_users())})

            if path == "/api/surveys" and method == "POST":
                if not admin:
                    return self._json(403, {"error": "forbidden"})
                b = self._body()
                now = time.time()
                cur = conn.execute(
                    "INSERT INTO surveys(title,intro,status,anonymous,show_results,schema,"
                    "created_at,created_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    ((b.get("title") or "새 설문").strip(), b.get("intro") or "",
                     "draft", 0, 1,
                     json.dumps(b.get("schema") or default_schema(), ensure_ascii=False),
                     now, user["username"], now))
                audit(conn, user, "create_survey", str(cur.lastrowid))
                conn.commit()
                return self._json(200, {"id": cur.lastrowid})

            # ---------------------------------------------------- 설문 1건
            parts = path.split("/")          # ['', 'api', 'surveys', '<id>', ...]
            if len(parts) >= 4 and parts[2] == "surveys" and parts[3].isdigit():
                sid = int(parts[3])
                tail = "/".join(parts[4:])
                s = conn.execute("SELECT * FROM surveys WHERE id=?", (sid,)).fetchone()
                if not s:
                    return self._json(404, {"error": "설문을 찾을 수 없습니다."})
                schema = json.loads(s["schema"])
                meta = {"id": s["id"], "title": s["title"], "intro": s["intro"],
                        "status": s["status"], "anonymous": bool(s["anonymous"]),
                        "showResults": bool(s["show_results"]), "schema": schema}

                if tail == "" and method == "GET":
                    if s["status"] == "draft" and not admin:
                        return self._json(403, {"error": "아직 공개되지 않은 설문입니다."})
                    r = conn.execute(
                        "SELECT * FROM responses WHERE survey_id=? AND username=?",
                        (sid, user["username"])).fetchone()
                    mine = None
                    if r:
                        mine = {"answers": json.loads(r["answers"]),
                                "submitted": bool(r["submitted"]),
                                "updatedAt": r["updated_at"]}
                    return self._json(200, {"survey": meta, "myResponse": mine,
                                            "awarenessOptions": AWARENESS_OPTIONS})

                if tail == "" and method == "PUT":
                    if not admin:
                        return self._json(403, {"error": "forbidden"})
                    b = self._body()
                    st = b.get("status") or s["status"]
                    if st not in ("draft", "open", "closed"):
                        raise ValueError("status 값이 잘못되었습니다.")
                    conn.execute(
                        "UPDATE surveys SET title=?,intro=?,status=?,anonymous=?,"
                        "show_results=?,schema=?,updated_at=? WHERE id=?",
                        ((b.get("title") or s["title"]).strip(),
                         b.get("intro", s["intro"]), st,
                         1 if b.get("anonymous") else 0,
                         1 if b.get("showResults", True) else 0,
                         json.dumps(b.get("schema") or schema, ensure_ascii=False),
                         time.time(), sid))
                    audit(conn, user, "update_survey", "%d status=%s" % (sid, st))
                    conn.commit()
                    return self._json(200, {"ok": True})

                if tail == "" and method == "DELETE":
                    if not admin:
                        return self._json(403, {"error": "forbidden"})
                    conn.execute("DELETE FROM responses WHERE survey_id=?", (sid,))
                    conn.execute("DELETE FROM surveys WHERE id=?", (sid,))
                    audit(conn, user, "delete_survey", str(sid))
                    conn.commit()
                    return self._json(200, {"ok": True})

                # ------------------------------------------------ 응답 저장
                if tail == "response" and method == "POST":
                    if s["status"] != "open":
                        return self._json(403, {"error": "지금은 응답을 받지 않는 설문입니다."})
                    b = self._body()
                    answers = b.get("answers")
                    if not isinstance(answers, dict):
                        raise ValueError("answers 가 없습니다.")
                    submitted = 1 if b.get("submitted") else 0
                    if submitted:
                        missing = validate(schema, answers)
                        if missing:
                            return self._json(400, {"error": "필수 문항이 비어 있습니다.",
                                                    "missing": missing})
                    now = time.time()
                    conn.execute(
                        "INSERT INTO responses(survey_id,username,display,answers,submitted,"
                        "created_at,updated_at) VALUES(?,?,?,?,?,?,?)"
                        " ON CONFLICT(survey_id,username) DO UPDATE SET"
                        " display=excluded.display, answers=excluded.answers,"
                        " submitted=excluded.submitted, updated_at=excluded.updated_at",
                        (sid, user["username"], user["display"],
                         json.dumps(answers, ensure_ascii=False), submitted, now, now))
                    audit(conn, user, "submit" if submitted else "save", str(sid))
                    conn.commit()
                    return self._json(200, {"ok": True, "submitted": bool(submitted)})

                # ------------------------------------------------ 결과/집계
                if tail in ("results", "export.csv") and method == "GET":
                    if not (admin or s["show_results"]):
                        return self._json(403, {"error": "결과 열람 권한이 없습니다."})
                    rows = list(conn.execute(
                        "SELECT * FROM responses WHERE survey_id=? AND submitted=1"
                        " ORDER BY updated_at", (sid,)))
                    hide = bool(s["anonymous"]) and not admin
                    if tail == "export.csv":
                        if not admin:
                            return self._json(403, {"error": "내보내기는 관리자만 가능합니다."})
                        name = "survey_%d_%s.csv" % (sid, time.strftime("%Y%m%d"))
                        return self._raw(200, csv_bytes(schema, rows, bool(s["anonymous"])),
                                         "text/csv; charset=utf-8",
                                         {"Content-Disposition":
                                          'attachment; filename="%s"' % name})
                    agg_schema = dict(schema)
                    agg_schema["_hide_names"] = hide
                    agg = aggregate(agg_schema, rows)
                    respondents = []
                    for r in rows:
                        respondents.append({
                            "who": "(익명)" if hide else (r["display"] or r["username"]),
                            "username": "" if hide else r["username"],
                            "at": r["updated_at"]})
                    pending = []
                    if admin:
                        done = {r["username"] for r in rows}
                        drafts = {r["username"] for r in conn.execute(
                            "SELECT username FROM responses WHERE survey_id=? AND submitted=0",
                            (sid,))}
                        for u in hub_users():
                            if u["username"] not in done:
                                pending.append({"who": u["display"] or u["username"],
                                                "username": u["username"],
                                                "state": "작성중" if u["username"] in drafts
                                                         else "미응답"})
                    return self._json(200, {"survey": meta, "agg": agg,
                                            "respondents": respondents,
                                            "pending": pending,
                                            "hubUsers": len(hub_users()),
                                            "awarenessOptions": AWARENESS_OPTIONS,
                                            "admin": admin})

                # -------------------------------------------- 개인 응답 보기
                if tail.startswith("response/") and method == "GET":
                    if not admin:
                        return self._json(403, {"error": "forbidden"})
                    who = tail.split("/", 1)[1]
                    r = conn.execute(
                        "SELECT * FROM responses WHERE survey_id=? AND username=?",
                        (sid, who)).fetchone()
                    if not r:
                        return self._json(404, {"error": "응답이 없습니다."})
                    return self._json(200, {"survey": meta,
                                            "answers": json.loads(r["answers"]),
                                            "who": r["display"] or r["username"],
                                            "submitted": bool(r["submitted"]),
                                            "awarenessOptions": AWARENESS_OPTIONS})

            return self._json(404, {"error": "not_found", "path": path})
        finally:
            conn.close()


def validate(schema, answers):
    """제출 시 필수 문항만 확인한다. 임시저장은 검사하지 않는다."""
    missing = []
    aw = answers.get("awareness") or {}
    for t in schema.get("tools") or []:
        if not aw.get(t["id"]):
            missing.append("awareness:%s" % t["id"])
    tl = answers.get("tools") or {}
    for t in schema.get("tools") or []:
        used = aw.get(t["id"]) in USED_VALUES
        qs = schema.get("usedQuestions" if used else "unusedQuestions") or []
        ans = tl.get(t["id"]) or {}
        for q in qs:
            if q.get("required") and ans.get(q["id"]) in (None, "", []):
                missing.append("tool:%s:%s" % (t["id"], q["id"]))
    cm = answers.get("common") or {}
    for q in schema.get("commonQuestions") or []:
        if q.get("required") and cm.get(q["id"]) in (None, "", []):
            missing.append("common:%s" % q["id"])
    return missing


def main():
    global SKEY
    init_db()
    SKEY = session_key()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    msg = "%s v%s  ->  http://localhost:%d   (db: %s)" % (APP_NAME, APP_VERSION,
                                                          PORT, DB_FILE)
    print(msg, flush=True)
    log("started " + msg)
    if DEV_USER:
        print("  [DEV] 인증 우회 사용자: %s" % DEV_USER, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        log("stopped")


if __name__ == "__main__":
    main()
