#!/usr/bin/env python3
# ui_telemetry_server.py
# - IPS(ui_tap.c) → UDP 127.0.0.1:9090 JSON 수신
# - 100ms 집계 후 SSE로 브라우저에 실시간 전송
# - 왼쪽: 모든 트래픽(PRE, 소스 IP별), 오른쪽: ACCEPT만(PRE가 아니라 VERDICT=ACCEPT)
# - 우측: 현재 표시 중인 IP 색상 범례 리스트
# - http://127.0.0.1:8086 대시보드 제공 (Plotly CDN 사용)

import socket, threading, queue, time, json, signal, os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 상단 설정부 교체 권장안 (안정화 + 원하는 기본값)
HOST_UDP   = os.environ.get("ARGUS_UI_HOST", "127.0.0.1").strip()
PORT_UDP   = int(os.environ.get("ARGUS_UI_PORT", "9090").strip())
HOST_HTTP  = os.environ.get("ARGUS_DASH_HOST", "127.0.0.1").strip()
PORT_HTTP  = int(os.environ.get("ARGUS_DASH_PORT", "8086").strip())

Y_TICK = int(os.environ.get("ARGUS_YTICK", "50").strip())      # 0=자동, >0이면 그 간격으로 눈금
X_DTICK_MS = int(os.environ.get("ARGUS_X_DTICK_MS", "0").strip())  # 0=자동, >0이면 그 간격(ms)으로 눈금

# 버킷 기본 1000ms(=1초)로 쓰고 싶다면 여기서 디폴트 변경
BUCKET_MS  = int(os.environ.get("ARGUS_BUCKET_MS", "1000").strip())
BUCKET_MS  = 1 if BUCKET_MS < 1 else BUCKET_MS

TOPK       = int(os.environ.get("ARGUS_TOPK", "10").strip())
PRINT_LOGS = os.environ.get("ARGUS_PRINT_RX", "0").strip() == "1"

# 자동 Y축/패딩/최소범위 (자동 줌을 쓸 때)
YAUTO       = int(os.environ.get("ARGUS_YAUTO", "1").strip())  # 1=자동, 0=끄기
YPAD_PCT    = float(os.environ.get("ARGUS_YPAD_PCT", "0.10").strip())  # 여유 10%
YMIN_RANGE  = int(os.environ.get("ARGUS_YMIN_RANGE", "300").strip())   # 최소 y범위
YAUTO_STICKY = int(os.environ.get("ARGUS_YAUTO_STICKY", "1").strip())  # 1=스케일 증가만 허용(축 줄이지 않음)

# 그룹/창/Y축/스무딩/링거
# GROUP = os.environ.get("ARGUS_GROUP", "session").strip()   # "session"/"ip"/"pair"
GROUP = "ip"   # "ip"로 고정 (소스 IP 기준)
# SESS_INCLUDE_DIR = os.environ.get("ARGUS_SESS_INCLUDE_DIR", "1").strip() == "1"
SESS_INCLUDE_DIR = False

# 10분 창을 기본으로 쓰려면 600으로
WINDOW_SEC = int(os.environ.get("ARGUS_WINDOW_SEC", "30").strip())

# 0이면 자동축. 고정 원하면 환경변수로 오버라이드
YMAX = int(os.environ.get("ARGUS_YMAX", "0").strip())

# EMA 스무딩 기본값 0.7로 쓰고 싶으면 여기 조정
SMOOTH_ALPHA = float(os.environ.get("ARGUS_SMOOTH_ALPHA", "0.7").strip())

# LINGER 기본 10분(600000ms)
LINGER_MS = int(os.environ.get("ARGUS_LINGER_MS", "600000").strip())

# pair 옵션들
PAIR_WITH_PORTS = os.environ.get("ARGUS_PAIR_WITH_PORTS", "0").strip() == "1"
PAIR_KEEP_DIR   = os.environ.get("ARGUS_PAIR_KEEP_DIR",   "0").strip() == "1"

def make_key(ft: dict, dir_str: str) -> str:
    """세션/IP/IP쌍(pair) 기준의 라인 키 생성"""
    proto = str(ft.get("proto", "")).upper() or "UNK"
    s = ft.get("saddr", "0.0.0.0"); d = ft.get("daddr", "0.0.0.0")
    sp = ft.get("sport", 0); dp = ft.get("dport", 0)

    g = GROUP.lower()
    if g == "session":
        base = f"{s}:{sp} \u2192 {d}:{dp} / {proto}"  # A:SP → B:DP / TCP
        return f"{base} [{dir_str}]" if (SESS_INCLUDE_DIR and dir_str) else base

    elif g == "pair":
        # Wireshark IPv4 탭 감각: IP쌍(A↔B), 프로토콜 합계(MIX)
        if PAIR_WITH_PORTS:
            a = f"{s}:{sp}"; b = f"{d}:{dp}"
        else:
            a = s; b = d
        if PAIR_KEEP_DIR:
            # 방향 유지: A→B
            return f"{a} \u2192 {b} / MIX"
        else:
            # 무방향: {A,B} 정렬하여 A↔B
            u, v = sorted([a, b])
            return f"{u} \u2194 {v} / MIX"

    else:
        # ip 모드: 소스 IP 하나로 묶음
        return s

in_q = queue.Queue(maxsize=100000)   # UDP -> aggregator
clients = set()                      # SSE client queues
clients_lock = threading.Lock()
running = True

def udp_receiver():
    """IPS(ui_tap.c)에서 보내는 UDP JSON 수신기.
       반드시 바인드 성공/실패를 콘솔에 출력해서 상태를 알 수 있게 한다.
    """
    global running
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind((HOST_UDP, PORT_UDP))
    except OSError as e:
        # ← 바인드 실패 시 바로 원인 출력(포트 충돌, 권한, 잘못된 주소 등)
        print(f"[UDP] bind failed on {HOST_UDP}:{PORT_UDP} -> {e}", flush=True)
        running = False
        return

    # ← 항상 출력(PRINT_LOGS 상관없이) — ss -lun 에도 떠야 정상
    print(f"[UDP] listening on {HOST_UDP}:{PORT_UDP}", flush=True)

    s.settimeout(0.5)
    while running:
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            msg = json.loads(data.decode("utf-8", "ignore"))
            in_q.put_nowait(msg)
        except Exception as e:
            if PRINT_LOGS:
                print("[UDP] bad json:", e, data[:120], flush=True)

def broadcast(obj):
    with clients_lock:
        for q in list(clients):
            try:
                q.put_nowait(obj)
            except queue.Full:
                pass

# // REPLACE: 집계기 전체 교체 (세션/IP Top-K + pps + 누적판정)
def aggregator():
    """매 BUCKET_MS마다 집계:
       - pre:   이번 버킷 '모든 트래픽(Pre)'  그룹키별 카운트
       - acc:   이번 버킷 'ACCEPT만(VERDICT)' 그룹키별 카운트
       - pps:   이번 버킷 패킷 합계 * (1000/BUCKET_MS)
       - verdict: 누적(ACCEPT/DROP)
    """
    bucket_s = BUCKET_MS / 1000.0
    verdict_tot = {"ACCEPT": 0, "DROP": 0}
    drop_ip_cum = {}

    next_t = time.time()
    while running:
        now = time.time()
        if now < next_t:
            time.sleep(min(next_t - now, 0.01))

        pre_map = {}
        acc_map = {}

        while True:
            try:
                msg = in_q.get_nowait()
            except queue.Empty:
                break

            stage = msg.get("stage")
            ft = msg.get("ft", {}) or {}
            dir_str = msg.get("dir", "")
            key = make_key(ft, dir_str)

            if stage == 0:  # PRE
                pre_map[key] = pre_map.get(key, 0) + 1
            else:           # VERDICT
                v = str(msg.get("verdict", "")).upper()
                verdict_tot[v] = verdict_tot.get(v, 0) + 1
                if v == "ACCEPT":
                    acc_map[key] = acc_map.get(key, 0) + 1
                elif v == "DROP":
                    sip = ft.get("saddr", "0.0.0.0")
                    drop_ip_cum[sip] = drop_ip_cum.get(sip, 0) + 1

        ts_ms = int(time.time() * 1000)

        def topk(d):
            if not d: return {}
            items = sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:TOPK]
            return {k: v for k, v in items}

        pre_top = topk(pre_map)
        acc_top = topk(acc_map)

        # // ADD: pps 보정 — pre가 비면 acc 합으로라도 pps 계산
        pkt_sum = sum(pre_map.values())
        if pkt_sum == 0:
            pkt_sum = sum(acc_map.values())
        pps = int(pkt_sum * (1000 / BUCKET_MS))

        # // ADD: All-plot 폴백 — pre가 비면 acc 맵으로라도 그려주기
        if not pre_top and acc_top:
            pre_top = acc_top.copy()

        snap = {
            "t": ts_ms,
            "bucket_ms": BUCKET_MS,
            "window_ms": WINDOW_SEC * 1000,
            "group_mode": GROUP,
            "pre": pre_top,         # 새 키(세션/IP 공용)
            "acc": acc_top,         # 새 키(세션/IP 공용)
            "pps": pps,
            "verdict": verdict_tot,
            "drop_ip": drop_ip_cum,
        }
        # 하위호환: ip 모드일 때 예전 키도 같이 보냄(프론트 변경 누락 대비)
        if GROUP.lower() != "session":
            snap["pre_ip"] = pre_top
            snap["acc_ip"] = acc_top

        broadcast(snap)
        next_t += bucket_s
        # 지연 누적 방지: 너무 밀렸으면 현재 시각 기준으로 재설정
        if next_t < time.time() - bucket_s:
            next_t = time.time()

# // ADD: 서버 설정을 INDEX_HTML에 주입해 주는 빌더
def build_index_html():
    cfg = {
        "bucket_ms": BUCKET_MS,
        "window_sec": WINDOW_SEC,
        "topk": TOPK,
        "ymax": YMAX,
        "smooth_alpha": SMOOTH_ALPHA,
        "group": GROUP,
        "sess_include_dir": SESS_INCLUDE_DIR,
        "pair_with_ports": PAIR_WITH_PORTS,
        "pair_keep_dir":   PAIR_KEEP_DIR,
        "linger_ms": LINGER_MS,
        "y_tick": Y_TICK,
        "x_dtick_ms": X_DTICK_MS,
        "y_auto": YAUTO,
        "y_pad_pct": YPAD_PCT,
        "y_min_range": YMIN_RANGE,
        "y_auto_sticky": YAUTO_STICKY,
    }
    import json as _json
    return INDEX_HTML.replace("/*__CFG__*/{}", _json.dumps(cfg))

class Handler(BaseHTTPRequestHandler):
    server_version = "ArgusUITap/1.1"

    def _send_bytes(self, b: bytes, status=HTTPStatus.OK, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/":
            # // MOD: 정적 HTML이 아니라 빌드된 HTML 반환
            self._send_bytes(build_index_html().encode("utf-8"))
            return
        if self.path == "/healthz":
            self._send_bytes(b"ok\n", content_type="text/plain; charset=utf-8")
            return
        if self.path.startswith("/stream"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = queue.Queue(maxsize=1000)
            with clients_lock:
                clients.add(q)
            try:
                import json as _json
                while running:
                    try:
                        snap = q.get(timeout=1.0)
                    except queue.Empty:
                        hb = f"event: ping\ndata: {int(time.time()*1000)}\n\n".encode("utf-8")
                        self.wfile.write(hb); self.wfile.flush()
                        continue
                    data = _json.dumps(snap, separators=(",", ":"))
                    msg = f"data: {data}\n\n".encode("utf-8")
                    self.wfile.write(msg); self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with clients_lock:
                    clients.discard(q)
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def log_message(self, fmt, *args):
        if os.environ.get("ARGUS_HTTP_LOG", "0") == "1":
            super().log_message(fmt, *args)

INDEX_HTML = r'''<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Argus Realtime View</title>
  <style>
    html, body { margin:0; padding:0; height:100%; font-family: system-ui, -apple-system, Segoe UI, Roboto, "Noto Sans", Arial; }
    #wrap { display:flex; flex-direction:column; height:100%; }
    header { padding:8px 12px; border-bottom:1px solid #e5e7eb; }
    main {
      flex:1; display:grid;
      grid-template-columns: 1fr 1fr 240px;
      grid-template-rows: 1fr 1fr;
      gap:10px; padding:10px;
    }
    #chart_all, #chart_acc, #chart_all_cum, #chart_acc_cum { width:100%; height:100%; }
    #chart_all { grid-column:1; grid-row:1; }
    #chart_acc { grid-column:2; grid-row:1; }
    #chart_all_cum { grid-column:1; grid-row:2; }
    #chart_acc_cum { grid-column:2; grid-row:2; }
    #legendCol { grid-column:3; grid-row:1 / span 2; border-left:1px solid #e5e7eb; padding-left:10px; overflow:auto; }
    #stats { display:flex; gap:16px; padding:8px 12px; font-size:14px; color:#374151;}
    .pill { background:#f3f4f6; border-radius:12px; padding:4px 8px; }
    .lg-item { display:flex; align-items:center; gap:8px; font-size:13px; margin:4px 0; white-space:nowrap; }
    .swatch { width:12px; height:12px; border-radius:2px; border:1px solid #e5e7eb; }
    h3 { margin:8px 0 6px; font-size:14px; color:#374151; }
  </style>
  <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
  <script>const CFG=/*__CFG__*/{};</script>
</head>
<body>
<div id="wrap">
  <header>
    <div style="display:flex; align-items:center; justify-content:space-between;">
      <div><strong>Argus Realtime View</strong> <span style="color:#6b7280">All Traffic vs ACCEPT-only</span></div>
      <div id="stats">
        <span class="pill" id="pps">pps: 0</span>
        <span class="pill" id="acc">ACCEPT: 0</span>
        <span class="pill" id="drp">DROP: 0</span>
        <span class="pill" id="dropPct">drop%: 0</span>
        <span class="pill" id="dbgSse">sse: ?</span>
        <span class="pill" id="dbgKeys">keys A:0/B:0</span>
      </div>
    </div>
  </header>
  <main>
    <div id="chart_all"></div>
    <div id="chart_acc"></div>
    <div id="chart_all_cum"></div>
    <div id="chart_acc_cum"></div>
    <div id="legendCol">
      <h3>Legend</h3>
      <div id="legendList"></div>
    </div>
  </main>
</div>
<script>
// === 서버 주입 설정 ===
const WINDOW_MS = (CFG.window_sec||60)*1000;
const BUCKET_MS = CFG.bucket_ms || 100;
const MAX_POINTS = Math.max(10, Math.round(WINDOW_MS / BUCKET_MS));
const topK = parseInt(new URLSearchParams(location.search).get("top") || (CFG.topk||10), 10);
const SMOOTH_ALPHA = (CFG.smooth_alpha !== undefined) ? CFG.smooth_alpha : 0.0; // 0=off
const YMAX = CFG.ymax || 0;
const LINGER_MS = (CFG.linger_ms !== undefined) ? CFG.linger_ms : 600000;
const MAX_TRACES = 40;   // Plotly 트레이스 객체 총 상한 (필요 시 조정)
const YAUTO      = (CFG.y_auto !== undefined) ? (CFG.y_auto|0) : 1;
const YPAD_PCT   = (CFG.y_pad_pct !== undefined) ? CFG.y_pad_pct : 0.10;
const YMIN_RANGE = (CFG.y_min_range !== undefined) ? CFG.y_min_range : 300;
const YAUTO_STICKY = (CFG.y_auto_sticky !== undefined) ? (CFG.y_auto_sticky|0) : 1;

function mkXaxis(){
  const xa = { type:"date", tickformat:"%H:%M:%S" };
  if (CFG.x_dtick_ms && CFG.x_dtick_ms > 0) {
    xa.dtick = CFG.x_dtick_ms; // 예: 5000 = 5초마다 눈금
  }
  return xa;
}

function pickDtickMs(windowMs) {
  const candidates = [1000, 2000, 5000, 10000, 15000, 30000, 60000, 120000];
  const target = windowMs / 9; // 8~10 눈금 정도
  let best = candidates[0], diff = Math.abs(candidates[0] - target);
  for (const c of candidates) {
    const d = Math.abs(c - target);
    if (d < diff) { diff = d; best = c; }
  }
  return best;
}

function mkYaxis(){
  // 자동축을 기본값으로: 처음엔 autorange, 이후 onmessage에서 sticky 적용
  const y = { title:"packets", rangemode:"tozero" };
  if (YAUTO === 1) {
    y.autorange = true;
    y.dtick = null;   // Plotly 자동 눈금
  } else if (YMAX > 0){
    y.range = [0, YMAX];
    y.autorange = false;
    if (CFG.y_tick && CFG.y_tick > 0) y.dtick = CFG.y_tick;
  } else {
    y.autorange = true;
  }
  y.tick0 = 0;
  return y;
}

function autoY_sticky(chartId, key, fixedYMax, observedMax, tms){
  if (YAUTO === 1) {
    const obs = Math.max(0, observedMax||0);
    // 스케일을 키울 필요가 있을 때만 올림(패딩 포함)
    const padded = Math.max(obs * (1 + YPAD_PCT), YMIN_RANGE);
    if (padded > (YHOLD[key] || 0)) {
      YHOLD[key] = padded;
      YHOLD_TS[key] = tms || Date.now();
    }
    // LINGER_MS 이후엔 리셋(옵션): “커진대로 계속” 원하면 이 if 블록 통째로 주석
    if (LINGER_MS > 0 && tms && YHOLD_TS[key] > 0 && (tms - YHOLD_TS[key]) > LINGER_MS) {
      // 마지막 확장 후 LINGER_MS가 지나면, 다시 최소 범위로 리셋
      YHOLD[key] = Math.max(YMIN_RANGE, obs * (1 + YPAD_PCT));
      YHOLD_TS[key] = tms;
    }
    // sticky: 축은 줄이지 않음(=YHOLD만 사용)
    Plotly.relayout(chartId, {
      "yaxis.range": [0, Math.max(YHOLD[key], YMIN_RANGE)],
      "yaxis.autorange": false,
      "yaxis.dtick": null  // 자동 눈금
    });
  } else if (fixedYMax > 0) {
    // 고정축 모드
    Plotly.relayout(chartId, {
      "yaxis.range": [0, fixedYMax],
      "yaxis.autorange": false,
      "yaxis.dtick": (CFG.y_tick && CFG.y_tick > 0) ? CFG.y_tick : null
    });
  } else {
    // Plotly 기본 자동축
    Plotly.relayout(chartId, {
      "yaxis.autorange": true,
      "yaxis.dtick": null
    });
  }
}

function gcOldKeys(map, lastSeen, cutoffMs) {
  const now = Date.now();
  for (const k of Object.keys(map)) {
    if (!lastSeen[k] || now - lastSeen[k] > cutoffMs) delete map[k];
  }
}

// === 색상 매핑(키 기반) ===
function colorForKey(key){
  let h=0; for(let i=0;i<key.length;i++){ h = (h*131 + key.charCodeAt(i)) >>> 0; }
  const hue = h % 360; const sat = 55 + (h % 20); const light = 45 + (Math.floor(h/7) % 15);
  return `hsl(${hue}, ${sat}%, ${light}%)`;
}

// === 상태 ===
let tracesAll = {};  // key -> trace index (All)
let tracesAcc = {};  // key -> trace index (ACCEPT)
let emaAll = {};     // key -> EMA value (All)
let emaAcc = {};     // key -> EMA value (ACCEPT)
let lastSeenAll = {}; // key -> last timestamp(ms) 관측
let lastSeenAcc = {};
let tracesAllCum = {};
let tracesAccCum = {};
let cumAll = {};   // key -> 누적 raw count
let cumAcc = {};

// 차트별 sticky y-hold 값과 마지막 갱신 시각
let YHOLD = { all:0, acc:0, all_cum:0, acc_cum:0 };
let YHOLD_TS = { all:0, acc:0, all_cum:0, acc_cum:0 };

// === 공통 TOP-K(10개) 가시 세트 유지 ===
// 누적합이 가장 안정적이라 "누적 합산 기준 topK"로 고정 추천
let VISIBLE_TOP = [];      // 배열(정렬된 10개)
let VISIBLE_SET = new Set();  // 빠른 포함 체크

// 페이지 JS 에러를 눈으로 보기
window.onerror = function(msg, src, line, col, err){
  const el = document.getElementById("dbgSse");
  if (el) el.textContent = "err: " + String(msg).slice(0,60);
};

// SSE 상태 표시
function markSse(txt){ const el=document.getElementById("dbgSse"); if(el) el.textContent=txt; }
markSse("connecting…");

// === Plot 초기화 ===
Plotly.newPlot("chart_all", [], {
  title: (CFG.group==="session"
        ? "All Traffic (per session, per bucket)"
        : (CFG.group==="pair"
            ? "All Traffic (per IP pair, per bucket)"
            : "All Traffic (per source IP, per bucket)")),
  xaxis: mkXaxis(),
  yaxis: mkYaxis(),
  showlegend: false,
  legend: { orientation:"h" },
  margin:{t:40,l:40,r:10,b:30}
});
Plotly.newPlot("chart_acc", [], {
  title: (CFG.group==="session"
        ? "ACCEPT-only (per session, per bucket)"
        : (CFG.group==="pair"
            ? "ACCEPT-only (per IP pair, per bucket)"
            : "ACCEPT-only (per source IP, per bucket)")),
  xaxis: mkXaxis(),
  yaxis: mkYaxis(),
  showlegend: false,
  legend: { orientation:"h" },
  margin:{t:40,l:40,r:10,b:30}
});

Plotly.newPlot("chart_all_cum", [], {
  title: "All Traffic (per source IP, cumulative)",
  xaxis: mkXaxis(),
  yaxis: { title:"packets (cumulative)", rangemode:"tozero" },
  showlegend: false,
  legend: { orientation:"h" },
  margin:{t:40,l:40,r:10,b:30}
});

Plotly.newPlot("chart_acc_cum", [], {
  title: "ACCEPT-only (per source IP, cumulative)",
  xaxis: mkXaxis(),
  yaxis: { title:"packets (cumulative)", rangemode:"tozero" },
  showlegend: false,
  legend: { orientation:"h" },
  margin:{t:40,l:40,r:10,b:30}
});

function ensureTrace(chartId, map, key){
  if (map[key] !== undefined) return map[key];
  const idx = Object.keys(map).length;
  map[key] = idx;
  Plotly.addTraces(chartId, [{ x:[], y:[], mode:"lines", name:key, line:{color:colorForKey(key)} }]);
  return idx;
}

function pruneTraces(chartId, map, keepSet){
  const names = Object.keys(map);
  if (names.length <= MAX_TRACES) return;

  // keepSet에 없는 오래된 것부터 제거
  for (const k of names){
    if (!keepSet.has(k)) {
      const idx = map[k];
      Plotly.deleteTraces(chartId, [idx]);
      delete map[k];
      // 인덱스 재빌드 (트레이스 삭제 후 index들이 당겨짐)
      const newMap = {};
      const gd = document.getElementById(chartId);
      (gd.data || []).forEach((tr, i) => { newMap[tr.name] = i; });
      Object.assign(map, newMap);

      if (Object.keys(map).length <= MAX_TRACES) break;
    }
  }
}

function extendChartCumulative(chartId, map, t, byMap, cumMap){
  // 1) 누적합 갱신 (raw count 그대로 합산)
  for (const k of Object.keys(byMap)){
    cumMap[k] = (cumMap[k] || 0) + (byMap[k] || 0);
  }
  // 2) 누적합 기준 Top-K
  const top = Object.entries(cumMap)
    .sort((a,b)=>b[1]-a[1])
    .slice(0, topK)
    .map(([k])=>k);
  // === 공통 TOP 세트 필터링 ===
  const topFiltered = top.filter(k => VISIBLE_SET.size === 0 || VISIBLE_SET.has(k));

  // 3) 그리기
  const update = { x:[], y:[], indices:[] };
  for (const k of topFiltered){
    const idx = ensureTrace(chartId, map, k);
    update.indices.push(idx);
    update.x.push([t]);
    update.y.push([cumMap[k]]);
  }
  if (update.indices.length > 0){
    Plotly.extendTraces(chartId, {x:update.x, y:update.y}, update.indices, MAX_POINTS);
  }
  pruneTraces(chartId, map, new Set(topFiltered));

  const maxY = update.y.reduce((m, arr)=> Math.max(m, (arr && arr.length ? arr[0] : 0)), 0);
  return { cands: topFiltered, maxY };
}

// byMap: { key: rawCount }
function extendChart(chartId, map, emaMap, lastSeenMap, t, tms, byMap){
  // 1) 이번 버킷 raw 기준 topK
  const curKeys = Object.keys(byMap);
  const curTop  = curKeys.sort((a,b)=>byMap[b]-byMap[a]).slice(0, topK);

  // 2) 과거 EMA 상위에서 잔상 보강(현재 topK에 없는 것만)
  const emaSorted = Object.entries(emaMap)
    .sort((a,b)=>(b[1]||0)-(a[1]||0))
    .map(([k])=>k)
    .filter(k => !curTop.includes(k));

  // 3) 최종 후보(현재 topK 우선 + EMA 보강 → topK개)
  const candidates = curTop.concat(emaSorted).slice(0, topK);
  // === 공통 TOP 세트 필터링 ===
  const candFiltered = candidates.filter(k => VISIBLE_SET.size === 0 || VISIBLE_SET.has(k));

  const update = { x:[], y:[], indices:[] };
  const seen = new Set();

  // 후보들만 그리기(EMA 스무딩/미관측 감쇠 포함)
  for (const k of candFiltered){
    const idx = ensureTrace(chartId, map, k);
    let y = (byMap[k] !== undefined) ? byMap[k] : ((emaMap[k] !== undefined) ? emaMap[k] : 0);

    // === 추가: 버킷 크기에 맞춰 초당 환산 (pps)
    const SCALE = 1000 / BUCKET_MS;
    y = y * SCALE;

    if (SMOOTH_ALPHA > 0){
      const prev = (emaMap[k] !== undefined) ? emaMap[k] : y;
      const sm = (byMap[k] !== undefined)
        ? (SMOOTH_ALPHA*prev + (1-SMOOTH_ALPHA)*y)   // 관측 시
        : (SMOOTH_ALPHA*prev + (1-SMOOTH_ALPHA)*0);  // 미관측 시 감쇠
      emaMap[k] = sm; y = sm;
    }

    update.indices.push(idx);
    update.x.push([t]);
    update.y.push([y]);
    seen.add(k);
  }

  // (기존 LINGER 블록 그대로 유지)
  for (const k in map){
    if (seen.has(k)) continue;
    const idx = map[k];

    const last = lastSeenMap[k] || 0;
    let y = 0;

    if (LINGER_MS > 0 && (tms - last) <= LINGER_MS){
      y = (emaMap[k] !== undefined) ? emaMap[k] : 0;
      if (SMOOTH_ALPHA > 0){
        const alpha = SMOOTH_ALPHA;
        const sm = alpha*y + (1-alpha)*0;
        emaMap[k] = sm;
        y = sm;
      }
    } else {
      if (SMOOTH_ALPHA > 0){
        const prev = emaMap[k] || 0;
        const alpha = SMOOTH_ALPHA;
        const sm = alpha*prev + (1-alpha)*0;
        emaMap[k] = sm;
        y = sm;
      } else {
        y = 0;
      }
    }

    update.indices.push(idx);
    update.x.push([t]);
    update.y.push([y]);
  }

  if (update.indices.length > 0){
    Plotly.extendTraces(chartId, {x:update.x, y:update.y}, update.indices, MAX_POINTS);
  }

  // 이번 버킷에 실제로 표시한 후보 목록 + 이번 버킷 최대 y
  const maxY = update.y.reduce((m, arr)=> Math.max(m, (arr && arr.length ? arr[0] : 0)), 0);
  pruneTraces(chartId, map, new Set(candFiltered));
  return { cands: candFiltered, maxY };
}

// cumAll, cumAcc 두 맵의 합산 값으로 전역 TOP-K 재계산
function recomputeVisibleTopFromCum(topK, cumAll, cumAcc) {
  const mix = {};
  for (const [k,v] of Object.entries(cumAll)) mix[k] = (mix[k]||0) + v;
  for (const [k,v] of Object.entries(cumAcc)) mix[k] = (mix[k]||0) + v;

  const top = Object.entries(mix)
    .sort((a,b)=>b[1]-a[1])
    .slice(0, topK)
    .map(([k])=>k);

  VISIBLE_TOP = top;
  VISIBLE_SET = new Set(top);
}

function renderLegendFromCandidates(cands){
  const box = document.getElementById("legendList");
  box.innerHTML = "";
  for(const k of cands){
    const div = document.createElement("div");
    div.className = "lg-item";
    const sw = document.createElement("span");
    sw.className = "swatch";
    sw.style.background = colorForKey(k);
    const txt = document.createElement("span");
    txt.textContent = k;
    div.appendChild(sw); div.appendChild(txt);
    box.appendChild(div);
  }
}

// SSE
const evt = new EventSource(new URL("/stream", window.location.href));
evt.onopen = ()=> markSse("open");
evt.onerror = (e)=> { markSse("err"); console.log("SSE error/reconnect", e); };
evt.onmessage = (e)=>{
  markSse("ok");
  const d = JSON.parse(e.data);
  const tms = d.t; const t = new Date(tms);

  // 새 키(pre/acc) 우선, 없으면 구 키(pre_ip/acc_ip) fallback
  const pre = d.pre || d.pre_ip || {};
  const acc = d.acc || d.acc_ip || {};

  // 키 개수 표시
  const dbgK = document.getElementById("dbgKeys");
  if (dbgK) dbgK.textContent = `keys A:${Object.keys(pre).length}/B:${Object.keys(acc).length}`;

  for (const k of Object.keys(pre)) lastSeenAll[k] = tms;
  for (const k of Object.keys(acc)) lastSeenAcc[k] = tms;

  const accTot = (d.verdict && d.verdict.ACCEPT) || 0;
  const drpTot = (d.verdict && d.verdict.DROP) || 0;
  const pps = d.pps || 0;
  const total = accTot + drpTot;
  const dropPct = total > 0 ? (drpTot/total)*100.0 : 0.0;

  document.getElementById("pps").textContent = "pps: " + Math.round(pps);
  document.getElementById("acc").textContent = "ACCEPT: " + accTot;
  document.getElementById("drp").textContent = "DROP: " + drpTot;
  document.getElementById("dropPct").textContent = "drop%: " + dropPct.toFixed(2);

  // SSE onmessage:
  // 1) 누적합 갱신(맵 업데이트) 먼저 실행
  const rCA = extendChartCumulative("chart_all_cum",  tracesAllCum, t, pre, cumAll);
  const rCB = extendChartCumulative("chart_acc_cum",  tracesAccCum, t, acc, cumAcc);

  // 2) 누적합 합산으로 공통 TOP10 재계산(이 시점에 VISIBLE_SET 갱신)
  recomputeVisibleTopFromCum(topK, cumAll, cumAcc);

  // 3) 공통 TOP10만 rate 차트에도 반영하여 그리기
  const rA = extendChart("chart_all", tracesAll, emaAll, lastSeenAll, t, tms, pre);
  const rB = extendChart("chart_acc", tracesAcc, emaAcc, lastSeenAcc, t, tms, acc);

  // 4) 커스텀 범례도 공통 TOP10로 고정
  renderLegendFromCandidates(VISIBLE_TOP);

  // --- 슬라이딩 윈도우 & 가변 눈금 ---
  if (WINDOW_MS > 0){
    const left = new Date(tms - WINDOW_MS);
    Plotly.relayout("chart_all",     {"xaxis.range":[left, t]});
    Plotly.relayout("chart_acc",     {"xaxis.range":[left, t]});
    Plotly.relayout("chart_all_cum", {"xaxis.range":[left, t]});
    Plotly.relayout("chart_acc_cum", {"xaxis.range":[left, t]});

    const dt = pickDtickMs(WINDOW_MS);
    Plotly.relayout("chart_all",     {"xaxis.dtick": dt});
    Plotly.relayout("chart_acc",     {"xaxis.dtick": dt});
    Plotly.relayout("chart_all_cum", {"xaxis.dtick": dt});
    Plotly.relayout("chart_acc_cum", {"xaxis.dtick": dt});
  }

  // --- 자동 Y 스케일(레이트 차트는 YAUTO 정책, 누적은 항상 자동 권장) ---
  autoY_sticky("chart_all",     "all",     YMAX, rA.maxY,  tms);
  autoY_sticky("chart_acc",     "acc",     YMAX, rB.maxY,  tms);
  autoY_sticky("chart_all_cum", "all_cum", 0,    rCA.maxY, tms);
  autoY_sticky("chart_acc_cum", "acc_cum", 0,    rCB.maxY, tms);
};
  gcOldKeys(cumAll, lastSeenAll, 10*60*1000);
  gcOldKeys(cumAcc, lastSeenAcc, 10*60*1000);
</script>
</body>
</html>
'''

def serve():
    httpd = ThreadingHTTPServer((HOST_HTTP, PORT_HTTP), Handler)
    print(f"[HTTP] http://{HOST_HTTP}:{PORT_HTTP}  (SSE stream at /stream)")
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

def main():
    global running
    # // MOD: 시작 시 적용된 CFG도 함께 보이게
    print(f"[CFG] UDP={HOST_UDP}:{PORT_UDP}  HTTP={HOST_HTTP}:{PORT_HTTP}  " f"bucket={BUCKET_MS}ms  topK={TOPK}  window={WINDOW_SEC}s  " f"ymax={YMAX}  smooth_alpha={SMOOTH_ALPHA} linger_ms={LINGER_MS} group={GROUP}  " f"pair_with_ports={PAIR_WITH_PORTS}  pair_keep_dir={PAIR_KEEP_DIR}", flush=True)

    def on_sig(sig, frm):
        global running
        running = False
    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGTERM, on_sig)

    th_udp = threading.Thread(target=udp_receiver, daemon=True)
    th_agg = threading.Thread(target=aggregator,   daemon=True)
    th_udp.start(); th_agg.start()
    serve()
    running=False
    th_udp.join(timeout=1.0)
    th_agg.join(timeout=1.0)

if __name__ == "__main__":
    main()

