import asyncio, time, math, heapq, collections
from collections import deque, defaultdict
from typing import Deque, Dict, Tuple
from config import CFG

VALID_STAGES = {"pre", "acc"}

_seen = collections.OrderedDict()
_SEEN_CAP = 50000

def _dedup(key):
    if key in _seen:
        _seen.move_to_end(key, last=True)
        return True
    _seen[key] = True
    if len(_seen) > _SEEN_CAP:
        _seen.popitem(last=False)
    return False

def _now_mono(): return time.monotonic()
def _now_wall(): return time.time()

class RollingStore:
    """IP별 100ms 카운트를 윈도우 길이만큼 보관(표시: 최근 윈도우 합)."""
    def __init__(self, buckets:int):
        self.store: Dict[str, Deque[int]] = defaultdict(lambda: deque(maxlen=buckets))
        self.last_seen_wall: Dict[str, float] = {}
        self.buckets = buckets
    def push(self, ip:str, cnt:int, ts_wall:float):
        self.store[ip].append(cnt)
        self.last_seen_wall[ip] = ts_wall
    def sum(self, ip:str) -> int:
        dq = self.store.get(ip)
        return 0 if not dq else sum(dq)
    def topk(self, k:int):
        # 성능: nlogk (nlargest)
        return heapq.nlargest(k, ((ip, self.sum(ip)) for ip in self.store.keys()),
                              key=lambda kv: kv[1])
    def gc(self, older_than_wall: float):
        dead = [ip for ip, ts in self.last_seen_wall.items() if ts < older_than_wall]
        for ip in dead:
            self.store.pop(ip, None)
            self.last_seen_wall.pop(ip, None)

class Aggregator:
    def __init__(self):
        self.bucket_ms = CFG.bucket_ms
        self.bucket_s  = CFG.bucket_ms / 1000.0

        # 100ms 버킷 카운트
        self.b_all = 0
        self.b_acc = 0
        self.ip_bucket_all: Dict[str,int] = defaultdict(int)
        self.ip_bucket_acc: Dict[str,int] = defaultdict(int)

        # 1초 PPS용 (100ms×10)
        self.last10_all = deque(maxlen=10)
        self.last10_acc = deque(maxlen=10)

        # 롤링 누적(윈도우 합)
        buckets = int((CFG.window_s*1000)//CFG.bucket_ms)
        self.roll_all = RollingStore(buckets=buckets)
        self.roll_acc = RollingStore(buckets=buckets)

        # DoS 베이스라인(글로벌)
        self.mean = 0.0; self.m2 = 0.0; self.n = 0
        self.ewma_all = None
        self.over_frames = 0
        self.dos_on = False  # 알람 상태

        # IP 드롭 추정 상태
        self.ip_suppress_cnt: Dict[str,int] = defaultdict(int)  # 연속 프레임 카운터
        self.ip_suppressed: Dict[str,bool] = defaultdict(bool)

    def _pps1s(self, last10: deque) -> float:
        # 100ms 합계를 초당으로 환산
        return sum(last10) * (1000.0/CFG.bucket_ms)

    def _update_baseline(self, val: float):
        # 알람 OFF 구간에서만 업데이트 권장
        self.n += 1
        d = val - self.mean
        self.mean += d / self.n
        self.m2 += d * (val - self.mean)

    def _std(self) -> float:
        return math.sqrt(self.m2 / max(self.n - 1, 1))

    def _detect_global_dos(self, pps_all: float) -> Tuple[bool, float]:
        std = self._std() or 1.0
        suspicious = (pps_all > self.mean + 3*std) or (pps_all > CFG.dos_pps)
        if suspicious:
            self.over_frames += 1
        else:
            self.over_frames = max(self.over_frames - 1, 0)
        new_on = self.over_frames >= 5  # 0.5s 지속
        if not new_on and self.n > 10:
            self._update_baseline(pps_all)
        z = (pps_all - self.mean)/std if std > 0 else 0.0
        return new_on, z

    def _detect_ip_drop_events(self, ts_wall: float,
                               pps_map_all: Dict[str,float],
                               pps_map_acc: Dict[str,float]) -> list:
        """ACC/ALL 비율이 낮아 사실상 차단된 IP 이벤트(DROP_ON/OFF) 생성."""
        evts = []
        ratio_thr = CFG.ip_drop_ratio
        hold = CFG.ip_drop_hold_frames

        # 관측된 모든 IP(유니온)
        ips = set(pps_map_all.keys()) | set(pps_map_acc.keys())

        for ip in ips:
            all_pps = pps_map_all.get(ip, 0.0)
            acc_pps = pps_map_acc.get(ip, 0.0)
            ratio = (acc_pps / all_pps) if all_pps > 0 else 1.0  # all=0이면 문제없음
            suppressed_now = (all_pps >= 1.0) and (ratio < ratio_thr)

            if suppressed_now:
                self.ip_suppress_cnt[ip] += 1
                if (not self.ip_suppressed[ip]) and (self.ip_suppress_cnt[ip] >= hold):
                    # 새로 차단 상태로 전이
                    self.ip_suppressed[ip] = True
                    evts.append({"type":"DROP_ON","ip":ip,"ts_wall":ts_wall})
            else:
                # 회복(ACC가 다시 흐름)
                if self.ip_suppressed[ip]:
                    evts.append({"type":"DROP_OFF","ip":ip,"ts_wall":ts_wall})
                self.ip_suppress_cnt[ip] = 0
                self.ip_suppressed[ip] = False

        return evts

    async def run(self, q_raw: asyncio.Queue, q_frame: asyncio.Queue):
        next_t = _now_mono()

        while True:
            # 수신 비우기(최대한 빠르게)
            while not q_raw.empty():
                msg = await q_raw.get()

                # ----- 입력 정규화 -----
                # 1) stage: 문자열("pre"/"acc") 또는 숫자(0/1) 모두 지원
                st = None
                sraw = msg.get("stage")
                if isinstance(sraw, str):
                    s = sraw.strip().lower()
                    if s in VALID_STAGES:
                        st = s
                elif isinstance(sraw, int):
                    st = {0: "pre", 1: "acc"}.get(sraw)

                # 2) verdict: 문자열이면 상단 공백 제거&대문자화
                verdict = msg.get("verdict")
                if isinstance(verdict, str):
                    verdict = verdict.strip().upper()
                else:
                    verdict = ""

                # 3) IP 추출: msg["ip"] 우선, 없으면 ft.saddr로 폴백
                ft  = msg.get("ft") or {}
                src = msg.get("ip") or ft.get("saddr") or "0.0.0.0"

                # 4) (pkt_id, stage) 기준 디듑: acc 이중 집계 방지
                pid = msg.get("pkt_id")
                if pid is not None and st is not None and _dedup((pid, st)):
                    continue

                # ----- 집계 규칙 -----
                # - 문자열 스키마("pre"/"acc"): pre → ALL, acc → ACC
                # - 숫자+verdict 스키마(0/1+ACCEPT): 0 → ALL, 1&ACCEPT → ACC
                if st == "pre":
                    self.b_all += 1
                    self.ip_bucket_all[src] += 1

                elif st == "acc":
                    # 문자열 스키마에서는 'acc' 자체가 accept 통과 의미
                    self.b_acc += 1
                    self.ip_bucket_acc[src] += 1

                else:
                    # st를 못 알아들었으면 과거 스키마(숫자) 가정
                    stage_num = msg.get("stage", None)
                    if isinstance(stage_num, int):
                        if stage_num == 0:
                            self.b_all += 1
                            self.ip_bucket_all[src] += 1
                        elif stage_num == 1 and verdict == "ACCEPT":
                            self.b_acc += 1
                            self.ip_bucket_acc[src] += 1
                    # 그 외는 무시

            now = _now_mono()
            if now < next_t:
                await asyncio.sleep(min(next_t - now, 0.01))
                continue

            # ----- 100ms 버킷 종료 -----
            self.last10_all.append(self.b_all); self.b_all = 0
            self.last10_acc.append(self.b_acc); self.b_acc = 0

            pps_all = self._pps1s(self.last10_all)
            pps_acc = self._pps1s(self.last10_acc)
            self.ewma_all = pps_all if self.ewma_all is None else 0.2*pps_all + 0.8*self.ewma_all

            ts_wall = _now_wall()

            # 롤링 누적(윈도우 합) 업데이트
            for ip, c in self.ip_bucket_all.items():
                self.roll_all.push(ip, c, ts_wall)
            for ip, c in self.ip_bucket_acc.items():
                self.roll_acc.push(ip, c, ts_wall)

            # IP별 PPS(100ms -> 초당 환산)
            SCALE = (1000.0/CFG.bucket_ms)
            pps_ip_all_list = heapq.nlargest(CFG.topk,
                ((ip, cnt*SCALE) for ip, cnt in self.ip_bucket_all.items()),
                key=lambda kv: kv[1])
            pps_ip_acc_list = heapq.nlargest(CFG.topk,
                ((ip, cnt*SCALE) for ip, cnt in self.ip_bucket_acc.items()),
                key=lambda kv: kv[1])

            pps_map_all = {ip:v for ip,v in pps_ip_all_list}
            pps_map_acc = {ip:v for ip,v in pps_ip_acc_list}

            # 롤링 누적 TopK
            cum_all = self.roll_all.topk(CFG.topk)
            cum_acc = self.roll_acc.topk(CFG.topk)

            # 메모리 GC
            self.roll_all.gc(older_than_wall=ts_wall - 120)
            self.roll_acc.gc(older_than_wall=ts_wall - 120)

            # 글로벌 DoS 감지
            dos_on_new, z = self._detect_global_dos(pps_all)
            events = []
            if dos_on_new and not self.dos_on:
                events.append({"type":"ALERT_ON","ts_wall":ts_wall})
            elif (not dos_on_new) and self.dos_on:
                events.append({"type":"ALERT_OFF","ts_wall":ts_wall})
            self.dos_on = dos_on_new

            # IP 드롭 추정 이벤트
            events += self._detect_ip_drop_events(ts_wall, pps_map_all, pps_map_acc)

            frame = {
                "ts_mono": _now_mono(),
                "ts_wall": ts_wall,
                "bucket_ms": CFG.bucket_ms,
                "window_s": CFG.window_s,
                "pps_all": pps_all,
                "pps_acc": pps_acc,
                "pps_ewma": self.ewma_all,
                "pps_ip_all": [{"ip":ip,"pps":v} for ip,v in pps_ip_all_list],
                "pps_ip_acc": [{"ip":ip,"pps":v} for ip,v in pps_ip_acc_list],
                "cum30s_all": [{"ip":ip,"sum":v} for ip,v in cum_all],
                "cum30s_acc": [{"ip":ip,"sum":v} for ip,v in cum_acc],
                "alert": {"on": bool(self.dos_on), "z": z},
                "events": events,
            }

            # 다음 버킷 준비
            self.ip_bucket_all.clear()
            self.ip_bucket_acc.clear()

            # 프레임 큐(가득 차면 오래된 것부터 버림)
            if q_frame.full():
                try: q_frame.get_nowait()
                except asyncio.QueueEmpty: pass
            await q_frame.put(frame)

            # 틱 정렬
            next_t += self.bucket_s
            if next_t < _now_mono() - self.bucket_s:
                next_t = _now_mono()

