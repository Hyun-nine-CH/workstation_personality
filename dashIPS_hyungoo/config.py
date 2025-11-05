import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Cfg:
    host_udp:   str = os.getenv("ARGUS_UI_HOST", "127.0.0.1")
    port_udp:   int = int(os.getenv("ARGUS_UI_PORT", "9090"))
    host_http:  str = os.getenv("ARGUS_DASH_HOST", "127.0.0.1")
    port_http:  int = int(os.getenv("ARGUS_DASH_PORT", "8086"))

    bucket_ms:  int = int(os.getenv("ARGUS_BUCKET_MS", "100"))      # 100ms 집계
    window_s:   float = float(os.getenv("ARGUS_WINDOW_SEC", "30"))  # 30s 윈도우
    topk:       int = int(os.getenv("ARGUS_TOPK", "10"))            # 표시 IP 수
    dos_pps:    int = int(os.getenv("ARGUS_DOS_PPS", "50000"))      # 글로벌 DoS 하드 임계(PPS)

    # IP 드롭 추정 규칙 (ACC/ALL 비율)
    ip_drop_ratio: float = float(os.getenv("ARGUS_IP_DROP_RATIO", "0.05"))  # 5% 미만
    ip_drop_hold_frames: int = int(os.getenv("ARGUS_IP_DROP_HOLD", "5"))    # 0.5s(=5프레임) 지속

CFG = Cfg()
FRAME_S = 0.1  # WebSocket 10Hz 송신

