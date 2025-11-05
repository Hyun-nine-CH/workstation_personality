import asyncio, json, socket
from config import CFG

async def udp_receiver(q_raw: asyncio.Queue):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 127.0.0.1:9090 -> recv UDP
    sock.bind((CFG.host_udp, CFG.port_udp))

    sock.setblocking(False)
    print(f"[UDP] listening on {CFG.host_udp}:{CFG.port_udp}", flush=True)

    while True:
        # uvloop에서 sock_recvfrom 미구현 → sock_recv로 대체
        data = await loop.sock_recv(sock, 65535)
        try:
            msg = json.loads(data.decode("utf-8", "ignore"))
        except Exception:
            continue
        if q_raw.full():
            try: q_raw.get_nowait()
            except asyncio.QueueEmpty:
                pass
        await q_raw.put(msg)
'''
#
# uvlooply

import asyncio, json
from config import CFG

class UdpProto(asyncio.DatagramProtocol):
    def __init__(self, q_raw: asyncio.Queue):
        self.q_raw = q_raw

    def datagram_received(self, data: bytes, addr):
        try:
            msg = json.loads(data.decode("utf-8", "ignore"))
        except Exception:
            return
        # 큐가 가득이면 가장 오래된 프레임 drop
        if self.q_raw.full():
            try: self.q_raw.get_nowait()
            except asyncio.QueueEmpty: pass
        try:
            self.q_raw.put_nowait(msg)
        except asyncio.QueueFull:
            pass

    def error_received(self, exc):
        # 필요시 로깅만
        # print(f"[UDP] error: {exc}")
        pass

async def udp_receiver(q_raw: asyncio.Queue):
    loop = asyncio.get_running_loop()
    # 127.0.0.1:9090 바인드 (NFQ C가 여기에 쏨)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UdpProto(q_raw),
        local_addr=(CFG.host_udp, CFG.port_udp),
        reuse_port=False,
        allow_broadcast=False,
    )
    print(f"[UDP] listening on {CFG.host_udp}:{CFG.port_udp}", flush=True)

    # 종료 신호가 없으니 영원히 대기
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()
'''
