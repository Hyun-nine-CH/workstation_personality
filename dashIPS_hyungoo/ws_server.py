import asyncio, json, os
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from config import CFG, FRAME_S
from recv_udp import udp_receiver
from agg import Aggregator  # 클래스

app = FastAPI()

# 정적은 /static으로 서비스, / 는 index.html 반환
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def index():
    return FileResponse(os.path.join(static_dir, "index.html"))

# 한 프로세스 내 공유 큐
q_raw = asyncio.Queue(maxsize=1000)  # UDP raw → 집계
queue_tx = asyncio.Queue(maxsize=5)  # 집계 스냅샷 → WS

@app.on_event("startup")
async def _startup():
    # UDP 수신 태스크
    app.state.t_udp = asyncio.create_task(udp_receiver(q_raw))
    # 집계 태스크
    ag = Aggregator()
    app.state.t_agg = asyncio.create_task(ag.run(q_raw, queue_tx))

@app.on_event("shutdown")
async def _shutdown():
    for name in ("t_udp", "t_agg"):
        t = getattr(app.state, name, None)
        if t:
            t.cancel()

from starlette.websockets import WebSocketDisconnect

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            # 10Hz 틱: 최신 프레임만 보내기 (없으면 그냥 넘어감)
            try:
                # FRAME_S 주기 동안 대기, 그 사이 들어온 건 모두 drain 후 마지막만 사용
                latest = None
                end_at = asyncio.get_running_loop().time() + FRAME_S
                while True:
                    timeout = max(0.0, end_at - asyncio.get_running_loop().time())
                    item = await asyncio.wait_for(queue_tx.get(), timeout=timeout)
                    latest = item
                    # 남아있으면 더 비움(가장 최신만 유지)
                    while not queue_tx.empty():
                        latest = queue_tx.get_nowait()
                    # 틱 종료
                    break
            except asyncio.TimeoutError:
                latest = None

            if latest is not None:
                try:
                    await ws.send_text(json.dumps(latest))
                except WebSocketDisconnect:
                    # 클라이언트가 정상 종료(1000/1001 등) → 루프 종료
                    break
                except Exception:
                    # 기타 전송 예외도 조용히 종료
                    break
            # 틱 간격 맞추기
            await asyncio.sleep(FRAME_S)
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await ws.close()
        except:
            pass

