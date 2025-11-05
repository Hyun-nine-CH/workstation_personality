import asyncio, uvloop
from recv_udp import udp_receiver
from agg import Aggregator
from ws_server import queue_tx

async def main():
    q_raw   = asyncio.Queue(maxsize=5000)
    agg     = Aggregator()
    await asyncio.gather(
        udp_receiver(q_raw),
        agg.run(q_raw, queue_tx),
    )

if __name__ == "__main__":
    uvloop.install()
    asyncio.run(main())

