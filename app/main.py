"""FastAPI 入口。"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import api, payloads
from app.db import close_pool, init_db
from app.keyring import get_keyring
from app.objectstore import init_object_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

OWNER_ID = (
    f"api:{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # 对象存储桶/目录就绪检查：不可用则启动失败（避免提交期才暴露）。
    await init_object_store()
    # 启动时加载本地密钥环：配置非法直接启动失败（避免运行期才暴露）；
    # 未配置则降级为只读（写入接口 503），详见 app/keyring.py。
    get_keyring()
    # 提交状态机后台恢复：崩溃/重启残留的“已登记/已上传未终结”提交由此续跑。
    recovery_task = asyncio.create_task(payloads.recovery_loop(OWNER_ID))
    try:
        yield
    finally:
        recovery_task.cancel()
        try:
            await recovery_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        await close_pool()


app = FastAPI(
    title="可靠 Webhook 投递服务",
    version="1.0.0",
    description=(
        "事件幂等提交、内容寻址载荷对象存储、严格顺序投递、租约抢占、"
        "指数退避、死信重放。交互文档见 /docs。"
    ),
    lifespan=lifespan,
)

app.include_router(api.router)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
