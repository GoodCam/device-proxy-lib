import asyncio

from .http import Authorization, Request, Response
from .native import lib
from .proxy import BlockRequest, ClientHandlerResult, DeviceHandlerResult, NativeProxy, ProxyConfig


__all__ = (
    'RequestHandler', 'Proxy', 'create_proxy',
)


class RequestHandler:
    def __init__(self) -> None:
        self.loop = None

    async def handle_device_request(self, authorization: Authorization) -> 'DeviceHandlerResult':
        return DeviceHandlerResult(DeviceHandlerResult.TYPE_UNAUTHORIZED)

    async def handle_client_request(self, request: Request) -> 'ClientHandlerResult':
        return BlockRequest(Response(501))


class Proxy(NativeProxy):
    async def run(self) -> None:
        loop = asyncio.get_running_loop()

        fut = loop.create_future()

        def join_cb(context, res):
            loop.call_soon_threadsafe(lambda: fut.set_result(res))

        cb = lib.PROXY_JOIN_CALLBACK(join_cb)

        self.call_method(lib.gcdp__proxy__join_async, cb, None)

        if (await fut) != 0:
            raise Exception(lib.get_last_error())

    def stop(self, timeout: float) -> None:
        self.call_method(lib.gcdp__proxy__stop, int(timeout * 1000))


async def create_proxy(config: ProxyConfig) -> 'Proxy':
    loop = asyncio.get_running_loop()

    config.request_handler.loop = loop

    fut = loop.create_future()

    def proxy_created(context, proxy):
        loop.call_soon_threadsafe(lambda: fut.set_result(proxy))

    cb = lib.NEW_PROXY_CALLBACK(proxy_created)

    config = config.to_native()

    lib.gcdp__proxy__new_async(config.raw_ptr, cb, None)

    raw_ptr = await fut

    if not raw_ptr:
        raise Exception(lib.get_last_error())

    proxy = Proxy(raw_ptr)

    # prevent the callbacks and contexts from being garbage collected
    proxy.device_request_handler = config.device_request_handler
    proxy.device_request_context = config.device_request_context
    proxy.client_request_handler = config.client_request_handler
    proxy.client_request_context = config.client_request_context

    return proxy
