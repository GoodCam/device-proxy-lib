import asyncio

from .http import Authorization, Request, Response
from .native import lib
from .proxy import BlockRequest, ClientHandlerResult, DeviceHandlerResult, NativeProxy, ProxyConfig


__all__ = (
    'RequestHandler', 'Proxy', 'create_proxy',
)


class RequestHandler:
    """Base class for asynchronous request handlers."""

    def __init__(self) -> None:
        self.loop = None

    async def handle_device_request(self, authorization: Authorization) -> 'DeviceHandlerResult':
        """Handle a given device request.

        The method is responsible for device authentication and (optionally)
        load balancing. It is called every time a GoodCam device connects to
        the proxy. The implementation should check the device ID and key in the
        authorization object.

        The method must return an instance of one of the following classes:

        * ``AcceptDevice`` - to accept the device connection
        * ``UnauthorizedDevice`` - to reject the device connection
        * ``RedirectDevice`` - to redirect the device to another proxy

        *The method is asynchronous. Do not use any blocking calls here! Always
        use the asynchronous alternatives (e.g. use aiohttp instead of
        requests).*

        :param authorization: device authorization object containing the device ID and key
        :returns: any subclass of ``DeviceHandlerResult``
        """
        return DeviceHandlerResult(DeviceHandlerResult.TYPE_UNAUTHORIZED)

    async def handle_client_request(self, request: Request) -> 'ClientHandlerResult':
        """Handle a given client requests.

        The method is responsible for authentication of a given client request.
        It is called every time a client is attempting to send an HTTP request
        to a GoodCam device. The implementation should verify the client
        identity and permission to access a given device. It is also
        responsible for extracting the target device ID from the request.

        The method must return an instance of one of the following classes:

        * ``ForwardRequest`` - to forward the client request to a given device
        * ``BlockRequest`` - to block the client request and return a given response instead

        *The method is asynchronous. Do not use any blocking calls here! Always
        use the asynchronous alternatives (e.g. use aiohttp instead of
        requests).*

        :param request: client request
        :returns: any subclass of ``ClientHandlerResult``
        """
        return BlockRequest(Response(501))


class Proxy(NativeProxy):
    """Device proxy handle."""

    async def run(self) -> None:
        """Run the proxy.

        This method will keep the current task busy until the proxy stops.
        """
        loop = asyncio.get_running_loop()

        fut = loop.create_future()

        def join_cb(context, res):
            loop.call_soon_threadsafe(lambda: fut.set_result(res))

        cb = lib.PROXY_JOIN_CALLBACK(join_cb)

        self.call_method(lib.gcdp__proxy__join_async, cb, None)

        if (await fut) != 0:
            raise Exception(lib.get_last_error())

    def stop(self, timeout: float) -> None:
        """Stop the proxy.

        This method only signals the proxy to stop. It does not wait until the
        proxy actually stops. Use the ``run`` method to join the background
        threads.

        If stopping the proxy takes more than a given amount of time, the proxy
        execution will be aborted.

        :param timeout: maximum amount of time (in seconds) to wait until the proxy stops
        """
        self.call_method(lib.gcdp__proxy__stop, int(timeout * 1000))


async def create_proxy(config: ProxyConfig) -> 'Proxy':
    """Create a new instance of the device proxy from a given configuration.

    :param config: proxy configuration
    :returns: proxy handle
    """
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
