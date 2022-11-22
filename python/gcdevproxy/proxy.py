import asyncio
import ctypes
import inspect
import time

from ctypes import POINTER, c_char_p, c_uint8, c_void_p, pointer, py_object

from .http import Authorization, Request, Response
from .native import lib, NativeObject


class RequestHandler:
    """Base class for request handlers."""

    def handle_device_request(self, authorization: Authorization) -> 'DeviceHandlerResult':
        """Handle a given device request.

        The method is responsible for device authentication and (optionally)
        load balancing. It is called every time a GoodCam device connects to
        the proxy. The implementation should check the device ID and key in the
        authorization object.

        The method must return an instance of one of the following classes:

        * ``AcceptDevice`` - to accept the device connection
        * ``UnauthorizedDevice`` - to reject the device connection
        * ``RedirectDevice`` - to redirect the device to another proxy

        :param authorization: device authorization object containing the device ID and key
        :returns: any subclass of ``DeviceHandlerResult``
        """
        return DeviceHandlerResult(DeviceHandlerResult.TYPE_UNAUTHORIZED)

    def handle_client_request(self, request: Request) -> 'ClientHandlerResult':
        """Handle a given client requests.

        The method is responsible for authentication of a given client request.
        It is called every time a client is attempting to send an HTTP request
        to a GoodCam device. The implementation should verify the client
        identity and permission to access a given device. It is also
        responsible for extracting the target device ID from the request.

        The method must return an instance of one of the following classes:

        * ``ForwardRequest`` - to forward the client request to a given device
        * ``BlockRequest`` - to block the client request and return a given response instead

        :param request: client request
        :returns: any subclass of ``ClientHandlerResult``
        """
        return BlockRequest(Response(501))


def handle_device_request(context: c_void_p, authorization: c_void_p, result: c_void_p):
    context = ctypes.cast(context, POINTER(py_object))
    authorization = Authorization(authorization)
    result = NativeDeviceHandlerResult(result)

    handler = context.contents.value

    if inspect.iscoroutinefunction(handler.handle_device_request):
        handle_device_request_async(handler, authorization, result)
    else:
        handle_device_request_blocking(handler, authorization, result)


def handle_device_request_blocking(handler, authorization, result):
    try:
        r = handler.handle_device_request(authorization)
    except Exception as ex:
        result.error(str(ex))
    else:
        r.update_native(result)


def handle_device_request_async(handler, authorization, result):
    async def handle():
        try:
            r = await handler.handle_device_request(authorization)
        except Exception as ex:
            result.error(str(ex))
        else:
            r.update_native(result)

    handler.loop.call_soon_threadsafe(lambda: asyncio.create_task(handle()))


def handle_client_request(context: c_void_p, request: c_void_p, result: c_void_p):
    context = ctypes.cast(context, POINTER(py_object))
    request = Request(request)
    result = NativeClientHandlerResult(result)

    handler = context.contents.value

    if inspect.iscoroutinefunction(handler.handle_client_request):
        handle_client_request_async(handler, request, result)
    else:
        handle_client_request_blocking(handler, request, result)


def handle_client_request_blocking(handler, request, result):
    try:
        r = handler.handle_client_request(request)
    except Exception as ex:
        result.error(str(ex))
    else:
        r.update_native(result)


def handle_client_request_async(handler, request, result):
    async def handle():
        try:
            r = await handler.handle_client_request(request)
        except Exception as ex:
            result.error(str(ex))
        else:
            r.update_native(result)

    handler.loop.call_soon_threadsafe(lambda: asyncio.create_task(handle()))


class NativeDeviceHandlerResult(NativeObject):
    def __init__(self, raw_ptr: c_void_p) -> None:
        super().__init__(raw_ptr, free_func=None)

    def accept(self) -> None:
        self.call_method(lib.gcdp__device_handler_result__accept)

    def unauthorized(self) -> None:
        self.call_method(lib.gcdp__device_handler_result__unauthorized)

    def redirect(self, location: str) -> None:
        self.call_method(lib.gcdp__device_handler_result__redirect, location.encode('utf-8'))

    def error(self, error: str) -> None:
        self.call_method(lib.gcdp__device_handler_result__error, error.encode('utf-8'))


class DeviceHandlerResult:
    """Base class for all possible device handler results."""

    def update_native(self, native: NativeDeviceHandlerResult) -> None:
        raise NotImplemented()


class AcceptDevice(DeviceHandlerResult):
    """This result will tell the proxy to accept connection from a given
    device."""

    def update_native(self, native: NativeDeviceHandlerResult) -> None:
        native.accept()


class UnauthorizedDevice(DeviceHandlerResult):
    """This result will tell the proxy to reject connection from a given
    device."""

    def update_native(self, native: NativeDeviceHandlerResult) -> None:
        native.unauthorized()


class RedirectDevice(DeviceHandlerResult):
    """This result will tell the proxy to redirect the corresponding device to
    a given location."""

    def __init__(self, location: str) -> None:
        """Create a new redirect result.

        :param location: redirect location
        """
        self.location = location

    def update_native(self, native: NativeDeviceHandlerResult) -> None:
        native.redirect(self.location)


class NativeClientHandlerResult(NativeObject):
    def __init__(self, raw_ptr: c_void_p) -> None:
        super().__init__(raw_ptr, free_func=None)

    def forward(self, device_id: str, request: Request) -> None:
        device_id = device_id.encode('utf-8')

        ret = self.call_method(lib.gcdp__client_handler_result__forward, device_id, request.native.raw_ptr)

        if ret != 0:
            raise Exception(lib.get_last_error())

        # note: on success, the native function takes ownership of the request
        request.native.forget()

    def block(self, response: Response) -> None:
        r = response.to_native()

        ret = self.call_method(lib.gcdp__client_handler_result__block, r.raw_ptr)

        if ret != 0:
            raise Exception(lib.get_last_error())

        # note: on success, the native function takes ownership of the response
        r.forget()

    def error(self, error: str) -> None:
        self.call_method(lib.gcdp__client_handler_result__error, error.encode('utf-8'))


class ClientHandlerResult:
    """Base class for all possible client handler results."""

    def update_native(self, native: NativeClientHandlerResult) -> None:
        raise NotImplemented()


class ForwardRequest(ClientHandlerResult):
    """This result will tell the proxy to forward a given client request to
    device with a given ID."""

    def __init__(self, device_id: str, request: Request) -> None:
        """Create a new *forward request* result.

        :param device_id: target device ID
        :param request: client request
        """
        self.device_id = device_id
        self.request = request

    def update_native(self, native: NativeClientHandlerResult) -> None:
        native.forward(self.device_id, self.request)


class BlockRequest(ClientHandlerResult):
    """This result will tell the proxy to block the original client request and
    return a given response instead."""

    def __init__(self, response: Response) -> None:
        """Create a new *block request* result.

        :param response: response to be returned to the client
        """
        self.response = response

    def update_native(self, native: NativeClientHandlerResult) -> None:
        native.block(self.response)


class NativeProxyConfig(NativeObject):
    def __init__(self, raw_ptr: c_void_p) -> None:
        super().__init__(raw_ptr, lib.gcdp__proxy_config__free)

        self.device_request_handler = None
        self.device_request_context = None
        self.client_request_handler = None
        self.client_request_context = None

    def set_device_request_handler(self, handler, context) -> None:
        handler = lib.DEVICE_HANDLER(handler)
        context = pointer(py_object(context))

        self.call_method(lib.gcdp__proxy_config__set_device_handler, handler, context)

        # prevent these values from being garbage-collected
        self.device_request_handler = handler
        self.device_request_context = context

    def set_client_request_handler(self, handler, context) -> None:
        handler = lib.CLIENT_HANDLER(handler)
        context = pointer(py_object(context))

        self.call_method(lib.gcdp__proxy_config__set_client_handler, handler, context)

        # prevent these values from being garbage-collected
        self.client_request_handler = handler
        self.client_request_context = context

    def set_hostname(self, hostname: str) -> None:
        self.call_method(lib.gcdp__proxy_config__set_hostname, hostname.encode('utf-8'))

    def add_http_bind_address(self, addr: str, port: int) -> None:
        if not (0 <= port < 65536):
            raise Exception("invalid port number")

        ret = self.call_method(lib.gcdp__proxy_config__add_http_bind_addr, addr.encode('utf-8'), port)

        if ret != 0:
            raise Exception(lib.get_last_error())

    def add_https_bind_address(self, addr: str, port: int) -> None:
        if not (0 <= port < 65536):
            raise Exception("invalid port number")

        ret = self.call_method(lib.gcdp__proxy_config__add_https_bind_addr, addr.encode('utf-8'), port)

        if ret != 0:
            raise Exception(lib.get_last_error())

    def use_lets_encrypt(self) -> None:
        self.call_method(lib.gcdp__proxy_config__use_lets_encrypt)

    def set_tls_identity(self, key: bytes, cert: bytes) -> None:
        key_len = len(key)
        key_data = ctypes.cast(c_char_p(key), POINTER(c_uint8))
        cert_len = len(cert)
        cert_data = ctypes.cast(c_char_p(cert), POINTER(c_uint8))

        self.call_method(lib.gcdp__proxy_config__set_tls_identity, key_data, key_len, cert_data, cert_len)


class ProxyConfig:
    """Device proxy configuration.

    .. py:attribute:: request_handler

       Your request handler.

       It must be a subclass of either ``gcdevproxy.RequestHandler`` or
       ``gcdevproxy.aio.RequestHandler``.

       :type: gcdevproxy.RequestHandler, gcdevproxy.aio.RequestHandler

    .. py:attribute:: private_key

       TLS private key in PEM format (used for HTTPS).

       :type: bytes
       :value: None

    .. py:attribute:: cert_chain

       Certificate chain in PEM format (used for HTTPS).

       :type: bytes
       :value: None

    .. py:attribute:: lets_encrypt

       Generate the TLS private key and the corresponding certificate chain
       automatically using Let's Encrypt.

       Please note that Let's Encrypt requires the proxy to be available on a
       public domain name and the HTTP server must be available on TCP port 80.
       Make sure that you set the ``hostname`` attribute to the corresponding
       domain name and that you add at least the ``('0.0.0.0', 80)`` binding to
       ``http_bindings``.

       :type: bool
       :value: False

    .. py:attribute:: hostname

       Hostname where your proxy is available.

       :type: str
       :value: 'localhost'

    .. py:attribute:: http_bindings

       HTTP bindings where your proxy will be available. For example::

            config.http_bindings = [
                ('0.0.0.0', 80),
                ('::', 80),
            ]

       :type: List[Tuple[str, int]]
       :value: []

    .. py:attribute:: https_bindings

       HTTPS bindings where your proxy will be available. For example::

            config.http_bindings = [
                ('0.0.0.0', 443),
                ('::', 443),
            ]

       :type: List[Tuple[str, int]]
       :value: []
    """

    def __init__(self) -> None:
        """Create a new proxy configuration."""
        self.request_handler = RequestHandler()
        self.private_key = None
        self.cert_chain = None
        self.lets_encrypt = False
        self.hostname = 'localhost'
        self.http_bindings = []
        self.https_bindings = []

    def to_native(self) -> NativeProxyConfig:
        raw_ptr = lib.gcdp__proxy_config__new()

        if raw_ptr is None:
            raise MemoryError("unable to allocate a proxy config")

        config = NativeProxyConfig(raw_ptr)

        config.set_device_request_handler(handle_device_request, self.request_handler)
        config.set_client_request_handler(handle_client_request, self.request_handler)

        config.set_hostname(self.hostname)

        if self.lets_encrypt:
            config.use_lets_encrypt()
        elif self.private_key and self.cert_chain:
            config.set_tls_identity(self.private_key, self.cert_chain)

        for addr, port in self.http_bindings:
            config.add_http_bind_address(addr, port)

        for addr, port in self.https_bindings:
            config.add_https_bind_address(addr, port)

        return config


class NativeProxy(NativeObject):
    def __init__(self, raw_ptr: c_void_p) -> None:
        super().__init__(raw_ptr, lib.gcdp__proxy__free)


class Proxy(NativeProxy):
    """Device proxy handle."""

    def run(self) -> None:
        """Run the proxy.

        This method will keep the current thread busy until the proxy stops or
        until the ``KeyboardInterrupt`` exception occurs.
        """
        while True:
            time.sleep(1)

    def stop(self, timeout: float) -> None:
        """Stop the proxy and wait until the background threads stop.

        If stopping the proxy takes more than a given amount of time, the proxy
        execution will be aborted.

        :param timeout: maximum amount of time (in seconds) to wait until the proxy stops
        """
        self.call_method(lib.gcdp__proxy__stop, int(timeout * 1000))
        if self.call_method(lib.gcdp__proxy__join) != 0:
            raise Exception(lib.get_last_error())


def create_proxy(config: ProxyConfig) -> 'Proxy':
    """Create a new instance of the device proxy from a given configuration.

    :param config: proxy configuration
    :returns: proxy handle
    """
    config = config.to_native()

    raw_ptr = lib.gcdp__proxy__new(config.raw_ptr)

    if not raw_ptr:
        raise Exception(lib.get_last_error())

    proxy = Proxy(raw_ptr)

    # prevent the callbacks and contexts from being garbage collected
    proxy.device_request_handler = config.device_request_handler
    proxy.device_request_context = config.device_request_context
    proxy.client_request_handler = config.client_request_handler
    proxy.client_request_context = config.client_request_context

    return proxy
