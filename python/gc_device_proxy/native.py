import ctypes
import logging
import os
import sys
import threading

from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    byref,
    c_char_p,
    c_int,
    c_size_t,
    c_uint8,
    c_uint16,
    c_uint32,
    c_void_p,
)

thread_local = threading.local()

logger = logging.getLogger(__name__)


def get_string(native_function, *args):
    global thread_local

    if not hasattr(thread_local, 'string_buffer'):
        thread_local.string_buffer = (None, 0)

    buf, capacity = thread_local.string_buffer

    size = c_size_t(capacity)

    native_function(*args, buf, byref(size))

    if size.value == 0:
        return None

    while (size.value + 1) > capacity:
        size.value += 1
        capacity = size.value
        buf = ctypes.create_string_buffer(capacity)
        thread_local.string_buffer = (buf, capacity)
        native_function(*args, buf, byref(size))

    data = buf.raw[:size.value]

    return data.decode('utf-8')


class DeviceProxyLib:
    """
    Loader for the device proxy lib.
    """

    lib_name = 'gc_device_proxy'

    min_version = (0, 1, 0)

    LOG_LEVEL_TRACE = 0
    LOG_LEVEL_DEBUG = 1
    LOG_LEVEL_INFO = 2
    LOG_LEVEL_WARN = 3
    LOG_LEVEL_ERROR = 4

    LOG_CALLBACK = CFUNCTYPE(None, c_void_p, c_void_p)

    DEVICE_HANDLER = CFUNCTYPE(None, c_void_p, c_void_p, c_void_p)
    CLIENT_HANDLER = CFUNCTYPE(None, c_void_p, c_void_p, c_void_p)

    def __init__(self):
        current_dir = os.path.dirname(__file__)

        if sys.platform in ('linux', 'linux2'):
            lib_file = f'lib{self.lib_name}.so'
        elif sys.platform == 'win32':
            lib_file = f'{self.lib_name}.dll'
        else:
            lib_file = None

        if lib_file:
            lib_path = os.path.join(current_dir, lib_file)
            if os.path.exists(lib_path):
                self.lib = CDLL(lib_path)
            else:
                self.lib = CDLL(lib_file)
        else:
            self.lib = CDLL(self.lib_name)

        self.check_version()
        self.load_symbols()

        def log_callback(context, record):
            level = self.gcdp__log_record__get_level(record)
            if level < self.LOG_LEVEL_DEBUG:
                return
            msg = get_string(self.gcdp__log_record__get_message, record)
            logger.debug(msg)

        self.__log_callback = self.LOG_CALLBACK(log_callback)

        self.gcdp_set_logger(self.__log_callback, None)

    def get_last_error(self) -> str:
        return get_string(self.gcdp_get_last_error)

    def load_function(self, name, argtypes=[], restype=None):
        function = getattr(self.lib, name)
        function.argtypes = list(argtypes)
        function.restype = restype
        setattr(self, name, function)

    def load_functions(self, functions):
        for function in functions:
            self.load_function(*function)

    def check_version(self):
        self.load_functions(
            (
                ('gcdp__version__major', [], c_int),
                ('gcdp__version__minor', [], c_int),
                ('gcdp__version__micro', [], c_int),
            )
        )

        major = self.gcdp__version__major()
        minor = self.gcdp__version__minor()
        micro = self.gcdp__version__micro()

        a, b, c = self.min_version

        is_supported = (
            (major == 0 and a == 0 and minor == b and micro >= c)
            or
            (major == a and minor >= b)
        )

        if not is_supported:
            raise Exception(f"unsupported library version (version: {major}.{minor}.{micro}, expected >= {a}.{b}.{c})")

        self.version = (major, minor, micro)

    def load_symbols(self):
        self.load_functions(
            (
                ('gcdp__version__major', [], c_int),
                ('gcdp__version__minor', [], c_int),
                ('gcdp__version__micro', [], c_int),

                ('gcdp_get_last_error', [c_char_p, POINTER(c_size_t)], c_int),
                ('gcdp_set_logger', [self.LOG_CALLBACK, c_void_p], c_int),

                ('gcdp__log_record__get_level', [c_void_p], c_int),
                ('gcdp__log_record__get_message', [c_void_p, c_char_p, POINTER(c_size_t)]),

                ('gcdp__proxy_config__new', [], c_void_p),
                ('gcdp__proxy_config__set_hostname', [c_void_p, c_char_p], c_int),
                ('gcdp__proxy_config__add_http_bind_addr', [c_void_p, c_char_p, c_uint16], c_int),
                ('gcdp__proxy_config__add_https_bind_addr', [c_void_p, c_char_p, c_uint16], c_int),
                ('gcdp__proxy_config__use_lets_encrypt', [c_void_p]),
                ('gcdp__proxy_config__set_tls_identity',
                    [c_void_p, POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t]),
                ('gcdp__proxy_config__set_device_handler',
                    [c_void_p, self.DEVICE_HANDLER, c_void_p]),
                ('gcdp__proxy_config__set_client_handler',
                    [c_void_p, self.CLIENT_HANDLER, c_void_p]),
                ('gcdp__proxy_config__free', [c_void_p]),

                ('gcdp__proxy__new', [c_void_p], c_void_p),
                ('gcdp__proxy__stop', [c_void_p, c_uint32], c_int),
                ('gcdp__proxy__abort', [c_void_p]),

                ('gcdp__device_handler_result__accept', [c_void_p]),
                ('gcdp__device_handler_result__unauthorized', [c_void_p]),
                ('gcdp__device_handler_result__redirect', [c_void_p, c_char_p], c_int),
                ('gcdp__device_handler_result__error', [c_void_p, c_char_p], c_int),

                ('gcdp__client_handler_result__forward', [c_void_p, c_char_p, c_void_p], c_int),
                ('gcdp__client_handler_result__block', [c_void_p, c_void_p], c_int),
                ('gcdp__client_handler_result__error', [c_void_p, c_char_p], c_int),

                ('gcdp__authorization__get_device_id', [c_void_p, c_char_p, POINTER(c_size_t)]),
                ('gcdp__authorization__get_device_key', [c_void_p, c_char_p, POINTER(c_size_t)]),

                ('gcdp__request__get_method', [c_void_p], c_char_p),
                ('gcdp__request__get_uri', [c_void_p, c_char_p, POINTER(c_size_t)]),
                ('gcdp__request__get_header_value',
                    [c_void_p, c_char_p, c_char_p, POINTER(c_size_t)], c_int),
                ('gcdp__request__get_header_iter', [c_void_p], c_void_p),
                ('gcdp__request__free', [c_void_p]),

                ('gcdp__header_iter__get_name', [c_void_p, c_char_p, POINTER(c_size_t)]),
                ('gcdp__header_iter__get_value', [c_void_p, c_char_p, POINTER(c_size_t)]),
                ('gcdp__header_iter__next', [c_void_p], c_void_p),
                ('gcdp__header_iter__free', [c_void_p]),

                ('gcdp__response__new', [c_uint16], c_void_p),
                ('gcdp__response__add_header', [c_void_p, c_char_p, c_char_p], c_int),
                ('gcdp__response__set_header', [c_void_p, c_char_p, c_char_p], c_int),
                ('gcdp__response__set_body', [c_void_p, POINTER(c_uint8), c_size_t]),
                ('gcdp__response__free', [c_void_p]),
            )
        )


lib = DeviceProxyLib()


class NativeObject:
    def __init__(self, raw_ptr: c_void_p, free_func=None) -> None:
        self.__raw_ptr = raw_ptr
        self.__free_func = free_func
        self.__free_lock = None if free_func is None else threading.Lock()

    def __del__(self):
        if self.__free_func is None:
            return
        if self.__raw_ptr is None:
            return

        with self.__free_lock:
            if self.__raw_ptr is not None:
                self.__free_func(self.__raw_ptr)
            self.__raw_ptr = None

    @property
    def raw_ptr(self) -> c_void_p:
        return self.__raw_ptr

    def forget(self) -> None:
        self.__raw_ptr = None

    def call_method(self, native_func, *args):
        assert self.__raw_ptr is not None
        return native_func(self.__raw_ptr, *args)
