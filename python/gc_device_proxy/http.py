import ctypes

from ctypes import POINTER, c_char_p, c_uint8, c_void_p
from typing import Dict, List, Optional, Tuple

from .native import get_string, lib, NativeObject


class Authorization(NativeObject):
    def __init__(self, raw_ptr: c_void_p) -> None:
        super().__init__(raw_ptr, None)

    @property
    def device_id(self):
        return get_string(lib.gcdp__authorization__get_device_id, self.raw_ptr)

    @property
    def device_key(self):
        return get_string(lib.gcdp__authorization__get_device_key, self.raw_ptr)


class NativeRequest(NativeObject):
    def __init__(self, raw_ptr: c_void_p) -> None:
        super().__init__(raw_ptr, lib.gcdp__request__free)

    @property
    def method(self) -> str:
        assert self.raw_ptr is not None
        method = self.call_method(lib.gcdp__request__get_method)
        return method.decode('utf-8')

    @property
    def uri(self) -> str:
        assert self.raw_ptr is not None
        return get_string(lib.gcdp__request__get_uri, self.raw_ptr)

    @property
    def headers(self) -> List[Tuple[str, str]]:
        res = []
        it = self.call_method(lib.gcdp__request__get_header_iter)
        while it is not None:
            name = get_string(lib.gcdp__header_iter__get_name, it)
            value = get_string(lib.gcdp__header_iter__get_value, it)
            res.append((name, value))
            it = lib.gcdp__header_iter__next(it)
        return res


class Request:
    def __init__(self, raw_ptr: c_void_p) -> None:
        self.native = NativeRequest(raw_ptr)

        self.uri = self.native.uri
        self.method = self.native.method
        self.headers = self.native.headers

        self.header_map: Dict[str, List[str]] = {}

        for name, value in self.headers:
            lname = name.lower()
            if lname not in self.header_map:
                self.header_map[lname] = []
            self.header_map[lname].append(value)

    def get_header_value(self, name: str) -> Optional[str]:
        try:
            return self.header_map[name.lower()][0]
        except KeyError:
            return None


class NativeResponse(NativeObject):
    def __init__(self, status_code: int) -> None:
        if not (100 <= status_code < 600):
            raise Exception("invalid status code")

        raw_ptr = lib.gcdp__response__new(status_code)

        if not raw_ptr:
            raise MemoryError("unable to allocate a new response")

        super().__init__(raw_ptr, lib.gcdp__response__free)

    def append_header(self, name: str, value: str) -> None:
        name = name.encode('utf-8')
        value = value.encode('utf-8')

        self.call_method(lib.gcdp__response__add_header, name, value)

    def set_body(self, body: bytes) -> None:
        length = len(body)
        body = c_char_p(body)
        body = ctypes.cast(body, POINTER(c_uint8))

        self.call_method(lib.gcdp__response__set_body, body, length)


class Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.headers: Dict[str, List[str]] = {}
        self.body = b''

    def append_header(self, name: str, value: str) -> None:
        lname = name.lower()
        if lname not in self.headers:
            self.headers[lname] = []
        self.headers[lname].append(value)

    def set_header(self, name: str, value: str) -> None:
        self.headers[name.lower()] = [value]

    def to_native(self) -> NativeResponse:
        response = NativeResponse(self.status_code)

        for name, values in self.headers:
            for value in values:
                response.append_header(name, value)

        response.set_body(self.body)

        return response
