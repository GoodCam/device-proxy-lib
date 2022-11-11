from gcdevproxy import (
    AcceptDevice,
    Authorization,
    BlockRequest,
    ClientHandlerResult,
    DeviceHandlerResult,
    ForwardRequest,
    Proxy,
    ProxyConfig,
    Request,
    RequestHandler,
    Response,
)


class MyRequestHandler(RequestHandler):
    def handle_device_request(self, authorization: Authorization) -> 'DeviceHandlerResult':
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # !!! Accepting all devices is a potential security risk. Never do  !!!
        # !!! this in production! You should always check the device ID and !!!
        # !!! key against your database.                                    !!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        return AcceptDevice()

    def handle_client_request(self, request: Request) -> 'ClientHandlerResult':
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # !!! Allowing clients to communicate with an arbitrary device is a !!!
        # !!! potential security risk. Never do this in production! You     !!!
        # !!! should always authenticate the client and check its           !!!
        # !!! permission to access a given device. A good way how to deal   !!!
        # !!! with this issue would be JWT tokens containing device ID      !!!
        # !!! signed with a trusted secret.                                 !!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        device_id = request.get_header_value('x-device')

        if device_id is None:
            return BlockRequest(Response(400))
        else:
            return ForwardRequest(device_id, request)


if __name__ == "__main__":
    config = ProxyConfig()
    config.hostname = 'my-goodcam-proxy.com'
    config.http_bindings = [('0.0.0.0', 8080)]
    config.https_bindings = [('0.0.0.0', 8443)]
    #config.lets_encrypt = True
    config.request_handler = MyRequestHandler()

    proxy = Proxy(config)

    proxy.run()
