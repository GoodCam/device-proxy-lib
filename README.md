# GoodCam Device Proxy

This library simplifies creating HTTP proxies that can be used to communicate
with GoodCam devices in various networks. GoodCam devices contain a
[built-in client](https://goodcam.github.io/goodcam-api/#tag/cloud) that
can be configured to connect automatically to a given proxy. Once
connected, the devices will wait for incoming HTTP requests. The proxy
simply forwards incoming HTTP requests to the connected devices.

## Usage example

See the `examples` directory in the root of this repository for a ready-to-use
example.

```rust
use gcdevproxy::{
    async_trait::async_trait,
    auth::BasicAuthorization,
    http::{Body, Request},
    ClientHandlerResult, DeviceHandlerResult, Error, RequestHandler,
};

struct MyRequestHandler;

#[async_trait]
impl RequestHandler for MyRequestHandler {
    async fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error> {
        ...
    }

    async fn handle_client_request(
        &self,
        request: Request<Body>,
    ) -> Result<ClientHandlerResult, Error> {
        ...
    }
}

let mut builder = ProxyBuilder::new();

builder
    .hostname(hostname)
    .http_bind_address(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)));

builder
    .build(MyRequestHandler)
    .await
    .unwrap()
    .await
    .unwrap();
```

## Bindings to other languages

The library provides a C API which can be used also in other programming
languages. See the `include` folder in the root of the repository for more
details.
