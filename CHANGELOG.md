# Changelog

## v0.3.0 (2024-02-14)

* Switch to the latest Hyper and update all dependencies

## v0.2.6 (2023-08-21)

* Add certificate renew timeout
* Mitigate possible slowloris attacks

## v0.2.5 (2023-08-14)

* Improve ACME client logging
* Disable TLS session cache to lower the memory footprint

## v0.2.4 (2023-08-10)

* Fix poll after error

## v0.2.3 (2023-01-23)

* Add missing Connection and Upgrade headers in responses to HTTP/1.1
  connection upgrades

## v0.2.2 (2023-01-11)

* Do not forward hop-by-hop and non-http2 headers to the device and fix
  connection upgrades

## v0.2.1 (2023-01-09)

* Improve logging in situations when a device is registered but forwarding a
  client request fails for some reason

## v0.2.0 (2022-12-13)

* Pass authorization ownership to the device handler (C API)

## v0.1.2 (2022-11-24)

* Detect broken device connections

## v0.1.1 (2022-11-23)

* Updated dependency info

## v0.1.0 (2022-11-23)

* Initial release
