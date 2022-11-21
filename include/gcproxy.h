#ifndef _H_GC_DEVICE_PROXY
#define _H_GC_DEVICE_PROXY

#include <stdint.h>
#include <stdlib.h>

/**
 * @brief Get last error.
 *
 * The function returns the last error code and optionally also the last error
 * message. The error message will be copied into a given buffer (unless it is
 * NULL).
 *
 * The size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the error message.
 * If size is NULL then the function will only return the last error code.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * @param buffer buffer for the error message
 * @param size buffer capacity / length of the message
 * @return int error code
 */
int gcdp_get_last_error(char* buffer, size_t* size);

typedef void log_record_t;
typedef void log_handler_t(void* context, const log_record_t* record);

typedef void authorization_t;
typedef void request_t;
typedef void response_t;
typedef void header_iter_t;

typedef void device_handler_result_t;
typedef void device_handler_t(void* context, const authorization_t* authorization, device_handler_result_t* result);

typedef void client_handler_result_t;
typedef void client_handler_t(void* context, request_t* request, client_handler_result_t* result);

typedef void proxy_config_t;
typedef void proxy_t;

typedef void new_proxy_cb_t(void* context, proxy_t* proxy);
typedef void join_proxy_cb_t(void* context, int res);

#define LOG_LEVEL_TRACE     0
#define LOG_LEVEL_DEBUG     1
#define LOG_LEVEL_INFO      2
#define LOG_LEVEL_WARNING   3
#define LOG_LEVEL_ERROR     4

/**
 * @brief Set log handler.
 *
 * The log handler can be set only once. The handler is expected to be a
 * function that accepts two arguments (context and log record) and does not
 * return anything (see the log_handler_t type for more info).
 *
 * The handler and the context MUST be thread-safe. It must be safe to share
 * the context between multiple threads and it must be safe to call the handler
 * from multiple threads.
 *
 * The context is optional and it may be NULL.
 *
 * @param handler log handler
 * @param context an arbitrary context that will be passed to the handler
 * @return int 0 on success, error code in case of an error
 */
int gcdp_set_logger(log_handler_t* handler, void* context);

/**
 * @brief Get log level from a given log record.
 *
 * @param record log record
 * @return int log level
 */
int gcdp__log_record__get_level(const log_record_t* record);

/**
 * @brief Get log message from a given log record.
 *
 * The log message will be copied into a given buffer (unless it is NULL). The
 * size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the log message.
 * The size cannot be NULL.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * @param record log record
 * @param buffer buffer for the log message
 * @param size buffer capacity / length of the message
 */
void gcdp__log_record__get_message(const log_record_t* record, char* buffer, size_t* size);

/**
 * @brief Create a new proxy configuration.
 *
 * @return proxy_config_t* proxy configuration
 */
proxy_config_t* gcdp__proxy_config__new(void);

/**
 * @brief Set proxy hostname.
 *
 * @param config proxy config
 * @param hostname hostname
 * @return int 0 on success, error code in case of an error
 */
int gcdp__proxy_config__set_hostname(proxy_config_t* config, const char* hostname);

/**
 * @brief Add HTTP binding.
 *
 * @param config proxy config
 * @param addr IPv4/IPv6 address as string (e.g. "192.168.1.1")
 * @param port port number
 * @return int 0 on success, error code in case of an error
 */
int gcdp__proxy_config__add_http_bind_addr(proxy_config_t* config, const char* addr, uint16_t port);

/**
 * @brief Add HTTPS binding
 *
 * @param config proxy config
 * @param addr IPv4/IPv6 address as string (e.g. "192.168.1.1")
 * @param port port number
 * @return int 0 on success, error code in case of an error
 */
int gcdp__proxy_config__add_https_bind_addr(proxy_config_t* config, const char* addr, uint16_t port);

/**
 * @brief Use Let's Encrypt to get an HTTPS certificate.
 *
 * In order to use Let's Encrypt, you need to set the proxy hostname and use
 * port 80 for HTTP binding.
 *
 * @param config proxy config
 */
void gcdp__proxy_config__use_lets_encrypt(proxy_config_t* config);

/**
 * @brief Set TLS identity (i.e. a private key and a certificate chain for HTTPS).
 *
 * @param config proxy config
 * @param key private key in PEM format
 * @param key_size private key size
 * @param cert certificate chain in PEM format
 * @param cert_size certificate chain size
 */
void gcdp__proxy_config__set_tls_identity(proxy_config_t* config, const uint8_t* key, size_t key_size, const uint8_t* cert, size_t cert_size);

/**
 * @brief Set device request handler.
 *
 * The device request handler will be called on every connection attempt
 * received from a GoodCam device. The handler may accept the request, reject
 * it or redirect the device to a different server.
 *
 * The handler is expected to be a function accepting three arguments (context,
 * authorization, result). See device_handler_t for more info. The context is
 * an arbitrary pointer passed to the handler. It may be NULL. The
 * authorization contains device ID and key. The result contains the decision
 * made by the handler.
 *
 * Both the handler and the context MUST be thread-safe. It must be safe to
 * share the context between multiple threads and it must be safe to call the
 * handler from multiple threads.
 *
 * @param config proxy config
 * @param handler device request handler
 * @param context arbitrary context (optional)
 */
void gcdp__proxy_config__set_device_handler(proxy_config_t* config, device_handler_t* handler, void* context);

/**
 * @brief Set client request handler.
 *
 * The client request handler will be called for each request received from a
 * client attempting to a access a GoodCam device. The handler may accept the
 * request and forward it to the corresponding device or it may block the
 * request by returning a custom response. The handler is responsible for
 * determining the target device ID from the request.
 *
 * The handler is expected to be a function accepting three arguments (context,
 * request, result). See client_handler_t for more info. The context is an
 * arbitrary pointer passed to the handler. It may be NULL. The request is the
 * request received from the client. The result contains the decision made by
 * the handler.
 *
 * The handler takes ownership of the request. It must either forward it or
 * free it.
 *
 * Both the handler and the context MUST be thread-safe. It must be safe to
 * share the context between multiple threads and it must be safe to call the
 * handler from multiple threads.
 *
 * @param config proxy config
 * @param handler client request handler
 * @param context arbitrary context (optional)
 */
void gcdp__proxy_config__set_client_handler(proxy_config_t* config, client_handler_t* handler, void* context);

/**
 * @brief Free the config.
 *
 * @param config proxy config
 */
void gcdp__proxy_config__free(proxy_config_t* config);

/**
 * @brief Create and start a new proxy from a given config.
 *
 * @param config proxy config
 * @return proxy_t* proxy
 */
proxy_t* gcdp__proxy__new(const proxy_config_t* config);

/**
 * @brief Create and start a new proxy from a given config.
 *
 * The function will return immediately and the resulting proxy will be passed
 * to a given callback once available.
 *
 * @param config proxy config
 * @param cb callback
 * @param context arbitrary context (optional)
 */
void gcdp__proxy__new_async(const proxy_config_t* config, new_proxy_cb_t* cb, void* context);

/**
 * @brief Gracefully stop a given proxy.
 *
 * If the proxy isn't stopped until the timeout, its execution will be aborted.
 *
 * The function only initiates the stop. The caller should also use the join
 * method to make sure that the proxy has stopped.
 *
 * @param proxy proxy
 * @param timeout timeout in milliseconds
 */
void gcdp__proxy__stop(proxy_t* proxy, uint32_t timeout);

/**
 * @brief Abort the proxy execution.
 *
 * The function only initiates the abort. The caller should also use the join
 * method to make sure that the proxy has stopped.
 *
 * @param proxy proxy
 */
void gcdp__proxy__abort(proxy_t* proxy);

/**
 * @brief Wait until the proxy stops.
 *
 * @param proxy proxy
 * @return int 0 on success, error code on error
 */
int gcdp__proxy__join(proxy_t* proxy);

/**
 * @brief Wait until the proxy stops.
 *
 * The function will return immediately and the join result will be passed to
 * a given callback once available.
 *
 * @param proxy proxy
 * @param cb callback
 * @param context arbitrary context (optional)
 */
void gcdp__proxy__join_async(proxy_t* proxy, join_proxy_cb_t* cb, void* context);

/**
 * @brief Free a given proxy.
 *
 * The proxy execution will be aborted if the proxy is still running.
 *
 * @param proxy proxy
 */
void gcdp__proxy__free(proxy_t* proxy);

/**
 * @brief Accept the corresponding GoodCam device.
 *
 * The function takes ownership of the result.
 *
 * @param result device handler result
 */
void gcdp__device_handler_result__accept(device_handler_result_t* result);

/**
 * @brief Reject the corresponding GoodCam device.
 *
 * The function takes ownership of the result.
 *
 * @param result device handler result
 */
void gcdp__device_handler_result__unauthorized(device_handler_result_t* result);

/**
 * @brief Redirect the corresponding GoodCam device to a given location.
 *
 * On success, this function takes ownership of the result.
 *
 * @param result device handler result
 * @param location new location (URL is expected)
 * @return int 0 on success, error code if the location is invalid
 */
int gcdp__device_handler_result__redirect(device_handler_result_t* result, const char* location);

/**
 * @brief Report a device handler error.
 *
 * The error will be logged and the corresponding GoodCam device will receive
 * an internal server error (i.e. HTTP 500). This function is useful if the
 * handler isn't able make its decision (e.g. it cannot connect to a database).
 *
 * On success, this function takes ownership of the result.
 *
 * @param result device handler result
 * @param error error message
 * @return int 0 on success, error code if the error message is invalid
 */
int gcdp__device_handler_result__error(device_handler_result_t* result, const char* error);

/**
 * @brief Forward a given request to a given GoodCam device.
 *
 * On success, this function takes ownership of the request and the result.
 *
 * @param result client handler result
 * @param device_id ID of the target GoodCam device
 * @param request request
 * @return int 0 on success, error code if the device ID or request are invalid
 */
int gcdp__client_handler_result__forward(client_handler_result_t* result, const char* device_id, request_t* request);

/**
 * @brief Block the corresponding client request and send a given response.
 *
 * On success, this function takes ownership of the response and the result.
 *
 * @param result client handler result
 * @param response response to be sent back to the corresponding client
 * @return int 0 on success, error code if the response is invalid
 */
int gcdp__client_handler_result__block(client_handler_result_t* result, response_t* response);

/**
 * @brief Report a client handler error.
 *
 * The error will be logged and the corresponding client will receive an
 * internal server error (i.e. HTTP 500). This function is useful if the
 * handler isn't able make its decision (e.g. it cannot connect to a database).
 *
 * On success, this function takes ownership of the result.
 *
 * @param result client handler result
 * @param error error message
 * @return int 0 on success, error code if the error message is invalid
 */
int gcdp__client_handler_result__error(client_handler_result_t* result, const char* error);

/**
 * @brief Get device ID from a given authorization object.
 *
 * The device ID will be copied into a given buffer (unless it is NULL). The
 * size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the device ID.
 * The size cannot be NULL.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * @param authorization device authorization
 * @param buffer buffer for the device ID
 * @param size buffer capacity / length of the device ID
 */
void gcdp__authorization__get_device_id(const authorization_t* authorization, char* buffer, size_t* size);

/**
 * @brief Get device key from a given authorization object.
 *
 * The device key will be copied into a given buffer (unless it is NULL). The
 * size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the device key.
 * The size cannot be NULL.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * @param authorization device authorization
 * @param buffer buffer for the device key
 * @param size buffer capacity / length of the device key
 */
void gcdp__authorization__get_device_key(const authorization_t* authorization, char* buffer, size_t* size);

/**
 * @brief Get request method.
 *
 * String identifier for the corresponding HTTP method will be returned (e.g.
 * "GET", "POST", etc.).
 *
 * @param request request
 * @return const char* HTTP method
 */
const char* gcdp__request__get_method(const request_t* request);

/**
 * @brief Get request URI.
 *
 * The request URI will be copied into a given buffer (unless it is NULL). The
 * size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the request URI.
 * The size cannot be NULL.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * @param request request
 * @param buffer buffer for the request URI
 * @param size buffer capacity / length of the request URI
 */
void gcdp__request__get_uri(const request_t* request, char* buffer, size_t* size);

/**
 * @brief Get value of the first header with a given name (case-insensitive).
 *
 * The header value will be copied into a given buffer (unless it is NULL). The
 * size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the header value.
 * The size cannot be NULL.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * If there is no such header, an empty string will be returned (i.e. size and
 * the first byte of the buffer will be both 0).
 *
 * @param request request
 * @param name header name
 * @param buffer buffer for the header value
 * @param size buffer capacity / length of the header value
 * @return int 0 on success, error code in case of an error
 */
int gcdp__request__get_header_value(const request_t* request, const char* name, char* buffer, size_t* size);

/**
 * @brief Get iterator over the request headers.
 *
 * The function returns NULL if there are no headers.
 *
 * @param request request
 * @return header_iter_t* iterator or NULL
 */
header_iter_t* gcdp__request__get_header_iter(const request_t* request);

/**
 * @brief Free a given request.
 *
 * @param request request
 */
void gcdp__request__free(request_t* request);

/**
 * @brief Get name of the current header.
 *
 * The header name will be copied into a given buffer (unless it is NULL). The
 * size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the header name.
 * The size cannot be NULL.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * @param iter header iterator
 * @param buffer buffer for the header name
 * @param size buffer capacity / length of the header name
 */
void gcdp__header_iter__get_name(const header_iter_t* iter, char* buffer, size_t* size);

/**
 * @brief Get value of the current header.
 *
 * The header value will be copied into a given buffer (unless it is NULL). The
 * size parameter is expected to contain the buffer capacity and after the
 * function returns, it will contain the original length of the header value.
 * The size cannot be NULL.
 *
 * The string copied into the buffer may be truncated but it will be always
 * null-terminated.
 *
 * @param iter header iterator
 * @param buffer buffer for the header value
 * @param size buffer capacity / length of the header value
 */
void gcdp__header_iter__get_value(const header_iter_t* iter, char* buffer, size_t* size);

/**
 * @brief Advance the header iterator.
 *
 * The function will return NULL and free the iterator if there are no more
 * items.
 *
 * @param iter header iterator
 * @return header_iter_t* new iterator or NULL
 */
header_iter_t* gcdp__header_iter__next(header_iter_t* iter);

/**
 * @brief Free a given header iterator.
 *
 * @param iter iterator
 */
void gcdp__header_iter__free(header_iter_t* iter);

/**
 * @brief Create a new HTTP response with a given status code.
 *
 * @param status status code
 * @return response_t* HTTP response
 */
response_t* gcdp__response__new(uint16_t status);

/**
 * @brief Add a given header to the response.
 *
 * @param response response
 * @param name header name
 * @param value header value
 * @return int 0 on success, error code in case of an error
 */
int gcdp__response__add_header(response_t* response, const char* name, const char* value);

/**
 * @brief Replace all header fields with a given name (case-insensitive).
 *
 * @param response response
 * @param name header name
 * @param value new header value
 * @return int 0 on success, error code in case of an error
 */
int gcdp__response__set_header(response_t* response, const char* name, const char* value);

/**
 * @brief Set response body.
 *
 * @param response response
 * @param body buffer containing the body
 * @param size size of the buffer
 */
void gcdp__response__set_body(response_t* response, const uint8_t* body, size_t size);

/**
 * @brief Free a given response.
 *
 * @param response response
 */
void gcdp__response__free(response_t* response);

#endif
