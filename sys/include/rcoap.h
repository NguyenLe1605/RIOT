#ifndef RCOAP_H
#define RCOAP_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>


#if defined(MODULE_SOCK_UDP)
#include "net/sock/udp.h"
#else
typedef void sock_udp_ep_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup net_nanocoap_conf    nanoCoAP compile configurations
 * @ingroup  net_nanocoap
 * @ingroup  config
 * @{
 */
/** @brief   Maximum number of Options in a message */
#ifndef CONFIG_RCOAP_NOPTS_MAX
#define CONFIG_RCOAP_NOPTS_MAX          (16)
#endif


/**
 * @brief   Declare a bitfield of a given size
 *
 * @note    SIZE should be a constant expression. This avoids variable length
 *          arrays.
 */
#ifndef BITFIELD
#define BITFIELD(NAME, SIZE)  uint8_t NAME[((SIZE) + 7) / 8]
#endif



/**
 * @brief   Method flag type
 *
 * Must be large enough to contain all @ref rcoap_method_flags "CoAP method flags"
 */
typedef uint16_t rcoap_method_flags_t;

/**
 * @brief   Raw CoAP PDU header structure
 */
typedef struct __attribute__((packed)) {
    uint8_t ver_t_tkl;          /**< version, token, token length           */
    uint8_t code;               /**< CoAP code (e.g.m 205)                  */
    uint16_t id;                /**< Req/resp ID                            */
} rcoap_hdr_t;

/**
 * @brief   CoAP option array entry
 */
typedef struct {
    uint16_t opt_num;           /**< full CoAP option number    */
    uint16_t offset;            /**< offset in packet           */
} rcoap_optpos_t;

/**
 * @brief   CoAP PDU parsing context structure
 *
 * When this struct is used to assemble the header, @p payload is used as the
 * write pointer and @p payload_len contains the number of free bytes left in
 * then packet buffer pointed to by @ref coap_pkt_t::hdr
 *
 * When the header was written, @p payload must not be changed, it must remain
 * pointing to the end of the header.
 * @p payload_len must then be set to the size of the payload that was further
 * copied into the packet buffer, after the header.
 */
typedef struct {
    rcoap_hdr_t *hdr;                                  /**< pointer to raw packet   */
    uint8_t *payload;                                 /**< pointer to end of the header */
    uint16_t payload_len;                             /**< length of payload       */
    uint16_t options_len;                             /**< length of options array */
    rcoap_optpos_t options[CONFIG_RCOAP_NOPTS_MAX]; /**< option offset array     */
    BITFIELD(opt_crit, CONFIG_RCOAP_NOPTS_MAX);    /**< unhandled critical option */
} rcoap_pkt_t;



/**
 * @brief   Forward declaration of internal CoAP resource request handler context
 */
typedef struct _coap_request_ctx rcoap_request_ctx_t;



/**
 * @brief   Resource handler type
 *
 * Functions that implement this must be prepared to be called multiple times
 * for the same request, as the server implementations do not perform message
 * deduplication. That optimization is [described in the CoAP
 * specification](https://tools.ietf.org/html/rfc7252#section-4.5).
 *
 * This should be trivial for requests of the GET, PUT, DELETE, FETCH and
 * iPATCH methods, as they are defined as idempotent methods in CoAP.
 *
 * For POST, PATCH and other non-idempotent methods, this is an additional
 * requirement introduced by the contract of this type.
 *
 * @param[in]  pkt      The request packet
 * @param[out] buf      Buffer for the response
 * @param[in]  len      Size of the response buffer
 * @param[in]  context  Request context
 *
 * @return     Number of response bytes written on success
 *             Negative error on failure
 */
typedef ssize_t (*rcoap_handler_t)(rcoap_pkt_t *pkt, uint8_t *buf, size_t len,
                                  rcoap_request_ctx_t *context);

/**
 * @brief   Type for CoAP resource entry
 */
typedef struct {
    const char *path;               /**< URI path of resource               */
    rcoap_method_flags_t methods;    /**< OR'ed methods this resource allows */
    rcoap_handler_t handler;         /**< ptr to resource handler            */
    void *context;                  /**< ptr to user defined context data   */
} rcoap_resource_t;

/**
 * @brief   CoAP resource request handler context
 * @internal
 */
struct _coap_request_ctx {
    const rcoap_resource_t *resource;    /**< resource of the request */
    sock_udp_ep_t *remote;              /**< remote endpoint of the request */
};

typedef struct {
    unsigned content_format;            /**< link format */
    size_t link_pos;                    /**< position of link within listener */
    uint16_t flags;                     /**< encoder switches; see @ref
                                             COAP_LINK_FLAG_ constants */
} rcoap_link_encoder_ctx_t;

/**
 * @brief   Handler function to write a resource link
 *
 * @param[in] resource      Resource for link
 * @param[out] buf          Buffer on which to write; may be null
 * @param[in] maxlen        Remaining length for @p buf
 * @param[in] context       Contextual information on what/how to write
 *
 * @return  count of bytes written to @p buf (or writable if @p buf is null)
 * @return  -1 on error
 */
typedef ssize_t (*rcoap_link_encoder_t)(const rcoap_resource_t *resource, char *buf,
                                        size_t maxlen, rcoap_link_encoder_ctx_t *context);


/**
 * @brief   Forward declaration of the gcoap listener state container
 */
typedef struct rcoap_listener rcoap_listener_t;

/**
 * @brief   Handler function for the request matcher strategy
 *
 * @param[in]  listener     Listener context
 * @param[out] resource     Matching resource
 * @param[in]  pdu          Pointer to the PDU
 *
 * @return  GCOAP_RESOURCE_FOUND      on resource match
 * @return  GCOAP_RESOURCE_NO_PATH    on no path found in @p resource
 *                                    that matches @p pdu
 * @return  GCOAP_RESOURCE_ERROR      on processing failure of the request
 */
typedef int (*rcoap_request_matcher_t)(rcoap_listener_t *listener,
                                       const rcoap_resource_t **resource,
                                       rcoap_pkt_t *pdu);

/**
 * @brief   CoAP socket types
 *
 * May be used as flags for @ref gcoap_listener_t, but must be used numerically
 * with @ref gcoap_req_send_tl().
 */
typedef enum {
    RCOAP_SOCKET_TYPE_UNDEF = 0x0,      /**< undefined */
    RCOAP_SOCKET_TYPE_UDP = 0x1,        /**< Unencrypted UDP transport */
    RCOAP_SOCKET_TYPE_DTLS = 0x2,       /**< DTLS-over-UDP transport */
} rcoap_socket_type_t;




/**
 * @brief   A modular collection of resources for a server
 */
struct rcoap_listener {
    const rcoap_resource_t *resources;   /**< First element in the array of resources */
    size_t resources_len;               /**< Length of array */
    /**
     * @brief   Transport type for the listener
     *
     * Any transport supported by the implementation can be set as a flag.
     * If @ref GCOAP_SOCKET_TYPE_UNDEF is set, the listener listens on all
     * supported transports. If non of the transports beyond UDP are compiled in
     * (i.e. no usage of modules `gcoap_dtls`, ...) this will be ignored and
     * @ref GCOAP_SOCKET_TYPE_UDP assumed.
     */
    rcoap_socket_type_t tl_type;
    rcoap_link_encoder_t link_encoder;  /**< Writes a link for a resource */
    struct rcoap_listener *next;        /**< Next listener in list */

    /**
     * @brief  Function that picks a suitable request handler from a
     * request.
     *
     * @note Leaving this NULL selects the default strategy that picks
     * handlers by matching their Uri-Path to resource paths (as per
     * the documentation of the @ref resources and @ref resources_len
     * fields). Alternative handlers may cast the @ref resources and
     * @ref resources_len fields to fit their needs.
     */
    rcoap_request_matcher_t request_matcher;
};


void hello(void);

#ifdef __cplusplus
}
#endif

#endif /* RCOAP_H */
