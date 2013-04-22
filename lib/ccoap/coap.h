/**
 * Copyright 2013 Toyota InfoTechnology Center, USA, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * coap.h
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#ifndef COAP_H_
#define COAP_H_

#include <stdint.h>
#include <stdbool.h>
#include "debug.h"

/**
 * Current CoAP version
 */
#define COAP_VERSION 1

/**
 * default, should be configurable
 */
#define COAP_SERVER_NAME "localhost"

/**
 * default, should be configurable
 */
#define COAP_UDP_PORT 5683

/**
 * default, should be configurable
 */
#define COAP_MAX_RETRANSMITION_COUNT 3

/**
 * default, should be configurable
 */
#define COAP_MAX_WAIT_CON_COUNT 3

/**
 * default, should be configurable
 */
#define COAP_RETRANSMITION_TIMEOUT 5    //sec

/**
 * default, should be configurable
 * should be at least COAP_MAX_RETRANSMITION_COUNT * COAP_RETRANSMITION_TIMEOUT
 */
#define COAP_SESSION_TIMEOUT 30 //sec

/**
 * default, should be configurable
 */
#define COAP_SESSIONS_CLEAN_UP_TIME_INTERVAL 60 //sec

/**
 * default, should be configurable, or let the protocol decides
 */
#define COAP_MAX_OPTION_COUNT 20

/**
 * default, should be configurable and dynamically adjustable
 */
#define COAP_INIT_SERVER_SESSION_THREADS	3

/**
 * default, should be configurable, the Client handles tasks by
 * itself or use task threads (dynamically adjustable)
 */
#define COAP_INIT_CLIENT_TASK_THREADS	3

/**
 * default, should be configurable and dynamically adjustable
 */
#define COAP_SEND_RECEIVE_BUFFER_SIZE     1024

/**
 * default, should be configurable and dynamically adjustable
 */
#define COAP_MAX_OPTION_LIST_SIZE     8

/**
 * default, should be configurable and dynamically adjustable
 */
#define COAP_SERVER_LISTEN_QUEUE     10

#define COAP_MAX_TOKEN_LENGTH		8
#define COAP_TOKEN_LEN          2     // The currently used length

#define COAP_MIN_OPTION_SIZE	2

#define COAP_MIN_MSG_SIZE	4

#define COAP_MAX_URI_PATH	8

#define COAP_MAX_URI_QUERY	8

/**
 * CoAP Msg Types
 */
typedef enum coap_msg_type_
{
    COAP_ENUM_MSG_TYPE_CON = 0,
    COAP_ENUM_MSG_TYPE_NON = 1,
    COAP_ENUM_MSG_TYPE_ACK = 2,
    COAP_ENUM_MSG_TYPE_RST = 3,
    COAP_ENUM_MSG_TYPE_UNKNOWN
} coap_msg_type;

/**
 * CoAP option id
 */
typedef enum coap_option_id_
{
    COAP_ENUM_OPTION_ID_CONTENT_TYPE = 1,
    COAP_ENUM_OPTION_ID_MAX_AGE = 2,
    COAP_ENUM_OPTION_ID_PROXY_URI = 3,
    COAP_ENUM_OPTION_ID_ETAG = 4,
    COAP_ENUM_OPTION_ID_URI_HOST = 5,
    COAP_ENUM_OPTION_ID_LOCATION_PATH = 6,
    COAP_ENUM_OPTION_ID_URI_PORT = 7,
    COAP_ENUM_OPTION_ID_LOCATION_QUERY = 8,
    COAP_ENUM_OPTION_ID_URI_PATH = 9,
    COAP_ENUM_OPTION_ID_OBSERVE = 10,
    COAP_ENUM_OPTION_ID_TOKEN = 11,
    COAP_ENUM_OPTION_ID_ACCEPT = 12,
    COAP_ENUM_OPTION_ID_IF_MATCH = 13,
    COAP_ENUM_OPTION_ID_MAX_OFE = 14,
    COAP_ENUM_OPTION_ID_URI_QUERY = 15,
    COAP_ENUM_OPTION_ID_IF_NONE_MATCH = 21,
    COAP_ENUM_OPTION_ID_UNKNOWN
} coap_option_id;

/**
 * CoAP Request/Response Codes
 */
#define COAP_RES_CODE_EMPTY						0
#define COAP_REQ_CODE_GET       				1
#define COAP_REQ_CODE_POST      				2
#define COAP_REQ_CODE_PUT       				3
#define COAP_REQ_CODE_DELETE    				4
#define COAP_RES_CODE_CREATED					65
#define COAP_RES_CODE_DELETED					66
#define COAP_RES_CODE_VALID						67
#define COAP_RES_CODE_CHANGED					68
#define COAP_RES_CODE_CONTENT					69
#define COAP_RES_CODE_BAD_REQUEST				128
#define COAP_RES_CODE_UNAUTHORIZED				129
#define COAP_RES_CODE_BAD_OPTION				130
#define COAP_RES_CODE_FORBIDEN					131
#define COAP_RES_CODE_NOT_FOUND					132
#define COAP_RES_CODE_METHOD_NOT_ALLOWED		133
#define COAP_RES_CODE_PRECONDITION_FAILED		140
#define COAP_RES_CODE_REQUEST_TOO_LARGE			141
#define COAP_RES_CODE_UNSUPPORTED_MEDIA			143
#define COAP_RES_CODE_INTERNAL_SERVER_ERROR		160
#define COAP_RES_CODE_NOT_IMPLEMENTED			161
#define COAP_RES_CODE_BAD_GATEWAY				162
#define COAP_RES_CODE_SERVICE_UNAVAILABLE		163
#define COAP_RES_CODE_GATEWAY_TIMEOUT			164
#define COAP_RES_CODE_PROXYING_NOT_SUPPORTED	165


#define COAP_RES_CODE_MASK              0xE0
#define COAP_RES_CODE_SUCCESS           2
#define COAP_RES_CODE_CLIENT_ERROR      4
#define COAP_RES_CODE_SERVER_ERROR      5

/**
 * CoAP Header
 */
#define COAP_HDR_BYTES				4
#define COAP_HDR_VER_MASK           0xC0
#define COAP_HDR_TYPE_MASK          0x30
#define COAP_HDR_OC_MASK            0x0F
#define COAP_HDR_CODE_MASK          0xFF
#define COAP_HDR_MSG_ID_MASK_HIGH   0xFF00
#define COAP_HDR_MSG_ID_MASK_LOW   	0x00FF
#define COAP_HDR_RESET_MASK			0x00000000

typedef enum coap_state_type_
{
    COAP_ENUM_STATE_WAIT_CON = 0,
    COAP_ENUM_STATE_WAIT_NON = 1,
    COAP_ENUM_STATE_WAIT_ACK = 2,
    COAP_ENUM_STATE_WAIT_REQ = 3,
    COAP_ENUM_STATE_SEND_CON = 4,
    COAP_ENUM_STATE_SEND_NON = 5,
    COAP_ENUM_STATE_SEND_ACK = 6,
    COAP_ENUM_STATE_SEND_RST = 7,
    COAP_ENUM_STATE_DONE = 8,
    COAP_ENUM_STATE_RST = 9,
    COAP_ENUM_STATE_UNKNOWN
} coap_state_type;

typedef struct coap_header_
{
    uint8_t ver;
    coap_msg_type type;
    uint8_t oc;
    uint8_t code;
    uint16_t msg_id;
} coap_header;

/**
 * macros for encode/decoding coap header.
 */
#define COAP_ENCODE_HEADER(hdr, ver, type, oc, code, msg_id) {	\
	*((uint8_t*)(hdr)) = 	\
	(((uint8_t)(ver) & 0x03) << 6) | \
	(((uint8_t)(type) & 0x03) << 4) | \
	((uint8_t)(oc) & 0x0F); \
	*((uint8_t*)(hdr) + 1) = (uint8_t)(code); \
	*((uint8_t*)(hdr) + 2) = ((uint16_t)(msg_id) & 0xFF00) >> 8; \
	*((uint8_t*)(hdr) + 3) = (uint16_t)(msg_id) & 0x00FF;	\
}

#define COAP_DECODE_HEADER(inbuf, hdr) {	\
	(hdr)->ver = (uint8_t)((*((uint8_t *)inbuf) & COAP_HDR_VER_MASK) >> 6);		\
	(hdr)->type = (uint8_t)((*((uint8_t *)inbuf) & COAP_HDR_TYPE_MASK) >> 4);	\
	(hdr)->oc = (uint8_t)(*((uint8_t *)inbuf) & COAP_HDR_OC_MASK);		\
	(hdr)->code = (uint8_t)(*((uint8_t *)inbuf + 1) & COAP_HDR_CODE_MASK);	\
	(hdr)->msg_id = ((uint16_t)(*((uint8_t *)inbuf + 2))) << 8	|	\
					((uint16_t)(*((uint8_t *)inbuf + 3)));	\
}

/**
 * Option for all format
 */
typedef struct coap_option_
{
    uint8_t number;             /*not delta, but option number */
    bool ext;                   /*0, short length, 1 extended length */
    uint8_t length;             /*if ext is 1, length = length + 15 */
    uint8_t *data;              /*option number implies the data type */
} coap_option;

/**
 * coap msg store
 */
typedef struct coap_message_
{
    coap_header hdr;
    uint8_t *token;
    uint8_t token_length;
    coap_option *option_list;
    //uint8_t oc;
    uint8_t *payload;
    uint16_t payload_len;
} coap_message;

/**
 *  Display a description of the message type.
 * @param type is the message type
 */
void coap_show_message_type (uint16_t type);

/**
 * Display a description of the request code.
 * @param code is the request code
 */
void coap_show_request_code (uint8_t code);

/**
 * Check header.
 * @param hdr is the header
 */
bool coap_header_is_valid (coap_header hdr);

/**
 * Check option id.
 * @param id is the option id
 */
bool coap_option_id_is_valid (uint8_t id);

/**
 * Display a description of the option id.
 * @param id is the option id
 */
void coap_show_option_id (uint8_t id);

/**
 * Display a description of the response code.
 * @param code is the response code
 */
void coap_show_response_code (uint8_t code);

/**
 * Display a description of the media type.
 * @param type is the media type
 */
void coap_show_media_type (uint8_t type);

/**
 * Encodes coap header. outbuf is cleaned first.
 * @param outbuf is the buffer for write/send
 * @param hdr is the header of the coap msg/pdu
 * @return -1 for error, or 0 for success
 */
inline int coap_encode_header (uint8_t * outbuf, coap_header hdr);

/**
 * Decodes coap header.
 * @param inbuf is the buffer to read/recv
 * @param size is the size of the coap msg/pdu
 * @param hdr is to store the decoded header
 * @return -1 for error, or 0 for success.
 */
inline int coap_decode_header (uint8_t * inbuf, uint16_t size,
                               coap_header * hdr);

/**
 * Add coap options at index on the list.
 * @param list is the option list
 * @param index is the index at the list
 * @param option_id is the option id
 * @param length is the length of the option data
 * @param data is a pointer to the option data
 * @return -1 if error, or 0 if success.
 */
int coap_add_option (coap_option * list, uint8_t index, uint8_t option_id,
                     uint16_t length, uint8_t * data);

/**
 * Create the token option
 * @param msg is the message in which the token must be created
 * @return NULL for error, or a pointer to the token option
 */
uint8_t *coap_create_token(coap_message *msg);

/**
 * Encodes coap options from the prebuilt options list with oc elements in outbuf.
 * @param outbuf is the buffer for write/send
 * @param msg is a pointer to the coap message to be encoded
 * @return NULL for error, or pointer to the location in outbuf where the payload might be added.
 */
uint8_t *coap_encode_options (uint8_t * outbuf, coap_message * msg);

/**
 * Decodes coap option and add it to the list.
 * @param inbuf is the buffer for read/recv
 * @param len is received coap msg/pdu size.
 * @param msg is a pointer to the decoded coap message
 * @return NULL for error, or pointer to the location in outbuf where the payload might be accessed.
 */
uint8_t *coap_decode_option (uint8_t * inbuf, uint32_t len,
                             coap_message * msg);

/**
 * Attach coap payload with payload_len at location buf_ptr in outbuf.
 * @param outbuf is the buffer for write/send
 * @param buf_ptr is the position on the outbuf to attach the payload
 * @param msg is a pointer to the coap message containing the payload to be attached to the outbuf
 * @return -1 for error, or coap msg/pdu size.
 */
int coap_attach_payload (uint8_t * outbuf, uint8_t * buf_ptr,
                         coap_message * msg);

/**
 * Dettach coap payload from location at buf_ptr in inbuf to payload.
 * @param inbuf is the buffer for read/recv
 * @param len is the size of the coap msg/pdu
 * @param buf_ptr is the position on the inbuf to get the payload
 * @param msg is to store the payload from the inbuf
 * @return -1 for error, or size of the payload.
 */
int coap_dettach_payload (uint8_t * inbuf, uint16_t len, uint8_t * buf_ptr,
                          coap_message * msg);

/**
 * Set coap msg/pdu to outbuf
 * @param outbuf is the buffer for write/send
 * @param msg is the coap msg/pdu to be set on outbuf
 * @return -1 for error, or size of coap msg/pdu to be send
 */
int coap_set_msg (uint8_t * outbuf, coap_message * msg);

/**
 * Get coap msg/pdu from inbuf
 * @param inbuf is the buffer for read/recv
 * @param len is the size of the coap msg/pdu
 * @param msg is to store the msg/pdu from the inbuf
 * @return -1 for error, or coap msg payload size (-1, 0, or > 0).
 */
int coap_get_msg (uint8_t * inbuf, uint16_t len, coap_message * msg);

/**
 * Set seed first by client/server using pid and time.
 */
void set_seed ();

/**
 * Generate 16 bit random number for msg_id and token.
 * @return 16 bit random number. need to
 */
uint16_t get_random ();

/**
 * Default configuration if not configured in file.
 */
void coap_default_config ();

/**
 * Convert integer val to string in buf
 * @param val interger
 * @param buf string
 * @return the size of the string
 */
int coap_itoa (int val, char *buf);

/**
 * Get service port from service name.
 * @param service is the service name
 * @param protocol is the protocol
 * @return service port
 */
uint16_t coap_resolve_service (const char *service, const char *protocol);

/**
 * Allocate memory for msg
 * @param oc is options count
 * @param payload_len is payload length
 * @return NULL for error, or pointer to the newly created msg
 */
coap_message *coap_create_msg (uint8_t oc, uint16_t payload_len);

/**
 * Fill the message with the type, code and payload
 * @param msg a pointer to the message that must be filled
 * @param type the message type
 * @param code the message code
 * @param payload the message payload
 * @param payload_len the payload length
 * @return -1 for error, or 0 for success
 */
int coap_fill_msg(coap_message *msg, coap_msg_type type,
                  uint8_t code, char *payload, uint16_t payload_len);

/**
 * Clean options
 * @param list is the option list
 * @param oc is option count
 */
void coap_clean_options (coap_option * list, uint8_t oc);

/**
 * Clean msg
 * @param msg is pointer to the msg to be cleaned
 */
void coap_clean_msg (coap_message * msg);

/**
 * COnvert byte array to hex string
 * @param byte_array is the array to be converted
 * @param size is the size of the array to be converted
 * @return pionter to the hext string
 */
char *byte_array_to_hex_string (uint8_t * byte_array, uint8_t size);

/**
 * This is for test/debug only, do not use in real app
 * @param msg is a pointer to the msg to be dumped.
 */
void coap_dump_msg (coap_message * msg);

/**
 * This is for test/debug only, do not use in real app
 * @param msg is a pointer to the msg containing the payload to be dumped.
 */
void coap_dump_payload (coap_message * msg);

/**
 * Read configuration file by the server.
 * @param file_name is the name of the config file
 */
void coap_config (char *file_name);

#endif /* COAP_H_ */
