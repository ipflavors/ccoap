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
 * coap.c
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#include <stdlib.h>             /* for atoi() and exit() */
#include <string.h>             /* for memset() */
#include <ctype.h>              /* for isspace() */
#include <unistd.h>             /* for close() and getpid() */
#include <stdint.h>
#include <stdbool.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>

#include "ccoaplib.h"

/* Used by client only, generally is per task,
 * So the global is not used except relay through a proxy
 */
char *coap_server_name;     

uint16_t coap_port;
uint8_t coap_max_retransmit;
uint8_t coap_max_wait_con;
uint8_t coap_retransmit_timeout;
uint8_t coap_session_timeout;
uint8_t coap_session_cleanup_time;
uint8_t coap_max_option_count;
uint8_t coap_init_server_session_threads;
uint8_t coap_init_client_task_threads;
uint16_t coap_send_receive_buffer_size;
uint8_t coap_max_option_list_size;
uint8_t coap_server_listen_queue;
/**
 * 0 piggy_backed mode, 1 seperate mode.
 */
bool coap_separate_mode;
bool coap_server_is_proxy;
coap_node *start, *end;
coap_locked_data thread_pool_parms;
pthread_mutex_t dump_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Message id to description
 */
#ifdef PRINT_DEBUG
static const char *messages[] = {
    "Message 0: CON",
    "Message 1: NON",
    "Message 2: ACK",
    "Message 3: RST",
};
#endif

/**
 * Request/Method code to description
 */
#ifdef PRINT_DEBUG
static const char *requests[] = {
    "Request/Method 1: GET",
    "Request/Method 2: POST",
    "Request/Method 3: PUT",
    "Request/Method 4: DELETE",
};
#endif

/**
 * Response code to description
 */
#ifdef PRINT_DEBUG
static const char *responses[] = {
    "Success 65: Created",
    "Success 66: Deleted",
    "Success 67: Valid",
    "Success 68: Changed",
    "Success 69: Content",
    "Client Error 128: Bad Request",
    "Client Error 129: Unauthorized",
    "Client Error 130: Bad Option",
    "Client Error 131: Forbidden",
    "Client Error 132: Not Found",
    "Client Error 133: Method Not Allowed",
    "Client Error 140: Precondition Failed",
    "Client Error 141: Request Entity Too Large",
    "Client Error 143: Unsupported Media Type",
    "Server Error 160: Internal Server Error",
    "Server Error 161: Not Implemented",
    "Server Error 162: Bad Gateway",
    "Server Error 163: Service Unavailable",
    "Server Error 164: Gateway Timeout",
    "Server Error 165: Proxying Not Supported",
};
#endif

/**
 * Option id to description
 */
#ifdef PRINT_DEBUG
static const char *options[] = {
    "Option 1: Content-Type",
    "Option 2: Max-Age",
    "Option 3: Proxy-Uri",
    "Option 4: ETag",
    "Option 5: Uri-Host",
    "Option 6: Location-Path",
    "Option 7: Uri-Port",
    "Option 8: Location-Query",
    "Option 9: Uri-Path",
    "Option 10: Observe",
    "Option 11: Token",
    "Option 12: Accept",
    "Option 13: If-Match",
    "Option 14: MAX-OFE",
    "Option 15: Uri-Query",
    "Option 17: Block2",
    "Option 19: Block1",
    "Option 21: If-None-Match",
};
#endif

/**
 * Media type to description
 */
#ifdef PRINT_DEBUG
static const char *medias[] = {
    "Media Type 0: text/plain; charset=utf-8",
    "Media Type 40: application/link-format",
    "Media Type 41: application/xml",
    "Media Type 42: application/octet-stream",
    "Media Type 47: application/exi",
    "Media Type 50: application/json",
};
#endif

/**
 * Display a description of the message type.
 * @param type is the message type
 */
void
coap_show_message_type (uint16_t type)
{
    DBG ("Message type is %s.\n", messages[type]);
}

/**
 * Display a description of the request code.
 * @param code is the request code
 */
void
coap_show_request_code (uint8_t code)
{
    DBG ("Request/Method is %s.\n", requests[code - 1]);
}

/**
 * Check header.
 * @param hdr is the header
 */
bool
coap_header_is_valid (coap_header hdr)
{
    if (hdr.ver != 1 ||
        hdr.type > 3 ||
        hdr.oc > 8 || (hdr.code > 31 && hdr.code < 64) || hdr.code > 191) {
        ERROR ("Invalid CoAP header\n");
        return false;
    }
    return true;
}

/**
 * Check option id.
 * @param id is the option id
 */
bool
coap_option_id_is_valid (uint8_t id)
{
    switch (id) {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
    case 17:
    case 19:
    case 21:
        return true;
        break;
    default:
        break;
    }
    return false;
}

/**
 * Display a description of the option id.
 * @param id is the option id
 */
void
coap_show_option_id (uint8_t id)
{
    switch (id) {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
        DBG ("Option is %s.\n", options[id - 1]);
        break;
    case 17:
        DBG ("Option is %s.\n", options[id - 2]);
        break;
    case 19:
        DBG ("Option is %s.\n", options[id - 3]);
        break;
    case 21:
        DBG ("Option is %s.\n", options[id - 4]);
        break;
    default:
        ERROR ("Option is unknown.\n");
        break;
    }
}

/**
 * Display a description of the response code.
 * @param code is the response code
 */
void
coap_show_response_code (uint8_t code)
{
    switch (code) {
    case 65:
    case 66:
    case 67:
    case 68:
    case 69:
        DBG ("Response is %s.\n", responses[code - 65]);
        break;
    case 128:
    case 129:
    case 130:
    case 131:
    case 132:
    case 133:
        DBG ("Response is %s.\n", responses[code - 123]);
        break;
    case 140:
    case 141:
        DBG ("Response is %s.\n", responses[code - 129]);
        break;
    case 143:
        DBG ("Response is %s.\n", responses[code - 130]);
        break;
    case 160:
    case 161:
    case 162:
    case 163:
    case 164:
    case 165:
        DBG ("Response is %s.\n", responses[code - 146]);
        break;
    default:
        ERROR ("Response is unknown.\n");
        break;
    }
}

/**
 * Display a description of the media type.
 * @param type is the media type
 */
void
coap_show_media_type (uint8_t type)
{
    switch (type) {
    case 0:
        DBG ("Media is %s.\n", medias[type]);
        break;
    case 40:
    case 41:
    case 42:
        DBG ("Media is %s.\n", medias[type - 39]);
        break;
    case 47:
        DBG ("Media is %s.\n", medias[type - 43]);
        break;
    case 50:
        DBG ("Media is %s.\n", medias[type - 45]);
        break;
    default:
        ERROR ("Media is unknown.\n");
        break;
    }
}

/**
 * Encodes coap header. outbuf is cleaned first.
 * @param outbuf is the buffer for write/send
 * @param hdr is the header of the coap msg/pdu
 * @return -1 for error, or 0 for success
 */
inline int
coap_encode_header (uint8_t * outbuf, coap_header hdr)
{
    if (!coap_header_is_valid (hdr)) {
        return -1;
    }
    memset (outbuf, 0, coap_send_receive_buffer_size);
    COAP_ENCODE_HEADER (outbuf, hdr.ver, hdr.type, hdr.oc, hdr.code,
                        hdr.msg_id);
    return 0;
}

/**
 * Decodes coap header.
 * @param inbuf is the buffer to read/recv
 * @param size is the size of the coap msg/pdu
 * @param hdr is to store the decoded header
 * @return -1 for error, or 0 for success.
 */
inline int
coap_decode_header (uint8_t * inbuf, uint16_t size, coap_header * hdr)
{
    if (size < COAP_HDR_BYTES) {
        ERROR ("hdr size less than %d bytes\n", COAP_HDR_BYTES);
        return -1;
    }
    COAP_DECODE_HEADER (inbuf, hdr);
    if (!coap_header_is_valid (*hdr)) {
        return -1;
    }
    return 0;
}

/**
 * Add coap options at index on the list.
 * @param list is the option list
 * @param index is the index at the list
 * @param option_id is the option id
 * @param length is the length of the option data
 * @param data is a pointer to the option data
 * @return -1 if error, or 0 if success.
 */
int
coap_add_option (coap_option * list, uint8_t index, uint8_t option_id,
                 uint16_t length, uint8_t * data)
{
    if (option_id > 21) {
        ERROR ("Invalid option id.\n");
        return -1;
    }

    if (list == NULL) {
        ERROR ("coap option list is NULL\n");
        return -1;
    }
    list[index].number = (uint8_t) option_id;

    if (length > 270) {
        ERROR ("Invalid option length.\n");
        return -1;
    }

    if (length <= 14) {
        list[index].ext = false;
        list[index].length = (uint8_t) length;
    } else {
        list[index].ext = true;
        list[index].length = (uint8_t) (length - 15);
    }

    if (length != 0 && data != NULL) {
        if ((list[index].data = (uint8_t *) malloc (length)) == NULL) {
            ERROR ("Allocate option data failed\n");
            return -1;
        }

        memcpy (list[index].data, data, length);
    }

    return 0;
}

/**
 * Encodes coap options from the prebuilt options list with oc elements in outbuf.
 * @param outbuf is the buffer for write/send
 * @param msg is a pointer to the coap message to be encoded
 * @return NULL for error, or pointer to the location in outbuf where the payload might be added.
 */
uint8_t *
coap_encode_options (uint8_t * outbuf, coap_message * msg)
{
    uint8_t delta = 0, accu_delta = 0;
    uint32_t index = 0;
    int diff;
    uint8_t byte;
    uint32_t len = 0, length;
    uint8_t *buf_ptr = outbuf + COAP_HDR_BYTES;
    uint8_t *original_buf_ptr = buf_ptr;
    bool error = false;

    if (msg->hdr.oc == 0 || msg->option_list == NULL) {
        DBG ("No option to encode.\n");

        if (msg->option_list != NULL){
            free (msg->option_list);
            msg->option_list = NULL;
        }
        return buf_ptr;
    }

    while (index < msg->hdr.oc) {
        if (msg->option_list[index].data == NULL) {
            ERROR ("Option with index %d NULL.\n", index);
            error = true;
            break;
        }

        if ((diff = msg->option_list[index].number - accu_delta) < 0 ||
            diff > 15) {
            ERROR ("Invalid option number, diff = %d (%d - %d)\n", diff, msg->option_list[index].number, accu_delta);
            error = true;
            break;
        } else if (diff == 0) {
            if (msg->option_list[index].number != COAP_ENUM_OPTION_ID_URI_PATH
                && msg->option_list[index].number !=
                COAP_ENUM_OPTION_ID_URI_QUERY
                && msg->option_list[index].number !=
                COAP_ENUM_OPTION_ID_LOCATION_PATH
                && msg->option_list[index].number !=
                COAP_ENUM_OPTION_ID_LOCATION_QUERY) {
                ERROR ("Invalid option number.\n");
                error = true;
                break;
            }
        }

        delta = (uint8_t) diff;

        if (msg->option_list[index].ext == false) {
            if (len + 1 + msg->option_list[index].length <=
                coap_send_receive_buffer_size) {
                byte =
                    (0x0F & delta) << 4 | (0x0F & msg->option_list[index].
                                           length);
                *(buf_ptr) = byte;
                memcpy (buf_ptr + 1, msg->option_list[index].data,
                        msg->option_list[index].length);
                length = msg->option_list[index].length + 1;
            } else {
                ERROR ("Output buffer overflow.\n");
                error = true;
                break;
            }
        } else {
            if (len + 2 + msg->option_list[index].length + 15 <=
                coap_send_receive_buffer_size) {
                byte = (0x0F & delta) << 4 | 0x0F;
                *(buf_ptr) = byte;
                *(buf_ptr + 1) = msg->option_list[index].length;
                memcpy (buf_ptr + 2, msg->option_list[index].data,
                        msg->option_list[index].length + 15);
                length = msg->option_list[index].length + 15 + 2;
            } else {
                ERROR ("Output buffer overflow.\n");
                error = true;
                break;
            }
        }

        buf_ptr += length;
        len += length;

        if (len == coap_send_receive_buffer_size) {
            if (msg->hdr.oc > 1) {
                ERROR ("Output buffer overflow.\n");
                error = true;
            }
            break;
        }

        accu_delta = msg->option_list[index].number;
        index++;
    }

    index = 0;

    /* Clean up the option list */
    while (index < msg->hdr.oc) {
        if (msg->option_list[index].data != NULL) {
            free (msg->option_list[index].data);
            msg->option_list[index].data = NULL;
        }
        index++;
    }

    free (msg->option_list);
    msg->option_list = NULL;

    if (len != (buf_ptr - original_buf_ptr)) {
        ERROR ("Option encoding misaligned.\n");
        return NULL;
    }

    if (error == true) {
        return NULL;
    }

    return buf_ptr;
}

/**
 * Decodes coap option and add it to the list.
 * @param inbuf is the buffer for read/recv
 * @param len is received coap msg/pdu size.
 * @param msg is a pointer to the decoded coap message
 * @return NULL for error, or pointer to the location in outbuf where the payload might be accessed.
 */
uint8_t *
coap_decode_option (uint8_t * inbuf, uint32_t len, coap_message * msg)
{
    uint8_t accu_delta = 0;
    //uint8_t delta = 0,
    bool error = false;
    uint8_t index = 0;
    uint8_t byte;
    uint16_t length, original_len;
    msg->token = NULL;
    msg->token_length = 0;

    /* Skip header (4 bytes) */
    uint8_t *buf_ptr = inbuf + COAP_HDR_BYTES;
    uint8_t *original_buf_ptr = buf_ptr;
    len -= COAP_HDR_BYTES;
    original_len = len;

    if (msg->hdr.oc == 0) {
        DBG ("No option to decode.\n");
        return buf_ptr;
    } else if (len < COAP_MIN_OPTION_SIZE) {
        DBG ("No option data.\n");
        return NULL;
    } else {
        msg->option_list =
            (coap_option *) malloc (msg->hdr.oc * sizeof (coap_option));
        if (msg->option_list == NULL) {
            ERROR ("Allocate option_list failed.\n");
            return NULL;
        }
    }

    while (index < msg->hdr.oc) {
        byte = *buf_ptr;
        msg->option_list[index].number = ((byte & 0xF0) >> 4) + accu_delta;
        if (!coap_option_id_is_valid (msg->option_list[index].number)) {
            ERROR ("client: option number %d is not valid.\n",
                   msg->option_list[index].number);
            //return NULL;
        }
        accu_delta = msg->option_list[index].number;

        if ((msg->option_list[index].length = (byte & 0x0F)) == 0x0F) {
            msg->option_list[index].ext = true;
            msg->option_list[index].length = *(buf_ptr + 1);
            length = msg->option_list[index].length + 15;
            buf_ptr += 2;
            len -= 2;
        } else {
            msg->option_list[index].ext = false;
            length = msg->option_list[index].length;
            buf_ptr += 1;
            len -= 1;
        }

        if (len < length) {
            ERROR ("Option missing data.\n");
            error = true;
            break;
        }

        if ((msg->option_list[index].data =
             (uint8_t *) malloc (length)) == NULL) {
            ERROR ("Allocate option data failed\n");
            return NULL;
        }

        memcpy (msg->option_list[index].data, buf_ptr, length);
        if (msg->option_list[index].number == COAP_ENUM_OPTION_ID_TOKEN &&
            length >= 1 && length <= 8) {
            if ((msg->token = (uint8_t *) malloc (length)) == NULL) {
                ERROR ("Allocate token failed\n");
                return NULL;;
            }

            memcpy (msg->token, msg->option_list[index].data, length);
            msg->token_length = length;
        }
        buf_ptr += length;
        len -= length;

        index++;

        if (len <= 0 && index < msg->hdr.oc) {
            ERROR ("Inbuf missing option.\n");
            error = true;
            break;
        }
    }

    if ((buf_ptr - original_buf_ptr) != (original_len - len)) {
        ERROR ("Option decoding misaligned.\n");
        return NULL;
    }

    if (error == true) {
        return NULL;
    }

    return buf_ptr;
}

/**
 * Attach coap payload with payload_len at location buf_ptr in outbuf.
 * @param outbuf is the buffer for write/send
 * @param buf_ptr is the position on the outbuf to attach the payload
 * @param msg is a pointer to the coap message containing the payload to be attached to the outbuf
 * @return -1 for error, or coap msg/pdu size.
 */
int
coap_attach_payload (uint8_t * outbuf, uint8_t * buf_ptr, coap_message * msg)
{
    uint16_t length = buf_ptr - outbuf + msg->payload_len;

    if (length > coap_send_receive_buffer_size) {
        ERROR ("Outbuf payload overflow.\n");
        if (msg->payload != NULL) {
            free (msg->payload);
            msg->payload = NULL;
            msg->payload_len = 0;
        }
        return -1;
    }

    if (msg->payload == NULL && msg->payload_len == 0) {
        DBG ("No payload attached.\n");
        return length;
    }

    if (msg->payload != NULL && msg->payload_len > 0) {
        memcpy (buf_ptr, (uint8_t *) msg->payload, msg->payload_len);
        free (msg->payload);
        msg->payload = NULL;
        msg->payload_len = 0;
        return length;
    } else {
        ERROR ("Invalid payload.\n");
        if (msg->payload != NULL) {
            free (msg->payload);
            msg->payload = NULL;
            msg->payload_len = 0;
        }
        return -1;
    }
}

/**
 * Dettach coap payload from location at buf_ptr in inbuf to payload.
 * @param inbuf is the buffer for read/recv
 * @param len is the size of the coap msg/pdu
 * @param buf_ptr is the position on the inbuf to get the payload
 * @param msg is to store the payload from the inbuf
 * @return -1 for error, or size of the payload.
 */
int
coap_dettach_payload (uint8_t * inbuf, uint16_t len, uint8_t * buf_ptr,
                      coap_message * msg)
{
    uint16_t length = buf_ptr - inbuf;

    if (length > len) {
        ERROR ("Payload miss aligned.\n");
        msg->payload = NULL;
        msg->payload_len = 0;
        return -1;
    } else if (length == len || msg->hdr.code == COAP_RES_CODE_EMPTY) {
        DBG ("No payload to dettach.\n");
        msg->payload = NULL;
        msg->payload_len = 0;
        return 0;
    } else {
        length = len - length;
        if ((msg->payload = (uint8_t *) malloc (length)) == NULL) {
            DBG ("Allocate payload failed\n");
            return -1;
        }
        msg->payload_len = length;
        memcpy (msg->payload, (uint8_t *) buf_ptr, length);
        return length;
    }
}

/**
 * Create the token option
 * @param msg is the message in which the token must be created
 * @return NULL for error, or a pointer to the token option
 */
uint8_t *
coap_create_token(coap_message *msg)
{
    if (msg == NULL) {
        return NULL;
    }

    msg->token_length = COAP_TOKEN_LEN;
    msg->token = (uint8_t *) malloc (msg->token_length);
    *(msg->token) = (uint8_t) (get_random () >> 8);
    *(msg->token + 1) = (uint8_t) get_random ();

    char *hex_string = byte_array_to_hex_string (msg->token, 2);
    DBG ("Message token = %s\n", hex_string);
    free (hex_string);

    return msg->token;
}

/**
 * Set coap msg/pdu to outbuf
 * @param outbuf is the buffer for write/send
 * @param msg is the coap msg/pdu to be set on outbuf
 * @return -1 for error, or size of coap msg/pdu to be send
 */
int
coap_set_msg (uint8_t * outbuf, coap_message * msg)
{
    uint8_t *buf_ptr;

    if (coap_encode_header (outbuf, msg->hdr) == -1) {
        return -1;
    }
    buf_ptr = coap_encode_options (outbuf, msg);

    if (buf_ptr != NULL) {
        return (coap_attach_payload (outbuf, buf_ptr, msg));
    } else {
        return -1;
    }
}

/**
 * Get coap msg/pdu from inbuf
 * @param inbuf is the buffer for read/recv
 * @param len is the size of the coap msg/pdu
 * @param msg is to store the msg/pdu from the inbuf
 * @return -1 for error, or coap msg payload size (-1, 0, or > 0).
 */
int
coap_get_msg (uint8_t * inbuf, uint16_t len, coap_message * msg)
{
    uint8_t *buf_ptr;

    if (coap_decode_header (inbuf, len, &(msg->hdr)) == -1) {
        return -1;
    }

    buf_ptr = coap_decode_option (inbuf, len, msg);

    if (buf_ptr != NULL) {
        return coap_dettach_payload (inbuf, len, buf_ptr, msg);
    } else {
        msg->payload = NULL;
        msg->payload_len = 0;
        return -1;
    }
}

/**
 * Set seed first by client/server using pid and time.
 */
void
set_seed ()
{
    //srand(getpid() * time(NULL));
    srand (getpid () ^ time (NULL));
}

/**
 * Generate 16 bit random number for msg_id and token.
 * @return 16 bit random number. need to
 */
uint16_t
get_random ()
{
    return (uint16_t) (rand () >> 15);
}

/**
 * Default configuration if not configured in file.
 */
void
coap_default_config ()
{
    coap_server_name = COAP_SERVER_NAME;
    if ((coap_port = coap_resolve_service ("coap", "udp")) == 0) {
        coap_port = COAP_UDP_PORT;
    }
    coap_max_retransmit = COAP_MAX_RETRANSMITION_COUNT;
    coap_retransmit_timeout = COAP_RETRANSMITION_TIMEOUT;
    coap_max_wait_con = COAP_MAX_WAIT_CON_COUNT;
    coap_session_timeout = COAP_SESSION_TIMEOUT;
    coap_session_cleanup_time = COAP_SESSIONS_CLEAN_UP_TIME_INTERVAL;
    coap_max_option_count = COAP_MAX_OPTION_COUNT;
    coap_init_server_session_threads = COAP_INIT_SERVER_SESSION_THREADS;
    coap_init_client_task_threads = COAP_INIT_CLIENT_TASK_THREADS;
    coap_send_receive_buffer_size = COAP_SEND_RECEIVE_BUFFER_SIZE;
    coap_max_option_list_size = COAP_MAX_OPTION_LIST_SIZE;
    coap_server_listen_queue = COAP_SERVER_LISTEN_QUEUE;
    coap_separate_mode = true;
    coap_server_is_proxy = true;
}

/**
 * Convert integer val to string in buf
 * @param val interger
 * @param buf string
 * @return the size of the string
 */
int
coap_itoa (int val, char *buf)
{
    const unsigned int radix = 10;

    char *p;
    unsigned int a;             /* Every digit */
    int len;
    char *b;                    /* Start of the digit char */
    char temp;
    unsigned int u;

    p = buf;

    if (val < 0) {
        *p++ = '-';
        val = 0 - val;
    }
    u = (unsigned int) val;

    b = p;

    do {
        a = u % radix;
        u /= radix;

        *p++ = a + '0';

    } while (u > 0);

    len = (int) (p - buf);

    *p-- = 0;

    /* Swap */
    do {
        temp = *p;
        *p = *b;
        *b = temp;
        --p;
        ++b;

    } while (b < p);

    return len;
}

/**
 * Get service port from service name.
 * @param service is the service name
 * @param protocol is the protocol
 * @return service port
 */
uint16_t
coap_resolve_service (const char *service, const char *protocol)
{
    struct servent *serv;       /* Structure containing service information */
    uint16_t port;              /* Port to return */

    if ((port = atoi (service)) == 0) { 
        /* Is port numeric? */
        /* Not numeric. Try to find as a name */
        if ((serv = getservbyname (service, protocol)) == NULL) {
            ERROR ("getservbyname() failed.\n");
            return 0;
        } else
            /* Found port (network byte order) by name */
            port = ntohs (serv->s_port);
    }

    return port;
}

/**
 * Allocate memory for msg
 * @param oc is options count
 * @param payload_len is payload length
 * @return NULL for error, or pointer to the newly created msg
 */
coap_message *
coap_create_msg (uint8_t oc, uint16_t payload_len)
{
    coap_message *msg = (coap_message *) malloc (sizeof (coap_message));
    if (msg == NULL) {
        ERROR ("Allocate msg failed.\n");
        return NULL;
    }

    /* default token is empty */
    msg->token = NULL;
    msg->token_length = 0;

    if (oc > 0) {
        msg->option_list = (coap_option *) malloc (oc * sizeof (coap_option));
        if (msg->option_list == NULL) {
            ERROR ("Allocate msg->option_list failed.\n");
            goto clean_up;
        }
    } else {
        msg->option_list = NULL;
    }

    msg->hdr.oc = oc;

    if (payload_len > 0) {
        msg->payload = (uint8_t *) malloc (payload_len);
        if (msg->payload == NULL) {
            ERROR ("Allocate msg->payload failed.\n");
            goto clean_up;
        }
    } else {
        msg->payload = NULL;
    }

    msg->payload_len = payload_len;

    /* Fill version and message ID */
    msg->hdr.ver = COAP_VERSION;
    msg->hdr.msg_id = get_random ();
    
    return msg;

clean_up:

    coap_clean_msg (msg);
    return NULL;
}

/**
 * Fill the message with the type, code and payload
 * @param msg a pointer to the message that must be filled
 * @param type the message type
 * @param code the message code
 * @param payload the message payload
 * @param payload_len the payload length
 * @return -1 for error, or 0 for success
 */
int
coap_fill_msg(coap_message *msg, coap_msg_type type,
                     uint8_t code, char *payload, uint16_t payload_len)
{
    if (msg == NULL) {
        return -1;
    }

    msg->hdr.type = type;
    msg->hdr.code = code;

    if (payload != NULL && payload_len > 0) {
        memcpy (msg->payload, payload, payload_len);
        msg->payload_len = payload_len;
    }

    return 0;
}

/**
 * Clean options
 * @param list is the option list
 * @param oc is option count
 */
void
coap_clean_options (coap_option * list, uint8_t oc)
{
    if (oc > 0 && list != NULL) {
        while (oc) {
            if (list[--(oc)].data != NULL) {
                free (list[oc].data);
            }
        }
    }
    if (list != NULL) {
        free (list);
    } 
}

/**
 * Clean msg
 * @param msg is pointer to the msg to be cleaned
 */
void
coap_clean_msg (coap_message * msg)
{
    if (msg != NULL) {
        if (msg->token != NULL) {
            free (msg->token);
        }
        coap_clean_options (msg->option_list, msg->hdr.oc);
        if (msg->payload != NULL) {
            free (msg->payload);
        }
        free (msg);
    }
}

/**
 * Convert byte array to hex string
 * @param byte_array is the array to be converted
 * @param size is the size of the array to be converted
 * @return pionter to the hext string
 */
char *
byte_array_to_hex_string (uint8_t * byte_array, uint8_t size)
{
    if (size > 8) {
        return NULL;
    }
    /* Lookup table */
    static char lookup[] =
        { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
          'D', 'E', 'F' };
    char *hex_string = (char *) malloc (20);
    hex_string[0] = '0';
    hex_string[1] = 'X';
    int n = 0;

    while (n < size) {
        hex_string[2 * n + 2] = lookup[byte_array[n] >> 4];
        hex_string[2 * n + 3] = lookup[byte_array[n] & 0x0F];
        n++;
    }
    hex_string[2 * n + 2] = '\0';
    return hex_string;
}

void
dump_lock ()
{
    assert (pthread_mutex_lock (&dump_mutex) == 0);
}

void
dump_unlock ()
{
    assert (pthread_mutex_unlock (&dump_mutex) == 0);
}

/**
 * This is for test/debug only, do not use in real app
 * @param msg is a pointer to the msg to be dumped.
 */
void
coap_dump_msg (coap_message * msg)
{
    uint8_t data[256], i, len;

    dump_lock ();
    CDBG ("======================== CoAP message ========================\n");

    /* Display header contents */
    CDBG ("hd: <ver> <type> <oc> <code> <id>\n");
    CDBG ("      %01d,    %01d,    %02d,   %03d,  0X%04X\n",
          msg->hdr.ver, msg->hdr.type, msg->hdr.oc, msg->hdr.code,
          msg->hdr.msg_id);

    /* Display options contents */
    CDBG ("op: <number> <length> <data>\n");
    for (i = 0; i < msg->hdr.oc; i++) {
        if (coap_option_id_is_valid (msg->option_list[i].number)) {
            if (msg->option_list[i].ext == true) {
                len = msg->option_list[i].length + 15;
            } else {
                len = msg->option_list[i].length;
            }
            memcpy (data, msg->option_list[i].data, len);
            data[len] = '\0';
            if (msg->option_list[i].number == COAP_ENUM_OPTION_ID_TOKEN) {
                char *hex_string = byte_array_to_hex_string (data, len);
                CDBG ("       %02d,     %03d,     %s\n",
                      msg->option_list[i].number, len, hex_string);
                free (hex_string);
            } else if (msg->option_list[i].number ==
                       COAP_ENUM_OPTION_ID_URI_PORT) {
#ifdef PRINT_DEBUG
                uint16_t uint16_value = ntohs (*((uint16_t *) data));
#endif
                CDBG ("       %02d,     %03d,     %d\n",
                      msg->option_list[i].number, len, uint16_value);
            } else if (msg->option_list[i].number ==
                       COAP_ENUM_OPTION_ID_CONTENT_TYPE
                       || msg->option_list[i].number ==
                       COAP_ENUM_OPTION_ID_OBSERVE) {
                if (len == 2) {
#ifdef PRINT_DEBUG
                    uint16_t uint16_value = ntohs (*((uint16_t *) data));
#endif
                    CDBG ("       %02d,     %03d,     %d\n",
                          msg->option_list[i].number, len, uint16_value);
                } else if (len == 1) {
                    CDBG ("       %02d,     %03d,     %d\n",
                          msg->option_list[i].number, len, *data);
                }
            } else if (msg->option_list[i].number ==
                       COAP_ENUM_OPTION_ID_MAX_AGE
                       || msg->option_list[i].number ==
                       COAP_ENUM_OPTION_ID_MAX_OFE) {
#ifdef PRINT_DEBUG
                uint32_t uint32_value = ntohl (*((uint32_t *) data));
#endif
                CDBG ("       %02d,     %03d,     %d\n",
                      msg->option_list[i].number, len, uint32_value);
            } else {
                CDBG ("       %02d,     %03d,     %s\n",
                      msg->option_list[i].number, len, data);
            }
        } else {
            CDBG ("unknown option.\n");
        }
    }

    /* Display payload contents, assume string, real app payload could be
     * serialized structure */
    if (msg->payload_len > 0) {
        CDBG ("pl: <length> <payload>\n");
        //memcpy(data, msg->payload, msg->payload_len);
        //data[msg->payload_len] = '\0';
        CDBG ("       %02d,    %.*s\n", msg->payload_len, msg->payload_len,
              msg->payload);
    }
    CDBG ("==============================================================\n");
    dump_unlock ();
}

/**
 * This is for test/debug only, do not use in real app
 * @param msg is a pointer to the msg containing the payload to be dumped.
 */
void
coap_dump_payload (coap_message * msg)
{
    dump_lock ();
    CDBG ("========================= Payload ============================\n");
    if (msg->payload_len != 0) {
        CDBG ("Payload length = %02d\n", msg->payload_len);
        CDBG ("Payload = %.*s\n", msg->payload_len, msg->payload);
    } else {
        CDBG ("Empty payload\n");
    }
    CDBG ("==============================================================\n");
    dump_unlock ();
}

/**
 * Remove blanks from line of characters. Helper function for coap_config()
 * @param buf the buffer which needs to be cleaned up of blanks
 */
void remove_blanks(char *buf)
{
    char *p1 = buf, *p2 = buf;

    while(*p1 != 0) {
        if(isspace(*p1)) {
            ++p1;
        } else {
            *p2++ = *p1++;
        }
    }
    *p2 = 0;
}

/**
 * Read configuration file by the server.
 * @param file_name is the name of the config file
 */
void
coap_config (char *file_name)
{
    static char *lookup[] = {
        [0] "server_name",
        [1] "port",
        [2] "max_retransmit",
        [3] "retransmit_timeout",
        [4] "max_wait_con",
        [5] "session_timeout",
        [6] "session_cleanup_time",
        [7] "max_option_count",             // TODO: unused at the moment
        [8] "init_server_session_threads",
        [9] "init_client_task_threads",
        [10] "send_receive_buffer_size",
        [11] "max_option_list_size",        // TODO: unused at the moment
        [12] "server_listen_queue",
        [13] "separate_mode",
        [14] "server_is_proxy",
    };

    int n = 0, comment = 0, linenum = 0;
    char line[80];
    char *value;
    char *key;
    char *p;
    FILE *fd;

    if (file_name == NULL) {
        return;
    }

    fd = fopen (file_name, "r");

    if (fd == NULL) {
        ERROR ("could not open config file.\n");
        return;
    }

    while (fgets (line, 80, fd) != NULL) {
        /* Remove spaces from the buffer */
        remove_blanks(line);
        comment = 0;
        linenum++;

        p = strchr (line, '#'); // '#' is used for comments
        if (p) {
            *p = '\0';
            comment = 1;
        }

        p = strchr (line, '\n');
        if (p) {
            *p = '\0';
        }

        p = strchr (line, '\r');
        if (p) {
            *p = '\0';
        }

        key = strtok_r (line, "=", &value);

        if (key == NULL || value == NULL) {
            if (!comment && line[0] != '\0') {
                ERROR ("Line %d - Configuration item %s does not exist\n", linenum, line);
            }

            /* Simply continue to the next line */
            continue;
        }

        n = 0;
        while (n < 15) {
            if (strcmp (lookup[n], key) == 0) {
                break;
            }
            n++;
        }

        switch (n) {
        case 0:
            coap_server_name = (char *) malloc (strlen (value) + 1);
            strcpy (coap_server_name, value);
            DBG ("%s=%s\n", key, value);
            break;
        case 1:
            coap_port = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 2:
            coap_max_retransmit = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 3:
            coap_retransmit_timeout = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 4:
            coap_max_wait_con = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 5:
            coap_session_timeout = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 6:
            coap_session_cleanup_time = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 7:
            coap_max_option_count = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 8:
            coap_init_server_session_threads = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 9:
            coap_init_client_task_threads = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 10:
            coap_send_receive_buffer_size = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 11:
            coap_max_option_list_size = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 12:
            coap_server_listen_queue = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 13:
            coap_separate_mode = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        case 14:
            coap_server_is_proxy = atoi (value);
            DBG ("%s=%d\n", key, atoi (value));
            break;
        default:
            ERROR ("Line %d - Configuration item %s does not exist\n", linenum, key);
            break;
        }
    }
    fclose (fd);
}
