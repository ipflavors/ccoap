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
 * client.c
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>

#include "client.h"
#include "ccoaplib.h"

//extern char* coap_server_name;
extern uint16_t coap_port;
extern uint8_t coap_max_retransmit;
extern uint8_t coap_retransmit_timeout;
extern uint8_t coap_max_wait_con;
//extern uint8_t coap_session_timeout;
//extern uint8_t coap_session_cleanup_time;
//extern uint8_t coap_max_option_count;
//extern uint8_t coap_init_server_session_threads;
extern uint8_t coap_init_client_task_threads;
extern uint16_t coap_send_receive_buffer_size;
//extern uint8_t coap_max_option_list_size;
//extern uint8_t coap_server_listen_queue;
//extern bool coap_separate_mode;
extern bool coap_server_is_proxy;

extern pthread_mutex_t dump_mutex;
extern coap_node *start, *end;
extern coap_user coap_user_code[];
extern coap_locked_data thread_pool_parms;

pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Read configuration file by the clients.
 * @param file_name is the client config file name
 */
void
coap_client_config (char *file_name)
{
    coap_config (file_name);
}

/**
 * Initialization by the clients,
 * socket, task queue, initial random msg_id/token, thread pool, etc.
 * @return -1 for error, or 0 for success
 */
int
coap_client_init ()
{
    coap_init_list ();
    set_seed ();
    thread_pool_parms.total_threads = 0;
    thread_pool_parms.active_threads = 0;
    thread_pool_parms.next_item = end;
    return 0;
}

/**
 * Get server address/port from address/port names.
 * IPv4/IPv6 independent. Connected socket.
 * @param host_name is the host name of the server
 * @param service_name is the service name of the service
 * @param family is the protocol family
 * @param socktype is the socket type
 * @return -1 for error, or connection socket for the client
 */
int
coap_open_client_socket (const char *host_name,
                         const char *service_name, int family, int socktype)
{
    struct addrinfo hints, *res, *ressave;
    int n, sockfd;
    char service_port[11];
    //unsigned short port = ntohs(coap_resolve_service(service_name, "udp"));
    unsigned short port = coap_port;
    coap_itoa (port, service_port);

    memset (&hints, 0, sizeof (struct addrinfo));

    hints.ai_family = family;
    hints.ai_socktype = socktype;

    n = getaddrinfo (host_name, service_port, &hints, &res);

    if (n < 0) {
        ERROR ("getaddrinfo: [%s]\n", gai_strerror (n));
        return -1;
    }

    ressave = res;

    sockfd = -1;
    while (res) {
        sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);

        if (!(sockfd < 0)) {
            if (connect (sockfd, res->ai_addr, res->ai_addrlen) == 0)
                break;

            close (sockfd);
            sockfd = -1;
        }
        res = res->ai_next;
    }

    freeaddrinfo (ressave);
    return sockfd;
}

/**
 * Allocate memory for a single task based on serv_name, oc and payload_len
 * @param type the application type
 * @param server_name is the server name.
 * @param oc is the element count for the option list.
 * @param payload_len is the length of the payload
 * @return NULL for error, or the task newly created.
 */
coap_task *
coap_client_create_task (coap_user_type type, char *server_name,
                         uint8_t oc, uint16_t payload_len)
{
    if (server_name == NULL) {
        ERROR ("server_name is NULL.\n");
        return NULL;
    }

    coap_task *task = (coap_task *) malloc (sizeof (coap_task));
    if (task == NULL) {
        ERROR ("Allocate task failed.\n");
        return NULL;
    }

    task->server_name = (char *) malloc (strlen (server_name) + 1);
    if (task->server_name == NULL) {
        ERROR ("Allocate task->serv_name failed.\n");
        goto clean_up;
    } else {
        strcpy (task->server_name, server_name);
    }

    task->server_service = (char *) malloc (strlen ("coap") + 1);
    if (task->server_service == NULL) {
        ERROR ("Allocate task->serv_service failed.\n");
        goto clean_up;
    } else {
        strcpy (task->server_service, "coap");
    }

    task->user = type;
    task->msg = coap_create_msg (oc, payload_len);

    return task;

clean_up:
    coap_client_clean_task (task);
    return NULL;
}

/**
 * Add coap options for a client task.
 * @param task a pointer to the task for with the option is added
 * @param index is the index at the list (the option count)
 * @param option_id is the option id
 * @param length is the length of the option data
 * @param data is a pointer to the option data
 * @return -1 if error, or 0 if success.
 */
int
coap_client_add_option (coap_task *task, uint8_t index, 
                        uint8_t option_id, uint16_t length,
                        uint8_t * data)
{
    if (task == NULL) {
        return -1;
    }

    return coap_add_option(task->msg->option_list, index, 
                           option_id, length, data);
}

/**
 * Create the token option
 * @param task a pointer to the task for which the token must be created
 * @return NULL for error, or a pointer to the token option
 */
uint8_t *
coap_client_create_token(coap_task *task)
{
    if (task == NULL) {
        return NULL;
    }
    return coap_create_token(task->msg);
}

/**
 * Fill the message of a task with the type, code and payload
 * @param task a pointer to the task for which the message must be filled
 * @param type the message type
 * @param code the message code
 * @param payload the message payload
 * @param payload_len the payload length
 * @return -1 for error, or 0 for success
 */
int
coap_client_fill_msg(coap_task *task, coap_msg_type type,
                     uint8_t code, char *payload, uint16_t payload_len)
{
    if (task == NULL) {
        return -1;
    }
    return coap_fill_msg(task->msg, type, code, payload, payload_len);
}

/**
 * Clean task when no longer needed.
 * @param task is a pointer to the task to be cleaned.
 */
void
coap_client_clean_task (coap_task * task)
{
    if (task != NULL) {
        if (task->server_name != NULL) {
            free (task->server_name);
        }
        if (task->server_service != NULL) {
            free (task->server_service);
        }
        coap_clean_msg (task->msg);
        free (task);
    }
}

/**
 * Set socket recv timeout timer used by clients/server.
 * @param connfd is the socket the timer to be set on.
 * @return -1 for error, or 0 for success
 */
int
set_socket_timer (int connfd)
{
    struct timeval tv;
    tv.tv_sec = coap_retransmit_timeout;
    tv.tv_usec = 0;

    if (setsockopt
        (connfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof (tv))) {
        perror ("setsockopt");
        return -1;
    }
    return 0;
}

/**
 * Used by a client to handle one single task from start to finish (state machine).
 * It will invoke a user application (via register) based on the task.
 * @param outbuf is the buffer per task thread for write/send
 * @param inbuf is the buffer per taskthread for read/recv
 * @param task is a task pointer to the task to be handled
 * @param connfd is the socket for communication with server, if connfd is -1, the socket
 * is per task and will be created by this function, otherwise, the socket is per thread for
 * communication to proxy or fixed single server.
 * @return -1 for error, or 0 for success
 */
int
coap_client_handle_task (uint8_t * outbuf, uint8_t * inbuf, coap_task * task,
                         int connfd)
{
    struct timeval t_start, t_stop;
    int p;
    bool error = false;
    bool socket_is_per_task = false;
    uint8_t wait_con = 0;
    coap_msg_type msg_type = task->msg->hdr.type;
    coap_message *msg = NULL;

    if (task == NULL) {
        ERROR ("client task is NULL.\n");
        return -1;
    }

    /* Task should not contain ACK or RST msg */
    if (task->msg->hdr.type == COAP_ENUM_MSG_TYPE_ACK ||
        task->msg->hdr.type == COAP_ENUM_MSG_TYPE_RST) {
        ERROR ("client task should not contain ACK or RST.\n");
        error = true;
        goto finish;
    }

    coap_state_type state = COAP_ENUM_STATE_UNKNOWN;
    uint8_t retrans_count = 0;

    /* Save the msg_id and token for response match */
    uint16_t msg_id = task->msg->hdr.msg_id;
    uint8_t msg_token[COAP_MAX_TOKEN_LENGTH];
    memcpy (msg_token, task->msg->token, task->msg->token_length);
    uint8_t msg_token_length = task->msg->token_length;
    coap_user_type task_user = task->user;

    int n, buf_len;
    uint16_t payload_len;

    if (connfd == -1) {
        /* This is per task socket/connection */
        socket_is_per_task = true;
        connfd = coap_open_client_socket (task->server_name,
                                          task->server_service, AF_UNSPEC,
                                          SOCK_DGRAM);
        if (connfd < 0) {
            ERROR ("could not create connected socket\n");
            error = true;
            goto finish;
        }
        if (set_socket_timer (connfd) < 0) {
            ERROR ("could not set socket timer\n");
            error = true;
            goto finish;
        }
    }

    buf_len = coap_set_msg (outbuf, task->msg);
    coap_client_clean_task (task);

    if (buf_len < COAP_MIN_MSG_SIZE) {
        ERROR ("could not set coap msg (buf_len = %d)\n", buf_len);
        error = true;
        goto finish;
    }

send:

    if ((gettimeofday (&t_start, NULL)) == -1) {
        perror ("gettimeofday");
        exit (1);
    }

    n = write (connfd, outbuf, buf_len);

    //if (n < 0) {
    if (n < buf_len) {
        ERROR ("could not write msg\n");
        error = true;
        goto finish;
    }

    switch (state) {
    case COAP_ENUM_STATE_UNKNOWN:
        if (msg_type == COAP_ENUM_MSG_TYPE_CON) {
            DBG ("client: Send CON\n");
            state = COAP_ENUM_STATE_WAIT_ACK;
        } else {
            DBG ("client: Send NON\n");
            state = COAP_ENUM_STATE_WAIT_NON;
        }
        break;
    case COAP_ENUM_STATE_SEND_ACK:
        DBG ("client: Send ACK\n");
        goto process_response;
    case COAP_ENUM_STATE_WAIT_ACK:
        DBG ("client: Retransmit CON %d times.\n", retrans_count);
        break;
    default:
        ERROR ("client: Should not be here.\n");
        goto finish;
    }

receive:

    memset (inbuf, 0, coap_send_receive_buffer_size);
    n = read (connfd, inbuf, coap_send_receive_buffer_size);

    /*
    if((gettimeofday(&t_stop, NULL)) == -1) {
        perror("gettimeofday");
        exit(1);
    }
    DBG("client: RTT is %ld us\n",
        (t_stop.tv_sec - t_start.tv_sec) * 1000000 + t_stop.tv_usec
        - t_start.tv_usec);
     */

    //if (n < 0) {
    if (n < COAP_MIN_MSG_SIZE) {
        ERROR ("could not read msg, msg size %d\n", n);

        switch (state) {
        case COAP_ENUM_STATE_WAIT_ACK:
            ERROR ("WAIT_ACK: ACK response not received.\n");
            if (retrans_count < coap_max_retransmit) {
                retrans_count++;
                sleep (retrans_count * coap_retransmit_timeout);
                goto send;
            } else {
                ERROR ("WAIT_ACK: Max retransmits %d reached.\n",
                       coap_max_retransmit);
                error = true;
                goto finish;
            }
            break;
        case COAP_ENUM_STATE_WAIT_CON:
            ERROR ("WAIT_CON: CON response not received.\n");
            wait_con++;
            if (wait_con < coap_max_wait_con) {
                /* Wait longer for expected CON */
                goto receive;
            } else {
                error = true;
                goto finish;
            }
        case COAP_ENUM_STATE_WAIT_NON:
            /* No more wait for NON */
            ERROR ("WAIT_NON: NON response not received.\n");
            goto finish;
        default:
            ERROR ("Should not be here.\n");
            goto finish;
        }
    }

    if (msg == NULL) {
        msg = (coap_message *) malloc (sizeof (coap_message));
    }

    if (msg == NULL) {
        ERROR ("client: could not allocate msg.\n");
        error = true;
        goto finish;
    }
    memset (msg, 0, sizeof (coap_message));

    if ( (p = coap_get_msg (inbuf, n, msg)) < 0) {
        ERROR ("could not get msg\n");
        error = true;
        goto finish;
    } else {
        payload_len = p;
    }

    switch (state) {
    case COAP_ENUM_STATE_WAIT_ACK:

        switch (msg->hdr.type) {
        case COAP_ENUM_MSG_TYPE_ACK:
            DBG ("WAIT_ACK: ACK received.\n");
            if (msg->hdr.msg_id != msg_id) {
                ERROR ("WAIT_ACK: Response msg_not matching request.\n");
                ERROR ("WAIT_ACK: Received msg_id is 0X%04X (sent one was 0X%04X).\n",
                       msg->hdr.msg_id, msg_id);
                error = true;
                goto finish;
            }

            if (msg->hdr.code == COAP_RES_CODE_EMPTY) {
                /* Got empty ACK, need to read again for CON */
                ERROR ("WAIT_ACK: ACK is empty (code %d).\n",
                       COAP_RES_CODE_EMPTY);
                state = COAP_ENUM_STATE_WAIT_CON;
                goto receive;
            } else if (msg_token_length != msg->token_length ||
                       memcmp (msg_token, msg->token,
                               msg->token_length) != 0) {
                ERROR
                    ("WAIT_ACK: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_ACK: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            } else {
                DBG ("WAIT_ACK: Expected ACK received.\n");
                if ((gettimeofday (&t_stop, NULL)) == -1) {
                    perror ("gettimeofday");
                    exit (1);
                }

                DBG ("client: RTT is %ld us\n",
                     (t_stop.tv_sec - t_start.tv_sec) * 1000000 +
                     t_stop.tv_usec - t_start.tv_usec);
            }
            break;
        case COAP_ENUM_MSG_TYPE_RST:
            DBG ("WAIT_ACK: RST received.\n");
            if (msg->hdr.msg_id == msg_id) {
                ERROR ("WAIT_ACK: RST received with error code %d: ",
                       msg->hdr.code);
                coap_show_response_code (msg->hdr.code);
            } else {
                ERROR ("WAIT_ACK: Response msg_not matching request.\n");
                ERROR ("WAIT_ACK: Received msg_id is 0X%04X (sent one was 0X%04X).\n",
                       msg->hdr.msg_id, msg_id);
            }
            error = true;
            goto finish;
            break;
        case COAP_ENUM_MSG_TYPE_CON:
            /* Got CON, need to send ACK(res) */
            DBG ("WAIT_ACK: CON received.\n");
            if (msg_token_length != msg->token_length ||
                memcmp (msg_token, msg->token, msg->token_length) != 0) {
                ERROR
                    ("WAIT_ACK: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_ACK: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            } else {
                state = COAP_ENUM_STATE_SEND_ACK;
            }
            break;
        case COAP_ENUM_MSG_TYPE_NON:
            DBG ("WAIT_ACK: NON received.\n");
            if (msg_token_length != msg->token_length ||
                memcmp (msg_token, msg->token, msg->token_length) != 0) {
                ERROR
                    ("WAIT_ACK: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_ACK: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            }
            break;
        default:
            ERROR ("WAIT_ACK: UNKNOWN type received.\n");
            error = true;
            goto finish;
            break;
        }
        break;
    case COAP_ENUM_STATE_WAIT_CON:

        switch (msg->hdr.type) {
        case COAP_ENUM_MSG_TYPE_ACK:
            DBG ("WAIT_CON: ACK received\n");
            if (msg->hdr.msg_id != msg_id) {
                ERROR ("WAIT_CON: Response msg_not matching request.\n");
                ERROR ("WAIT_CON: Received msg_id is 0X%04X (sent one was 0X%04X).\n",
                       msg->hdr.msg_id, msg_id);
                error = true;
                goto finish;
            }

            if (msg->hdr.code == COAP_RES_CODE_EMPTY) {
                /* Got empty ACK, need to read again for CON */
                ERROR ("WAIT_CON: ACK is empty.\n");
                goto receive;
            } else if (msg_token_length != msg->token_length ||
                       memcmp (msg_token, msg->token,
                               msg->token_length) != 0) {
                ERROR
                    ("WAIT_CON: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_CON: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            }
            break;
        case COAP_ENUM_MSG_TYPE_RST:
            if (msg->hdr.msg_id == msg_id) {
                ERROR ("WAIT_CON: RST received with error code %d: ",
                       msg->hdr.code);
                coap_show_response_code (msg->hdr.code);
            } else {
                ERROR ("WAIT_CON: Response msg_not matching request.\n");
                ERROR ("WAIT_CON: Received msg_id is 0X%04X (sent one was 0X%04X).\n",
                       msg->hdr.msg_id, msg_id);
            }
            error = true;
            goto finish;
            break;
        case COAP_ENUM_MSG_TYPE_CON:
            /* Got CON, need to send ACK(res) */
            if (msg_token_length != msg->token_length ||
                memcmp (msg_token, msg->token, msg->token_length) != 0) {
                ERROR
                    ("WAIT_CON: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_CON: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            } else {
                DBG ("WAIT_CON: Expected CON received.\n");
                state = COAP_ENUM_STATE_SEND_ACK;
                if ((gettimeofday (&t_stop, NULL)) == -1) {
                    perror ("gettimeofday");
                    exit (1);
                }

                DBG ("client: RTT is %ld us\n",
                     (t_stop.tv_sec - t_start.tv_sec) * 1000000 +
                     t_stop.tv_usec - t_start.tv_usec);
            }
            break;
        case COAP_ENUM_MSG_TYPE_NON:
            DBG ("WAIT_CON: NON received.\n");
            if (msg_token_length != msg->token_length ||
                memcmp (msg_token, msg->token, msg->token_length) != 0) {
                ERROR
                    ("WAIT_NON: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_NON: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            }
            break;
        default:
            ERROR ("WAIT_CON: UNKNOWN type received.\n");
            error = true;
            goto finish;
            break;
        }
        break;
    case COAP_ENUM_STATE_WAIT_NON:
        switch (msg->hdr.type) {
        case COAP_ENUM_MSG_TYPE_ACK:
            DBG ("WAIT_NON: ACK received\n");
            if (msg->hdr.msg_id != msg_id) {
                ERROR ("WAIT_NON: Response msg_not matching request.\n");
                ERROR ("WAIT_NON: Received msg_id is 0X%04X (sent one was 0X%04X).\n",
                       msg->hdr.msg_id, msg_id);
                error = true;
                goto finish;
            }

            if (msg->hdr.code == COAP_RES_CODE_EMPTY) {
                /* Got empty ACK, don't read again for NON */
                ERROR ("WAIT_NON: ACK is empty.\n");
                error = true;
                goto finish;
            } else if (msg_token_length != msg->token_length ||
                       memcmp (msg_token, msg->token,
                               msg->token_length) != 0) {
                ERROR
                    ("WAIT_NON: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_NON: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            }
            break;
        case COAP_ENUM_MSG_TYPE_RST:
            ERROR ("WAIT_NON: RST received with error code %d: ",
                   msg->hdr.code);
            if (msg->hdr.msg_id == msg_id) {
                ERROR ("WAIT_NON: RST received with error code %d: ",
                       msg->hdr.code);
                coap_show_response_code (msg->hdr.code);
            } else {
                ERROR ("WAIT_NON: Response msg_not matching request.\n");
                ERROR ("WAIT_NON: Received msg_id is 0X%04X (sent one was 0X%04X).\n",
                       msg->hdr.msg_id, msg_id);
            }
            error = true;
            goto finish;
            break;
        case COAP_ENUM_MSG_TYPE_CON:
            /* Got CON, need to send ACK(res) */
            DBG ("WAIT_NON: CON received.\n");
            if (msg_token_length != msg->token_length ||
                memcmp (msg_token, msg->token, msg->token_length) != 0) {
                ERROR
                    ("WAIT_NON: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_NON: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            } else {
                state = COAP_ENUM_STATE_SEND_ACK;
            }
            break;
        case COAP_ENUM_MSG_TYPE_NON:
            DBG ("WAIT_NON: NON received.\n");
            if (msg_token_length != msg->token_length ||
                memcmp (msg_token, msg->token, msg->token_length) != 0) {
                ERROR
                    ("WAIT_NON: Response msg_token not matching request.\n");
                char *tx_token =
                    byte_array_to_hex_string (msg_token, msg_token_length);
                char *rx_token =
                    byte_array_to_hex_string (msg->token, msg->token_length);
                ERROR
                    ("WAIT_NON: Received token is %s (length %dB.), sent one was %s (length %dB.).\n",
                     rx_token, msg->token_length, tx_token, msg_token_length);
                free (tx_token);
                free (rx_token);
                error = true;
                goto finish;
            } else {
                DBG ("WAIT_NON: Expected NON received.\n");
                if ((gettimeofday (&t_stop, NULL)) == -1) {
                    perror ("gettimeofday");
                    exit (1);
                }

                DBG ("client: RTT is %ld us\n",
                     (t_stop.tv_sec - t_start.tv_sec) * 1000000 +
                     t_stop.tv_usec - t_start.tv_usec);
            }
            break;
        default:
            ERROR ("WAIT_NON: UNKNOWN type received.\n");
            error = true;
            goto finish;
            break;
        }
        break;
    default:
        ERROR ("UNKNOWN STATE: Should not be here.\n");
        error = true;
        goto finish;
    }

process_response:

    /* Call the user-specific code that the user registered
     * for this task.
     */
    if (coap_user_code[task_user] != NULL) {
        if (coap_user_code[task_user] 
                (connfd, outbuf, inbuf, msg, state) < 0) {
            goto finish;
        }
        goto send_ack;
    } else {
        DBG("No user-specific code defined, cannot process reply\n");
        goto finish;
    }

send_ack:
   if (state == COAP_ENUM_STATE_SEND_ACK) {
        /* Need to send ACK(empty) */
        uint16_t buf_len;
        uint16_t msg_id = msg->hdr.msg_id;
        memcpy (msg_token, msg->token, msg->token_length);
        uint8_t msg_token_length = msg->token_length;
        //int m, retrans_count = 0;

        coap_message *out_msg;

        if (msg_token_length != 0) {
            out_msg = coap_create_msg (1, 0);
        } else {
            out_msg = coap_create_msg (0, 0);
        }

        if (out_msg != NULL) {
            out_msg->hdr.ver = 1;
            out_msg->hdr.type = COAP_ENUM_MSG_TYPE_ACK;
            out_msg->hdr.code = COAP_RES_CODE_EMPTY;
            out_msg->hdr.msg_id = msg_id;
            DBG ("Creating message with msg_id = 0X%04X\n",
                 out_msg->hdr.msg_id);

            /*
            if(msg_token_length != 0) {
                coap_add_option(out_msg->option_list, 0,
                                COAP_ENUM_OPTION_ID_TOKEN,
                                msg_token_length, msg_token);
                out_msg->hdr.oc = 1;
            } else {
                out_msg->hdr.oc = 0;
            }
            */

            out_msg->hdr.oc = 0;
            out_msg->payload = NULL;
            out_msg->payload_len = 0;

            buf_len = coap_set_msg (outbuf, out_msg);
            coap_clean_msg (out_msg);

//resend_ack:
            n = write (connfd, outbuf, buf_len);

            if (n < 0) {
                ERROR ("client error: could not write msg\n");
                return -1;
            }

            DBG ("Send ACK.\n");
            /* Still need to call coap_get_msg in case ACK is not received 
             * by the server and server retransmits CON
             *
             * RK Note: this is a bad idea: this lowers greatly the performance 
             * as the client blocks some time on the 'read'
            */
            /*
            memset (inbuf, 0, coap_send_receive_buffer_size);
            m = read (connfd, inbuf, coap_send_receive_buffer_size);

            if (m > 0) {
                coap_message *in_msg =
                    (coap_message *) malloc (sizeof (coap_message));

                if (in_msg == NULL) {
                    ERROR ("user_default: could not allocate msg.\n");
                }

                memset (in_msg, 0, sizeof (coap_message));

                if ((p = coap_get_msg (inbuf, m, in_msg)) < 0) {
                    ERROR ("Get msg failed.\n");
                    coap_clean_msg (in_msg);
                    return -1;
                } else {
                    payload_len = p;
                }

                if (in_msg->token_length != msg_token_length ||
                    memcmp (in_msg->token, msg_token,
                            msg_token_length) != 0) {
                    ERROR ("Response token not matching request.\n");
                    // Just ignore
                } else {
                    if (retrans_count < coap_max_retransmit) {
                        coap_clean_msg (in_msg);
                        retrans_count++;
                        goto resend_ack;
                    } else {
                        ERROR ("Max retransmits %d reached.\n",
                               coap_max_retransmit);
                    }
                }
                coap_clean_msg (in_msg);
            }
            */
        }
    }

finish:
    coap_clean_msg (msg);

    if (socket_is_per_task && connfd > 0) {
        close (connfd);
    }

    if (error) {
        return -1;
    } else {
        return 0;
    }
}

/**
 * This is the task thread (from a pool) for client.
 * It has its own in/out buffer to be used to handle
 * all tasks (picked from a task queue) the thread will handle.
 * It has its own socket if the server is a proxy and will be shared by
 * all tasks, otherwise, socket will be created per task.
 * @param task is the first task (passed by main thread) to be handled by this thread,
 * after that, this thread will pick next available task from the task queue and
 * handle it, and repeat indefinitely.
 * @return pointer to void
 */
void *
coap_client_task_handler (void *task)
{
    //pthread_detach(pthread_self());
    uint8_t *outbuf = (uint8_t *) malloc (coap_send_receive_buffer_size);
    uint8_t *inbuf = (uint8_t *) malloc (coap_send_receive_buffer_size);
    int connfd = -1;

    if (outbuf == NULL || inbuf == NULL) {
        ERROR ("Task handler allocate buffer failed.\n");
        goto cleanup;
    }

    coap_task *my_task = (coap_task *) task;

    if (coap_server_is_proxy) {
        connfd = coap_open_client_socket (my_task->server_name,
                                          my_task->server_service, AF_UNSPEC,
                                          SOCK_DGRAM);

        if (connfd < 0) {
            ERROR ("could not create connected socket\n");
            goto cleanup;
        }

        if (set_socket_timer (connfd) < 0) {
            ERROR ("could not set socket timer\n");
            goto cleanup;
        }
    }

    if (coap_client_handle_task (outbuf, inbuf, task, connfd) == -1) {
        ERROR ("Could not handle task\n");
        //goto cleanup;
    }

    while (1) {
        task_lock ();
        if (thread_pool_parms.next_item != end) {
            task = (coap_task *) (thread_pool_parms.next_item->data);
            coap_node *temp = thread_pool_parms.next_item;
            if (start != temp) {
                ERROR ("Task start failed\n");
                exit (1);
            }
            thread_pool_parms.next_item = thread_pool_parms.next_item->next;
            coap_delete_node (temp);
            task_unlock ();
            if (coap_client_handle_task (outbuf, inbuf, task, connfd) == -1) {
                ERROR ("Could not handle task\n");
                //break;
            }
        } else {
            task_unlock ();
            DBG ("No more tasks.\n");
            break;
        }
    }

cleanup:
    if (outbuf != NULL) {
        free (outbuf);
    }
    if (inbuf != NULL) {
        free (inbuf);
    }
    if (coap_server_is_proxy && connfd > 0) {
        close (connfd);
    }

    DBG ("thread 0x%x exits now.\n", (unsigned int) pthread_self ());
    pthread_exit (NULL);

    return NULL;
}

/**
 * Main loop function for the CoAP client.
 * @param tasks is the number of tasks
 * @param get_task is a callback function that retrieves the task to perform
 * @param data is the data given as argument to the get_task function
 * @return 0 on success, -1 on failure
 */
int
coap_client_run(int tasks, coap_task *get_task(void *d), void *data)
{
    int i;
    coap_task *task;

    if (get_task == NULL) {
        ERROR("Cannot get task (NULL function)\n");
        return -1;
    }

    if (tasks >= coap_init_client_task_threads) {
        /* Each thread will be launched with a task so we decrease 
         * the number of tasks by the number of threads
         */
        tasks -= coap_init_client_task_threads;
    } else {
        coap_init_client_task_threads = tasks;
        tasks = 0;
    }

    for (i = 0; i < tasks; i++) {
        task = get_task (data);
        coap_insert_node (task);
    }

    pthread_t task_thread_id[coap_init_client_task_threads];
    pthread_t acting_task_thread_id[coap_init_client_task_threads];

    task_lock ();
    for (i = 0; i < coap_init_client_task_threads; i++) {
        task = get_task (data);
        if (pthread_create (&task_thread_id[i], NULL, 
                            coap_client_task_handler, task) != 0) {
            ERROR ("Error creating task_thread %d\n", i);
        } else {
            DBG ("Created task_thread %d with task_thread_id 0x%x\n",
                  i, (unsigned int) task_thread_id[i]);
            acting_task_thread_id[thread_pool_parms.total_threads++] 
                = task_thread_id[i];
        }
    }
    task_unlock ();

    for (i = 0; i < thread_pool_parms.total_threads; i++) {
        pthread_join (acting_task_thread_id[i], NULL);
    }

    return 0;
}

/**
 * Cleanup the client mutex
 * @return void
 */
void 
coap_client_cleanup(void) 
{
    pthread_mutex_destroy (&task_mutex);
    pthread_mutex_destroy (&dump_mutex);
}

void
task_lock ()
{
    assert (pthread_mutex_lock (&task_mutex) == 0);
}

void
task_unlock ()
{
    assert (pthread_mutex_unlock (&task_mutex) == 0);
}
