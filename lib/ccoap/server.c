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
 * server.c
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <assert.h>

#include "ccoaplib.h"

//extern char* coap_server_name;
//extern uint16_t coap_port;
extern uint8_t coap_max_retransmit;
extern uint8_t coap_retransmit_timeout;
//extern uint8_t coap_max_wait_con;
extern uint8_t coap_session_timeout;
extern uint8_t coap_session_cleanup_time;
//extern uint8_t coap_max_option_count;
extern uint8_t coap_init_server_session_threads;
//extern uint8_t coap_init_client_task_threads;
extern uint16_t coap_send_receive_buffer_size;
//extern uint8_t coap_max_option_list_size;
extern uint8_t coap_server_listen_queue;
extern bool coap_separate_mode;
//extern bool coap_server_is_proxy;

extern pthread_mutex_t dump_mutex;
extern coap_node *start, *end;
extern coap_req_handle coap_req_handlers[];
extern coap_locked_data thread_pool_parms;

/* Used to identify the application specific code
 * (demos and real apps), in each real app, there should be
 * sub types based on the user request like uri_path, the sub type
 * will invoke the right handle via register.
 */
coap_req_type req_type = COAP_ENUM_REQ_DEFAULT;

pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t session_cond = PTHREAD_COND_INITIALIZER;

void
session_lock ()
{
    assert (pthread_mutex_lock (&session_mutex) == 0);
}

void
session_unlock ()
{
    assert (pthread_mutex_unlock (&session_mutex) == 0);
}

/**
 * Open new coap session.
 * @param buf_size is the size of the inbuf and outbuf for read and write
 * @return a pointer to the newly created session
 */
coap_session *
coap_session_open (int buf_size)
{
    uint8_t *inbuf = (uint8_t *) malloc (buf_size);
    if (inbuf == NULL) {
        ERROR ("Not enough memory, exit now!\n");
        exit (1);
    }

    uint8_t *outbuf = (uint8_t *) malloc (buf_size);
    if (outbuf == NULL) {
        ERROR ("Not enough memory, exit now!\n");
        free (inbuf);
        exit (1);
    }

    coap_session *p = (coap_session *) malloc (sizeof (coap_session));
    if (p == NULL) {
        ERROR ("Not enough memory, exit now!\n");
        free (inbuf);
        free (outbuf);
        exit (1);
    }

    p->inbuf = inbuf;
    p->outbuf = outbuf;

    p->msg_id = 0;
    p->msg_token_length = 0;

    /*
    if(coap_seperate_mode) {
        p->acked = true;
    } else {
        p->acked = false;
    }
    */

    p->retrans = false;
    p->retrans_count = 0;
    p->state = COAP_ENUM_STATE_WAIT_REQ;

    return p;
}

/**
 * Close coap session.
 * @param session is a pointer to the session
 */
void
coap_session_close (coap_session * session)
{
    if (session != NULL) {
        free (session->inbuf);
        free (session->outbuf);
        free (session);
    }
}

/**
 * Attach received coap msg/pdu in inbuf to a session
 * @param session is a pointer to the session
 * @param inbuf is the buffer containing received coap msg from the socket
 * @param size is the size of the coap msg/pdu in the buffer
 */
void
coap_attach_inbuf (coap_session * session, uint8_t * inbuf, int size)
{
    memset (session->inbuf, 0, coap_send_receive_buffer_size);
    memcpy (session->inbuf, inbuf, size);
    session->inbuf_len = size;
}

/**
 * Read configuration file by the server.
 * @param file_name is the server config file name
 */
void
coap_server_config (char *file_name)
{
    coap_config (file_name);
}

/**
 * Initialization by the server,
 * session queue, initial random msg_id/token (seed), thread pool, etc.
 * @return -1 for error, or 0 for success
 */
int
coap_server_init ()
{
    coap_init_list ();
    set_seed ();
    thread_pool_parms.total_threads = 0;
    thread_pool_parms.active_threads = 0;
    thread_pool_parms.next_item = end;
    return 0;
}

/**
 * Get server address/port from address/port names. Bind the address/port.
 * IPv4/IPv6 independent. Connectionless socket.
 * @param hostname is the host name of the server
 * @param service is the service name of the service
 * @param family is the protocol family
 * @param socktype is the socket type
 * @return -1 for error, or binded socket for the server
 */
int
coap_open_server_socket (const char *hostname,
                         const char *servicename, int family, int socktype)
{
    struct addrinfo hints, *res, *ressave;
    int n, sockfd;
    char service[11];
    //unsigned short port = ntohs(coap_resolve_service(servicename, "udp"));
    unsigned short port = coap_port;
    coap_itoa (port, service);

    memset (&hints, 0, sizeof (struct addrinfo));

    /* AI_PASSIVE flag: we use the resulting address to bind
     * to a socket for accepting incoming connections.
     * So, when the hostname==NULL, getaddrinfo function will
     * return one entry per allowed protocol family containing
     * the unspecified address for that family.
     */
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
    hints.ai_family = family;
    hints.ai_socktype = socktype;

    /* For AI_PASSIVE, hostname must be NULL */
    hostname = NULL;

    n = getaddrinfo (hostname, service, &hints, &res);

    if (n < 0) {
        ERROR ("getaddrinfo error [%s]\n", gai_strerror (n));
        return -1;
    }

    ressave = res;

    /* Try open socket with each address getaddrinfo returned,
     * until we get a valid listening socket.
     */
    sockfd = -1;
    while (res) {
        sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);

        if (!(sockfd < 0)) {
            if (bind (sockfd, res->ai_addr, res->ai_addrlen) == 0)
                break;

            close (sockfd);
            sockfd = -1;
        }
        res = res->ai_next;
    }

    if (sockfd < 0) {
        freeaddrinfo (ressave);
        ERROR ("socket error: could not open socket\n");
        return -1;
    }

    listen (sockfd, coap_server_listen_queue);
    freeaddrinfo (ressave);

    return sockfd;
}

/**
 * Used by coap server to find a matching session (and move it to the end)
 * or create one (and put it to the queue), attach a coap msg/pdu to the session
 * @param client_name is the host name of the client
 * @param client_port is the port of the client
 * @param inbuf is the buffer containing received coap msg from the socket
 * @param size is the size of the coap msg/pdu in the buffer
 * @return -1 for error, or 0 for success
 */
int
coap_dispatch_request (int listenfd, struct sockaddr_storage client_addr,
                       socklen_t client_addr_len, char *client_name,
                       char *client_port, uint8_t * inbuf, uint16_t size)
{
    coap_node *p = NULL;
    coap_msg_type msg_type;
    coap_session *session;

    if (size < COAP_MIN_MSG_SIZE) {
        ERROR ("msg size less than %d bytes\n", COAP_MIN_MSG_SIZE);
        return -1;
    }

    msg_type =
        (coap_msg_type) ((*((uint8_t *) inbuf) & COAP_HDR_TYPE_MASK) >> 4);

    session_lock ();

    p = coap_search_session_node (client_name, client_port);

    if (p != NULL) {
        time (&(((coap_session *) (p->data))->last_active_time));
        coap_attach_inbuf ((coap_session *) (p->data), inbuf, size);
        coap_transfer_node_to_end (p);
        pthread_cond_signal (&session_cond);
    } else if (msg_type != COAP_ENUM_MSG_TYPE_ACK) {
        session = coap_session_open (coap_send_receive_buffer_size);
        strcpy (session->client_name, client_name);
        strcpy (session->client_port, client_port);
        session->client_addr = client_addr;
        session->client_addr_len = client_addr_len;
        session->listenfd = listenfd;
        //session->last_active_time = get_current_time();

        time (&(session->last_active_time));
        coap_attach_inbuf (session, inbuf, size);
        p = coap_insert_node (session);
        session->this_node = p;
        pthread_cond_signal (&session_cond);
    } else {
        /* If ACK and no session matches, silently drop the msg */
        ;
    }

    session_unlock ();

    return 0;
}

/**
 * Called by server main thread to receive requests from network/clients and
 * either find a matching session and transfer it to the end of session queue or
 * create a new session and put it to the end of the session queue. The dispatcher has
 * inbuf for receiving request/response from clients. May have outbuf if
 * in case of in the seperate_mode. The session coantains both inbuf, outbuf as well as
 * socket for communication with the specific client that the session is associated with.
 * @param my_host_name is the server's name.
 * @return pointer to void
 */
void *
coap_server_request_dispatcher (void *my_host_name)
{
    uint16_t payload_len;
    uint16_t buf_len;

    int listenfd, n, m, p;
    socklen_t client_addr_len;
    struct sockaddr_storage client_addr;
    char client_name[NI_MAXHOST];
    char client_port[NI_MAXSERV];

    uint8_t *outbuf = NULL;
    uint8_t *inbuf = (uint8_t *) malloc (coap_send_receive_buffer_size);
    if (inbuf == NULL) {
        ERROR ("server: Allocate inbuf failed.\n");
        goto cleanup;
    }

    if (coap_separate_mode) {
        outbuf = (uint8_t *) malloc (coap_send_receive_buffer_size);
        if (outbuf == NULL) {
            ERROR ("server: Allocate outbuf failed.\n");
            goto cleanup;
        }
    }

    listenfd =
        coap_open_server_socket (my_host_name, "coap", AF_UNSPEC, SOCK_DGRAM);

    if (listenfd < 0) {
        ERROR ("server error: Could not create listening socket\n");
        goto cleanup;
    }

    if (set_socket_timer (listenfd) < 0) {
        ERROR ("server error: could not set socket timer\n");
        goto cleanup;
    }

    client_addr_len = sizeof (client_addr);

    while (1) {
        memset (inbuf, 0, coap_send_receive_buffer_size);
        n = recvfrom (listenfd,
                      inbuf,
                      coap_send_receive_buffer_size,
                      0, (struct sockaddr *) &client_addr, &client_addr_len);

        if (n < 0) {
            //DBG("server: receive timeout\n");

            session_lock ();
            coap_clean_session_list ();
            session_unlock ();

            continue;
        }

        if (coap_separate_mode) {
            /* If CON, need to send ACK(empty) first */
            coap_msg_type msg_type = (coap_msg_type) ((*((uint8_t *) inbuf) &
                                                       COAP_HDR_TYPE_MASK) >>
                                                      4);
            if (msg_type == COAP_ENUM_MSG_TYPE_CON) {
                /* Need to send ACK(empty) */
                coap_message *in_msg =
                    (coap_message *) malloc (sizeof (coap_message));

                if (in_msg == NULL) {
                    ERROR ("server: Could not allocate msg.\n");
                    goto cleanup;
                }
                memset (in_msg, 0, sizeof (coap_message));

                if ((p = coap_get_msg (inbuf, n, in_msg)) < 0) {
                    ERROR ("server error: Could not get msg\n");
                    coap_clean_msg (in_msg);
                    continue;
                } else {
                    payload_len = p;
                }

                uint16_t msg_id = in_msg->hdr.msg_id;
                coap_clean_msg (in_msg);

                coap_message *out_msg = coap_create_msg (0, 0);
                if (out_msg == NULL) {
                    ERROR ("dispatcher: Can not create msg.\n");
                    goto cleanup;
                } else {
                    out_msg->hdr.ver = 1;
                    out_msg->hdr.type = COAP_ENUM_MSG_TYPE_ACK;
                    out_msg->hdr.code = COAP_RES_CODE_EMPTY;
                    out_msg->hdr.msg_id = msg_id;
                    out_msg->option_list = NULL;
                    out_msg->hdr.oc = 0;

                    out_msg->payload = NULL;
                    out_msg->payload_len = 0;

                    buf_len = coap_set_msg (outbuf, out_msg);
                    coap_clean_msg (out_msg);

//send:

                    /* Replace flag 0 by MSG_DONTWAIT? */
                    m = sendto (listenfd, outbuf, buf_len, 0 /* flags */,
                                (struct sockaddr *) &client_addr,
                                client_addr_len);

                    if (m < 0) {
                        ERROR ("server error: could not send msg\n");
                        continue;
                    } else {
                        DBG ("server: send ACK(empty).\n");
                    }
                }
            }
        }

        memset (client_name, 0, sizeof (client_name));
        memset (client_port, 0, sizeof (client_port));

        getnameinfo ((struct sockaddr *) &client_addr, client_addr_len,
                     client_name, sizeof (client_name),
                     client_port, sizeof (client_port), NI_NUMERICHOST);

        DBG ("server: Received request from host = [%s], port = [%s].\n",
             client_name, client_port);

        if (coap_dispatch_request (listenfd, client_addr, client_addr_len,
                                   client_name, client_port, inbuf, n) < 0) {
            ERROR ("server: Dispatch request failed.\n");
            //goto cleanup;
        }
    }

cleanup:

    if (outbuf != NULL) {
        free (outbuf);
    }
    if (inbuf != NULL) {
        free (inbuf);
    }

    pthread_exit (NULL);

    return NULL;
}

/**
 * Send response in the form ACK(res) or CON(res) for the session passed to it
 * by the session handler thread.
 * It will invoke user applications (via register) based on the requests.
 * @param my_session is a session pointer to the session to be handled, the session
 * has inbuf, outbuf, state and client sockaddr in it.
 * @return -1 for error, or 0 for success
 */
void
coap_server_handle_session (coap_session ** my_session)
{
    int n, i, p;
    uint8_t oc = 0;
    bool separate = false;
    coap_session *session = *my_session;
    uint16_t payload_len;
    char *payload = NULL;
    //bool error = false;
    coap_message *msg = (coap_message *) malloc (sizeof (coap_message));
    coap_message *out_msg;

    if (msg == NULL) {
        ERROR ("client: could not allocate msg.\n");
        exit (1);
        /*
        error = true;
        session->state = COAP_ENUM_STATE_RST;
        goto process_request;
        */
    }

    memset (msg, 0, sizeof (coap_message));
    if ( (p = coap_get_msg (session->inbuf, session->inbuf_len, msg)) < 0) {
        ERROR ("server error: could not get msg\n");
        //error = true;
        session->state = COAP_ENUM_STATE_RST;
        goto process_request;
    } else {
        payload_len = p;
    }

    switch (session->state) {
    case COAP_ENUM_STATE_WAIT_ACK:
        /* Retransmission only set by dispatcher, reset to false after each
         * retrans. Must send CON, not ACK(res), because in piggy mode, we 
         * do not keep sessions. So this is only in separate mode.
         */
        if (session->retrans) {
            session->state = COAP_ENUM_STATE_SEND_CON;
            break;
        }

        if (msg->hdr.msg_id != session->msg_id) {
            ERROR ("WAIT_ACK: Error, response Message ID (0X%04X) "
                   "not matching request (0X%04X).\n",
                   msg->hdr.msg_id, session->msg_id);
            // TODO: Should resend CON ?
            break;
        }

        switch (msg->hdr.type) {
        case COAP_ENUM_MSG_TYPE_ACK:
            DBG ("WAIT_ACK: Expected ACK received.\n");
            session->state = COAP_ENUM_STATE_DONE;
            break;
        case COAP_ENUM_MSG_TYPE_RST:
            ERROR ("WAIT_ACK: RST received with error code %d: ",
                   msg->hdr.code);
            coap_show_response_code (msg->hdr.code);
            session->state = COAP_ENUM_STATE_RST;
            break;
        case COAP_ENUM_MSG_TYPE_CON:   
            /* Got CON */
            DBG ("WAIT_ACK: CON received.\n");
            if (session->msg_id != msg->hdr.msg_id ||
                session->msg_token_length != msg->token_length ||
                memcmp (session->msg_token, msg->token,
                        msg->token_length) != 0) {
                /* This is not retransmission, but from the same client
                 * implies implicitely acked by client 
                 */
                session->msg_id = msg->hdr.msg_id;
                memcpy (session->msg_token, msg->token, msg->token_length);
                session->msg_token_length = msg->token_length;
                session->retrans_count = 0;
                //session->acked = false;
                session->retrans = false;
            } else {
                /* This is retransmission, need to send CON */
                session->retrans_count++;
                if (session->retrans_count > coap_max_retransmit) {
                    /* No more retransmissions */
                    session->state = COAP_ENUM_STATE_DONE;
                    session->retrans = false;
                } else {
                    session->retrans = true;
                }
            }

            if (session->state != COAP_ENUM_STATE_DONE) {
                if (coap_separate_mode) {
                    /* ACK(empty) already sent, need to send CON and wait ACK(res) */
                    session->state = COAP_ENUM_STATE_SEND_CON;
                } else {
                    /* Need to send ACK(res) */
                    session->state = COAP_ENUM_STATE_SEND_ACK;
                }
            }
            break;
        case COAP_ENUM_MSG_TYPE_NON:
            session->msg_id = msg->hdr.msg_id;
            memcpy (session->msg_token, msg->token, msg->token_length);
            session->msg_token_length = msg->token_length;
            DBG ("WAIT_ACK: NON received.\n");
            session->state = COAP_ENUM_STATE_SEND_NON;
            break;
        default:
            ERROR ("WAIT_ACK: UNKNOWN type received.\n");
            session->state = COAP_ENUM_STATE_DONE;
            break;
        }
        break;
    case COAP_ENUM_STATE_WAIT_REQ:
        switch (msg->hdr.type) {
        case COAP_ENUM_MSG_TYPE_ACK:
            DBG ("WAIT_REQ: ACK received\n");
            session->state = COAP_ENUM_STATE_DONE;
            break;
        case COAP_ENUM_MSG_TYPE_RST:
            ERROR ("WAIT_REQ: RST received with error code %d: ",
                   msg->hdr.code);
            session->state = COAP_ENUM_STATE_RST;
            break;
        case COAP_ENUM_MSG_TYPE_CON:
            /* Got CON */
            session->msg_id = msg->hdr.msg_id;
            memcpy (session->msg_token, msg->token, msg->token_length);
            session->msg_token_length = msg->token_length;
            DBG ("WAIT_REQ: CON received.\n");
            if (coap_separate_mode) {
                /* ACK(empty) already sent, need to send CON and wait ACK(res) */
                session->state = COAP_ENUM_STATE_SEND_CON;
            } else {
                /* Need to send ACK(res) */
                session->state = COAP_ENUM_STATE_SEND_ACK;
            }
            break;
        case COAP_ENUM_MSG_TYPE_NON:
            session->msg_id = msg->hdr.msg_id;
            memcpy (session->msg_token, msg->token, msg->token_length);
            session->msg_token_length = msg->token_length;
            DBG ("WAIT_REQ: NON received.\n");
            session->state = COAP_ENUM_STATE_SEND_NON;
            break;
        default:
            ERROR ("UNKNOWN: UNKNOWN type received.\n");
            session->state = COAP_ENUM_STATE_DONE;
            break;
        }
        break;
    default:
        ERROR ("UNKNOWN: Should not be here.\n");
        session->state = COAP_ENUM_STATE_DONE;
        break;
    }

process_request:

    /* Call the user-specific code that the user registered
     * for this session.
     */

    /* req_type should be per server (means this server)
     * sub type should be based on uri and be handled by the 
     * registered handlers
     */
    if (coap_req_handlers[req_type] != NULL) {
        if (coap_req_handlers[req_type] 
                (session, msg, &payload, &payload_len) < 0) {
            ERROR("error handling the client message\n");
            goto finish;
        }
        goto reply_request;
    } else {
        DBG("No user-specific code defined, cannot process request\n");
        goto finish;
    }

reply_request:
 
    /* Looking for 'separate' option */
    for (i = 0; i < msg->hdr.oc; i++) {
        if (msg->option_list[i].number == COAP_ENUM_OPTION_ID_URI_PATH) {
            if (!strncmp
                ((char *) msg->option_list[i].data, "separate",
                 msg->option_list[i].length)) {
                separate = true;
            }
            break;
        }
    }

    if (separate && session->state == COAP_ENUM_STATE_SEND_ACK) {
        /* Need to send ACK(empty) */
        coap_message *out_msg = coap_create_msg (0, 0);
        if (out_msg == NULL) {
            ERROR ("Can not create msg.\n");
        } else {
            out_msg->hdr.ver = 1;
            out_msg->hdr.type = COAP_ENUM_MSG_TYPE_ACK;
            out_msg->hdr.code = COAP_RES_CODE_EMPTY;
            out_msg->hdr.msg_id = msg->hdr.msg_id;
            out_msg->option_list = NULL;
            out_msg->hdr.oc = 0;

            out_msg->payload = NULL;
            out_msg->payload_len = 0;

            session->outbuf_len = coap_set_msg (session->outbuf, out_msg);
            coap_clean_msg (out_msg);

            n = sendto (session->listenfd, session->outbuf,
                        session->outbuf_len, 0,
                        (struct sockaddr *) &(session->client_addr),
                        session->client_addr_len);

            if (n < 0) {
                ERROR ("Could not send msg\n");
            } else {
                DBG ("Send ACK(empty).\n");
                session->state = COAP_ENUM_STATE_SEND_CON;
            }
        }
    }

    if (session->retrans) {
        session->retrans = false;
        session->retrans_count++;

        n = sendto (session->listenfd, session->outbuf, session->outbuf_len,
                    0, (struct sockaddr *) &(session->client_addr),
                    session->client_addr_len);

        if (n < 0) {
            ERROR ("Could not send msg\n");
            session->state = COAP_ENUM_STATE_DONE;
        } else if (session->retrans_count > coap_max_retransmit) {
            session->state = COAP_ENUM_STATE_DONE;
        } else {
            session->state = COAP_ENUM_STATE_WAIT_ACK;
        }
        goto clean_session;
    }

    if (session->state == COAP_ENUM_STATE_SEND_ACK ||
        session->state == COAP_ENUM_STATE_SEND_CON ||
        session->state == COAP_ENUM_STATE_SEND_NON ||
        session->state == COAP_ENUM_STATE_SEND_RST) {

        if (session->state == COAP_ENUM_STATE_SEND_RST) {
            oc = 0;
            payload_len = 0;
            payload = NULL;
        } else {
            if (session->msg_token_length != 0) {
                oc++;
            }
            if (msg->hdr.code == COAP_REQ_CODE_GET) {
                oc++;
            }
        }

        out_msg = coap_create_msg (oc, payload_len);

        if (out_msg == NULL) {
            ERROR ("Can not create msg.\n");
            session->state = COAP_ENUM_STATE_DONE;
        } else {
            out_msg->hdr.ver = 1;

            switch (session->state) {
            case COAP_ENUM_STATE_SEND_ACK:
                out_msg->hdr.type = COAP_ENUM_MSG_TYPE_ACK;
                if (msg->hdr.code == COAP_REQ_CODE_GET) {
                    out_msg->hdr.code = COAP_RES_CODE_CONTENT;
                } else if (msg->hdr.code == COAP_REQ_CODE_POST) {
                    out_msg->hdr.code = COAP_RES_CODE_CREATED;
                } else if (msg->hdr.code == COAP_REQ_CODE_PUT) {
                    out_msg->hdr.code = COAP_RES_CODE_CHANGED;
                } else if (msg->hdr.code == COAP_REQ_CODE_DELETE) {
                    out_msg->hdr.code = COAP_RES_CODE_DELETED;
                } else {
                    out_msg->hdr.code = COAP_RES_CODE_METHOD_NOT_ALLOWED;
                }
                out_msg->hdr.msg_id = session->msg_id;
                session->state = COAP_ENUM_STATE_DONE;
                break;
            case COAP_ENUM_STATE_SEND_CON:
                out_msg->hdr.type = COAP_ENUM_MSG_TYPE_CON;
                if (msg->hdr.code == COAP_REQ_CODE_GET) {
                    out_msg->hdr.code = COAP_RES_CODE_CONTENT;
                } else if (msg->hdr.code == COAP_REQ_CODE_POST) {
                    out_msg->hdr.code = COAP_RES_CODE_CREATED;
                } else if (msg->hdr.code == COAP_REQ_CODE_PUT) {
                    out_msg->hdr.code = COAP_RES_CODE_CHANGED;
                } else if (msg->hdr.code == COAP_REQ_CODE_DELETE) {
                    out_msg->hdr.code = COAP_RES_CODE_DELETED;
                } else {
                    out_msg->hdr.code = COAP_RES_CODE_METHOD_NOT_ALLOWED;
                }
                out_msg->hdr.msg_id = get_random ();
                DBG ("Creating CON message with msg_id = 0X%04X\n", out_msg->hdr.msg_id);            

                /* Update the session information */
                session->msg_id = out_msg->hdr.msg_id;
                session->state = COAP_ENUM_STATE_WAIT_ACK;
                time (&(session->last_active_time));
                break;
            case COAP_ENUM_STATE_SEND_NON:
                out_msg->hdr.type = COAP_ENUM_MSG_TYPE_NON;
                if (msg->hdr.code == COAP_REQ_CODE_GET) {
                    out_msg->hdr.code = COAP_RES_CODE_CONTENT;
                } else if (msg->hdr.code == COAP_REQ_CODE_POST) {
                    out_msg->hdr.code = COAP_RES_CODE_CREATED;
                } else if (msg->hdr.code == COAP_REQ_CODE_PUT) {
                    out_msg->hdr.code = COAP_RES_CODE_CHANGED;
                } else if (msg->hdr.code == COAP_REQ_CODE_DELETE) {
                    out_msg->hdr.code = COAP_RES_CODE_DELETED;
                } else {
                    out_msg->hdr.code = COAP_RES_CODE_METHOD_NOT_ALLOWED;
                }
                out_msg->hdr.msg_id = get_random ();    /* or same ? */
                session->state = COAP_ENUM_STATE_DONE;
                break;
            case COAP_ENUM_STATE_SEND_RST:
                out_msg->hdr.type = COAP_ENUM_MSG_TYPE_RST;
                out_msg->hdr.code = COAP_RES_CODE_NOT_IMPLEMENTED;
                out_msg->hdr.msg_id = session->msg_id;
                session->state = COAP_ENUM_STATE_DONE;
                break;
            default:
                session->state = COAP_ENUM_STATE_DONE;
                break;
            }

            oc = 0;

            if (out_msg->hdr.type == COAP_ENUM_MSG_TYPE_RST) {
                /* RST must be empty */
                out_msg->hdr.oc = 0;
                out_msg->option_list = NULL;
                out_msg->payload = NULL;
                out_msg->payload_len = 0;
            } else if (msg->hdr.code == COAP_REQ_CODE_GET) {
                uint8_t ct = 0;
                //ct = htons(ct);
                coap_add_option (out_msg->option_list, oc++,
                                 COAP_ENUM_OPTION_ID_CONTENT_TYPE,
                                 sizeof (ct), (uint8_t *) & (ct));
                /* Fill the payload */
                if (payload != NULL && payload_len != 0) {
                    memcpy (out_msg->payload, payload, payload_len);
                    out_msg->payload_len = payload_len;
                }
            } else {
                out_msg->payload = NULL;
                out_msg->payload_len = 0;
            }

            if (session->msg_token_length != 0) {
                coap_add_option (out_msg->option_list, oc++,
                                 COAP_ENUM_OPTION_ID_TOKEN,
                                 session->msg_token_length,
                                 session->msg_token);
            }

            if (!oc) {
                out_msg->option_list = NULL;
            }
            out_msg->hdr.oc = oc;

            session->outbuf_len = coap_set_msg (session->outbuf, out_msg);

            coap_clean_msg (out_msg);

            n = sendto (session->listenfd, session->outbuf,
                        session->outbuf_len, 0,
                        (struct sockaddr *) &(session->client_addr),
                        session->client_addr_len);

            if (n < 0) {
                ERROR ("Could not send msg\n");
                session->state = COAP_ENUM_STATE_DONE;
            }
        }
    }

clean_session:
    if (payload != NULL)
        free (payload);

finish:
    coap_clean_msg (msg);

    /*
    if(error) {
        return -1;
    } else {
        return 0;
    }
    */
}

/**
 * This is the server session thread (from a pool) to handle sessions on the session queue.
 * @param my_session is a session pointer to the session to be handled, the session
 * has inbuf, outbuf, state and client sockaddr in it.
 * @return pointer to void
 */
void *
coap_server_session_handler (void *my_session)
{
    //pthread_detach(pthread_self());

    /* Handler only get session from the queue, this is just for 
     * debug purpose.
     */
    coap_session *session = (coap_session *) my_session;
    if (session != NULL) {
        /*
        if(coap_server_handle_session(session) == -1) {
            ERROR("server error: could not handle session\n");
            // Shall we remove the session?
        }
        */
        session_lock ();
        session->in_processing = true;
        session_unlock ();

        coap_server_handle_session (&session);

        session_lock ();
        if (session->state != COAP_ENUM_STATE_WAIT_ACK) {
            coap_delete_session_node (session);
        } else {
            time (&(session->last_active_time));
            session->in_processing = false;
        }
        session_unlock ();
        return NULL;
    }

    while (1) {
        session_lock ();
        while (thread_pool_parms.next_item == end) {
            thread_pool_parms.active_threads--;
            pthread_cond_wait (&session_cond, &session_mutex);
            thread_pool_parms.active_threads++;
        }
        session = (coap_session *) (thread_pool_parms.next_item->data);
        thread_pool_parms.next_item = thread_pool_parms.next_item->next;
        //session_unlock();
 
        /*
        if(coap_server_handle_session(&session) == -1) {
            ERROR("server error: could not handle session\n");
            // Shall we remove the session?
            break;
        }
        */

        //session_lock();
        session->in_processing = true;
        session_unlock ();

        coap_server_handle_session (&session);

        session_lock ();
        if (session->state != COAP_ENUM_STATE_WAIT_ACK) {
            coap_delete_session_node (session);
        } else {
            time (&(session->last_active_time));
            session->in_processing = false;
        }
        session_unlock ();
    }

    session_lock ();
    thread_pool_parms.active_threads--;
    thread_pool_parms.total_threads--;
    DBG ("                              total session threads: %d\n",
         thread_pool_parms.total_threads);
    session_unlock ();

    pthread_exit (NULL);

    return NULL;
}

/**
 * Main loop function for the CoAP server.
 * @return 0 on success, -1 on failure
 */
int
coap_server_run(void)
{
    int i;
    pthread_t session_thread_id[coap_init_server_session_threads];
    pthread_t acting_session_thread_id[coap_init_server_session_threads];

    session_lock ();
    for (i = 0; i < coap_init_server_session_threads; i++) {
        if (pthread_create
            (&session_thread_id[i], NULL, coap_server_session_handler,
             NULL) != 0) {
            ERROR ("Error creating session_thread %d\n", i);
        } else {
            DBG ("Created session_thread %d with session_thread_id 0x%x\n", i,
                 (unsigned int) session_thread_id[i]);
            acting_session_thread_id[thread_pool_parms.total_threads++] =
                session_thread_id[i];
            thread_pool_parms.active_threads++;
        }
    }
    session_unlock ();

    pthread_t dispacher_thread_id;
    if (pthread_create
        (&dispacher_thread_id, NULL, coap_server_request_dispatcher,
         NULL) != 0) {
        ERROR ("Error creating session dispacher thread.\n");
    } else {
        DBG ("Created session dispacher thread 0x%x.\n",
             (unsigned int) dispacher_thread_id);
        pthread_join (dispacher_thread_id, NULL);
    }

    for (i = 0; i < thread_pool_parms.total_threads; i++) {
        pthread_cancel (acting_session_thread_id[i]);
    }

    return 0;
}

/**
 * Cleanup the server mutex
 * @return void
 */
void 
coap_server_cleanup(void) 
{
    pthread_mutex_destroy (&session_mutex);
    pthread_cond_destroy (&session_cond);
    pthread_mutex_destroy (&dump_mutex);
}

/**
 * Search for a node (session) up to the next_item pointer.
 * There is at most one session node per client with CON msg,
 * but may have more than one session node per client with NON msg.
 * NON session node are short lived, once processed will be removed by the
 * processing thread, where CON session node in separate mode is kept for ACK
 * from the client and in case ACK is not received, retransmit.
 * This is based on the assumption that client get ACK/RST for the CON
 * before sending the next msg, either CON, NON, ACK or RST. If client
 * can send multiple CON msgs at the same time (msg multiplex), then the
 * session structure need to be modified to contain a per session CON msg
 * list and state per CON msg. According to the coap rfc, the authors recommend
 * no msg miltiplex. So our assumption is a valid/good one.
 * For CON, always do search/transfer, for NON, always do insert.
 * thread_pool_parm.next_item points to end node means no more item to process.
 * @param client_name is the host name of the client
 * @param client_port is the port of the client
 * @return NULL if not found, or a pointer to the session node
 */
coap_node *
coap_search_session_node (char *client_name, char *client_port)
{
    coap_node *p;

    if ((p = start) == end) {
        //DBG("                                   p = end\n");
        return NULL;
    }

    time_t current_time;
    time (&current_time);
    coap_node *temp;

    while (p != thread_pool_parms.next_item) {
        coap_session *session = (coap_session *) (p->data);
        if (session->in_processing == false) {
            /* No trans node if in_processing, to avoid delete after next */
            if (strcmp (session->client_name, client_name) == 0 &&
                strcmp (session->client_port, client_port) == 0) {
                //DBG("                                 find session match\n");
                break;
            }

            if (session->state == COAP_ENUM_STATE_WAIT_ACK) {
                if (current_time - session->last_active_time >
                    coap_retransmit_timeout) {
                    temp = p->next;
                    if (++(session->retrans_count) > coap_max_retransmit) {
                        coap_delete_session_node (session);
                        //DBG("                             delete session node\n");
                    } else {
                        coap_transfer_node_to_end (p);
                        //DBG("                             trans session node\n");
                    }
                    p = temp;
                } else {
                    p = p->next;
                }
            } else if (session->state == COAP_ENUM_STATE_DONE) {
                if (current_time - session->last_active_time >
                    coap_session_timeout) {
                    temp = p->next;
                    coap_delete_session_node (session);
                    p = temp;
                } else {
                    p = p->next;
                }
            } else {
                if (current_time - session->last_active_time >
                    coap_session_cleanup_time) {
                    temp = p->next;
                    coap_delete_session_node (session);
                    p = temp;
                } else {
                    p = p->next;
                }
            }
        } else {
            p = p->next;
        }
    }

    // Debug
    /*
    if(p == thread_pool_parms.next_item) {
        ERROR("                               node not found\n");
    } else {
        DBG("                               found node\n");
    }
    */

    return (p == thread_pool_parms.next_item) ? NULL : p;
}

/**
 * Delete a single session node if session is done or no longer active
 * @param session is a pointer to the session containing a pointer to the node to be deleted
 */
void
coap_delete_session_node (coap_session * session)
{
    if (session == NULL) {
        return;
    }
    if (session->this_node != NULL && session->this_node != end) {
        if ((coap_session *) (session->this_node->data) != session) {
            ERROR ("session->this_node->data != session\n");
            exit (1);
        }
        coap_delete_node (session->this_node);
        session->this_node = NULL;
        coap_session_close (session);
    }
}

/**
 * Delete a single NON node (transient session) right after get the node (treat like a task)
 * @param session is a pointer to the session containing a poniter to the NON node to be deleted
 */
void
coap_delete_NON_session_node (coap_session * session)
{
    if (session->state != COAP_ENUM_STATE_UNKNOWN &&
        session->state != COAP_ENUM_STATE_WAIT_NON) {
        return;
    }
    coap_delete_session_node (session);
}

/**
 * Clean all the inactive session nodes or retransmit when timeout from receive
 */
void
coap_clean_session_list ()
{
    coap_node *p;

    if ((p = start) == end) {
        //DBG("                                   p = end\n");
        return;
    }

    time_t current_time;
    time (&current_time);
    coap_node *temp;

    while (p != thread_pool_parms.next_item && p != end) {
        coap_session *session = (coap_session *) (p->data);
        if (session->in_processing == false) {
            if (session->state == COAP_ENUM_STATE_WAIT_ACK) {
                if (current_time - session->last_active_time >
                    coap_retransmit_timeout) {
                    temp = p->next;
                    if (++(session->retrans_count) > coap_max_retransmit) {
                        coap_delete_session_node (session);
                        //DBG("                             delete session node\n");
                    } else {
                        coap_transfer_node_to_end (p);
                        //DBG("                             trans session node\n");
                    }
                    p = temp;
                } else {
                    p = p->next;
                }
            } else if (session->state == COAP_ENUM_STATE_DONE) {
                if (current_time - session->last_active_time >
                    coap_session_timeout) {
                    temp = p->next;
                    coap_delete_session_node (session);
                    p = temp;
                } else {
                    p = p->next;
                }
            } else {
                if (current_time - session->last_active_time >
                    coap_session_cleanup_time) {
                    temp = p->next;
                    coap_delete_session_node (session);
                    p = temp;
                } else {
                    p = p->next;
                }
            }
        } else {
            p = p->next;
        }
    }
}

