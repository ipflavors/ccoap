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
 * server.h
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#ifndef COAP_SERVER_H_
#define COAP_SERVER_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <netdb.h>

#include "coap.h"
#include "queue.h"

/**
 * Used by server to support multiple clients.
 * Uniquely defined by the client's ip address and port
 * since the server side ip/port are known by the server and
 * transport is UDP, session can only be created/closed by the
 * master thread. Client also can use it for mapping request/reply.
 * Optional means implemented if timeout/retransmit are enabled/implemented.
 */
typedef struct coap_session_
{
    coap_state_type state;      /* state type */
    //char* ip_addr;                /* the other endpoint ip/port can be used as session id */
    //uint16_t port;                /* the other endpoint ip/port can be used as session id */
    struct sockaddr_storage client_addr;    /* for store client address */
    socklen_t client_addr_len;  /* client address length */
    char client_name[NI_MAXHOST];   /* client host name for matching session */
    char client_port[NI_MAXSERV];   /* client port number for matching session */
    uint16_t msg_id;            /* coap msg id */
    uint8_t msg_token[COAP_MAX_TOKEN_LENGTH];   /* coap req/res token */
    uint8_t msg_token_length;   /* coap req/res token_length */
    int listenfd;               /* for send response */
    //uint32_t thread_id;           /* thread handling this session*/
    uint8_t *inbuf;             /* buffer for receiving coap PDU */
    uint16_t inbuf_len;         /* length of the in_buf */
    uint8_t *outbuf;            /* buffer for sending coap PDU */
    uint16_t outbuf_len;        /* length of the out_buf, */
    time_t last_active_time;    /* if elapsed time > session timeout time, close the session */
    //time_t retransmit_time;       /* time when most recent CON is sent, optional*/
    //bool acked;                   /* indicate if ACK is received for CON, optional*/
    bool retrans;               /* indicate if need retrans (timeouted) */
    uint8_t retrans_count;      /* increment by 1 till reached MAX_RETRANSMITION_COUNT, optional */
    coap_node *this_node;       /* pointer to the node containing the session */
    bool in_processing;         /* indicator so that it will not be cleaned */
} coap_session;

/**
 * Open new coap session.
 * @param buf_size is the size of the inbuf and outbuf for read and write
 * @return a pointer to the newly created session
 */
coap_session *coap_session_open (int buf_size);

/**
 * Close coap session.
 * @param session is a pointer to the session
 */
void coap_session_close (coap_session * session);

/**
 * Attach received coap msg/pdu in inbuf to a session
 * @param session is a pointer to the session
 * @param inbuf is the buffer containing received coap msg from the socket
 * @param size is the size of the coap msg/pdu in the buffer
 */
void coap_attach_inbuf (coap_session * session, uint8_t * inbuf, int size);

/**
 * Read configuration file by the server.
 * @param file_name is the server config file name
 */
void coap_server_config (char *file_name);

/**
 * Initialization by the server,
 * socket, session queue, initial random msg_id/token, thread pool, etc.
 * @return -1 for error, or 0 for success
 */
int coap_server_init ();

/**
 * Get server address/port from address/port names. Bind the address/port.
 * IPv4/IPv6 independent. Connectionless socket.
 * @param hostname is the host name of the server
 * @param service is the service name of the service
 * @param family is the protocol family
 * @param socktype is the socket type
 * @return -1 for error, or binded socket for the server
 */
int coap_open_server_socket (const char *hostname,
                             const char *servicename,
                             int family, int socktype);

/**
 * Used by coap server to find a matching session (and move it to the end)
 * or create one (and put it to the queue), attach a coap msg/pdu to the session
 * @param client_name is the host name of the client
 * @param client_port is the port of the client
 * @param inbuf is the buffer containing received coap msg from the socket
 * @param size is the size of the coap msg/pdu in the buffer
 * @return -1 for error, or 0 for success
 */
int coap_dispatch_request (int listenfd, struct sockaddr_storage client_addr,
                           socklen_t client_addr_len, char *client_name,
                           char *client_port, uint8_t * inbuf, uint16_t size);

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
void *coap_server_request_dispatcher (void *my_host_name);

/**
 * Send response in the form ACK(res) or CON(res) for the session passed to it
 * by the session handler thread.
 * It will invoke user applications (via register) based on the requests.
 * @param my_session is a session pointer to the session to be handled, the session
 * has inbuf, outbuf, state and client sockaddr in it.
 * @return -1 for error, or 0 for success
 */
void coap_server_handle_session (coap_session ** my_session);

/**
 * This is the server session thread (from a pool) to handle sessions on the session queue.
 * @param my_session is a session pointer to the session to be handled, the session
 * has inbuf, outbuf, state and client sockaddr in it.
 * @return pointer to void
 */
void *coap_server_session_handler (void *my_session);

/**
 * Main loop function for the CoAP server.
 * @return 0 on success, -1 on failure
 */
int coap_server_run(void);

/**
 * Cleanup the server mutex
 * @return void
 */
void coap_server_cleanup(void);

/**
 * Search for a node (session) up to the next_task pointer.
 * There is at most one session node per client with CON msg,
 * but may have more than one session node per client with NON msg.
 * NON session node are short lived, once processed will be removed by the
 * processing thread, where CON session node is kept in the list untill
 * timeout. True (CON) session node is indicated by CON_RECV, CON_SEND, RST_RECV,
 * RST_SEND, ACK_SEND, ACK_RECV, transient session node is indicated by
 * UNKNOWN. So CON session is stateful and long lived,
 * NON session is stateless and short lived.
 * This is based on the assumption that client get ACK/RST for the CON
 * before sending the next msg, either CON, NON, ACK or RST. If client
 * can send multiple CON msgs at the same time (msg multiplex), then the
 * session structure need to be modified to contain a per session CON msg
 * list and state per CON msg. According to the coap rfc, the authors recommend
 * no msg miltiplex. So our assumption is a valid/good one.
 * For CON, always do search/transfer, for NON, always do insert.
 * thread_pool_task.next_task points to end node means no more task.
 * @param client_name is the host name of the client
 * @param client_port is the port of the client
 * @return NULL if not found, or a pointer to the session node
 */
coap_node *coap_search_session_node (char *client_name, char *client_port);

/**
 * Delete a single session node if session is done or no longer active
 * @param session is a pointer to the session containing a pointer to the node to be deleted
 */
void coap_delete_session_node (coap_session * session);

/**
 * Delete a single NON node (transient session) right after get the node (treat like a task)
 * @param session is a pointer to the session containing a poniter to the NON node to be deleted
 */
void coap_delete_NON_session_node (coap_session * session);

/**
 * Clean all the inactive session nodes or retransmit when timeout from receive
 */
void coap_clean_session_list ();

#endif /* COAP_SERVER_H_ */
