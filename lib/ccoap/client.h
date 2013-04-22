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
 * client.h
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#ifndef COAP_CLIENT_H_
#define COAP_CLIENT_H_

#include <stdint.h>

#include "coap.h"
#include "tasks.h"

/**
 * coap task store to be send by client to the server (name, service/port)
 */
typedef struct coap_task_
{
    char *server_name;
    char *server_service;
    coap_message *msg;
    coap_user_type user;
} coap_task;

/**
 * Read configuration file by the clients.
 * @param file_name is the client config file name
 */
void coap_client_config (char *file_name);

/**
 * Initialization by the clients,
 * socket, task queue, initial random msg_id/token, thread pool, etc.
 * @return -1 for error, or 0 for success
 */
int coap_client_init ();

/**
 * Get server address/port from address/port names.
 * IPv4/IPv6 independent. Connection socket.
 * @param host_name is the host name of the server
 * @param service_name is the service name of the service
 * @param family is the protocol family
 * @param socktype is the socket type
 * @return -1 for error, or connection socket for the client
 */
int coap_open_client_socket (const char *host_name,
                             const char *service_name,
                             int family, int socktype);

/**
 * Add coap options for a client task.
 * @param task a pointer to the task for with the option is added
 * @param index is the index at the list (the option count)
 * @param option_id is the option id
 * @param length is the length of the option data
 * @param data is a pointer to the option data
 * @return -1 if error, or 0 if success.
 */
int coap_client_add_option (coap_task *task, uint8_t index, 
                            uint8_t option_id, uint16_t length,
                            uint8_t * data);

/**
 * Create the token option
 * @param task a pointer to the task for which the token must be created
 * @return NULL for error, or a pointer to the token option
 */
uint8_t *coap_client_create_token(coap_task *task);

/**
 * Fill the message of a task with the type, code and payload
 * @param task a pointer to the task for which the message must be filled
 * @param type the message type
 * @param code the message code
 * @param payload the message payload
 * @param payload_len the payload length
 * @return -1 for error, or 0 for success
 */
int coap_client_fill_msg(coap_task *task, coap_msg_type type,
                         uint8_t code, char *payload, uint16_t payload_len);

/**
 * Allocate memory for a single task based on serv_name, oc and payload_len
 * @param type the application type
 * @param server_name is the server name.
 * @param oc is the element count for the option list.
 * @param payload_len is the length of the payload
 * @return NULL for error, or the task newly created.
 */
coap_task *coap_client_create_task (coap_user_type type, char *server_name,
                                    uint8_t oc, uint16_t payload_len);

/**
 * Clean task when no longer needed.
 * @param task is a pointer to the task to be cleaned.
 */
void coap_client_clean_task (coap_task * task);

/**
 * Set socket recv timeout timer used by clients.
 * @param connfd is the socket the timer to be set on.
 * @return -1 for error, or 0 for success
 */
int set_socket_timer (int connfd);

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
int coap_client_handle_task (uint8_t * outbuf, uint8_t * inbuf,
                             coap_task * task, int connfd);

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
void *coap_client_task_handler (void *task);

/**
 * Main loop function for the CoAP client.
 * @param tasks is the number of tasks
 * @param get_task is a callback function that retrieves the task to perform
 * @param data is the data given as argument to the get_task function
 * @return 0 on success, -1 on failure
 */
int coap_client_run(int tasks, coap_task *get_task(void *d), void *data);

/**
 * Cleanup the client mutex
 * @return void
 */
void coap_client_cleanup(void); 

/**
 * Tasks access protection
 */
void task_lock ();
void task_unlock ();

#endif /* COAP_CLIENT_H_ */
