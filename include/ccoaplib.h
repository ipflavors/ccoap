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
 * @mainpage The CCOAP library API
 *
 * @file ccoaplib.h
 * @date Dec 14, 2011
 * @author Jichang Hou
 * 
 * The CCOAP library API for client/server application developpers.
 */

#ifndef COAP_LIB_H_
#define COAP_LIB_H_

#include "coap.h"
#include "handlers.h"
#include "tasks.h"
#include "client.h"
#include "server.h"
#include "queue.h"
#include "debug.h"

/*******************************
 * Client and server functions *
 *******************************/

/**
 * Load the default configuration.
 * @return void
 */
void coap_default_config (void);


/*****************************
 * Client-specific functions *
 *****************************/

/**
 * Register a user task
 * @param user_type application type.
 * @param user callback function called upon message reception
 * @return -1 for error, or 0 for success
 */
int coap_client_task_regist(coap_user_type user_type, coap_user user);

/**
 * Parse the configuration file of the client.
 * @param file_name the client config file name
 * @return void
 */
void coap_client_config (char *file_name);

/**
 * Initialization of the client. Must be called at startup.
 * @return -1 for error, or 0 for success
 */
int coap_client_init (void);

/**
 * Main loop function for the CoAP client.
 * @param tasks the number of tasks
 * @param get_task callback function that retrieves the task to perform
 * @param data data given as argument to the get_task function
 * @return 0 on success, -1 on failure
 */
int coap_client_run(int tasks, coap_task *get_task(void *d), void *data);

/**
 * Cleanup the client mutex. Must be called before exiting.
 * @return void
 */
void coap_client_cleanup(void); 

/**
 * Allocate memory for a single task based on serv_name, oc and payload_len
 * @param type application type
 * @param server_name server name.
 * @param oc element count for the option list.
 * @param payload_len length of the payload
 * @return NULL for error, or the task newly created.
 */
coap_task *coap_client_create_task (coap_user_type type, char *server_name,
                                    uint8_t oc, uint16_t payload_len);

/**
 * Add coap options for a client task.
 * @param task pointer to the task for with the option is added
 * @param index index at the list (the option count)
 * @param option_id the option id
 * @param length length of the option data
 * @param data pointer to the option data
 * @return -1 if error, or 0 if success.
 */
int coap_client_add_option (coap_task *task, uint8_t index, 
                            uint8_t option_id, uint16_t length,
                            uint8_t * data);

/**
 * Create the token option
 * @param task pointer to the task for which the token must be created
 * @return NULL for error, or a pointer to the token option
 */
uint8_t *coap_client_create_token(coap_task *task);

/**
 * Fill the message of a task with the type, code and payload
 * @param task pointer to the task for which the message must be filled
 * @param type message type
 * @param code message code
 * @param payload message payload
 * @param payload_len payload length
 * @return -1 for error, or 0 for success
 */
int coap_client_fill_msg(coap_task *task, coap_msg_type type,
                         uint8_t code, char *payload, uint16_t payload_len);

/*****************************
 * Server-specific functions *
 *****************************/

/**
 * Register a server handler
 * @param req_type application type.
 * @param req_handle callback function called upon message reception
 * @return -1 for error, or 0 for success
 */
int coap_serv_handler_regist (coap_req_type req_type,
                              coap_req_handle req_handle);

/**
 * Parse the configuration file of the server.
 * @param file_name the server config file name
 * @return void
 */
void coap_server_config (char *file_name);

/**
 * Initialization of the server. Must be called at startup.
 * @return -1 for error, or 0 for success
 */
int coap_server_init (void);

/**
 * Main loop function for the CoAP server.
 * @return 0 on success, -1 on failure
 */
int coap_server_run(void);

/**
 * Cleanup the server mutex. Must be called before exiting.
 * @return void
 */
void coap_server_cleanup(void);


/***********************************************
 * Variables retrieved from configuration file * 
 * and accessible to the user applications     *
 ***********************************************/

/**
 * The FQDN of the targeted server 
 */
extern char *coap_server_name;

/** 
 * The CoAP port 
 */
extern uint16_t coap_port;

#endif /* COAP_LIB_H_ */
