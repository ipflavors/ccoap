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
 * queue.h
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#ifndef COAP_QUEUE_H_
#define COAP_QUEUE_H_

#include <time.h>               /* for time_t */

/**
 * A node in a linked list (implemented like a queue).
 * The server receives a request from one of the clients and
 * search the list/queue to see if the session is already there, i.e.
 * client is not new. If new, the server creats a session node (defined by
 * the new client's ip/port) and put the session node on the list, new node
 * is always inserted at the end of the list. The server (master process/thread)
 * init a task pointer to the first task to be processed (the first node in the queue).
 * The task pointer should be protected (locked/unlocked),
 * but the list should not be. Each slave thread
 * gets a task(node) pointed to by the task pointer, updates the task pointer
 * by new task pointer = current task pointer -> next and the time stamp in the session.
 * If the task pointer is end, then all the slave should be
 * sleep until waked up by the master. If not new, the server moves the session node to
 * the end of the list, if the task pointer is end, let it point to the new task.
 * At a fixed time interval, the server gets a signal to check each
 * session in the list starting from the front/first node, timeout by comparing the
 * (current time - session time stamp > COAP_SESSION_TIMEOUT) ?
 * If true, the server simply remove the session from the list. All these should be
 * hidden from the server/application and handled by the lib's API.
 */
typedef struct coap_node_
{
    void *data;
    struct coap_node_ *next;
    struct coap_node_ *pre;
} coap_node;

typedef struct coap_locked_data_
{
    int total_threads;
    int active_threads;
    coap_node *next_item;
} coap_locked_data;

/**
 * Allocate a node for task or session
 * @return a pointer for the node
 */
coap_node *coap_get_node ();

/**
 * Initialize a list
 */
void coap_init_list ();

/**
 * Insert a new node at the end of the queue
 * @param data is either task(for client use) or session(for server use)
 * @return a pointer to the newly created node
 */
coap_node *coap_insert_node (void *data);

/**
 * Delete a single task node p after get the task
 * @param p is a pointer to the task node to be deleted
 */
void coap_delete_node (coap_node * p);

/**
 * Transfer an existing node (CON/ACK session) to the end of the queue
 * @param p is a pointer to the existing node
 */
void coap_transfer_node_to_end (coap_node * p);

#endif /* COAP_QUEUE_H_ */
