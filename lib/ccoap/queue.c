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
 * queue.c
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#include <stdlib.h>             /* for atoi() and exit() */
#include <string.h>             /* for memset() */

#include "ccoaplib.h"
#include "queue.h"

extern coap_node *start, *end;
extern coap_locked_data thread_pool_parms;
//extern uint8_t coap_retransmit_timeout;
//extern uint8_t coap_max_retransmit;

/**
 * Allocate a node for task or session
 * @return a pointer for the node
 */
coap_node *
coap_get_node ()
{
    coap_node *p = (coap_node *) malloc (sizeof (coap_node));
    if (p == NULL) {
        ERROR ("Not enough memory, exit now!\n");
        exit (1);
    }
    return p;
}

/**
 * Initialize a list
 */
void
coap_init_list ()
{
    start = end = coap_get_node ();
    thread_pool_parms.next_item = end;
}

/**
 * Insert a new node at the end of the queue
 * @param data is either task(for client use) or session(for server use)
 * @return a pointer to the newly created node
 */
coap_node *
coap_insert_node (void *data)
{
    //DBG("                               insert node\n");
    coap_node *p = coap_get_node ();
    end->data = data;
    end->next = p;
    p->pre = end;
    end = p;
    return end->pre;
}

/**
 * Delete a single task node p after get the task
 * @param p is a pointer to the task node to be deleted
 */
void
coap_delete_node (coap_node * p)
{
    //DBG("                               delete node\n");
    if (p == NULL || p == end) {
        return;
    } else if (p == start) {
        start = p->next;
    } else {
        (p->pre)->next = p->next;
        (p->next)->pre = p->pre;
    }
    p->data = NULL;
    free (p);
}

/**
 * Transfer an existing node (CON/ACK session) to the end of the queue
 * @param p is a pointer to the existing node
 */
void
coap_transfer_node_to_end (coap_node * p)
{
    //DBG("                               trans node\n");
    /*
    if(start == end || p == end) {
        return;
    }
    */

    if (thread_pool_parms.next_item == end) {
        thread_pool_parms.next_item = p;
    }

    if (p->next == end) {
        /* Already at end */
        return;
    } else if (p == start) {
        start = start->next;
    } else {
        (p->pre)->next = p->next;
        (p->next)->pre = p->pre;
    }
    (end->pre)->next = p;
    p->next = end;
    p->pre = end->pre;
    end->pre = p;
}
