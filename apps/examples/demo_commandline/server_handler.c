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

/*
 * server_handler.c
 *
 * Created on: Mar 12, 2012
 * Author: Jichang Hou
 */

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "server_handler.h"

int delay = 0;

/**
 * This is a demo to show a fake server handler, use real handler(s) to replace this.
 * In general, server handler can open DB, socket or other communication means as needed.
 * @param session is the session the request belongs to and will be handled by this handler.
 * @param msg is the msg decoded from the inbuf and will be handled by this handler.
 * @param payload is the payload for the reply
 * @param payload_len is the payload length
 * @return -1 for error, or 0 for success
 */
int
coap_req_handler_demo (coap_session * session, coap_message * msg,
                       char **payload, uint16_t *payload_len)
{
    time_t now;

    /* Display the received message */
    coap_dump_msg(msg);

    /* Application developper can access the type of request 
     * by accessing msg->hdr.code, which has one of the following
     * value: COAP_REQ_CODE_GET, COAP_REQ_CODE_POST,
     * COAP_REQ_CODE_PUT or COAP_REQ_CODE_DELETE
     */

    /* In this example, we only support the GET message */
    if (msg->hdr.code == COAP_REQ_CODE_GET) {
        /* Fill the payload with the current time in text format */
        *payload = (char *) malloc (256);
        memset (*payload, 0, sizeof (*payload));
        time (&now);
        ctime_r (&now, *payload);
        *payload_len = strlen (*payload);
    }

    /* Set a delay to simulate lossy networks, if specified by 
     * the command line (see demo_commandline/server_main.c)
     */
    if (delay) {
        struct timespec remaining;
        struct timespec mytimeout = {
            .tv_sec = delay,
            .tv_nsec = 0,
        };

        DBG("Delaying the reply as requested...\n");
        nanosleep (&mytimeout, &remaining);
        DBG("... Resuming operations.\n");
    }

    return 0;
}
