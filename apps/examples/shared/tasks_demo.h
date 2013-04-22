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
 * tasks_demo.h
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#ifndef COAP_TASKS_DEMO_H_
#define COAP_TASKS_DEMO_H_

#include "ccoaplib.h"

/**
 * This is a demo to show a fake user application, use real app to replace this.
 * In general, user app can open DB, socket as needed.
 * @param connfd is the socket to communication with peers.
 * @param outbuf is the buffer per task thread for write/send
 * @param inbuf is the buffer per task thread for read/recv
 * @param msg is pointer to the msg to be processed
 * @param state is the state when the msg is passed
 * @return -1 for error, or 0 for success
 */
int coap_tasks_demo (int connfd, uint8_t * outbuf, uint8_t * inbuf,
                     coap_message * msg, coap_state_type state);

#endif /* COAP_TASKS_DEMO_H_ */
