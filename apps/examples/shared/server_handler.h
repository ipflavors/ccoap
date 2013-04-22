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
 * server_handler.h
 *
 * Created on: Jan 25, 2012
 * Author: Jichang Hou
 */

#ifndef COAP_HANDLER_DEMO_H_
#define COAP_HANDLER_DEMO_H_

#include "ccoaplib.h"

/**
 * This is a demo to show a fake server handler, use real handler(s) to replace this.
 * In general, server handler can open DB, socket or other communication means as needed.
 * @param session is the session the request belongs to and will be handled by this handler.
 * @param msg is the msg decoded from the inbuf and will be handled by this handler.
 * @param payload is the payload for the reply
 * @param payload_len is the payload length
 * @return -1 for error, or 0 for success
 */
int coap_req_handler_demo (coap_session * session, coap_message * msg,
                           char **payload, uint16_t *payload_len);

#endif /* COAP_HANDLER_DEMO_H_ */
