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
 * handlers.h
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#ifndef COAP_HANDLERS_H_
#define COAP_HANDLERS_H_

#include "server.h"

typedef enum coap_req_type_
{
    COAP_ENUM_REQ_DEFAULT = 0,
    COAP_ENUM_REQ_TIME = 1,
    COAP_ENUM_REQ_COMMANDLINE = 2,
    COAP_ENUM_REQ_MAX
} coap_req_type;

typedef int (*coap_req_handle) (coap_session *, coap_message *,
                                char **, uint16_t *);

/**
 * Register a server handler
 * @param req_type is the type of request.
 * @param req_handle is the server handle (function pointer)
 * @return -1 for error, or 0 for success
 */
int coap_serv_handler_regist (coap_req_type req_type,
                              coap_req_handle req_handle);

#endif /* COAP_HANDLERS_H_ */
