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
 * handlers.c
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#include "handlers.h"

coap_req_handle coap_req_handlers[COAP_ENUM_REQ_MAX];

/**
 * Register a server handler
 * @param req_type is the type of request.
 * @param req_handle is the server handle (function pointer)
 * @return -1 for error, or 0 for success
 */
int
coap_serv_handler_regist (coap_req_type req_type, coap_req_handle req_handle)
{
    if (req_type < COAP_ENUM_REQ_MAX) {
        coap_req_handlers[req_type] = req_handle;
        return 0;
    }
    return -1;
}
