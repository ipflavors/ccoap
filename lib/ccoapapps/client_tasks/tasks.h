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
 * tasks.h
 *
 * Created on: Dec 12, 2011
 * Author: Jichang Hou
 */

#ifndef COAP_TASKS_H_
#define COAP_TASKS_H_

#include <stdint.h>
#include "coap.h"

typedef enum coap_user_type_
{
    COAP_ENUM_USER_DEFAULT = 0,
    COAP_ENUM_USER_TIME = 1,
    COAP_ENUM_USER_COMMANDLINE = 2,
    COAP_ENUM_USER_MAX
} coap_user_type;

typedef int (*coap_user) (int, uint8_t *, uint8_t *, coap_message *,
                          coap_state_type);

/**
 * Register user task
 * @param user_type is the type of task.
 * @param user is the user task (function pointer)
 * @return -1 for error, or 0 for success
 */
int coap_client_task_regist(coap_user_type user_type, coap_user user);

#endif /* COAP_TASKS_H_ */
