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
 * client_main.c
 *
 * Created on: Jan 16, 2012
 * Author: Jichang Hou
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "ccoaplib.h"
#include "tasks_demo.h"

/**
 * The application type, defined in the coap_user_type 
 * structure of lib/ccoapapps/client_tasks/tasks.h
 */
#define APPLICATION_TYPE COAP_ENUM_USER_TIME

/**
 * Application data, given as commandline arguments and 
 * used to fill the CoAP header and options.
 */
typedef struct task_data_
{
    coap_msg_type type; /* The request type (CON or NON) */
} task_data;

void
print_help (char *pname)
{
    fprintf (stderr, "%s [options]\n"
             " -f path/to/config: specify configuration file name\n"
             " -t [0 (CON) / 1 (NON)]: specify msg type, default is 0\n"
             " -s [1-1000]: specify number of tasks, default is 1\n"
             " -h : help\n", pname);
}

/** 
 * Callback function called when the client sends a message.
 * This function builds the CoAP message and sets the relevant
 * options.
 */
coap_task *
get_task (void *data)
{
    task_data *d = (task_data *) data;
    uint8_t option_counter = 2; /* Token option and URI path option */
    uint8_t oc = 0;
    uint8_t *token = NULL;
    void *payload = "";
    uint16_t payload_len = 0;

    /* Create a task */
    coap_task *task = coap_client_create_task (APPLICATION_TYPE, 
                                               coap_server_name,
                                               option_counter,
                                               payload_len);
    if (task == NULL) {
        ERROR ("Creating task failed.\n");
        exit (1);
    }

    /* Fill the message type, code, and payload */ 
    coap_client_fill_msg(task, d->type, COAP_REQ_CODE_GET,
                         payload, payload_len);

    /* Add the message options */
    /* The URI Path option */
    coap_client_add_option (task, oc++, COAP_ENUM_OPTION_ID_URI_PATH,
                            (uint8_t) strlen("time"), (uint8_t *) "time");

    /* The Token option */
    token = coap_client_create_token(task);
    coap_client_add_option (task, oc++, COAP_ENUM_OPTION_ID_TOKEN,
                            COAP_TOKEN_LEN, token);

    return task;
}

/* The main */
int
main (int argc, char **argv)
{
    int c, tasks = 1;
    char *config_file = NULL;
    task_data d;

    /* Initialize the task_data structure */
    d.type = COAP_ENUM_MSG_TYPE_CON;

    /* Import the default configuration. Will be 
     * overwritten by the client config file. 
     */
    coap_default_config ();

    /* Register the application type */
    if (coap_client_task_regist (APPLICATION_TYPE, coap_tasks_demo) < 0) {
        exit (1);
    }

    /* Read the command line arguments */
    while ((c = getopt (argc, argv, "f:t:s:h")) != EOF) {
        switch (c) {
        case 'f':
            config_file = optarg;
            break;
        case 't':
            if (!strncmp ("0", optarg, 1)) {
                d.type = COAP_ENUM_MSG_TYPE_CON;
            } else if (!strncmp ("1", optarg, 1)) {
                d.type = COAP_ENUM_MSG_TYPE_NON;
            } else {
                print_help (argv[0]);
                exit (1);
            }
            break;
        case 's':
            tasks = atoi (optarg);
            if (tasks < 1 || tasks > 1000) {
                print_help (argv[0]);
                exit (1);
            }
            break;
        case 'h':
        default:
            print_help (argv[0]);
            exit (0);
        }
    }

    /* Read the client configuration file */
    coap_client_config (config_file);

    /* CoAP client initialization */
    if (coap_client_init () < 0) {
        ERROR ("Client init failed.\n");
        exit (1);
    }

    /* Run the client */
    coap_client_run(tasks, get_task, (void *) &d);

    /* Cleanup the client */
    coap_client_cleanup();

    return 0;
}
