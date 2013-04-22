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
 * server_main.c
 *
 * Created on: Jan 16, 2012
 * Author: Jichang Hou
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "ccoaplib.h"
#include "server_handler.h"

extern coap_req_type req_type;

void
print_help (char *pname)
{
    fprintf (stderr, "%s [options]\n"
             " -f path/to/config: specify configuration file name\n"
             " -h : help\n", pname);
}

int
main (int argc, char **argv)
{
    int c;
    char *config_file = NULL;

    /* Import the default configuration. Will be 
     * overwritten by the client config file. 
     */
    coap_default_config ();

    /* Register the application type */
    if (coap_serv_handler_regist (COAP_ENUM_REQ_TIME,
                                  coap_req_handler_demo) < 0) {
        exit (1);
    }

    /* Global here for demo purpose, but should be based on URI instead */
    req_type = COAP_ENUM_REQ_TIME;

    /* Read the command line arguments */
    while ((c = getopt (argc, argv, "f:h")) != EOF) {
        switch (c) {
        case 'f':
            config_file = optarg;
            break;
        case 'h':
        default:
            print_help (argv[0]);
            exit (0);
        }
    }

    /* Read the server configuration file */
    coap_server_config (config_file);

    /* CoAP client initialization */
    if (coap_server_init () < 0) {
        ERROR ("\nServer init failed.\n");
        exit (1);
    }

    /* Run the server */
    coap_server_run();

    /* Cleanup the server */
    coap_server_cleanup();

    return 0;
}
