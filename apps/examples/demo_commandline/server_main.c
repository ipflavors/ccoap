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
 * Created on: Feb 24, 2012
 * Author: Jichang Hou
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "ccoaplib.h"
#include "server_handler.h"

extern coap_req_type req_type;
extern int delay;   // defined and used in server_handler.c

void
print_help (char *pname)
{
    fprintf (stderr, "%s\n"
             " -f path/to/config: specify configuration file name\n"
             " -d [0, 10-20], specify delay (simulates lossy),\n"
             "    0 for no delay or between 10 and 20 (sec.), default: 0\n"
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
    if (coap_serv_handler_regist (COAP_ENUM_REQ_COMMANDLINE,
                                  coap_req_handler_demo) < 0) {
        exit (1);
    }

    /* Global here for demo purpose, but should be based on URI instead */
    req_type = COAP_ENUM_REQ_COMMANDLINE;

    /* read the command line arguments */
    while ((c = getopt (argc, argv, "f:d:h")) != EOF) {
        switch (c) {
        case 'f':
            config_file = optarg;
            break;
        case 'd':
            delay = atoi (optarg);
            if (delay > 20) {
                delay = 20;
            } else if (delay < 10 && delay != 0) {
                delay = 10;
            }
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
