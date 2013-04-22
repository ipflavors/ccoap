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
 * Created on: Feb 24, 2012
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
#define APPLICATION_TYPE COAP_ENUM_USER_COMMANDLINE

/**
 * Application data, given as commandline arguments and 
 * used to fill the CoAP header and options.
 */
typedef struct coap_uri_
{
    char *host;
    uint16_t port;
    char *path[COAP_MAX_URI_PATH];
    uint8_t path_count;
    char *query[COAP_MAX_URI_QUERY];
    uint8_t query_count;
} coap_uri;

typedef struct task_data_
{
    coap_msg_type type;     /* request type (NON/CON) */
    uint8_t code;           /* request code (GET/POST/PUT/DELETE) */
    bool ct_on;             /* whether there is a content */
    uint16_t ct;            /* content type */
    uint8_t ct_size;        /* content type size */
    uint8_t oc;             /* option count */
    bool token_on;          /* whether token is enabled */
    coap_uri uri;           /* URI options */
    char *payload;          /* payload */
    uint16_t payload_len;   /* payload length */
} task_data;

void
print_help (char *pname)
{
    fprintf (stderr, "%s [options]\n"
             " -f path/to/config: specify config file name\n"
             " -p [1024-65535]: specify port number, default is 5683\n"
             " -t [0 (CON) / 1 (NON)]: specify msg type, default is 0\n"
             " -m [1 (GET) / 2 (POST) / 3 (PUT) / 4 (DELETE)]: method, default is 1\n"
             " -c [0-65535]: specify content type, default is 0 (plain text)\n"
             " -k [0 (off) / 1 (on)]: enables token, default is 1\n"
             " -s [name/ip-addr]: specify URI or host\n"
             " -o [1024-65535]: specify URI port\n"
             " -a path: specify URI path\n"
             " -q query: specify URI query\n"
             " -d payload: specify payload\n"
             " -h : help\n"
             " Set -s and -o when connecting to proxy, otherwise omit\n"
             "\n"
             "Some examples:\n"
             "$ %s -p 5683 -t 0 -m 2 -k 1 -a test -c 0 -d \"Sample payload\"\n"
             "$ %s -p 5683 -t 0 -m 1 -k 1 -a seg1 -a seg2 -a seg3\n"
             "$ %s -p 5683 -t 0 -m 1 -k 1 -a query -q first=1 -q second=2 -q third=3\n"
             "$ %s -p 5683 -t 1 -m 1 -k 1 -a separate\n",
             pname, pname, pname, pname, pname);
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
    uint8_t option_counter = 0;
    int i;

    /* Create a task */
    coap_task *task = coap_client_create_task (APPLICATION_TYPE, 
                                               coap_server_name, d->oc,
                                               d->payload_len);
    if (task == NULL) {
        ERROR ("Creating task failed.\n");
        exit (1);
    }

    /* Fill the message type, code, and payload */ 
    coap_client_fill_msg(task, d->type, d->code, d->payload, d->payload_len);

    /* Add the message options */
    /* The Content Type option */
    if (d->ct_on && d->payload_len) {
        coap_client_add_option (task, option_counter++,
                         COAP_ENUM_OPTION_ID_CONTENT_TYPE,
                         d->ct_size, (uint8_t *) &(d->ct));
    }

    /* The URI Host option */
    if (d->uri.host != NULL) {
        coap_client_add_option (task, option_counter++,
                         COAP_ENUM_OPTION_ID_URI_HOST,
                         (uint8_t) strlen (d->uri.host),
                         (uint8_t *) d->uri.host);
    }

    /* The URI Port option */
    if (d->uri.port != 0) {
        d->uri.port = htons (d->uri.port);
        coap_client_add_option (task, option_counter++,
                         COAP_ENUM_OPTION_ID_URI_PORT,
                         sizeof (d->uri.port),
                         (uint8_t *) &(d->uri.port));
    }

    /* The URI Port Path options */
    for (i = 0; i < d->uri.path_count; i++) {
        coap_client_add_option (task, option_counter++,
                         COAP_ENUM_OPTION_ID_URI_PATH,
                         (uint8_t) strlen (d->uri.path[i]),
                         (uint8_t *) (d->uri.path[i]));
    }

    /* The Token option */
    if (d->token_on) {
        uint8_t *token = coap_client_create_token(task);
        coap_client_add_option (task, option_counter++,
                         COAP_ENUM_OPTION_ID_TOKEN,
                         COAP_TOKEN_LEN, token);
    }

    /* The URI Query option */
    for (i = 0; i < d->uri.query_count; i++) {
        coap_client_add_option (task, option_counter++,
                         COAP_ENUM_OPTION_ID_URI_QUERY,
                         (uint8_t) strlen (d->uri.query[i]),
                         (uint8_t *) (d->uri.query[i]));
    }

    return task;
}

/* The main */
int
main (int argc, char **argv)
{
    int c, p;
    char *config_file = NULL;
    task_data d;

    /* Initialize the task_data structure */
    d.type = COAP_ENUM_MSG_TYPE_CON;
    d.code = COAP_REQ_CODE_GET;
    d.ct_on = false;
    d.ct = 0;
    d.ct_size = 0;
    d.oc = 1;   /* Token option is activated by default */
    d.token_on = true;
    d.payload = NULL;
    d.payload_len = 0;
    d.uri.host = NULL;
    d.uri.port = 0;
    d.uri.path_count = d.uri.query_count = 0;

    /* Import the default configuration. Will be 
     * overwritten by the client config file. 
     */
    coap_default_config ();

    /* Register the application type */
    if (coap_client_task_regist (APPLICATION_TYPE, coap_tasks_demo) < 0) {
        exit (1);
    }

    /* Read the command line arguments */
    while ((c = getopt (argc, argv, "p:f:t:m:c:k:s:o:a:q:d:h")) != EOF) {
        switch (c) {
        case 'p':
            p = atoi (optarg);
            if (p < 1024 || p > 65535) {
                print_help (argv[0]);
                exit (1);
            }
            coap_port = p;
            break;
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
        case 'm':
            if (!strncmp ("1", optarg, 1)) {
                d.code = COAP_REQ_CODE_GET;
            } else if (!strncmp ("2", optarg, 1)) {
                d.code = COAP_REQ_CODE_POST;
            } else if (!strncmp ("3", optarg, 1)) {
                d.code = COAP_REQ_CODE_PUT;
            } else if (!strncmp ("4", optarg, 1)) {
                d.code = COAP_REQ_CODE_DELETE;
            } else {
                print_help (argv[0]);
                exit (1);
            }
            break;
        case 'c':
            p = atoi (optarg);
            if (c < 0 || c > 65535) {
                print_help (argv[0]);
                exit (1);
            } else {
                d.ct_on = true;
                d.ct = c;
            }
            if (d.ct < 256) {
                d.ct_size = 1;
            } else {
                d.ct = htons (d.ct);
                d.ct_size = 2;
            }
            break;
        case 'k':
            if (!strncmp ("0", optarg, 1)) {
                d.token_on = false;
                d.oc--; /* Token option is activated by default */
            } else if (!strncmp ("1", optarg, 1)) {
                d.token_on = true;
            } else {
                print_help (argv[0]);
                exit (1);
            }
            break;
        case 's':
            d.uri.host = optarg;
            d.oc++;
            break;
        case 'o':
            p = atoi (optarg);
            if (p < 1024 || p > 65535) {
                print_help (argv[0]);
                exit (1);
            }
            d.oc++;
            d.uri.port = p;
            break;
        case 'a':
            d.uri.path[d.uri.path_count++] = optarg;
            d.oc++;
            break;
        case 'q':
            d.uri.query[d.uri.query_count++] = optarg;
            d.oc++;
            break;
        case 'd':
            d.payload = optarg;
            d.payload_len = strlen (d.payload);
            break;
        case 'h':
        default:
            print_help (argv[0]);
            exit (0);
        }
    }

    if (d.ct_on == true && d.payload_len) {
        d.oc++;
    }

    /* Read the client configuration file */
    coap_client_config (config_file);

    /* CoAP client initialization */
    if (coap_client_init () < 0) {
        ERROR ("Client init failed.\n");
        exit (1);
    }

    /* Run the client */
    coap_client_run(1 /* Number of tasks */, get_task, (void *) &d);

    /* Cleanup the client */
    coap_client_cleanup();

    return 0;
}
