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
 * debug.h
 *
 * Created on: Dec 7, 2012
 * Author: Romain Kuntz
 */

#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdio.h>

/* DBG macro prints debug messages (with function name). 
 * CDBG macro prints debug messages (without function name).
 * Can be activated by using the CMAKE_BUILD_TYPE=Debug option at cmake time.
 */
#ifdef PRINT_DEBUG
#define DBG(...) dbgprint(__FUNCTION__, __VA_ARGS__)
#define CDBG(...) dbgprint(NULL, __VA_ARGS__)
#else
#define DBG(...)
#define CDBG(...)
#endif /* PRINT_DEBUG */

/* ERROR macro to print error messages */
#define ERROR(...) dbgprint(__FUNCTION__, __VA_ARGS__)

void dbgprint (const char *fname, const char *fmt, ...);

#endif /* DEBUG_H_ */
