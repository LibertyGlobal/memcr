/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef __MEMCR_CLIENT_LIB_H__
#define __MEMCR_CLIENT_LIB_H__

/* open connection to memcr daemon
 * params:
 *   comm_location - string containing the TCP socket port, or path to UNIX domain socket file
 * result:
 *   connection descryptor
 */
int memcr_client_connect(const char* comm_location);

/* close connection to memcr daemon
 * params:
 *   cd - connection descriptor returned by memcr_client_connect
 */
void memcr_client_disconnect(const int cd);

/* suspend process
 * params:
 *   cd - connection descriptor returned by memcr_client_connect
 *   pid - pid of process to suspend
* result:
 *   0 on success, <0 on error
 */
int memcr_client_checkpoint(const int cd, const unsigned int pid);

/* restore process
 * params:
 *   cd - connection descriptor returned by memcr_client_connect
 *   pid - pid of process to suspend
* result:
 *   0 on success, <0 on error
 */
int memcr_client_restore(const int cd, const unsigned int pid);

#endif /* __MEMCR_CLIENT_LIB_H__ */
