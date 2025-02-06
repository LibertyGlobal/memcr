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

#ifndef __MEMCR_CLIENT_PROTO_H__
#define __MEMCR_CLIENT_PROTO_H__

typedef enum {
  MEMCR_CHECKPOINT = 100,
  MEMCR_RESTORE
} memcr_svc_cmd;

struct service_command {
  memcr_svc_cmd cmd;
  pid_t pid;
} __attribute__((packed));

typedef enum {
  MEMCR_OK = 0,
  MEMCR_ERROR_GENERAL = -1,
  MEMCR_INVALID_PID = -2
} memcr_svc_response;

struct service_response {
  memcr_svc_response resp_code;
} __attribute__((packed));

#endif /* __MEMCR_CLIENT_PROTO_H__ */
