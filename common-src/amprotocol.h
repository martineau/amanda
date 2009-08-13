/*
 *                  Copyright (C) Zmanda Incorporated.
 *                            All Rights Reserved.
 *
 *  The software you have just accessed, its contents, output and underlying
 *  programming code are the proprietary and confidential information of Zmanda
 *  Incorporated.  Only specially authorized employees, agents or licensees of
 *  Zmanda may access and use this software.  If you have not been given
 *  specific written permission by Zmanda, any attempt to access, use, decode,
 *  modify or otherwise tamper with this software will subject you to civil
 *  liability and/or criminal prosecution to the fullest extent of the law.
 */

#ifndef AMPROTOCOL_H
#define AMPROTOCOL_H

#include <stdlib.h>
#include <stdint.h>

/* If you add a new command, it must replace CMD_MAX and CMD_MAX must be
 * increaed by one.
 */
#define CMD_DEVICE		0
#define REPLY_DEVICE		1
#define CMD_TAPE_OPEN		2
#define REPLY_TAPE_OPEN		3
#define CMD_TAPE_CLOSE		4
#define REPLY_TAPE_CLOSE	5
#define CMD_TAPE_MTIO   	6
#define REPLY_TAPE_MTIO		7
#define CMD_TAPE_WRITE		8
#define REPLY_TAPE_WRITE	9
#define CMD_TAPE_READ		10
#define REPLY_TAPE_READ		11
#define CMD_MAX			12

typedef struct amprotocol_s {
    uint16_t magic;
    int	     fd;
    int      number_of_args[CMD_MAX][2];
} amprotocol_t;

typedef struct command_s {
    uint16_t magic;
    uint16_t command;
    uint32_t block_size;
    uint32_t nb_arguments;
} command_t;

typedef struct argument_s {
    uint32_t  argument_size;
} argument_t;

typedef struct an_argument_s {
    uint32_t  size;
    char     *data;
} an_argument_t;

typedef struct amprotocol_packet_s {
    uint16_t       magic;
    uint16_t       command;
    uint32_t       block_size;
    uint32_t       nb_arguments;
    an_argument_t *arguments;
} amprotocol_packet_t;

ssize_t amprotocol_send(amprotocol_t *protocol, amprotocol_packet_t *packet);

amprotocol_packet_t *amprotocol_get(amprotocol_t *protocol);
amprotocol_packet_t * amprotocol_parse(amprotocol_t *protocol, char *buf_data, size_t len);

ssize_t amprotocol_send_list(amprotocol_t *protocol,
		int cmd, int nb_arguments, ...);
ssize_t amprotocol_send_binary(amprotocol_t *protocol,
		int cmd, int nb_arguments, ...);

void free_amprotocol_packet(amprotocol_packet_t *packet);

#endif /* AMPROTOCOL_H */
