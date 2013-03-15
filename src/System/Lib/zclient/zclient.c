/* Zebra's client library.
 * Copyright (C) 1999 Kunihiro Ishiguro
 * Copyright (C) 2005 Andrew J. Schorr
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"
#include "buffer.h"
#include "network.h"
#include "if.h"
#include "log.h"
#include "thread.h"
#include "libclient.h"
#include "memory.h"
#include "table.h"

/* Zebra client events. */
enum event {ZCLIENT_SCHEDULE, ZCLIENT_READ, ZCLIENT_CONNECT};

/* Prototype for event manager. */
static void client_event (enum event, struct client *);

extern struct thread_master *master;

extern char *client_serv_path = NULL;

static int client_port = -1;

/* This file local debug flag. */
int client_debug = 0;

/* Allocate client structure. */
struct client *
client_new ()
{
  struct client *client;
  client = XCALLOC (MTYPE_ZCLIENT, sizeof (struct client));

  client->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  client->obuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  client->wb = buffer_new(0);

  return client;
}

/* This function is only called when exiting, because
   many parts of the code do not check for I/O errors, so they could
   reference an invalid pointer if the structure was ever freed.

   Free client structure. */
void
client_free (struct client *client)
{
  if (client->ibuf)
    stream_free(client->ibuf);
  if (client->obuf)
    stream_free(client->obuf);
  if (client->wb)
    buffer_free(client->wb);

  XFREE (MTYPE_ZCLIENT, client);
}

/* Initialize zebra client.  Argument redist_default is unwanted
   redistribute route type. */
void
client_init (struct client *client)
{
  int i;
  
  /* Enable zebra client connection by default. */
  client->enable = 1;

  /* Set -1 to the default socket value. */
  client->sock = -1;

  /* Schedule first client connection. */
  if (client_debug)
    zlog_debug ("client start scheduled");

  client_event (ZCLIENT_SCHEDULE, client);
}

/* Stop zebra client services. */
void
client_stop (struct client *client)
{
  if (client_debug)
    zlog_debug ("client stopped");

  /* Stop threads. */
  THREAD_OFF(client->t_read);
  THREAD_OFF(client->t_connect);
  THREAD_OFF(client->t_write);

  /* Reset streams. */
  stream_reset(client->ibuf);
  stream_reset(client->obuf);

  /* Empty the write buffer. */
  buffer_reset(client->wb);

  /* Close socket. */
  if (client->sock >= 0)
    {
      close (client->sock);
      client->sock = -1;
    }
  client->fail = 0;
}

void
client_reset (struct client *client)
{
  client_stop (client);
  client_init (client);
}

#if 1

/* Make socket to zebra daemon. Return zebra socket. */
static int
client_socket(void)
{
  int sock;
  int ret;
  struct sockaddr_in serv;

  /* We should think about IPv6 connection. */
  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;
  
  /* Make server socket. */ 
  memset (&serv, 0, sizeof (struct sockaddr_in));
  serv.sin_family = AF_INET;
  serv.sin_port = htons (client_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
  serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
  serv.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  /* Connect to zebra. */
  ret = connect (sock, (struct sockaddr *) &serv, sizeof (serv));
  if (ret < 0)
    {
      close (sock);
      return -1;
    }
  return sock;
}

#else

/* For sockaddr_un. */
#include <sys/un.h>

static int
client_socket_un (const char *path)
{
  int ret;
  int sock, len;
  struct sockaddr_un addr;

  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;
  
  /* Make server socket. */ 
  memset (&addr, 0, sizeof (struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, path, strlen (path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
  len = addr.sun_len = SUN_LEN(&addr);
#else
  len = sizeof (addr.sun_family) + strlen (addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

  ret = connect (sock, (struct sockaddr *) &addr, len);
  if (ret < 0)
    {
      close (sock);
      return -1;
    }
  return sock;
}

#endif /* HAVE_TCP_ZEBRA */

/**
 * Connect to zebra daemon.
 * @param client a pointer to client structure
 * @return socket fd just to make sure that connection established
 * @see client_init
 * @see client_new
 */
int
client_socket_connect (struct client *client)
{
  client->sock = client_socket ();
  return client->sock;
}

static int
client_failed(struct client *client)
{
  client->fail++;
  client_stop(client);
  client_event(ZCLIENT_CONNECT, client);
  return -1;
}

static int
client_flush_data(struct thread *thread)
{
  struct client *client = THREAD_ARG(thread);

  client->t_write = NULL;
  if (client->sock < 0)
    return -1;
  switch (buffer_flush_available(client->wb, client->sock))
    {
    case BUFFER_ERROR:
      zlog_warn("%s: buffer_flush_available failed on client fd %d, closing",
      		__func__, client->sock);
      return client_failed(client);
      break;
    case BUFFER_PENDING:
      client->t_write = thread_add_write(master, client_flush_data,
					  client, client->sock);
      break;
    case BUFFER_EMPTY:
      break;
    }
  return 0;
}

int
client_send_message(struct client *client)
{
  if (client->sock < 0)
    return -1;
  switch (buffer_write(client->wb, client->sock, STREAM_DATA(client->obuf),
		       stream_get_endp(client->obuf)))
    {
    case BUFFER_ERROR:
      zlog_warn("%s: buffer_write failed to client fd %d, closing",
      		 __func__, client->sock);
      return client_failed(client);
      break;
    case BUFFER_EMPTY:
      THREAD_OFF(client->t_write);
      break;
    case BUFFER_PENDING:
      THREAD_WRITE_ON(master, client->t_write,
		      client_flush_data, client, client->sock);
      break;
    }
  return 0;
}

void
client_create_header (struct stream *s, uint16_t command)
{
  /* length placeholder, caller can update */
  stream_putw (s, ZEBRA_HEADER_SIZE);
  stream_putc (s, ZEBRA_HEADER_MARKER);
  stream_putc (s, ZSERV_VERSION);
  stream_putw (s, command);
}

/* Send simple Zebra message. */
static int
zebra_message_send (struct client *client, int command)
{
  struct stream *s;

  /* Get client output buffer. */
  s = client->obuf;
  stream_reset (s);

  /* Send very simple command only Zebra message. */
  client_create_header (s, command);
  
  return client_send_message(client);
}

static int
zebra_hello_send (struct client *client)
{
#if 0
  struct stream *s;
  if (client->redist_default)
    {
      s = client->obuf;
      stream_reset (s);

      client_create_header (s, ZEBRA_HELLO);
      stream_putc (s, client->redist_default);
      stream_putw_at (s, 0, stream_get_endp (s));
      return client_send_message(client);
    }
#endif
  return 0;
}

/* Make connection to zebra daemon. */
int
client_start (struct client *client)
{
  int i;

  if (client_debug)
    zlog_debug ("client_start is called");

  /* client is disabled. */
  if (! client->enable)
    return 0;

  /* If already connected to the zebra. */
  if (client->sock >= 0)
    return 0;

  /* Check connect thread. */
  if (client->t_connect)
    return 0;

  if (client_socket_connect(client) < 0)
    {
      if (client_debug)
	zlog_debug ("client connection fail");
      client->fail++;
      client_event (ZCLIENT_CONNECT, client);
      return -1;
    }

  if (set_nonblocking(client->sock) < 0)
    zlog_warn("%s: set_nonblocking(%d) failed", __func__, client->sock);

  /* Clear fail count. */
  client->fail = 0;
  if (client_debug)
    zlog_debug ("client connect success with socket [%d]", client->sock);
      
  /* Create read thread. */
  client_event (ZCLIENT_READ, client);

  zebra_hello_send (client);

  return 0;
}

/* This function is a wrapper function for calling client_start from
   timer or event thread. */
static int
client_connect (struct thread *t)
{
  struct client *client;

  client = THREAD_ARG (t);
  client->t_connect = NULL;

  if (client_debug)
    zlog_debug ("client_connect is called");

  return client_start (client);
}
static int
memconstant(const void *s, int c, size_t n)
{
  const u_char *p = s;

  while (n-- > 0)
    if (*p++ != c)
      return 0;
  return 1;
}

/* Zebra client message read function. */
static int
client_read (struct thread *thread)
{
  size_t already;
  uint16_t length, command;
  uint8_t marker, version;
  struct client *client;

  /* Get socket to zebra. */
  client = THREAD_ARG (thread);
  client->t_read = NULL;

  /* Read zebra header (if we don't have it already). */
  if ((already = stream_get_endp(client->ibuf)) < ZEBRA_HEADER_SIZE)
    {
      ssize_t nbyte;
      if (((nbyte = stream_read_try(client->ibuf, client->sock,
				     ZEBRA_HEADER_SIZE-already)) == 0) ||
	  (nbyte == -1))
	{
	  if (client_debug)
	   zlog_debug ("client connection closed socket [%d].", client->sock);
	  return client_failed(client);
	}
      if (nbyte != (ssize_t)(ZEBRA_HEADER_SIZE-already))
	{
	  /* Try again later. */
	  client_event (ZCLIENT_READ, client);
	  return 0;
	}
      already = ZEBRA_HEADER_SIZE;
    }

  /* Reset to read from the beginning of the incoming packet. */
  stream_set_getp(client->ibuf, 0);

  /* Fetch header values. */
  length = stream_getw (client->ibuf);
  marker = stream_getc (client->ibuf);
  version = stream_getc (client->ibuf);
  command = stream_getw (client->ibuf);
  
  if (marker != ZEBRA_HEADER_MARKER || version != ZSERV_VERSION)
    {
      zlog_err("%s: socket %d version mismatch, marker %d, version %d",
               __func__, client->sock, marker, version);
      return client_failed(client);
    }
  
  if (length < ZEBRA_HEADER_SIZE) 
    {
      zlog_err("%s: socket %d message length %u is less than %d ",
	       __func__, client->sock, length, ZEBRA_HEADER_SIZE);
      return client_failed(client);
    }

  /* Length check. */
  if (length > STREAM_SIZE(client->ibuf))
    {
      struct stream *ns;
      zlog_warn("%s: message size %u exceeds buffer size %lu, expanding...",
	        __func__, length, (u_long)STREAM_SIZE(client->ibuf));
      ns = stream_new(length);
      stream_copy(ns, client->ibuf);
      stream_free (client->ibuf);
      client->ibuf = ns;
    }

  /* Read rest of zebra packet. */
  if (already < length)
    {
      ssize_t nbyte;
      if (((nbyte = stream_read_try(client->ibuf, client->sock,
				     length-already)) == 0) ||
	  (nbyte == -1))
	{
	  if (client_debug)
	    zlog_debug("client connection closed socket [%d].", client->sock);
	  return client_failed(client);
	}
      if (nbyte != (ssize_t)(length-already))
	{
	  /* Try again later. */
	  client_event (ZCLIENT_READ, client);
	  return 0;
	}
    }

  length -= ZEBRA_HEADER_SIZE;

  if (client_debug)
    zlog_debug("client 0x%p command 0x%x \n", client, command);

  switch (command)
    {
    default:
	client->call_back (command, client, length);
      break;
    }

  if (client->sock < 0)
    /* Connection was closed during packet processing. */
    return -1;

  /* Register read thread. */
  stream_reset(client->ibuf);
  client_event (ZCLIENT_READ, client);

  return 0;
}

static void
client_event (enum event event, struct client *client)
{
  switch (event)
    {
    case ZCLIENT_SCHEDULE:
      if (! client->t_connect)
	client->t_connect =
	  thread_add_event (master, client_connect, client, 0);
      break;
    case ZCLIENT_CONNECT:
      if (client->fail >= 10)
	return;
      if (client_debug)
	zlog_debug ("client connect schedule interval is %d", 
		   client->fail < 3 ? 10 : 60);
      if (! client->t_connect)
	client->t_connect = 
	  thread_add_timer (master, client_connect, client,
			    client->fail < 3 ? 10 : 60);
      break;
    case ZCLIENT_READ:
      client->t_read = 
	thread_add_read (master, client_read, client, client->sock);
      break;
    }
}

void
client_serv_path_set (char *path)
{
  struct stat sb;

  /* reset */
  client_serv_path = NULL;

  /* test if `path' is socket. don't set it otherwise. */
  if (stat(path, &sb) == -1)
    {
      zlog_warn ("%s: zebra socket `%s' does not exist", __func__, path);
      return;
    }

  if ((sb.st_mode & S_IFMT) != S_IFSOCK)
    {
      zlog_warn ("%s: `%s' is not unix socket, sir", __func__, path);
      return;
    }

  /* it seems that path is unix socket */
  client_serv_path = path;
}

void client_set_port (int port)
{
	client_port = port;
	return 0;
}
