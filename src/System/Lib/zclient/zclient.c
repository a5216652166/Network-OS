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
#include "zclient.h"
#include "memory.h"
#include "table.h"

/* Zebra client events. */
enum event {ZCLIENT_SCHEDULE, ZCLIENT_READ, ZCLIENT_CONNECT};

/* Prototype for event manager. */
static void nclient_event (enum event, struct nclient *);

extern struct thread_master *master;

char *nclient_serv_path = NULL;

/* This file local debug flag. */
int nclient_debug = 0;

/* Allocate nclient structure. */
struct nclient *
nclient_new ()
{
  struct nclient *nclient;
  nclient = XCALLOC (MTYPE_ZCLIENT, sizeof (struct nclient));

  nclient->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  nclient->obuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  nclient->wb = buffer_new(0);

  return nclient;
}

/* This function is only called when exiting, because
   many parts of the code do not check for I/O errors, so they could
   reference an invalid pointer if the structure was ever freed.

   Free nclient structure. */
void
nclient_free (struct nclient *nclient)
{
  if (nclient->ibuf)
    stream_free(nclient->ibuf);
  if (nclient->obuf)
    stream_free(nclient->obuf);
  if (nclient->wb)
    buffer_free(nclient->wb);

  XFREE (MTYPE_ZCLIENT, nclient);
}

/* Initialize zebra client.  Argument redist_default is unwanted
   redistribute route type. */
void
nclient_init (struct nclient *nclient)
{
  int i;
  
  /* Enable zebra client connection by default. */
  nclient->enable = 1;

  /* Set -1 to the default socket value. */
  nclient->sock = -1;

  /* Schedule first nclient connection. */
  if (nclient_debug)
    zlog_debug ("nclient start scheduled");

  nclient_event (ZCLIENT_SCHEDULE, nclient);
}

/* Stop zebra client services. */
void
nclient_stop (struct nclient *nclient)
{
  if (nclient_debug)
    zlog_debug ("nclient stopped");

  /* Stop threads. */
  THREAD_OFF(nclient->t_read);
  THREAD_OFF(nclient->t_connect);
  THREAD_OFF(nclient->t_write);

  /* Reset streams. */
  stream_reset(nclient->ibuf);
  stream_reset(nclient->obuf);

  /* Empty the write buffer. */
  buffer_reset(nclient->wb);

  /* Close socket. */
  if (nclient->sock >= 0)
    {
      close (nclient->sock);
      nclient->sock = -1;
    }
  nclient->fail = 0;
}

void
nclient_reset (struct nclient *nclient)
{
  nclient_stop (nclient);
  nclient_init (nclient);
}

#ifdef HAVE_TCP_ZEBRA

/* Make socket to zebra daemon. Return zebra socket. */
static int
nclient_socket(void)
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
  serv.sin_port = htons (ZEBRA_PORT);
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
nclient_socket_un (const char *path)
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
 * @param nclient a pointer to nclient structure
 * @return socket fd just to make sure that connection established
 * @see nclient_init
 * @see nclient_new
 */
int
nclient_socket_connect (struct nclient *nclient)
{
#ifdef HAVE_TCP_ZEBRA
  nclient->sock = nclient_socket ();
#else
  nclient->sock = nclient_socket_un (nclient_serv_path ? nclient_serv_path : ZEBRA_SERV_PATH);
#endif
  return nclient->sock;
}

static int
nclient_failed(struct nclient *nclient)
{
  nclient->fail++;
  nclient_stop(nclient);
  nclient_event(ZCLIENT_CONNECT, nclient);
  return -1;
}

static int
nclient_flush_data(struct thread *thread)
{
  struct nclient *nclient = THREAD_ARG(thread);

  nclient->t_write = NULL;
  if (nclient->sock < 0)
    return -1;
  switch (buffer_flush_available(nclient->wb, nclient->sock))
    {
    case BUFFER_ERROR:
      zlog_warn("%s: buffer_flush_available failed on nclient fd %d, closing",
      		__func__, nclient->sock);
      return nclient_failed(nclient);
      break;
    case BUFFER_PENDING:
      nclient->t_write = thread_add_write(master, nclient_flush_data,
					  nclient, nclient->sock);
      break;
    case BUFFER_EMPTY:
      break;
    }
  return 0;
}

int
nclient_send_message(struct nclient *nclient)
{
  if (nclient->sock < 0)
    return -1;
  switch (buffer_write(nclient->wb, nclient->sock, STREAM_DATA(nclient->obuf),
		       stream_get_endp(nclient->obuf)))
    {
    case BUFFER_ERROR:
      zlog_warn("%s: buffer_write failed to nclient fd %d, closing",
      		 __func__, nclient->sock);
      return nclient_failed(nclient);
      break;
    case BUFFER_EMPTY:
      THREAD_OFF(nclient->t_write);
      break;
    case BUFFER_PENDING:
      THREAD_WRITE_ON(master, nclient->t_write,
		      nclient_flush_data, nclient, nclient->sock);
      break;
    }
  return 0;
}

void
nclient_create_header (struct stream *s, uint16_t command)
{
  /* length placeholder, caller can update */
  stream_putw (s, ZEBRA_HEADER_SIZE);
  stream_putc (s, ZEBRA_HEADER_MARKER);
  stream_putc (s, ZSERV_VERSION);
  stream_putw (s, command);
}

/* Send simple Zebra message. */
static int
zebra_message_send (struct nclient *nclient, int command)
{
  struct stream *s;

  /* Get nclient output buffer. */
  s = nclient->obuf;
  stream_reset (s);

  /* Send very simple command only Zebra message. */
  nclient_create_header (s, command);
  
  return nclient_send_message(nclient);
}

static int
zebra_hello_send (struct nclient *nclient)
{
#if 0
  struct stream *s;
  if (nclient->redist_default)
    {
      s = nclient->obuf;
      stream_reset (s);

      nclient_create_header (s, ZEBRA_HELLO);
      stream_putc (s, nclient->redist_default);
      stream_putw_at (s, 0, stream_get_endp (s));
      return nclient_send_message(nclient);
    }
#endif
  return 0;
}

/* Make connection to zebra daemon. */
int
nclient_start (struct nclient *nclient)
{
  int i;

  if (nclient_debug)
    zlog_debug ("nclient_start is called");

  /* nclient is disabled. */
  if (! nclient->enable)
    return 0;

  /* If already connected to the zebra. */
  if (nclient->sock >= 0)
    return 0;

  /* Check connect thread. */
  if (nclient->t_connect)
    return 0;

  if (nclient_socket_connect(nclient) < 0)
    {
      if (nclient_debug)
	zlog_debug ("nclient connection fail");
      nclient->fail++;
      nclient_event (ZCLIENT_CONNECT, nclient);
      return -1;
    }

  if (set_nonblocking(nclient->sock) < 0)
    zlog_warn("%s: set_nonblocking(%d) failed", __func__, nclient->sock);

  /* Clear fail count. */
  nclient->fail = 0;
  if (nclient_debug)
    zlog_debug ("nclient connect success with socket [%d]", nclient->sock);
      
  /* Create read thread. */
  nclient_event (ZCLIENT_READ, nclient);

  zebra_hello_send (nclient);

  return 0;
}

/* This function is a wrapper function for calling nclient_start from
   timer or event thread. */
static int
nclient_connect (struct thread *t)
{
  struct nclient *nclient;

  nclient = THREAD_ARG (t);
  nclient->t_connect = NULL;

  if (nclient_debug)
    zlog_debug ("nclient_connect is called");

  return nclient_start (nclient);
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
nclient_read (struct thread *thread)
{
  size_t already;
  uint16_t length, command;
  uint8_t marker, version;
  struct nclient *nclient;

  /* Get socket to zebra. */
  nclient = THREAD_ARG (thread);
  nclient->t_read = NULL;

  /* Read zebra header (if we don't have it already). */
  if ((already = stream_get_endp(nclient->ibuf)) < ZEBRA_HEADER_SIZE)
    {
      ssize_t nbyte;
      if (((nbyte = stream_read_try(nclient->ibuf, nclient->sock,
				     ZEBRA_HEADER_SIZE-already)) == 0) ||
	  (nbyte == -1))
	{
	  if (nclient_debug)
	   zlog_debug ("nclient connection closed socket [%d].", nclient->sock);
	  return nclient_failed(nclient);
	}
      if (nbyte != (ssize_t)(ZEBRA_HEADER_SIZE-already))
	{
	  /* Try again later. */
	  nclient_event (ZCLIENT_READ, nclient);
	  return 0;
	}
      already = ZEBRA_HEADER_SIZE;
    }

  /* Reset to read from the beginning of the incoming packet. */
  stream_set_getp(nclient->ibuf, 0);

  /* Fetch header values. */
  length = stream_getw (nclient->ibuf);
  marker = stream_getc (nclient->ibuf);
  version = stream_getc (nclient->ibuf);
  command = stream_getw (nclient->ibuf);
  
  if (marker != ZEBRA_HEADER_MARKER || version != ZSERV_VERSION)
    {
      zlog_err("%s: socket %d version mismatch, marker %d, version %d",
               __func__, nclient->sock, marker, version);
      return nclient_failed(nclient);
    }
  
  if (length < ZEBRA_HEADER_SIZE) 
    {
      zlog_err("%s: socket %d message length %u is less than %d ",
	       __func__, nclient->sock, length, ZEBRA_HEADER_SIZE);
      return nclient_failed(nclient);
    }

  /* Length check. */
  if (length > STREAM_SIZE(nclient->ibuf))
    {
      struct stream *ns;
      zlog_warn("%s: message size %u exceeds buffer size %lu, expanding...",
	        __func__, length, (u_long)STREAM_SIZE(nclient->ibuf));
      ns = stream_new(length);
      stream_copy(ns, nclient->ibuf);
      stream_free (nclient->ibuf);
      nclient->ibuf = ns;
    }

  /* Read rest of zebra packet. */
  if (already < length)
    {
      ssize_t nbyte;
      if (((nbyte = stream_read_try(nclient->ibuf, nclient->sock,
				     length-already)) == 0) ||
	  (nbyte == -1))
	{
	  if (nclient_debug)
	    zlog_debug("nclient connection closed socket [%d].", nclient->sock);
	  return nclient_failed(nclient);
	}
      if (nbyte != (ssize_t)(length-already))
	{
	  /* Try again later. */
	  nclient_event (ZCLIENT_READ, nclient);
	  return 0;
	}
    }

  length -= ZEBRA_HEADER_SIZE;

  if (nclient_debug)
    zlog_debug("nclient 0x%p command 0x%x \n", nclient, command);

  switch (command)
    {
    default:
      break;
    }

  if (nclient->sock < 0)
    /* Connection was closed during packet processing. */
    return -1;

  /* Register read thread. */
  stream_reset(nclient->ibuf);
  nclient_event (ZCLIENT_READ, nclient);

  return 0;
}

static void
nclient_event (enum event event, struct nclient *nclient)
{
  switch (event)
    {
    case ZCLIENT_SCHEDULE:
      if (! nclient->t_connect)
	nclient->t_connect =
	  thread_add_event (master, nclient_connect, nclient, 0);
      break;
    case ZCLIENT_CONNECT:
      if (nclient->fail >= 10)
	return;
      if (nclient_debug)
	zlog_debug ("nclient connect schedule interval is %d", 
		   nclient->fail < 3 ? 10 : 60);
      if (! nclient->t_connect)
	nclient->t_connect = 
	  thread_add_timer (master, nclient_connect, nclient,
			    nclient->fail < 3 ? 10 : 60);
      break;
    case ZCLIENT_READ:
      nclient->t_read = 
	thread_add_read (master, nclient_read, nclient, nclient->sock);
      break;
    }
}

void
nclient_serv_path_set (char *path)
{
  struct stat sb;

  /* reset */
  nclient_serv_path = NULL;

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
  nclient_serv_path = path;
}

