/* Zebra daemon server routine.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <zebra.h>

#include "prefix.h"
#include "command.h"
#include "if.h"
#include "thread.h"
#include "stream.h"
#include "memory.h"
#include "table.h"
#include "network.h"
#include "sockunion.h"
#include "log.h"
#include "libclient.h"
#include "privs.h"
#include "network.h"
#include "buffer.h"

#include "libserv.h"

int server_port = -1;

extern struct thread_master *master;

/* Event list of server. */
enum event { ZEBRA_SERV, ZEBRA_READ, ZEBRA_WRITE };

struct server_t serverd;

static void server_event (enum event event, int sock, struct server *client);

extern struct zebra_privs_t server_privs;

static void server_client_close (struct server *client);

static int
server_delayed_close(struct thread *thread)
{
  struct server *client = THREAD_ARG(thread);

  client->t_suicide = NULL;
  server_client_close(client);
  return 0;
}

/* When client connects, it sends hello message
 * with promise to send server routes of specific type.
 * Zebra stores a socket fd of the client into
 * this array. And use it to clean up routes that
 * client didn't remove for some reasons after closing
 * connection.
 */
static int route_type_oaths[ZEBRA_ROUTE_MAX];

static int
server_flush_data(struct thread *thread)
{
  struct server *client = THREAD_ARG(thread);

  client->t_write = NULL;
  if (client->t_suicide)
    {
      server_client_close(client);
      return -1;
    }
  switch (buffer_flush_available(client->wb, client->sock))
    {
    case BUFFER_ERROR:
      zlog_warn("%s: buffer_flush_available failed on server client fd %d, "
      		"closing", __func__, client->sock);
      server_client_close(client);
      break;
    case BUFFER_PENDING:
      client->t_write = thread_add_write(master, server_flush_data,
      					 client, client->sock);
      break;
    case BUFFER_EMPTY:
      break;
    }
  return 0;
}

int
server_send_message(struct server *client)
{
  if (client->t_suicide)
    return -1;
  switch (buffer_write(client->wb, client->sock, STREAM_DATA(client->obuf),
		       stream_get_endp(client->obuf)))
    {
    case BUFFER_ERROR:
      zlog_warn("%s: buffer_write failed to server client fd %d, closing",
      		 __func__, client->sock);
      /* Schedule a delayed close since many of the functions that call this
         one do not check the return code.  They do not allow for the
	 possibility that an I/O error may have caused the client to be
	 deleted. */
      client->t_suicide = thread_add_event(master, server_delayed_close,
					   client, 0);
      return -1;
    case BUFFER_EMPTY:
      THREAD_OFF(client->t_write);
      break;
    case BUFFER_PENDING:
      THREAD_WRITE_ON(master, client->t_write,
		      server_flush_data, client, client->sock);
      break;
    }
  return 0;
}

void
server_create_header (struct stream *s, uint16_t cmd)
{
  /* length placeholder, caller can update */
  stream_putw (s, ZEBRA_HEADER_SIZE);
  stream_putc (s, ZEBRA_HEADER_MARKER);
  stream_putc (s, ZSERV_VERSION);
  stream_putw (s, cmd);
}

static void
server_encode_interface (struct stream *s, struct interface *ifp)
{
  /* Interface information. */
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);
  stream_putl (s, ifp->ifindex);
  stream_putc (s, ifp->status);
  stream_putq (s, ifp->flags);
  stream_putl (s, ifp->metric);
  stream_putl (s, ifp->mtu);
  stream_putl (s, ifp->mtu6);
  stream_putl (s, ifp->bandwidth);
#ifdef HAVE_STRUCT_SOCKADDR_DL
  stream_put (s, &ifp->sdl, sizeof (ifp->sdl_storage));
#else
  stream_putl (s, ifp->hw_addr_len);
  if (ifp->hw_addr_len)
    stream_put (s, ifp->hw_addr, ifp->hw_addr_len);
#endif /* HAVE_STRUCT_SOCKADDR_DL */

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));
}

/* Close server client. */
static void
server_client_close (struct server *client)
{
  /* Close file descriptor. */
  if (client->sock)
    {
      close (client->sock);
      client->sock = -1;
    }

  /* Free stream buffers. */
  if (client->ibuf)
    stream_free (client->ibuf);
  if (client->obuf)
    stream_free (client->obuf);
  if (client->wb)
    buffer_free(client->wb);

  /* Release threads. */
  if (client->t_read)
    thread_cancel (client->t_read);
  if (client->t_write)
    thread_cancel (client->t_write);
  if (client->t_suicide)
    thread_cancel (client->t_suicide);

  /* Free client structure. */
  listnode_delete (serverd.client_list, client);
  XFREE (0, client);
}

/* Make new client. */
static void
server_client_create (int sock)
{
  struct server *client;

  client = XCALLOC (0, sizeof (struct server));

  /* Make client input/output buffer. */
  client->sock = sock;
  client->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  client->obuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  client->wb = buffer_new(0);

  /* Add this client to linked list. */
  listnode_add (serverd.client_list, client);
  
  /* Make new read thread. */
  server_event (ZEBRA_READ, sock, client);
}

/* Handler of server service request. */
static int
server_client_read (struct thread *thread)
{
  int sock;
  struct server *client;
  size_t already;
  uint16_t length, command;
  uint8_t marker, version;

  /* Get thread data.  Reset reading thread because I'm running. */
  sock = THREAD_FD (thread);
  client = THREAD_ARG (thread);
  client->t_read = NULL;

  if (client->t_suicide)
    {
      server_client_close(client);
      return -1;
    }

  /* Read length and command (if we don't have it already). */
  if ((already = stream_get_endp(client->ibuf)) < ZEBRA_HEADER_SIZE)
    {
      ssize_t nbyte;
      if (((nbyte = stream_read_try (client->ibuf, sock,
				     ZEBRA_HEADER_SIZE-already)) == 0) ||
	  (nbyte == -1))
	{
	  //if (IS_ZEBRA_DEBUG_EVENT)
	   // zlog_debug ("connection closed socket [%d]", sock);
	  server_client_close (client);
	  return -1;
	}
      if (nbyte != (ssize_t)(ZEBRA_HEADER_SIZE-already))
	{
	  /* Try again later. */
	  server_event (ZEBRA_READ, sock, client);
	  return 0;
	}
      already = ZEBRA_HEADER_SIZE;
    }

  /* Reset to read from the beginning of the incoming packet. */
  stream_set_getp(client->ibuf, 0);

  /* Fetch header values */
  length = stream_getw (client->ibuf);
  marker = stream_getc (client->ibuf);
  version = stream_getc (client->ibuf);
  command = stream_getw (client->ibuf);

  if (marker != ZEBRA_HEADER_MARKER || version != ZSERV_VERSION)
    {
      zlog_err("%s: socket %d version mismatch, marker %d, version %d",
               __func__, sock, marker, version);
      server_client_close (client);
      return -1;
    }
  if (length < ZEBRA_HEADER_SIZE) 
    {
      zlog_warn("%s: socket %d message length %u is less than header size %d",
	        __func__, sock, length, ZEBRA_HEADER_SIZE);
      server_client_close (client);
      return -1;
    }
  if (length > STREAM_SIZE(client->ibuf))
    {
      zlog_warn("%s: socket %d message length %u exceeds buffer size %lu",
	        __func__, sock, length, (u_long)STREAM_SIZE(client->ibuf));
      server_client_close (client);
      return -1;
    }

  /* Read rest of data. */
  if (already < length)
    {
      ssize_t nbyte;
      if (((nbyte = stream_read_try (client->ibuf, sock,
				     length-already)) == 0) ||
	  (nbyte == -1))
	{
	  //if (IS_ZEBRA_DEBUG_EVENT)
	  //  zlog_debug ("connection closed [%d] when reading server data", sock);
	  server_client_close (client);
	  return -1;
	}
      if (nbyte != (ssize_t)(length-already))
        {
	  /* Try again later. */
	  server_event (ZEBRA_READ, sock, client);
	  return 0;
	}
    }

  length -= ZEBRA_HEADER_SIZE;

  /* Debug packet information. */
  //if (IS_ZEBRA_DEBUG_EVENT)
  //  zlog_debug ("server message comes from socket [%d]", sock);

  //if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
  //  zlog_debug ("server message received [%s] %d", 
//	       server_command_string (command), length);

  switch (command) 
    {
    default:
      zlog_info ("Zebra received unknown command %d", command);
      break;
    }

  if (client->t_suicide)
    {
      /* No need to wait for thread callback, just kill immediately. */
      server_client_close(client);
      return -1;
    }

  stream_reset (client->ibuf);
  server_event (ZEBRA_READ, sock, client);
  return 0;
}


/* Accept code of server server socket. */
static int
server_accept (struct thread *thread)
{
  int accept_sock;
  int client_sock;
  struct sockaddr_in client;
  socklen_t len;

  accept_sock = THREAD_FD (thread);

  /* Reregister myself. */
  server_event (ZEBRA_SERV, accept_sock, NULL);

  len = sizeof (struct sockaddr_in);
  client_sock = accept (accept_sock, (struct sockaddr *) &client, &len);

  if (client_sock < 0)
    {
      zlog_warn ("Can't accept server socket: %s", safe_strerror (errno));
      return -1;
    }

  /* Make client socket non-blocking.  */
  set_nonblocking(client_sock);
  
  /* Create new server client. */
  server_client_create (client_sock);

  return 0;
}

#if 1
/* Make server's server socket. */
static void
server_serv ()
{
  int ret;
  int accept_sock;
  struct sockaddr_in addr;

  accept_sock = socket (AF_INET, SOCK_STREAM, 0);

  if (accept_sock < 0) 
    {
      zlog_warn ("Can't create server stream socket: %s", 
                 safe_strerror (errno));
      zlog_warn ("server can't provice full functionality due to above error");
      return;
    }

  memset (&route_type_oaths, 0, sizeof (route_type_oaths));
  memset (&addr, 0, sizeof (struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (server_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
  addr.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  sockopt_reuseaddr (accept_sock);
  sockopt_reuseport (accept_sock);

  if ( server_privs.change(ZPRIVS_RAISE) )
    zlog (NULL, LOG_ERR, "Can't raise privileges");
    
  ret  = bind (accept_sock, (struct sockaddr *)&addr, 
	       sizeof (struct sockaddr_in));
  if (ret < 0)
    {
      zlog_warn ("Can't bind to stream socket: %s", 
                 safe_strerror (errno));
      zlog_warn ("server can't provice full functionality due to above error");
      close (accept_sock);      /* Avoid sd leak. */
      return;
    }
    
  if ( server_privs.change(ZPRIVS_LOWER) )
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  ret = listen (accept_sock, 1);
  if (ret < 0)
    {
      zlog_warn ("Can't listen to stream socket: %s", 
                 safe_strerror (errno));
      zlog_warn ("server can't provice full functionality due to above error");
      close (accept_sock);	/* Avoid sd leak. */
      return;
    }

  server_event (ZEBRA_SERV, accept_sock, NULL);
}
#endif /* HAVE_TCP_ZEBRA */

/* For sockaddr_un. */
#include <sys/un.h>

/* server server UNIX domain socket. */
static void
server_serv_un (const char *path)
{
  int ret;
  int sock, len;
  struct sockaddr_un serv;
  mode_t old_mask;

  /* First of all, unlink existing socket */
  unlink (path);

  /* Set umask */
  old_mask = umask (0077);

  /* Make UNIX domain socket. */
  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      zlog_warn ("Can't create server unix socket: %s", 
                 safe_strerror (errno));
      zlog_warn ("server can't provide full functionality due to above error");
      return;
    }

  memset (&route_type_oaths, 0, sizeof (route_type_oaths));

  /* Make server socket. */
  memset (&serv, 0, sizeof (struct sockaddr_un));
  serv.sun_family = AF_UNIX;
  strncpy (serv.sun_path, path, strlen (path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
  len = serv.sun_len = SUN_LEN(&serv);
#else
  len = sizeof (serv.sun_family) + strlen (serv.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

  ret = bind (sock, (struct sockaddr *) &serv, len);
  if (ret < 0)
    {
      zlog_warn ("Can't bind to unix socket %s: %s", 
                 path, safe_strerror (errno));
      zlog_warn ("server can't provide full functionality due to above error");
      close (sock);
      return;
    }

  ret = listen (sock, 5);
  if (ret < 0)
    {
      zlog_warn ("Can't listen to unix socket %s: %s", 
                 path, safe_strerror (errno));
      zlog_warn ("server can't provide full functionality due to above error");
      close (sock);
      return;
    }

  umask (old_mask);

  server_event (ZEBRA_SERV, sock, NULL);
}


static void
server_event (enum event event, int sock, struct server *client)
{
  switch (event)
    {
    case ZEBRA_SERV:
      thread_add_read (master, server_accept, client, sock);
      break;
    case ZEBRA_READ:
      client->t_read = 
	thread_add_read (master, server_client_read, client, sock);
      break;
    case ZEBRA_WRITE:
      /**/
      break;
    }
}

/* Initialisation of server and installation of commands. */
void
server_init (void)
{
  /* Client list init. */
  serverd.client_list = list_new ();
}

void server_set_port (int port)
{
	server_port = port;
	return 0;
}

/* Make server server socket, wiping any existing one (see bug #403). */
void
server_socket_init (char *path)
{
#if 1
  server_serv ();
#else
  server_serv_un (path ? path : ZEBRA_SERV_PATH);
#endif /* HAVE_TCP_ZEBRA */
}
