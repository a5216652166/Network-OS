#include <zebra.h>
#include "command.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "memory.h"
#include "network.h"
#include "table.h"
#include "log.h"
#include "stream.h"
#include "thread.h"
#include "zclient.h"
#include "filter.h"
#include "sockopt.h"
#include "privs.h"
#include "vtysh.h"
#include "libclient.h"
#include "libserv.h"
#include "linklist.h"


/* static prototypes */
/* For interface multicast configuration. */
#define IF_ZEBRA_MULTICAST_UNSPEC 0
#define IF_ZEBRA_MULTICAST_ON     1
#define IF_ZEBRA_MULTICAST_OFF    2

/* For interface shutdown configuration. */
#define IF_ZEBRA_SHUTDOWN_UNSPEC 0
#define IF_ZEBRA_SHUTDOWN_ON     1
#define IF_ZEBRA_SHUTDOWN_OFF    2

extern struct server_t serverd;

int  if_notify_interface_link_status (struct interface *ifp, int cmd)
{
	struct stream *s;
	struct listnode *node,*nnode;
	struct server *client;
	int rval = 0;

	for (ALL_LIST_ELEMENTS (serverd.client_list, node, nnode, client)) {
		s = client->obuf;
		stream_reset (s);
		client_create_header (s, cmd);
  		stream_putl (s, ifp->ifindex);
      		stream_putw_at (s, 0, stream_get_endp (s));
		rval = server_send_message(client);
	}
	return rval;
}
