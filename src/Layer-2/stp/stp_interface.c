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


/* static prototypes */

extern struct zebra_privs_t stpd_privs;
vector stp_enable_interface;

/* This will be executed when interface goes up. */
static void
stp_request_interface (struct interface *ifp)
{
  /* In default stpd doesn't send RIP_REQUEST to the loopback interface. */
  if (if_is_loopback (ifp))
    return;

  /* If interface is down, don't send RIP packet. */
  if (! if_is_operative (ifp))
    return;


}

/* Multicast packet receive socket. */
int
stp_interface_down (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;

  s = zclient->ibuf;  

  /* zebra_interface_state_read() updates interface structure in
     iflist. */
  ifp = zebra_interface_state_read(s);

  if (ifp == NULL)
    return 0;

  stp_if_down(ifp);
 
  if (0)
    zlog_debug ("interface %s index %d flags %llx metric %d mtu %d is down",
	       ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
	       ifp->metric, ifp->mtu);

  return 0;
}

/* Inteface link up message processing */
int
stp_interface_up (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  /* zebra_interface_state_read () updates interface structure in
     iflist. */
  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

//  if (STP_DEBUG)
    zlog_debug ("interface %s index %d flags %#llx metric %d mtu %d is up",
	       ifp->name, ifp->ifindex, (unsigned long long) ifp->flags,
	       ifp->metric, ifp->mtu);

  return 0;
}

/* Inteface addition message from zebra. */
int
stp_interface_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

//  if (IS_RIP_DEBUG_ZEBRA)
    zlog_debug ("interface add %s index %d flags %#llx metric %d mtu %d",
		ifp->name, ifp->ifindex, (unsigned long long) ifp->flags,
		ifp->metric, ifp->mtu);

  return 0;
}

int
stp_interface_delete (int command, struct zclient *zclient,
		      zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;


  s = zclient->ibuf;  
  /* zebra_interface_state_read() updates interface structure in iflist */
  ifp = zebra_interface_state_read(s);

  if (ifp == NULL)
    return 0;

  if (if_is_up (ifp)) {
    //stp_if_down(ifp);
  } 
  
  zlog_info("interface delete %s index %d flags %#llx metric %d mtu %d",
	    ifp->name, ifp->ifindex, (unsigned long long) ifp->flags,
	    ifp->metric, ifp->mtu);
  
  /* To support pseudo interface do not free interface structure.  */
  /* if_delete(ifp); */
  ifp->ifindex = IFINDEX_INTERNAL;

  return 0;
}

void
stp_interface_clean (void)
{
  struct listnode *node;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
    }
}

void
stp_interface_reset (void)
{
  struct listnode *node;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
    }
}

int
stp_if_down(struct interface *ifp)
{
  return 0;
}

/* Needed for stop RIP process. */
void
stp_if_down_all ()
{
  struct interface *ifp;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (iflist, node, nnode, ifp))
    stp_if_down (ifp);
}


static int
stp_enable_if_lookup (const char *ifname)
{
  unsigned int i;
  char *str;

  for (i = 0; i < vector_active (stp_enable_interface); i++)
    if ((str = vector_slot (stp_enable_interface, i)) != NULL)
      if (strcmp (str, ifname) == 0)
	return i;
  return -1;
}

/* Add interface to stp_enable_if. */
static int
stp_enable_if_add (const char *ifname)
{
  int ret;

  ret = stp_enable_if_lookup (ifname);
  if (ret >= 0)
    return -1;

  vector_set (stp_enable_interface, strdup (ifname));


  return 1;
}

/* Delete interface from stp_enable_if. */
static int
stp_enable_if_delete (const char *ifname)
{
  int index;
  char *str;

  index = stp_enable_if_lookup (ifname);
  if (index < 0)
    return -1;

  str = vector_slot (stp_enable_interface, index);
  free (str);
  vector_unset (stp_enable_interface, index);

  return 1;
}

/* Join to multicast group and send request to the interface. */
static int
stp_interface_wakeup (struct thread *t)
{
  struct interface *ifp;

  /* Get interface. */
  ifp = THREAD_ARG (t);

  return 0;
}

/* Write stp configuration of each interface. */
static int
stp_interface_config_write (struct vty *vty)
{
  return 0;
}

static struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
  1,
};

/* Called when interface structure allocated. */
static int
stp_interface_new_hook (struct interface *ifp)
{
  return 0;
}

/* Called when interface structure deleted. */
static int
stp_interface_delete_hook (struct interface *ifp)
{
  ifp->info = NULL;
  return 0;
}

/* Allocate and initialize interface vector. */
void
stp_if_init (void)
{
  /* Default initial size of interface vector. */
  if_init();
  if_add_hook (IF_NEW_HOOK, stp_interface_new_hook);
  if_add_hook (IF_DELETE_HOOK, stp_interface_delete_hook);
  
  /* Install interface node. */
  install_node (&interface_node, stp_interface_config_write);

  /* Install commands. */
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (CONFIG_NODE, &no_interface_cmd);
  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
}
