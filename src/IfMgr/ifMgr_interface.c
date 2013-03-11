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

#include "zebra/connected.h"

/* static prototypes */

extern struct zebra_privs_t ifMgrd_privs;
vector ifMgr_enable_interface;

/* This will be executed when interface goes up. */
static void
ifMgr_request_interface (struct interface *ifp)
{
  /* In default ifMgrd doesn't send RIP_REQUEST to the loopback interface. */
  if (if_is_loopback (ifp))
    return;

  /* If interface is down, don't send RIP packet. */
  if (! if_is_operative (ifp))
    return;


}

/* Multicast packet receive socket. */
int
ifMgr_interface_down (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;

  s = zclient->ibuf;  

  /* zebra_interface_state_read() updates interface structure in
     iflist. */
  ifp = zebra_interface_state_read(s);

  if (ifp == NULL)
    return 0;

  ifMgr_if_down(ifp);
 
  if (0)
    zlog_debug ("interface %s index %d flags %llx metric %d mtu %d is down",
	       ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
	       ifp->metric, ifp->mtu);

  return 0;
}

/* Inteface link up message processing */
int
ifMgr_interface_up (int command, struct zclient *zclient, zebra_size_t length)
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
ifMgr_interface_add (int command, struct zclient *zclient, zebra_size_t length)
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
ifMgr_interface_delete (int command, struct zclient *zclient,
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
    //ifMgr_if_down(ifp);
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
ifMgr_interface_clean (void)
{
  struct listnode *node;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
    }
}

void
ifMgr_interface_reset (void)
{
  struct listnode *node;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
    }
}

int
ifMgr_if_down(struct interface *ifp)
{
  return 0;
}

/* Needed for stop RIP process. */
void
ifMgr_if_down_all ()
{
  struct interface *ifp;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (iflist, node, nnode, ifp))
    ifMgr_if_down (ifp);
}


static int
ifMgr_enable_if_lookup (const char *ifname)
{
  unsigned int i;
  char *str;

  for (i = 0; i < vector_active (ifMgr_enable_interface); i++)
    if ((str = vector_slot (ifMgr_enable_interface, i)) != NULL)
      if (strcmp (str, ifname) == 0)
	return i;
  return -1;
}

/* Add interface to ifMgr_enable_if. */
static int
ifMgr_enable_if_add (const char *ifname)
{
  int ret;

  ret = ifMgr_enable_if_lookup (ifname);
  if (ret >= 0)
    return -1;

  vector_set (ifMgr_enable_interface, strdup (ifname));


  return 1;
}

/* Delete interface from ifMgr_enable_if. */
static int
ifMgr_enable_if_delete (const char *ifname)
{
  int index;
  char *str;

  index = ifMgr_enable_if_lookup (ifname);
  if (index < 0)
    return -1;

  str = vector_slot (ifMgr_enable_interface, index);
  free (str);
  vector_unset (ifMgr_enable_interface, index);

  return 1;
}

/* Join to multicast group and send request to the interface. */
static int
ifMgr_interface_wakeup (struct thread *t)
{
  struct interface *ifp;

  /* Get interface. */
  ifp = THREAD_ARG (t);

  return 0;
}

/* Write ifMgr configuration of each interface. */
static int
ifMgr_interface_config_write (struct vty *vty)
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
ifMgr_interface_new_hook (struct interface *ifp)
{
  return 0;
}

/* Called when interface structure deleted. */
static int
ifMgr_interface_delete_hook (struct interface *ifp)
{
  ifp->info = NULL;
  return 0;
}

/* Allocate and initialize interface vector. */
void
ifMgr_if_init (void)
{
  /* Default initial size of interface vector. */
  if_add_hook (IF_NEW_HOOK, ifMgr_interface_new_hook);
  if_add_hook (IF_DELETE_HOOK, ifMgr_interface_delete_hook);
  
  /* Install interface node. */
  install_node (&interface_node, ifMgr_interface_config_write);

  /* Install commands. */
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (CONFIG_NODE, &no_interface_cmd);
  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &ospf_cost_u32_inet4_cmd_vtysh);
}
