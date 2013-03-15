/*
 * Common ioctl functions.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "linklist.h"
#include "if.h"
#include "prefix.h"
//#include "ioctl.h"
#include "log.h"
#include "privs.h"

//#include "zebra/rib.h"
//#include "zebra/rt.h"
//#include "zebra/interface.h"

#ifdef HAVE_BSD_LINK_DETECT
#include <net/if_media.h>
#endif /* HAVE_BSD_LINK_DETECT*/

extern struct zebra_privs_t ifMgrd_privs;

static void
if_flags_mangle (struct interface *ifp, uint64_t *newflags)
{
#ifdef SUNOS_5
  struct zebra_if *zif = ifp->info;
  
  zif->primary_state = *newflags & (IFF_UP & 0xff);
  
  if (CHECK_FLAG (zif->primary_state, IFF_UP)
      || listcount(ifp->connected) > 0)
    SET_FLAG (*newflags, IFF_UP);
  else
    UNSET_FLAG (*newflags, IFF_UP);
#endif /* SUNOS_5 */
}


/* Update the flags field of the ifp with the new flag set provided.
 * Take whatever actions are required for any changes in flags we care
 * about.
 *
 * newflags should be the raw value, as obtained from the OS.
 */
void
if_flags_update (struct interface *ifp, uint64_t newflags)
{
  if_flags_mangle (ifp, &newflags);
    
  if (if_is_operative (ifp))
    {
      /* operative -> inoperative? */
      ifp->flags = newflags;
      if (!if_is_operative (ifp))
        if_down (ifp);
    }
  else
    {
      /* inoperative -> operative? */
      ifp->flags = newflags;
      if (if_is_operative (ifp))
        if_up (ifp);
    }
}


/* clear and set interface name string */
void
ifreq_set_name (struct ifreq *ifreq, struct interface *ifp)
{
  strncpy (ifreq->ifr_name, ifp->name, IFNAMSIZ);
}

/* call ioctl system call */
int
if_ioctl (u_long request, caddr_t buffer)
{
  int sock;
  int ret;
  int err;

  if (ifMgrd_privs.change(ZPRIVS_RAISE))
    zlog (NULL, LOG_ERR, "Can't raise privileges");
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      int save_errno = errno;
      if (ifMgrd_privs.change(ZPRIVS_LOWER))
        zlog (NULL, LOG_ERR, "Can't lower privileges");
      zlog_err("Cannot create UDP socket: %s", safe_strerror(save_errno));
      exit (1);
    }
  if ((ret = ioctl (sock, request, buffer)) < 0)
    err = errno;
  if (ifMgrd_privs.change(ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");
  close (sock);
  
  if (ret < 0) 
    {
      errno = err;
      return ret;
    }
  return 0;
}

/* get interface flags */
void
if_get_flags (struct interface *ifp)
{
  int ret;
  struct ifreq ifreq;
#ifdef HAVE_BSD_LINK_DETECT
  struct ifmediareq ifmr;
#endif /* HAVE_BSD_LINK_DETECT */

  ifreq_set_name (&ifreq, ifp);

  ret = if_ioctl (SIOCGIFFLAGS, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      zlog_err("if_ioctl(SIOCGIFFLAGS) failed: %s", safe_strerror(errno));
      return;
    }
#ifdef HAVE_BSD_LINK_DETECT /* Detect BSD link-state at start-up */

  /* Per-default, IFF_RUNNING is held high, unless link-detect says
   * otherwise - we abuse IFF_RUNNING inside zebra as a link-state flag,
   * following practice on Linux and Solaris kernels
   */
  SET_FLAG(ifreq.ifr_flags, IFF_RUNNING);
  
  if (CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
    {
      (void) memset(&ifmr, 0, sizeof(ifmr));
      strncpy (ifmr.ifm_name, ifp->name, IFNAMSIZ);
      
      /* Seems not all interfaces implement this ioctl */
      if (if_ioctl(SIOCGIFMEDIA, (caddr_t) &ifmr) < 0)
        zlog_err("if_ioctl(SIOCGIFMEDIA) failed: %s", safe_strerror(errno));
      else if (ifmr.ifm_status & IFM_AVALID) /* Link state is valid */
        {
          if (ifmr.ifm_status & IFM_ACTIVE)
            SET_FLAG(ifreq.ifr_flags, IFF_RUNNING);
          else
            UNSET_FLAG(ifreq.ifr_flags, IFF_RUNNING);
        }
  }
#endif /* HAVE_BSD_LINK_DETECT */

  if_flags_update (ifp, (ifreq.ifr_flags & 0x0000ffff));
}

/* Set interface flags */
int
if_set_flags (struct interface *ifp, uint64_t flags)
{
  int ret;
  struct ifreq ifreq;

  memset (&ifreq, 0, sizeof(struct ifreq));
  ifreq_set_name (&ifreq, ifp);

  ifreq.ifr_flags = ifp->flags;
  ifreq.ifr_flags |= flags;

  ret = if_ioctl (SIOCSIFFLAGS, (caddr_t) &ifreq);

  if (ret < 0)
    {
      zlog_info ("can't set interface flags");
      return ret;
    }
  return 0;
}

/* Unset interface's flag. */
int
if_unset_flags (struct interface *ifp, uint64_t flags)
{
  int ret;
  struct ifreq ifreq;

  memset (&ifreq, 0, sizeof(struct ifreq));
  ifreq_set_name (&ifreq, ifp);

  ifreq.ifr_flags = ifp->flags;
  ifreq.ifr_flags &= ~flags;

  ret = if_ioctl (SIOCSIFFLAGS, (caddr_t) &ifreq);

  if (ret < 0)
    {
      zlog_info ("can't unset interface flags");
      return ret;
    }
  return 0;
}

