/* IRON: iron_headers */
/*
 * Distribution A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
 * DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
 * Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contracts No. HR0011-15-C-0097 and
 * HR0011-17-C-0050. Any opinions, findings and conclusions or
 * recommendations expressed in this material are those of the author(s)
 * and do not necessarily reflect the views of the Defense Advanced
 * Research Project Agency.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* IRON: end */
#include "VirtIF.hh"
#include "IPPacket.hh"
#include "ZLog.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" {
#include <linux/if_tun.h>
};

VirtIF::VirtIF() 
{
  _viffd = -1;
}

VirtIF::~VirtIF() 
{
  close();
}

bool VirtIF::open
	(const char *dev)
{
  struct ifreq ifr;
  int          err;

  if (dev)
    {
      strncpy(&_devName[0], dev, IFNAMSIZ);
    }
  else
    {
      zlogE("VirtIF","open", 
	    ("Device name must be specified\n"));
      return false;
    }

  if ((_viffd = ::open((char *)"/dev/net/tun", O_RDWR)) < 0 )
    {
      zlogE("VirtIF","open", 
	    ("Could not open tun/tap device\n"));
      return false;
    }
  
  memset(&ifr, 0, sizeof(ifr));
  
  /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
   *        IFF_TAP   - TAP device (includes ethernet headers)  
   *
   *        IFF_NO_PI - Do not provide packet information  
   */ 
  
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  
  strncpy(ifr.ifr_name,&_devName[0],IFNAMSIZ);

  if ((err = ::ioctl(_viffd, TUNSETIFF, (void *) &ifr)) < 0)
    {
      zlogE("VirtIF","open", 
	    ("ioctl failed on device %s\n",ifr.ifr_name));
      close();
      return false;
    }

  return true;
}

void VirtIF::close() 
{
  // Close the virtual interface

  if (_viffd != -1) 
  {
    ::close(_viffd);
  }
  _viffd = -1;

}

void VirtIF::send(const IPPacket *qPkt) 
{
  int nWritten;
  
  zlogD("VirtIF","send",
	("Sending packet through VIF device\n"));

  if ((nWritten = write(_viffd, qPkt->getPktData(), qPkt->getPktLen())) 
      != qPkt->getPktLen())
    {
      zlogE("VirtIF","send",
	    ("errno=%s\n",strerror(errno)));
    }
  else
    {
      zlogD("VirtIF","send",
	    ("sent %d bytes\n",nWritten));
    }
}

void VirtIF::send(const IPPacket& qPkt) 
{
  int nWritten;
  
  zlogD("VirtIF","send",
	("Sending packet through VIF device\n"));

  if ((nWritten = write(_viffd, qPkt.getPktData(), qPkt.getPktLen())) 
      != qPkt.getPktLen())
    {
      zlogE("VirtIF","send",
	    ("errno=%s\n",strerror(errno)));
    }
  else
    {
      zlogD("VirtIF","send",
	    ("sent %d bytes\n",nWritten));
    }
}

void VirtIF::recv(IPPacket& qPkt) 
{
  zlogD("VirtIF","recv",
       ("Receiving packet on VIF device\n"));

  int nRead = read(_viffd, qPkt.getPktData(), qPkt.getMaxPktSize());

  if (nRead < 0)
  {
    zlogE("VirtIF","recv",
	  ("errno=%s\n",strerror(errno)));
    qPkt.setPktLen(0);
  }
  else
  {
    zlogD("VirtIF","recv",
	  ("received %d bytes\n",nRead));
    qPkt.setPktLen(nRead);
  }
}
