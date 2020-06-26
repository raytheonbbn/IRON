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
#include "RawIF.hh"
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

#include <linux/filter.h>

RawIF::RawIF() 
{
  _rawfd    = -1;
}

RawIF::~RawIF() 
{
  close();
}

bool RawIF::open
	()
{
  // Open the raw socket

  if ((_rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_ESP)) < 0) 
    {
      zlogE("RawIF","open", 
	    ("failed to open raw socket\n"));
      close();
      return false;
    }

  // Tell the kernel that we are going to send down the packet
  // with the IP header already to go

  int one = 1;

  if (setsockopt(_rawfd,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one)) < 0)
    {
      zlogW("RawIF","open", 
	    ("failed to set HDRINCL option on raw socket\n"));
      close();
      return false;
    }

  return true;
}

void RawIF::close() 
{
  // Close the raw sockets.

  if (_rawfd != -1) 
  {
    ::close(_rawfd);
  }
  _rawfd = -1;
}


void RawIF::send(const IPPacket *qPkt) 
{
  unsigned long  daddr;
  unsigned short dport;
  int nWritten;
  
  struct sockaddr_in tgtAddr;

  zlogD("RawIF","send",
	("Sending packet through RawIF socket\n"));

  // Setup the sendto address

  qPkt->getDstAddr(daddr);
  qPkt->getDstPort(dport);

  tgtAddr.sin_family      = AF_INET;
  tgtAddr.sin_addr.s_addr = daddr;
  tgtAddr.sin_port        = dport;

  if ((nWritten = sendto(_rawfd, 
			 qPkt->getPktData(), 
			 qPkt->getPktLen(),
			 0,
			 (struct sockaddr *)&tgtAddr,
			 sizeof(tgtAddr)))
      != qPkt->getPktLen())
  {
    zlogW("RawIF","send",
          ("errno=%s\n",strerror(errno)));
  }
  else
  {
    zlogD("RawIF","send",
          ("sent %d bytes\n",nWritten));
  }
}

void RawIF::send(const IPPacket& qPkt) 
{
  unsigned long  daddr;
  unsigned short dport;
  int nWritten;

  struct sockaddr_in tgtAddr;
  
  zlogD("RawIF","send",
	("Sending packet through RawIF socket\n"));

  // Setup the sendto address

  qPkt.getDstAddr(daddr);
  qPkt.getDstPort(dport);

  tgtAddr.sin_family      = AF_INET;
  tgtAddr.sin_addr.s_addr = daddr;
  tgtAddr.sin_port        = dport;

  if ((nWritten = sendto(_rawfd, 
			 qPkt.getPktData(), 
			 qPkt.getPktLen(),
			 0,
			 (struct sockaddr *)&tgtAddr,
			 sizeof(tgtAddr)))
      != qPkt.getPktLen())
  {
    zlogW("RawIF","send",
          ("errno=%s\n",strerror(errno)));
  }
  else
  {
    zlogD("RawIF","send",
          ("sent %d bytes\n",nWritten));
  }
}

void RawIF::recv(IPPacket& qPkt) 
{
  zlogD("RawIF","recv",
       ("Receiving packet on RawIF socket\n"));

  int nRead = read(_rawfd, qPkt.getPktData(), qPkt.getMaxPktSize());

  if (nRead < 0)
  {
    zlogW("RawIF","recv",
	  ("errno=%s\n",strerror(errno)));
    qPkt.setPktLen(0);
  }
  else
  {
    zlogD("RawIF","recv",
	  ("received %d bytes\n",nRead));
    qPkt.setPktLen(nRead);
  }
}

