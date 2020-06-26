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
#include <string.h>
#include <stdio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "IPPacket.hh"

/**
 * IPPacket memory pool
 */

IPPacketPool *IPPacket::_packetPool = (IPPacketPool *) NULL;



/**
 * Constructor that builds 
 */
IPPacket::IPPacket(unsigned long  saddr,
                     unsigned long  daddr,
                     unsigned short sport,
                     unsigned short dport,
                     unsigned long  protocol)
{
  struct iphdr  *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;
  
  //  struct icmphdr *icmp;
  
  ip = (struct iphdr *)&_pktdata[0];
  
  // IP header
  
  ip->version  = 4;                           // IPv4
  ip->ihl      = 5;                           // Standard 20 byte header
  ip->tos      = 0;                           // Default TOS setting
  ip->id       = 1;                           // Nominal IP packet ID
  ip->frag_off = 0;                           // No fragmentation
  ip->ttl      = 64;                          // Something believable
  ip->protocol = protocol;                    // Whatever protocol was specified
  ip->check    = 0;                           // Zero checksum until payload available
  ip->tot_len  = htons(sizeof(struct iphdr)); // Initially this is only the IP header
  ip->saddr    = htonl(saddr);                // Source address specified
  ip->daddr    = htonl(daddr);                // Destination address specified
  
  _pktlen      = sizeof(struct iphdr);
  
  // Protocol-specific header
  
  if (protocol == IPPROTO_TCP) // This is TCP
  {
    tcp = (struct tcphdr *)&_pktdata[sizeof(struct iphdr)];
    
    // TCP header
    
    tcp->source  = htons(sport);              // from port 
    tcp->dest    = htons(dport);              // to port
    tcp->seq     = ntohl(1);                  // Nominal value
    tcp->ack_seq = ntohl(1);                  // Nominal value
    tcp->doff    = sizeof(struct tcphdr) / 4; // barebones TCP header
    tcp->res1    = 0;                         // Nominal value
    tcp->res2    = 0;                         // Nominal value
    tcp->urg     = 0;                         // Nominal value
    tcp->ack     = 0;                         // Nominal value
    tcp->psh     = 0;                         // Nominal value
    tcp->rst     = 0;                         // Nominal value
    tcp->syn     = 0;                         // Nominal value
    tcp->fin     = 0;                         // Nominal value
    tcp->window  = ntohs(32);                 // Nominal value
    tcp->check   = 0;                         // Need to caclulate this
    tcp->urg_ptr = 0;                         // Nominal value
    
    ip->tot_len  = htons(ntohs(ip->tot_len) + sizeof(struct tcphdr));
    _pktlen     += sizeof(struct tcphdr);
  }
  
  else if (protocol == IPPROTO_UDP) // This is UDP
  {
    // UDP header
    
    udp = (struct udphdr *)&_pktdata[sizeof(struct iphdr)];
    
    udp->source  = htons(sport);                                   // from specified port
    udp->dest    = htons(dport);                                   // to specified port
    udp->len     = ntohs((unsigned short)(sizeof(struct udphdr))); // Nominal value
    udp->check   = 0;                                              // Nominal value
    
    ip->tot_len  = htons(ntohs(ip->tot_len) + sizeof(struct udphdr));
    _pktlen     += sizeof(struct udphdr);
  }
}

bool IPPacket::getFiveTuple 
	(unsigned long  &saddr,
	 unsigned long  &daddr,
	 unsigned short &sport,
	 unsigned short &dport,
	 unsigned int   &proto) const
{
  struct iphdr  *ip;
  struct udphdr *udp;
  struct tcphdr *tcp;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  if (ip->protocol == IPPROTO_TCP)       // TCP
    {
      if (_pktlen < (int)((ip->ihl * 4) + sizeof(struct tcphdr)))
	{
	  return false;
	}
      
      tcp   = (struct tcphdr *)&_pktdata[ip->ihl * 4];
      sport = htons(tcp->source);
      dport = htons(tcp->dest);
    }
  else if (ip->protocol == IPPROTO_UDP) // UDP
    {
      if (_pktlen < (int)((ip->ihl * 4) + sizeof(struct udphdr)))
	{
	  return false;
	}
      
      udp   = (struct udphdr *)&_pktdata[ip->ihl * 4];
      sport = htons(udp->source);
      dport = htons(udp->dest);
    }
  else // Not TCP or UDP
    {
      return false;
    }

  saddr = htonl(ip->saddr);
  daddr = htonl(ip->daddr);
  proto = ip->protocol;

  return true;
}

bool IPPacket::getSrcAddr (unsigned long &saddr) const
{
  struct iphdr  *ip;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  saddr = ip->saddr;

  return true;
}

bool IPPacket::getDstAddr (unsigned long &daddr) const 
{
  struct iphdr  *ip;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  daddr = ip->daddr;

  return true;
}

bool IPPacket::getProtocol (unsigned long &protocol) const
{
  struct iphdr  *ip;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  protocol = ip->protocol;

  return true;
}

bool IPPacket::getSrcPort (unsigned short &sport) const
{
  struct iphdr  *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  if (ip->protocol == IPPROTO_TCP)       // TCP
    {
      tcp   = (struct tcphdr *)&_pktdata[ip->ihl * 4];
      sport = tcp->source;
    }
  else if (ip->protocol == IPPROTO_UDP) // UDP
    {
      udp   = (struct udphdr *)&_pktdata[ip->ihl * 4];
      sport = udp->source;
    }

  return true;
}

bool IPPacket::getDstPort (unsigned short &dport) const 
{
  struct iphdr  *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  if (ip->protocol == IPPROTO_TCP)
    {
      tcp   = (struct tcphdr *)&_pktdata[ip->ihl * 4];
      dport = tcp->dest;
    }
  else if (ip->protocol == IPPROTO_UDP)
    {
      udp   = (struct udphdr *)&_pktdata[ip->ihl * 4];
      dport = udp->dest;
    }

  return true;
}

bool IPPacket::getDSCP (unsigned char &dscp) const
{
  struct iphdr  *ip;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  dscp = ip->tos;

  return true;
}

bool IPPacket::setSrcPort (unsigned short sport) const
{
  struct iphdr  *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  if (ip->protocol == IPPROTO_TCP)       // TCP
    {
      tcp         = (struct tcphdr *)&_pktdata[ip->ihl * 4];
      tcp->source = sport;
    }
  else if (ip->protocol == IPPROTO_UDP) // UDP
    {
      udp         = (struct udphdr *)&_pktdata[ip->ihl * 4];
      udp->source = sport;
    }

  return true;
}

bool IPPacket::setDstPort (unsigned short dport) const 
{
  struct iphdr  *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  if (ip->protocol == IPPROTO_TCP)       // TCP
    {
      tcp       = (struct tcphdr *)&_pktdata[ip->ihl * 4];
      tcp->dest = dport;
    }
  else if (ip->protocol == IPPROTO_UDP) // UDP
    {
      udp       = (struct udphdr *)&_pktdata[ip->ihl * 4];
      udp->dest = dport;
    }

  return true;
}

bool IPPacket::setDSCP (unsigned char dscp) const
{
  struct iphdr  *ip;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  ip->tos = dscp;

  return true;
}


bool IPPacket::getVariousLens(unsigned short &ipLen,
                               unsigned short &ipHdrLen,
                               unsigned short &xportLen) const
{
  struct iphdr *ip;
  struct udphdr *udp;

  ipLen    = 0;
  xportLen = 0;
  
  // Must at least long enough for an IP header for this to make sense

  if (_pktlen < (int)sizeof(struct iphdr))
    return false;

  ip       = (struct iphdr  *)&_pktdata[0];
  ipLen    = ntohs(ip->tot_len);
  ipHdrLen = ip->ihl*4;

  if (ip->protocol == IPPROTO_UDP)
    {
      if (_pktlen >= (int)((ip->ihl * 4) + sizeof(struct udphdr)))
	{
	  udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
	  xportLen = htons(udp->len);
	}
    }
  
  return true;
}

bool IPPacket::updateIPLen () const
{
  struct iphdr *ip;
  struct udphdr *udp;

  // Must at least long enough for an IP header for this to make sense

  if (_pktlen < (int)sizeof(struct iphdr))
    return false;

  ip          = (struct iphdr  *)&_pktdata[0];
  ip->tot_len = htons((unsigned short)_pktlen);

  if (ip->protocol == IPPROTO_UDP)
    {
      if (_pktlen >= (int)((ip->ihl * 4) + sizeof(struct udphdr)))
	{
	  udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
	  udp->len = htons((unsigned short)(_pktlen - (ip->ihl * 4)));
	}
    }
  
  return true;
}

bool IPPacket::updateIPLen (const int len)
{
  struct iphdr *ip;
  struct udphdr *udp;

  // Must at least long enough for an IP header for this to make sense

  if (len < (int)sizeof(struct iphdr))
    return false;

  _pktlen = len;

  ip          = (struct iphdr  *)&_pktdata[0];
  ip->tot_len = htons((unsigned short)_pktlen);

  if (ip->protocol == IPPROTO_UDP)
    {
      if (_pktlen >= (int)((ip->ihl * 4) + sizeof(struct udphdr)))
	{
	  udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
	  udp->len = htons((unsigned short)(_pktlen - (ip->ihl * 4)));
	}
    }
  
  return true;
}

bool IPPacket::trimIPLen (const int len)
{
  struct iphdr *ip;
  struct udphdr *udp;
  
  // Need at least "len" bytes
  
  if (_pktlen < len)
    {
      return false;
    }
  
  _pktlen     -= len;
  
  ip           = (struct iphdr  *)&_pktdata[0];
  ip->tot_len  = htons((unsigned short)_pktlen);
  
  if (ip->protocol == IPPROTO_UDP)
    {
      udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
      udp->len = htons((unsigned short)(_pktlen - (ip->ihl * 4)));
    }
  
  return true;
}

bool IPPacket::updateChecksums () const 
{
  if (!updateTransportChecksum())
    return false;

  if (!updateIPChecksum())
    return false;
  
  return true;
}

bool IPPacket::updateIPChecksum () const
{
  struct iphdr   *ip       = (struct iphdr *)&_pktdata[0];

  int             nleft    = ip->ihl * 4;
  int             sum      = 0;

  unsigned short *w        = (unsigned short *)ip;
  unsigned short  odd_byte = 0;
  
  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  /* We absolutely must clear the checksum */

  ip->check = 0;

  /*
   * Our algorithm is simple.  Using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the carry
   * bits from the top 16 bits into the lower 16 bits.qPkt.getPktData()
   */

  while (nleft > 1)
  {
    sum   += *w++;
    nleft -= 2;
  }
  
  /*
   * Mop up an odd byte, if necessary.
   */
  
  if (nleft == 1)
  {
    *(unsigned char *)(&odd_byte) = *(unsigned char *)w;
    sum += odd_byte;
  }
  
  /*
   * Add back carry outs from top 16 bits to low 16 bits.
   */
  sum     = (sum >> 16) + (sum & 0xffff);  /* add hi 16 to low 16 */
  sum    += (sum >> 16);                   /* add carry */
  
  ip->check = (unsigned short)~sum;

  return true;
}

bool IPPacket::updateTransportChecksum () const
{
  struct iphdr  *ip  = (struct iphdr  *)&_pktdata[0];
  struct udphdr *udp = (struct udphdr *)NULL;
  struct tcphdr *tcp = (struct tcphdr *)NULL;

  unsigned char *hdr;

  unsigned long saddr;
  unsigned long daddr;
  unsigned long protocol;
  unsigned      len;

  if (!getSrcAddr(saddr))
    return false;

  if (!getDstAddr(daddr))
    return false;

  if (!getProtocol(protocol))
    return false;

  hdr = (unsigned char *)&_pktdata[ip->ihl * 4];

  if (protocol == IPPROTO_TCP) // TCP
    {
      tcp        = (struct tcphdr *)hdr;
      tcp->check = 0;
    }
  else if (protocol == IPPROTO_UDP) // UDP
    {
      udp        = (struct udphdr *)hdr;
      udp->check = 0;
    }
  else
    {
      return false;
    }

  len = _pktlen - (ip->ihl * 4);

  unsigned short  pbuf[4];
  unsigned short *buf;
  unsigned long   sum = 0;
  unsigned        i;

  // Everything added to the sum must be in NETWORK BYTE ORDER!
  // Caller absolutely MUST clear the checksum field before
  // calling this function
  
  /*
   * Compute the transport psuedo header checksum.  Do not actually assemble the
   * psuedo header in memory, just add in the fields required.  These are:
   *
   *    0      7 8     15 16    23 24    31 
   *   +--------+--------+--------+--------+
   *   |          source address           |
   *   +--------+--------+--------+--------+
   *   |        destination address        |
   *   +--------+--------+--------+--------+
   *   |  zero  |protocol|     length      |
   *   +--------+--------+--------+--------+
   */
  
  memcpy((void *)&pbuf[0],&saddr,sizeof(saddr));
  memcpy((void *)&pbuf[2],&daddr,sizeof(daddr));

  for (i=0; i<4; i++)
  {
    sum += pbuf[i];
  }

  sum += htons((unsigned short)protocol);
  sum += htons((unsigned short)len);
  
  // Add a pad byte if needed at the end of the data.
  
  if (len & 0x1)
  {
    ((char *)hdr)[len] = 0;
    len++;
  }
  
  // Compute the transport header and data checksum.  Convert len from number of
  // bytes to number of shorts to make things easier.
  
  len /= 2;
  buf  = (unsigned short *)hdr;
  
  for (i = 0; i < len; i++)
  {
    sum += *buf;
    buf++;
  }
  
  // Add back carry.  Do this twice, just to be sure.
  
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  
  // Return the ones complement of sum
  
  if (protocol == IPPROTO_TCP) // TCP
    {
      tcp->check = ((unsigned short)(~sum));
    }
  else // if (protocol == IPPROTO_UDP) // UDP
    {
      udp->check = ((unsigned short)(~sum));
    }

  return true;
}

bool IPPacket::insertBlockInPayload
	(void         *data,
	 unsigned int  len,
	 unsigned int  offset)
{
  struct iphdr  *ip;
  struct udphdr *udp;
  unsigned long  protocol;

  // Must have enough room

  if ((_pktlen + len) > MAXPKTSIZE)
    {
      return false;
    }

  long start     = getPayloadOffset() + offset;
  long moveBytes = _pktlen - start;

  if (moveBytes < 0)
    {
      return false;
    }

  memmove(&_pktdata[start+len],&_pktdata[start],moveBytes);
  memcpy (&_pktdata[start    ],data,            len);

  _pktlen += len;

  // Make sure to adjust the various embedded lengths

  ip          = (struct iphdr  *)&_pktdata[0];
  ip->tot_len = htons(ntohs(ip->tot_len) + len);


  getProtocol(protocol);
  if (protocol == IPPROTO_UDP)
    {
      udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
      udp->len = htons((ntohs(udp->len) + len));
    }

  return true;
}

bool IPPacket::deleteBlockFromPayload
	(void         *data,
	 unsigned int  len,
	 unsigned int  offset)
{
  struct iphdr  *ip;
  struct udphdr *udp;
  unsigned long  protocol;

  // Must have enough data

  if (_pktlen < (int)len)
    {
      return false;
    }

  long start     = getPayloadOffset() + offset;
  long moveBytes = _pktlen - start - len;

  if (moveBytes < 0)
    {
      return false;
    }

  memcpy (data,            &_pktdata[start    ],len);
  memmove(&_pktdata[start],&_pktdata[start+len],moveBytes);
  _pktlen -= len;

  // Make sure to adjust the various embedded lengths

  ip          = (struct iphdr  *)&_pktdata[0];
  ip->tot_len = htons(ntohs(ip->tot_len) - len);

  getProtocol(protocol);
  if (protocol == IPPROTO_UDP)
    {
      udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
      udp->len = htons((ntohs(udp->len) - len));
    }

  return true;
}

bool IPPacket::appendBlockToEnd
  	(void         *data,
	 unsigned int  len)
{
  struct iphdr  *ip;
  struct udphdr *udp;
  unsigned long  protocol;

 // Must have enough room

  if ((_pktlen + (int)len) > MAXPKTSIZE)
    {
      return false;
    }

  memcpy (&_pktdata[_pktlen],data,len);

  _pktlen += len;

  // Make sure to adjust the various embedded lengths

  ip          = (struct iphdr  *)&_pktdata[0];
  ip->tot_len = htons(ntohs(ip->tot_len) + len);

  getProtocol(protocol);

  if (protocol == IPPROTO_UDP)
    {
      udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
      udp->len = htons((ntohs(udp->len) + len));
    }

  return true;
}
 
/**
 * Support routine to copy and remove a block of data from the end of an IPPacket
 */
bool IPPacket::removeBlockFromEnd
	(void         *data,
	 unsigned int  len)
{
  struct iphdr  *ip;
  struct udphdr *udp;
  unsigned long  protocol;

  // Must have enough data

  if (_pktlen < (int)len)
    {
      return false;
    }

  _pktlen -= len;

  memcpy (data,&_pktdata[_pktlen],len);

  // Make sure to adjust the various embedded lengths
  ip          = (struct iphdr  *)&_pktdata[0];
  ip->tot_len = htons(ntohs(ip->tot_len) - len);

  getProtocol(protocol);
  if (protocol == IPPROTO_UDP)
    {
      udp      = (struct udphdr *)&_pktdata[ip->ihl * 4];
      udp->len = htons((ntohs(udp->len) - len));
    }

  return true;
}

/**
 * Support routine to copy a block of data from the end of an IPPacket
 */
bool IPPacket::copyBlockFromEnd
	(void         *data,
	 unsigned int  len)
{
  // Must have enough data

  if (_pktlen < (int)len)
    {
      return false;
    }

  memcpy (data,&_pktdata[_pktlen-len],len);

  return true;
}

unsigned long IPPacket::getPayloadOffset () const
{
  struct iphdr  *ip;
  struct tcphdr *tcp;
  unsigned long  protocol;

  // Need at least an IP header to go further

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return (_pktlen);
    }

  ip = (struct iphdr  *)&_pktdata[0];

  getProtocol(protocol);

  if (protocol == IPPROTO_TCP) // TCP
    {
      // Need at least a TCP header to go further

      if (_pktlen < (int)((ip->ihl * 4) + sizeof(struct tcphdr)))
	{
	  return (_pktlen);
	}

      tcp = (struct tcphdr *)&_pktdata[ip->ihl * 4];

      return ((ip->ihl * 4) + (tcp->doff * 4));

    }
  else if (protocol == IPPROTO_UDP) // UDP
    {
      // Need at least a UDP header to go further

      if (_pktlen < (int)((ip->ihl * 4) + sizeof(struct udphdr)))
	{
	  return (_pktlen);
	}

      return ((ip->ihl * 4) + sizeof(struct udphdr));
    }
  else
    {
      return (_pktlen);
    }
}
//=============================================================================
unsigned long IPPacket::getPayloadLen () const
{
  return (_pktlen - getPayloadOffset());
}

//=============================================================================
IPPacket *IPPacket::clone()
{
  IPPacket *rpkt = new IPPacket();

  if (rpkt != NULL)
    {
      memcpy(rpkt->getPktData(), &_pktdata[0], _pktlen);
      rpkt->setPktLen(_pktlen);
    }

  return (rpkt);
}

IPPacket *IPPacket::cloneHeaderOnly()
{
  IPPacket *rpkt = new IPPacket();

  struct iphdr  *ip;
  struct udphdr *udp;

  int   hdrLen = getPayloadOffset();
  byte *hdrPtr;

  if (rpkt != NULL)
    {
      memcpy(rpkt->getPktData(), &_pktdata[0], hdrLen);
      rpkt->setPktLen(hdrLen);
    }

  hdrPtr = rpkt->getPktData();

  ip           = (struct iphdr  *)hdrPtr;
  ip->tot_len  = htons((unsigned short)hdrLen);
  
  if (ip->protocol == IPPROTO_UDP)
    {
      udp      = (struct udphdr *)&hdrPtr[ip->ihl * 4];
      udp->len = htons((unsigned short)(hdrLen - (ip->ihl * 4)));
    }
  
  return (rpkt);
}

IPPacket *IPPacket::cloneIPHeaderOnly()
{
  IPPacket *rpkt = new IPPacket();

  struct iphdr  *ip;
  int hdrLen;
  
  ip     = (struct iphdr  *)&_pktdata[0];
  hdrLen = ip->ihl * 4;
                 
  if (rpkt != NULL)
    {
      byte *hdrPtr = rpkt->getPktData();
      
      memcpy((void *)hdrPtr, &_pktdata[0], hdrLen);

      // Fixup the various parameters

      ip           = (struct iphdr  *)hdrPtr;
      ip->tot_len  = htons((unsigned short)hdrLen);


      // Update the control structure
      
      rpkt->setPktLen(hdrLen);
    }

  return (rpkt);
}

std::ostream& operator<<(std::ostream& o, const IPPacket& qpkt)
{
  o << (void*)qpkt._pktdata << "[" << qpkt.getPktLen() << "," << qpkt.getMaxSize() << "]";
  return o;
}



//=============================================================================

bool IPPacket::isDFSet() 
{
  struct iphdr  *ip;
  
  // Need at least an IP header to go further

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  ip = (struct iphdr  *)&_pktdata[0];
  
  if ( ntohs(ip->frag_off) & IP_DF ) return true;
  else return false;
}

//=============================================================================
bool IPPacket::setDF(bool val)
{
  struct iphdr  *ip;
    
  // Need at least an IP header to go further

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }
  
  ip = (struct iphdr  *)&_pktdata[0];
  
  if ( val ) {
    ip->frag_off |= htons(IP_DF);
  } else {
    ip->frag_off &= htons(0xBFFF);
  }

  return true;
}


//=============================================================================
bool IPPacket::isMFSet() 
{
  struct iphdr  *ip;
  
  // Need at least an IP header to go further

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  ip = (struct iphdr  *)&_pktdata[0];
  
  if ( ntohs(ip->frag_off) & IP_MF ) return true;
  else return false;
}



//=============================================================================
bool IPPacket::getIHLen (unsigned int &len) const
{
  struct iphdr  *ip;

  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  len = ip->ihl;

  return true;
}


//=============================================================================
bool IPPacket::setMF(bool val)
{
  struct iphdr  *ip;
    
  // Need at least an IP header to go further

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }
  
  ip = (struct iphdr  *)&_pktdata[0];
  
  if ( val ) 
    {
      ip->frag_off |= htons(IP_MF);
    } 
  else 
    {
      ip->frag_off &= htons((unsigned short)~0xDFFF);
    }

  return true;
}


//=============================================================================
bool IPPacket::getFragmentOffset(int &offset) const
{
  struct iphdr  *ip;
  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  // get the offset
  offset = ntohs(ip->frag_off) & IP_OFFMASK ;
  
  return true;
}

//=============================================================================
bool IPPacket::setFragmentOffset(int offset) {

  struct iphdr  *ip;
  
  // Need at least an IP header

  if (_pktlen < (int)sizeof(struct iphdr))
    {
      return false;
    }

  // Get the IP header

  ip = (struct iphdr *)&_pktdata[0];

  // Clear the offset 
  ip->frag_off &= htons(0xE000);

  // Set the offset
  ip->frag_off |= htons(offset & IP_OFFMASK);
  
  return true;
}
