// IRON: iron_headers
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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <pcap.h>
#include <pcap/sll.h>
#include <math.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdint.h>

static int32_t removeSondHeader
	(char *dumpFileIn, 
         char *dumpFileOut);

int main
	(int    argc, 
	 char **argv)
{
  int32_t nPkts;

  if (argc < 3)
    {
      printf("Usage: sonddecap sond_dumpfile_in decap_dumpfile_out\n");
      exit(-1);
    }

  nPkts = removeSondHeader(argv[1],argv[2]);

  printf("Converted %d packets\n",nPkts); 

  return (0);
}

static int32_t removeSondHeader
	(char *dumpFileIn, 
         char *dumpFileOut)
{
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *p        = (pcap_t        *)NULL;
  pcap_dumper_t *q = (pcap_dumper_t *)NULL;

  struct pcap_pkthdr pktHdr;
  struct sll_header *sll = (struct sll_header *)NULL;;

  int ptype;

  uint16_t netProto;
  int32_t  plen;
  int32_t  iphlen;
  int32_t  frhlen;

  uint8_t* pktDataIn;
  uint8_t  pktDataOut[65536];
  
  struct ether_header *eth;
  struct iphdr        *ip;

  int32_t nPkts   = 0;
  int32_t badPkts = 0;

  // Open the capture file

  if ((p = pcap_open_offline(dumpFileIn,&errbuf[0])) == NULL)
    {
      printf("Open failed: explanation is:\n    %s\n",&errbuf[0]);
      nPkts = -1;
      goto ErrorExit;
    }
  
  // Can only process the file if we have ethernet or cooked packets
  
  ptype = pcap_datalink(p);

  if ((ptype != DLT_EN10MB   ) && 
      (ptype != DLT_LINUX_SLL))
    {
      printf("This application only understands dumps from ethernet or cooked captures\n");
      nPkts = -1;
      goto ErrorExit;
    }

  // Open the output file

  if ((q = pcap_dump_open(p,dumpFileOut)) == NULL)
    {
      printf("Open failed: explanation is:\n    %s\n",&errbuf[0]);
      nPkts = -1;
      goto ErrorExit;
    }

  // Begin processing the data

  while ((pktDataIn = (unsigned char *) pcap_next(p,&pktHdr)) != NULL)
    {
      // Retrieve the IP header if this is an IP packet
      
      ip = NULL;
      if (ptype == DLT_EN10MB)
	{
	  // Get the ethernet payload
	  
	  eth      = (struct ether_header *)pktDataIn;
	  netProto = ntohs(eth->ether_type);
	  
	  frhlen   = sizeof(struct ether_header);

	  if (netProto == ETHERTYPE_IP)
	    {
	      ip = (struct iphdr *)&pktDataIn[sizeof(struct ether_header)];	
	    }
	}
      else // if (ptype == DLT_LINUX_SLL)
	{
	  // From the ethereal/tcpdump source code, cooked packets
	  // contain a MAC-like pseudo header that is 16 bytes long
	  
	  sll = (struct sll_header *)pktDataIn;
	  netProto = ntohs(sll->sll_protocol);

	  frhlen   = sizeof(struct sll_header);

	  if (netProto == ETHERTYPE_IP)
	    {
	      ip = (struct iphdr *)&pktDataIn[sizeof(struct sll_header)];
	    }
	}

      // Only process if this is an IP packet

      if (ip != NULL)
	{
	  // Handle the case where IP may have options
	  iphlen = (ip->ihl << 2);
	  
	  // Only process if this is a UDP packet
	      
	  if (ip->protocol == IPPROTO_UDP)
	    {
	      plen = pktHdr.caplen - 
		(frhlen + iphlen + sizeof(struct udphdr));

	      if (plen <= 0)
		{
		  printf("   Packet too short to decapsulate\n");
		  badPkts++;
		}
	      else
		{
		  
		  memcpy(&pktDataOut[0],&pktDataIn[0],frhlen);
		  memcpy(&pktDataOut[frhlen],
			 &pktDataIn[frhlen + iphlen + sizeof(struct udphdr)],
			 plen);

		  pktHdr.len    -= (iphlen + sizeof(struct udphdr));
		  pktHdr.caplen -= (iphlen + sizeof(struct udphdr));
		  
		  pcap_dump((unsigned char *)q,&pktHdr,&pktDataOut[0]);

		  nPkts++;
		}
	    }
	}
    }

 ErrorExit:

  if (p)
    {
      pcap_close(p);
      p = (pcap_t *)NULL;
    }

  if (q)
    {
      pcap_dump_close(q);
      q = (pcap_dumper_t *)NULL;
    }

  
  if (badPkts > 0)
    {
      printf("**** Total of %d short packets found ****\n",badPkts);
    }

  return (nPkts);
}
