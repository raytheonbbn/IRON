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
#include <unistd.h>

#include "sliq.h"

static int32_t removeSliqHeader(char *dumpFileIn, char *dumpFileOut);

int main(int argc, char **argv)
{
  extern int optind;

  int     c;
  int     errflg     = 0;
  int32_t nPkts;

  while ((c = getopt(argc, argv, "h")) != -1)
  {
    switch (c)
    {
      case 'h':
      case '?':
      default:
        errflg++;
    }
  }

  if ((errflg) || ((argc - optind) != 2))
  {
    printf("Usage: sliqdecap sliq_dumpfile_in decap_dumpfile_out\n\n");
    exit(-1);
  }

  nPkts = removeSliqHeader(argv[optind],argv[optind+1]);

  printf("Converted %d packets\n",nPkts);

  return (0);
}

static int32_t removeSliqHeader(char *dumpFileIn, char *dumpFileOut)
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
  struct udphdr       *udp;

  int32_t nPkts     = 0;
  int32_t shortPkts = 0;

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
    printf("This application only understands dumps from ethernet or cooked "
           "captures\n");
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

        if (plen <= (int32_t)sizeof(struct iphdr))
        {
          // printf("   Packet is way too short to decapsulate\n");
          shortPkts++;
        }
        else
        {
          // Only process if this is a SLIQ data packet

          udp           =  (struct udphdr*)((uint8_t *)ip  + iphlen);
          uint8_t* sptr =  (uint8_t *)((uint8_t *)udp +
                                       sizeof(struct udphdr));

          uint8_t* send = sptr + plen;

          while (sptr < send)
          {
            uint8_t type = *sptr;

            if (type == CONNECTION_HANDSHAKE_HEADER)
            {
              // Make sure there is enough data to completely read the front
              // end info
              if ((size_t)(send - sptr) > sizeof(struct connHndshkFrontend))
              {
                struct connHndshkFrontend *chfe =
                  (struct connHndshkFrontend *)sptr;
                size_t chSize = kConnHandshakeHdrBaseSize +
                  (size_t)(chfe->num_cc_algs) * kConnHandshakeHdrCcAlgSize;
                sptr += chSize;
              }
              else
              {
                sptr = send;
              }
            }
            else if (type == RESET_CONNECTION_HEADER)
            {
              sptr += kConnResetHdrSize;
            }
            else if (type == CLOSE_CONNECTION_HEADER)
            {
              sptr += kConnCloseHdrSize;
            }
            else if (type == CREATE_STREAM_HEADER)
            {
              sptr += kCreateStreamHdrSize;
            }
            else if (type == RESET_STREAM_HEADER)
            {
              sptr += kResetStreamHdrSize;
            }
            else if (type == ACK_HEADER)
            {
              // Make sure there is enough data to completely read the front
              // end info
              if ((size_t)(send - sptr) > sizeof(struct ackFrontend))
              {
                struct ackFrontend *afe = (struct ackFrontend *)sptr;
                size_t ackSize =
                  (kAckHdrBaseSize +
                   ((size_t)((afe->num_opt_abo >> 5) & 0x07) *
                    kAckHdrObsTimeSize) +
                   ((size_t)(afe->num_opt_abo & 0x1f) *
                    kAckHdrAckBlockOffsetSize));
                sptr += ackSize;
              }
              else
              {
                sptr = send;
              }
            }
            else if (type == CC_SYNC_HEADER)
            {
              sptr += kCcSyncHdrSize;
            }
            else if (type == RCVD_PKT_CNT_HEADER)
            {
              sptr += kRcvdPktCntHdrSize;
            }
            else if (type == CC_PKT_TRAIN_HEADER)
            {
              sptr = send;
            }
            else if (type == DATA_HEADER)
            {
              // Make sure there is enough data to completely read the front
              // end info
              if ((size_t)(send - sptr) > sizeof(struct dataFrontend))
              {
                struct dataFrontend *dfe = (struct dataFrontend *)sptr;
                size_t dataHdrSize =
                  (kDataHdrBaseSize +
                   ((dfe->flags & 0x10) ? kDataHdrMoveFwdSize : 0) +
                   ((dfe->flags & 0x20) ? kDataHdrFecSize : 0) +
                   ((dfe->flags & 0x40) ? kDataHdrEncPktLenSize : 0) +
                   (dfe->num_ttg * kDataHdrTimeToGoSize));

                sptr += dataHdrSize;
                plen  = send - sptr;

                // Process CAT headers until an IP header is found
                while (sptr < send)
                {
                  uint8_t dtype = *sptr;

                  if (dtype == CAT_PKT_DST_VEC_HEADER)
                  {
                    sptr += kCatPktDstVecHdrSize;
                  }
                  else if (dtype == CAT_PKT_ID_HEADER)
                  {
                    sptr += kCatPktIdHdrSize;
                  }
                  else if (dtype == CAT_PKT_HISTORY_HEADER)
                  {
                    sptr += kCatPktHistoryHdrSize;
                  }
                  else if (dtype == CAT_PKT_LATENCY_HEADER)
                  {
                    sptr += kCatPktLatencyHdrSize;
                  }
                  else
                  {
                    plen = send - sptr;

                    if (plen <= (int32_t)sizeof(struct iphdr))
                    {
                      // printf("   Packet too short to decapsulate properly."
                      //        " Increase snaplen\n");
                      shortPkts++;
                    }
                    else
                    {
                      // Only reinsert this if the decapsulated packet is an
                      // IP packet

                      if ((sptr[0] >> 4) == 0x4)
                      {
                        memcpy(&pktDataOut[0],&pktDataIn[0],frhlen);
                        memcpy(&pktDataOut[frhlen],sptr,plen);

                        struct iphdr* innerIp = (struct iphdr *)sptr;
                        size_t innerLen       = ntohs(innerIp->tot_len);

                        pktHdr.len    = frhlen + innerLen;
                        pktHdr.caplen = frhlen + plen;

                        pcap_dump((unsigned char *)q,&pktHdr,&pktDataOut[0]);

                        nPkts++;
                      }
                    }

                    sptr = send;
                  }
                }
              }

              sptr = send;
            }
            else
            {
              printf("Found unknown packet type %d on UDP port pair[%u,%u], "
                     "skipping\n",type,ntohs(udp->source),ntohs(udp->dest));
              sptr = send;
            }
          }
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


  if (shortPkts > 0)
  {
    printf("**** Total of %d packets too short to decapsulate ****\n",
           shortPkts);
  }

  return (nPkts);
}
