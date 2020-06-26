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
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "amp_relay_port.h"

static char sBuf[1500];

// This program sends a single, small UDP packet to the receiver specified as
// argv[1].
//
// Usage:  amp_relay_sndr hostname arg1 [arg2 arg3 ...]

//==========================================================================
int main(int argc, char **argv)
{
  int                 s;
  int                 len;
  int                 rv;
  struct sockaddr_in  addr;

  uint16_t udp_port = AMP_RELAY_PORT;
  
  // Check the number of arguments.
  if (argc < 3)
  {
    printf("Usage: amp_relay tgt address arg1 [arg2 arg3 ...]\n");
    exit(-1);
  }

  // Initialize the string.
  sBuf[0] = 0;

  for (int i = 2; i < argc; i++)
  {
    strcat(sBuf, argv[i]);
    if (i < (argc - 1))
    {
      strcat(sBuf," ");
    }
  }
  
  // Create a UDP socket.
  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket()");
    exit(1);
  }
  
  // Construct the sendto() address.
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(udp_port);

  struct  hostent*  h_ent;
  if ((h_ent = gethostbyname(argv[1])) == NULL)
  {
    printf("Error retrieving host information.\n");
    exit(0);
  }

  bcopy(h_ent->h_addr_list[0], &addr.sin_addr, h_ent->h_length);
  
  // if (inet_aton(argv[1], &addr.sin_addr) == 0)
  // {
  //   printf("inet_aton(): to translate unicast address.\n");
  //   exit(1);
  // }
  
  // Fire!
  len = strlen(sBuf);
  if ((rv = sendto(s, sBuf, len, 0, (struct sockaddr *)&addr,
		   sizeof(addr))) != len)
  {
    if (rv < 0)
    {
      perror("sendto()");
    }
    else
    {
      printf("Only sent %d bytes.\n", rv);
    }
    
    close(s);
    exit(1);
  }
  
  // Clean up.
  close(s);
  
  return 0;
}
