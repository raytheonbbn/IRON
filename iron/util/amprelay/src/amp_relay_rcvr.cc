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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "amp_relay_port.h"
#include "remote_control.h"

static char sBuf[1500];
static char src[16];
static char dst[16];
static char sport[16];
static char dport[16];
static char fileSize[32];
static char deadline[32];
static char priority[32];
static char cmdBuf[1024];

static char natsrc[16];
static char natdst[16];
static char natsport[16];
static char natdport[16];

static ::iron::RemoteControlClient  s_rc_client;
static uint16_t  kDefaultAmpCtlPort = 3140;

// This program:
//    - receives a string via a UDP unicast packet
//    - pulls the string apart into addresses and ports to use with contrack
//    - execs conntrack with the supplied addresses and ports to get NAT info
//    - pulls the returned string apart to retrieve individual params
//    - calls the dummy send-to-amp method to set the utility function
//
// Usage:  amp_relay_rcvr amp_ip_addr

/*==========================================================================*/
int main(int argc, char** argv)
{
  int                 s       = 0;
  int                 len     = 0;
  int                 flag    = 1;
  int                 forever = 1;
  socklen_t           addrLen = 0;
  struct sockaddr_in  addr;
  int                 start = 0;

  uint16_t udp_port = AMP_RELAY_PORT;

  // Check the number of arguments in case the user wants to change the port
  if (argc != 2)
  {
    printf("Usage: amp_relay_rcvr amp_ip_addr\n");
    exit(-1);
  }
  
  // Connect to the AMP.
  struct sockaddr_in  amp_addr;
  memset(&amp_addr, 0, sizeof(amp_addr));
  amp_addr.sin_family       = AF_INET;
  amp_addr.sin_addr.s_addr  = inet_addr(argv[1]);
  amp_addr.sin_port         = htons(kDefaultAmpCtlPort);
  uint32_t amp_ep           = 0;
  while (amp_ep ==0)
  {
    // LogD(kClassName, __func__, "Connecting to AMP\n");
    printf("Connecting to AMP\n");
    amp_ep = s_rc_client.Connect(amp_addr);
    if (amp_ep != 0)
    {
      // LogD(kClassName, __func__, "Connected to AMP\n");
      printf("Connected to AMP\n");
      break;
    }
    sleep(2);
  }

  // Create a UDP socket.
  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket()");
    exit(-1);
  }
  
  // Allow reuse of the port number.
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                 (const void*)&flag, sizeof(flag)) < 0)
  {
    perror("setsockopt()");
    exit(1);
  }
  
  // Bind the port number to the socket.
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(udp_port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("bind()");
    close(s);
    exit(-1);
  }
  
  // Receive and dump packets.
  while (forever)
  {
    memset(&addr, 0, sizeof(addr));
    addrLen = sizeof(addr);
    
    if ((len = recvfrom(s, sBuf, 1500, 0, (struct sockaddr *)&addr,
                        &addrLen)) < 0)
    {
      perror("recvfrom()");
      close(s);
      exit(-1);
    }

    // Make sure the string is null terminated
    sBuf[len] = 0;
    
    if (len > 0)
    {
      printf("Received \"%s\"\n",sBuf);
      
      fflush(stdout);
    }

    // Pull the string apart.
    start = 0;
    int i;
    for (i=start; i<len; i++)
    {
      if (sBuf[i] == ':')
      {
	sBuf[i] = 0;
        break;
      }
    }
    
    strncpy(src,&sBuf[start],sizeof(src)-1);
    start = i+1;

    if (start >= len) // parse error: we don't have enough args
    {
      printf("Not enough args for src port\n");      
      continue;
    }
    
    for (i=start; i<len; i++)
    {
      if (sBuf[i] == ' ')
      {
	sBuf[i] = 0;
        break;
      }
    }

    strncpy(sport,&sBuf[start],sizeof(sport)-1);
    start = i+1;

    if (start >= len) // parse error: we don't have enough args
    {
      printf("Not enough args for dst\n");
      continue;
    }

    for (i=start; i<len; i++)
    {
      if (sBuf[i] == ':')
      {
	sBuf[i] = 0;
        break;
      }
    }

    strncpy(dst,&sBuf[start],sizeof(dst)-1);
    start = i+1;
    
    if (start >= len) // parse error: we don't have enough args
    {
      printf("Not enough args for dst port\n");
      continue;
    }

    for (i=start; i<len; i++)
    {
      if (sBuf[i] == ' ')
      {
	sBuf[i] = 0;
        break;
      }
    }

    strncpy(dport,&sBuf[start],sizeof(dport)-1);
    start = i+1;

    if (start >= len) // parse error: we don't have enough args
    {
      printf("Not enough args for filesize\n");
      continue;
    }

    for (i=start; i<len; i++)
    {
      if (sBuf[i] == ' ')
      {
	sBuf[i] = 0;
        break;
      }
    }

    strncpy(fileSize,&sBuf[start],sizeof(fileSize)-1);
    start = i+1;

    if (start >= len) // parse error: we don't have enough args
    {
      printf("Not enough args for deadline\n");
      continue;
    }

    for (i=start; i<len; i++)
    {
      if (sBuf[i] == ' ')
      {
	sBuf[i] = 0;
        break;
      }
    }

    strncpy(deadline,&sBuf[start],sizeof(deadline)-1);
    start = i + 1;
    
    if (start >= len) // parse error: we don't have enough args
    {
      printf("Not enough args for priority.\n");
      continue;
    }

    for (i=start; i<len; i++)
    {
      if (sBuf[i] == ' ')
      {
	sBuf[i] = 0;
        break;
      }
    }

    strncpy(priority, &sBuf[start], sizeof(priority)-1);

    // Input parsing completed!
    //
    // Form the conntrack command and exec it using a pipe to capture the output
    snprintf(cmdBuf,sizeof(cmdBuf)-1,
             "sudo conntrack -G -p tcp -s %s --sport %s -d %s --dport %s 2> /dev/null",
	     src,sport,dst,dport);

    // printf("conntrack command is: \"%s\"\n",cmdBuf);

    FILE* conntrackPipe = popen(cmdBuf,"r");
    char  retBuf[1024];
    if (fgets(retBuf,sizeof(retBuf),conntrackPipe) == 0)
    {
      printf("conntrack lookup failed\n");
      continue;
    }
    else
    {
      // Get rid of any trailing '\n' characters
      int lastChar = strlen(retBuf);
      if (retBuf[lastChar-1] == '\n')
      {
	retBuf[lastChar-1] = 0;
      }
      
      // printf("contrack returned \"%s\"\n",retBuf);
    }
    pclose(conntrackPipe);

    int retlen = strlen(retBuf);
    
    // Now parse the return string.
    char testbuf[1024];

    i     = 0;
    start = 0;
    int count = 0;
    while (start<retlen)
    {
      if ((retBuf[i] == ' ') || (retBuf[i] == 0))
      {
	// printf("Copying %d characters\n",i-start);
	strncpy(testbuf,&retBuf[start],i-start);
	testbuf[i-start] = 0;
	// printf("Token is %s\n",testbuf);

	// Check to see if we have one of the tokens we need.
	if (strncmp(testbuf,"src",3) == 0)
        {
          // printf("Got a src spec: %s\n",testbuf);
          for (int j=0; j<(int)strlen(testbuf); j++)
          {
            if (testbuf[j] == '=')
            {
              strncpy(natdst,&testbuf[j+1],sizeof(natdst));
              break;
            }
          }
          count++;
        }
	else if (strncmp(testbuf,"dst",3) == 0)
        {
          // printf("Got a dst spec: %s\n",testbuf);
          for (int j=0; j<(int)strlen(testbuf); j++)
          {
            if (testbuf[j] == '=')
            {
              strncpy(natsrc,&testbuf[j+1],sizeof(natsrc));
              break;
            }
          }
          count++;
        }
	else if (strncmp(testbuf,"sport",5) == 0)
        {
          //	    printf("Got a sport spec: %s\n",testbuf);
          for (int j=0; j<(int)strlen(testbuf); j++)
          {
            if (testbuf[j] == '=')
            {
              strncpy(natdport,&testbuf[j+1],sizeof(natdport));
              break;
            }
          }
          count++;
        }
	else if (strncmp(testbuf,"dport",5) == 0)
        {
          // printf("Got a dport spec: %s\n",testbuf);
          for (int j=0; j<(int)strlen(testbuf); j++)
          {
            if (testbuf[j] == '=')
            {
              strncpy(natsport,&testbuf[j+1],sizeof(natsport));
              break;
            }
          }
          count++;
        }

	// Get rid of any gratuitous white space
	while ((i<retlen) && (retBuf[i] == ' '))
	{
	  i++;
	}
	start = i;
      }
      else
      {
	i++;
      }
    }

    if (count == 8)
    {
      printf("NAT addresses: src:sport is %s:%s, dst:dport is "
             "%s:%s\n", natsrc, natsport, natdst, natdport); 
      char  msg[1024];
      memset(msg, 0, sizeof(msg));

      snprintf(msg, sizeof(msg) - 1,
               "parameter;ft_params;flow_tuple;%s:%s -> "
               "%s:%s;deadline;%s;size;%s;priority;%s", 
               natsrc, natsport, natdst, natdport, deadline, fileSize,
               priority);
      s_rc_client.SendSetMessage(amp_ep, "amp", msg);
    }
    else
    {
      printf("failed to parse conntrack return string\n");
    }
  }
  
  // Clean up.
  close(s);
  
  return 0;
}
