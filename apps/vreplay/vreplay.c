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
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <fcntl.h>

//#include <sys/sockio.h>
#include <sys/socket.h>
//#include <net/if.h>
//#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <pcap.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <math.h>
#include <errno.h>
#include <pthread.h>

int openVIF 
(const char *dev);

void *readDiscardProc
	(void *arg);

int startThread
	(void *(*fn)(void *),
	 void      *arg,
	 pthread_t *thread);

int stopThread
	(pthread_t thread);

int main(int argc, char **argv)
{
  char *dev       = NULL;
  char  defname[] = "vif0";

  pcap_t *p = (pcap_t *)NULL;

  int ptype;

  int fd      = -1;

  unsigned char      *pktData;
  struct pcap_pkthdr  pktHdr;
  double              timestamp;
  double              delta;
  double              fracpart;
  double              intpart;
  double              starttime;
  double              now;
  double              baseOffset;

  int firstTime;

  char errbuf[PCAP_ERRBUF_SIZE];

  struct ether_header  *eth;
  struct iphdr         *ip;

  u_int16_t eth_type;
  int plen;

  struct timeval timeout;
  struct timeval currtime;

  pthread_t rdpthread = (pthread_t)NULL;

  char c;

  if (argc < 2)
    {
      printf("Usage: vifreplay tcpdumpfile [device_name]\n");
      exit (0);
    }

  // Open the capture file and play it through the VIF

  if ((p = pcap_open_offline(argv[1],&errbuf[0])) == NULL)
    {
      printf("Open failed: explanation is:\n    %s\n",&errbuf[0]);
      goto ErrorExit;
    }
  

  // Only process if these are ethernet packets
  
  if ((ptype = pcap_datalink(p)) != DLT_EN10MB)
    {
      printf("This application only understands dumps from ethernet datalinks\n");
      goto ErrorExit;
    }


  // Setup the device name pointer

  if (argc > 2)
    {
      dev = argv[2];
    }
  else
    {
      dev = &defname[0];
    }


  // Open the VIF

  if ((fd = openVIF (dev)) < 0)
    {
      printf("failed to open VIF device\n");
      goto ErrorExit;
    }


  // Start the read & discard process for the "output" side of the VIF

  startThread(readDiscardProc,(void *)&fd,&rdpthread);


  // Begin processing the data from the tcpdump file

  firstTime = 1;
  while ((pktData = (unsigned char *) pcap_next(p,&pktHdr)) != NULL)
    {
      timestamp =  (double)pktHdr.ts.tv_sec + 
	          ((double)pktHdr.ts.tv_usec) / 1000000.0;

      if (firstTime)
	{
	  printf("Ready to begin run: press any key to start\n");
	  scanf("%c",&c);
	  baseOffset = timestamp;
	  gettimeofday(&currtime,NULL);
	  starttime  = (double) currtime.tv_sec + ((double)currtime.tv_usec) / 1000000.0;
	  firstTime  = 0;
	}

#ifdef DEBUG      
      printf("Packet header info:\n");
      printf("  Timestamp:      %f\n",timestamp);
      printf("  Capture length: %d\n",pktHdr.caplen);
      printf("  Packet length:  %d\n",pktHdr.len);
#endif

// For IRON, we will relax the checks on the captured packet length.
#if 0
      if (pktHdr.caplen < pktHdr.len)
	{
	  printf("Short packet found! snaplen must be increased\n");
	  goto ErrorExit;
	}
#endif

      // Get the ethernet payload

      eth      = (struct ether_header *)pktData;
      eth_type = ntohs(eth->ether_type);

      // Only send if this is an IP packet

      if (eth_type == ETHERTYPE_IP)
	{
	  ip   = (struct iphdr *)(pktData + sizeof(struct ether_header));
	  plen = ntohs(ip->tot_len);

// For IRON, we will relax the checks on the captured packet length.
#if 0
	  if (plen > (pktHdr.caplen - sizeof(struct ether_header)))
	    {
	      printf("Short IP packet found! snaplen must be increased\n");
	      goto ErrorExit;
	    }
#endif

	  // Figure out when to send this packet

	  gettimeofday(&currtime,NULL);
	  now =  (double)currtime.tv_sec + 
	    ((double)currtime.tv_usec) / 1000000.0;
	  
	  delta = (starttime + (timestamp - baseOffset)) - now;
	  
	  // Wait, if we need to wait
	  
	  while (delta > 0.0)
	    {
	      fracpart        = modf(delta,&intpart);
	      timeout.tv_sec  = (unsigned long)intpart;
	      timeout.tv_usec = (unsigned long)(fracpart * 1000000.0);
	      
	      select(0,(fd_set *)NULL,(fd_set *)NULL,(fd_set *)NULL, &timeout);
	      
	      delta =  (double)timeout.tv_sec + 
		((double)timeout.tv_usec) / 1000000.0;
	    }
	  
	  // Spit out the ethernet packet
	  
	  write(fd,ip,plen);
	}
    }

  printf("Run completed: press any key to shutdown VIF and exit\n");
  scanf("%c",&c);

 ErrorExit:  

  if (p)
    {
      pcap_close(p);
      p = (pcap_t *)NULL;
    }

  if (fd >= 0)
    {
      close(fd);
      fd = -1;
    }

  return (0);
}

int openVIF 
	(const char    *dev)
{
  struct ifreq ifr;
  int          err;
  int          fd = -1;

  if ((fd = open((char *)"/dev/net/tun", O_RDWR)) < 0 )
    {
      printf("Could not open tun/tap device\n");
      return (-1);
    }
  
  memset(&ifr, 0, sizeof(ifr));
  
  /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
   *        IFF_TAP   - TAP device (includes ethernet headers)  
   *
   *        IFF_NO_PI - Do not provide packet information  
   */ 
  
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  
  strncpy(ifr.ifr_name,dev,sizeof(ifr.ifr_name)-1);
  
  if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
      printf("ioctl failed on device %s\n",ifr.ifr_name);;
      close(fd);
      return (-1);
    }

  return (fd);
}

void *readDiscardProc
	(void *arg)
{
  char buffer[2048];
  int fd;

  fd = *(int *)arg;

  while (1)
    {
      read(fd,buffer,sizeof(buffer));
      printf(".");
      fflush(stdout);
    }

  return (NULL);
}

//============================================================================
int startThread
	(void *(*fn)(void *),
	 void      *arg,
	 pthread_t *thread)
{
  pthread_attr_t attr;
  
  int rc;

  // Initially everything is okay

  rc = 0;

  if (fn == NULL)
  {
    printf("Null function pointer specified.\n");
    return(-1);
  }
  
  /*
   * Create a detached thread.
   */
  
  if (pthread_attr_init(&attr) != 0)
  {
    printf("pthread_attr_init error.\n");
    return(-1);
  }
  
  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
  {
    printf("pthread_attr_setdetachedstate error.\n");
    rc = -1;
    goto ErrorExit;
  }
  
  if (pthread_create(thread, &attr, fn, arg) != 0)
  {
    printf("pthread_create error.\n");
    rc = -1;
    goto ErrorExit;
  }

 ErrorExit:
  
  if (pthread_attr_destroy(&attr) != 0)
  {
    printf("pthread_attr_destroy error.\n");
  }

  return (rc);
}  

//============================================================================
int stopThread
	(pthread_t thread)
{
  int              rv = 0;
  struct timespec  sleepTime;
  struct timespec  remTime;
  
  rv = pthread_cancel(thread);
    
  /*
   * Sleep for a small amount of time to let the thread terminate.
   */
  
  sleepTime.tv_sec  = 1;
  sleepTime.tv_nsec = 0;
  
  while ((sleepTime.tv_sec != 0) || (sleepTime.tv_nsec != 0))
    {
      if ((nanosleep(&sleepTime, &remTime) < 0) && (errno == EINTR))
	{
	  memcpy(&sleepTime, &remTime, sizeof(remTime));
	}
      else
	{
	  break;
	}
    }
  
  return(rv);
}
