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

#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <linux/if.h>
#include <linux/if_tun.h>

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
  char *dev;
  char  defName[] = "vif0";

  int fd = -1;
  int rc =  0;

  pthread_t rdpthread = (pthread_t)NULL;

  // Nonsensical usage message since we do not require any arguments
  // printf("Usage: vifrcvr [device_name]\n");

  if (argc > 1)
    {
      dev = argv[1];
    }
  else
    {
      dev = &defName[0];
    }

  // Open the VIF

  if ((fd = openVIF (dev)) < 0)
    {
      printf("failed to open VIF device\n");
      goto ErrorExit;
    }

  // Start the read & discard process for the other end of the vif

  if ((rc = startThread(readDiscardProc,(void *)&fd,&rdpthread)) != 0)
    {
      printf("failed to start VIF read-and-discard thread\n");
      goto ErrorExit;
    }

  // Sleep (half of) forever

  sleep(0x8fffffff);

 ErrorExit:  

  if (rdpthread)
    {
      stopThread(rdpthread);
      rdpthread = (pthread_t)NULL;
    }

  if (fd >= 0)
    {
      close(fd);
      fd = -1;
    }

  return (0);
}

int openVIF 
	(const char *dev)
{
  struct ifreq ifr;
  int          err;
  int          fd;

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
  
  strncpy(ifr.ifr_name,dev,IFNAMSIZ);
  
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



