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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

int main(int argc, char **argv)
{
  char *dev       = NULL;
  char  defname[] = "vif0";

  int fd = -1;
  int err;

  struct ifreq ifr;

  // Since this may have no arguments, no usage message
  // printf("Usage: vifcreate [device_name]\n");

  // Setup the device name pointer

  if (argc > 1)
    {
      dev = argv[1];
    }
  else
    {
      dev = &defname[0];
    }

  // Open the base tun/tap device

  if ((fd = open((char *)"/dev/net/tun", O_RDWR)) < 0 )
    {
      printf("Could not open tun/tap device\n");
      goto ErrorExit;
    }
  
  // Set the device type and name

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
      goto ErrorExit;
    }

  // Make this device persistent (it exists after this app terminates)

  if ((err = ioctl(fd, TUNSETPERSIST, 1)) < 0)
    {
      printf("ioctl failed on device %s\n",ifr.ifr_name);;
      goto ErrorExit;
    }

 ErrorExit:  

  // Close the device if it was opened okay

  if (fd >= 0)
    {
      close(fd);
      fd = -1;
    }

  return (0);
}
