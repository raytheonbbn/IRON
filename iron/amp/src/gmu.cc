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

#include "gmu.h"
#include "log.h"
#include "unused.h"

#include <iostream>
#include <string>
#include <unistd.h>

using ::iron::GMU;
using ::iron::Log;
using ::std::string;

namespace
{
  /// The default remote control BPF port number.
  const uint16_t  kDefaultAmpCtlPort              = 3140;

  const char* UNUSED(kClassName)                  = "GMU";

}

//=============================================================================
GMU::GMU()
    : rc_client_()
{}

//=============================================================================
GMU::~GMU()
{}

//=============================================================================
void GMU::SendSetMsgToAmp(string action, string mcast_addr, string amp_addr)
{

  // Connect to the AMP.
  struct sockaddr_in  amp_sock_addr;
  ::memset(&amp_sock_addr, 0, sizeof(amp_sock_addr));
  amp_sock_addr.sin_family       = AF_INET;
  amp_sock_addr.sin_addr.s_addr  = inet_addr(amp_addr.c_str());
  amp_sock_addr.sin_port         = htons(kDefaultAmpCtlPort);
  uint32_t amp_ep                = 0;
  while (amp_ep ==0)
  {
    LogD(kClassName, __func__, "Connecting to AMP\n");
    amp_ep = rc_client_.Connect(amp_sock_addr);
    if (amp_ep != 0)
    {
      LogD(kClassName, __func__, "Connected to AMP\n");
      break;
    }
    sleep(2);
  }

  LogD(kClassName, __func__,
       "Sending message to AMP: %s multicast group %s\n",
        action.c_str(), mcast_addr.c_str());

  rc_client_.SendSetMessage(amp_ep, "bpf", "parameter;mcast_group;action;" + action +
                                 ";addr;" + mcast_addr);

}

//=============================================================================
int main(int argc, char** argv)
{
  if (argc != 4)
  {
    LogF(kClassName, __func__, "Wrong number of arguments (%d). Usage: "
         "gmu join/leave mcast_addr amp_arrd\n", argc);
  }

  GMU* gmu = new (std::nothrow) GMU();

  if (!gmu)
  {
    LogF(kClassName, __func__, "Unable to allocate memory for GMU.\n");
  }

  //
  // Send the message to AMP.
  //

  gmu->SendSetMsgToAmp(argv[1], argv[2], argv[3]);

  exit(0);
}

