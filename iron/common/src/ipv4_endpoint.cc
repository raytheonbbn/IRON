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

#include "ipv4_endpoint.h"
#include "list.h"
#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <cstring>


using ::iron::Ipv4Endpoint;
using ::iron::List;
using ::iron::Log;
using ::std::string;


namespace
{
  const char*  UNUSED(kClassName) = "Ipv4Endpoint";
}


//============================================================================
Ipv4Endpoint::Ipv4Endpoint()
    : Ipv4Address(), port_nbo_(0)
{
}

//============================================================================
Ipv4Endpoint::Ipv4Endpoint(const std::string& ep_str)
{
  List<string> tokens;
  StringUtils::Tokenize(ep_str, ":", tokens);

  if (tokens.size() != 2)
  {
    LogE(kClassName, __func__, "Invalid Ipv4Endpoint string provided: %s\n",
         ep_str.c_str());
    address_  = 0;
    port_nbo_ = 0;
  }
  else
  {
    string  token;
    tokens.Pop(token);
    set_address(token);

    tokens.Peek(token);
    port_nbo_ =
      static_cast<uint16_t>(htons(StringUtils::GetUint(token)));
  }
}

//============================================================================
Ipv4Endpoint::Ipv4Endpoint(const std::string& addr, uint16_t port_hbo)
    : Ipv4Address(addr), port_nbo_(htons(port_hbo))
{
}

//============================================================================
Ipv4Endpoint::Ipv4Endpoint(uint32_t addr_nbo, uint16_t port_nbo)
    : Ipv4Address(addr_nbo), port_nbo_(port_nbo)
{
}

//============================================================================
Ipv4Endpoint::Ipv4Endpoint(const uint8_t* addr_nbo, uint16_t port_nbo)
    : Ipv4Address(addr_nbo), port_nbo_(port_nbo)
{
}

//============================================================================
Ipv4Endpoint::Ipv4Endpoint(const Ipv4Address& addr, uint16_t port_nbo)
    : Ipv4Address(addr), port_nbo_(port_nbo)
{
}

//============================================================================
Ipv4Endpoint::Ipv4Endpoint(const Ipv4Endpoint& ep)
    : Ipv4Address(ep.address_), port_nbo_(ep.port_nbo_)
{
}

//============================================================================
Ipv4Endpoint::~Ipv4Endpoint()
{
  // Nothing to destroy.
}

//============================================================================
bool Ipv4Endpoint::SetEndpoint(const string& ep_str)
{
  List<string> tokens;
  StringUtils::Tokenize(ep_str, ":", tokens);

  if (tokens.size() != 2)
  {
    return false;
  }

  string  addr_str;
  tokens.Pop(addr_str);
  string  port_str;
  tokens.Peek(port_str);
  unsigned int  port_hbo  = StringUtils::GetUint(port_str);

  if ((port_hbo == UINT_MAX) || (!SetAddress(addr_str)))
  {
    return false;
  }

  port_nbo_ = static_cast<uint16_t>(htons(port_hbo));

  return true;
}

//============================================================================
string Ipv4Endpoint::ToString() const
{
  return Ipv4Address::ToString() + ":" +
    StringUtils::ToString(ntohs(port_nbo_));
}

//============================================================================
void Ipv4Endpoint::ToSockAddr(struct sockaddr* address) const
{
  struct sockaddr_in*  addr = reinterpret_cast<struct sockaddr_in*>(address);

  ::memset(addr, 0, sizeof(struct sockaddr_in));

  addr->sin_family      = AF_INET;
  addr->sin_port        = port_nbo_;
  addr->sin_addr.s_addr = address_;
}

//============================================================================
Ipv4Endpoint& Ipv4Endpoint::operator=(const Ipv4Endpoint& ep)
{
  address_  = ep.address_;
  port_nbo_ = ep.port_nbo_;

  return *this;
}

namespace iron
{

//=========================================================================
bool operator==(const Ipv4Endpoint& left, const Ipv4Endpoint& right)
{
  return((left.address() == right.address()) &&
         (left.port() == right.port()));
}

//=========================================================================
bool operator!=(const Ipv4Endpoint& left, const Ipv4Endpoint& right)
{
  return((left.address() != right.address()) ||
         (left.port() != right.port()));
}

}
