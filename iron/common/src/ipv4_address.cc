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

#include "ipv4_address.h"

#include "log.h"
#include "unused.h"

#include <cstring>
#include <netinet/in.h>

using ::iron::Ipv4Address;
using ::iron::Log;

namespace
{
  const char*  UNUSED(kClassName) = "Ipv4Address";
}


//=========================================================================
Ipv4Address::Ipv4Address()
    : address_(0)
{
}

//=========================================================================
Ipv4Address::Ipv4Address(const std::string& addr)
    : address_(0)
{
  if (inet_pton(AF_INET, addr.c_str(), &address_) != 1)
  {
    LogE(kClassName, __func__, "Invalid IPv4 address: %s\n", addr.c_str());
  }
}

//=========================================================================
Ipv4Address::Ipv4Address(uint32_t addr)
    : address_(addr)
{
}

//=========================================================================
Ipv4Address::Ipv4Address(const uint8_t* addr)
{
  if (addr)
  {
    std::memcpy(&address_, addr, sizeof(address_));
  }
  else
  {
    address_ = 0;
  }
}

//=========================================================================
Ipv4Address::Ipv4Address(const Ipv4Address& addr)
    : address_(addr.address_)
{
}

//=========================================================================
Ipv4Address::~Ipv4Address()
{
}

//============================================================================
void Ipv4Address::set_address(const std::string& addr)
{
  if (inet_pton(AF_INET, addr.c_str(), &address_) != 1)
  {
    LogE(kClassName, __func__, "Invalid IPv4 address: %s\n", addr.c_str());
    address_ = 0;
  }
}

//============================================================================
bool Ipv4Address::SetAddress(const std::string& addr)
{
  return (inet_pton(AF_INET, addr.c_str(), &address_) == 1);
}

//=========================================================================
std::string Ipv4Address::ToString() const
{
  char  addr_str[INET_ADDRSTRLEN];

  if (inet_ntop(AF_INET, &address_, addr_str, INET_ADDRSTRLEN) == NULL)
  {
    LogE(kClassName, __func__, "Error converting IPv4 address to string\n");
    return "?.?.?.?";
  }

  return addr_str;
}

//=========================================================================
Ipv4Address& Ipv4Address::operator=(const std::string& addr)
{
  if (inet_pton(AF_INET, addr.c_str(), &address_) != 1)
  {
    LogE(kClassName, __func__, "Invalid IPv4 address: %s\n", addr.c_str());
    address_ = 0;
  }

  return *this;
}

//=========================================================================
Ipv4Address& Ipv4Address::operator=(const Ipv4Address& addr)
{
  address_ = addr.address_;

  return *this;
}

//=========================================================================
Ipv4Address& Ipv4Address::operator=(uint32_t addr)
{
  address_ = addr;

  return *this;
}

namespace iron
{

//=========================================================================
bool operator==(const Ipv4Address& left, const Ipv4Address& right)
{
  // Two numbers are equal whether they are in network or host byte order.
  return left.address_ == right.address_;
}

//=========================================================================
bool operator!=(const Ipv4Address& left, const Ipv4Address& right)
{
  // Two numbers are equal whether they are in network or host byte order.
  return left.address_ != right.address_;
}

//=========================================================================
bool operator<(const Ipv4Address& left, const Ipv4Address& right)
{
  return ntohl(left.address_) < ntohl(right.address_);
}

//=========================================================================
bool operator>(const Ipv4Address& left, const Ipv4Address& right)
{
  return ntohl(left.address_) > ntohl(right.address_);
}

//=========================================================================
bool operator<=(const Ipv4Address& left, const Ipv4Address& right)
{
  return ntohl(left.address_) <= ntohl(right.address_);
}

//=========================================================================
bool operator>=(const Ipv4Address& left, const Ipv4Address& right)
{
  return ntohl(left.address_) >= ntohl(right.address_);
}

}
