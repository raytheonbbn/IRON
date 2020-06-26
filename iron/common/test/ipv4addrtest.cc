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

/*
 * File:   ipv4addrtest.cpp
 * Author: Dabideen
 *
 * Created on Jul 29, 2015, 1:09:16 PM
 */
#include "ipv4addrtest.h"

using ::iron::Ipv4Address;
using ::iron::ipv4addrtest;

CPPUNIT_TEST_SUITE_REGISTRATION(ipv4addrtest);

ipv4addrtest::ipv4addrtest()
    : ip1_(NULL), ip2_(NULL), ip3_(NULL), ip4_(NULL), addr_()
{
}

ipv4addrtest::~ipv4addrtest()
{
}

void ipv4addrtest::setUp()
{
  std::string  addr          = "0.0.1.10";
  uint8_t      addr_bytes[4] = { 1, 1, 0, 0 };

  ip1_ = new Ipv4Address();
  ip2_ = new Ipv4Address(addr.c_str());
  ip3_ = new Ipv4Address(htonl(266));
  ip4_ = new Ipv4Address(addr_bytes);
}

void ipv4addrtest::tearDown()
{
  delete ip1_;
  delete ip2_;
  delete ip3_;
  delete ip4_;
}

void ipv4addrtest::TestIpv4Address()
{
  CPPUNIT_ASSERT(ip1_->address() == 0);
}

void ipv4addrtest::TestIpv4Address2()
{
  uint32_t  expected_addr;

  CPPUNIT_ASSERT(inet_pton(AF_INET, "0.0.1.10", &expected_addr) == 1);
  CPPUNIT_ASSERT(ip2_->address() == expected_addr);
}

void ipv4addrtest::TestIpv4Address3()
{
  CPPUNIT_ASSERT(ip3_->address() == htonl(266));
}

void ipv4addrtest::TestIpv4Address4()
{
  uint32_t  expected_addr;

  CPPUNIT_ASSERT(inet_pton(AF_INET, "1.1.0.0", &expected_addr) == 1);
  CPPUNIT_ASSERT(ip4_->address() == expected_addr);
}

void ipv4addrtest::TestToString()
{
  std::string result = ip3_->ToString();
  CPPUNIT_ASSERT(result == "0.0.1.10");
}

void ipv4addrtest::TestGetIpv4Address()
{
  uint32_t  expected_addr;

  CPPUNIT_ASSERT(inet_pton(AF_INET, "0.0.1.10", &expected_addr) == 1);
  CPPUNIT_ASSERT(ip2_->address() == expected_addr);
}

void ipv4addrtest::TestSetAddress()
{
  ip1_->set_address(266);
  CPPUNIT_ASSERT(ip1_->address() == 266);
}

void ipv4addrtest::TestEquality()
{
  Ipv4Address  ip6 = Ipv4Address("0.0.1.14");
  Ipv4Address  ip7 = Ipv4Address("0.0.1.14");

  CPPUNIT_ASSERT(ip6 == ip7);
}

void ipv4addrtest::TestInequality()
{
  Ipv4Address  ip8 = Ipv4Address("1.2.3.4");
  Ipv4Address  ip9 = Ipv4Address("3.0.0.0");

  CPPUNIT_ASSERT(ip8 != ip9);
  CPPUNIT_ASSERT(ip8 < ip9);
  CPPUNIT_ASSERT(ip8 <= ip9);
  CPPUNIT_ASSERT(ip9 > ip8);
  CPPUNIT_ASSERT(ip9 >= ip8);
}

void ipv4addrtest::TestAssignment()
{
  std::string  ip_str("0.0.1.10");
  Ipv4Address  ip10 = ip_str;
  Ipv4Address  ip11 = htonl(266);
  Ipv4Address  ip12 = ip11;

  CPPUNIT_ASSERT(ip10 == *ip3_);
  CPPUNIT_ASSERT(ip11 == *ip3_);
  CPPUNIT_ASSERT(ip12 == *ip3_);
}

void ipv4addrtest::TestCopy()
{
  Ipv4Address  ip10 = Ipv4Address(266);
  Ipv4Address  ip11(ip10);

  CPPUNIT_ASSERT(ip10 == ip11);
}
