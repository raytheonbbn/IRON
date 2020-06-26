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

#include <cppunit/extensions/HelperMacros.h>

#include "ipv4_endpoint.h"
#include "log.h"


using ::iron::Ipv4Address;
using ::iron::Ipv4Endpoint;
using ::iron::Log;


//============================================================================
class Ipv4EndpointTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(Ipv4EndpointTest);

  CPPUNIT_TEST(TestConstructors);
  CPPUNIT_TEST(TestToString);
  CPPUNIT_TEST(TestCopyOperator);

  CPPUNIT_TEST_SUITE_END();

public:

  //==========================================================================
  void setUp()
  {

    //
    // Turn down logging levels for the unit testing.
    //

    Log::SetDefaultLevel("F");
  }

  //==========================================================================
  void tearDown()
  {

    //
    // Restore default logging levels so we don't break other unit tests.
    //

    Log::SetDefaultLevel("FEWI");
  }


  //==========================================================================
  void TestConstructors()
  {

    //
    // In addition to testing the various constructors, this method also tests
    // the following methods:
    //
    // - set_address()
    // - set_port()
    // - address()
    // - port()
    //
    // We will not author individual tests for the above identified methods as
    // they are tested here.
    //

    //
    // Test default no-arg constructor.
    //

    Ipv4Endpoint  ep1;
    ep1.set_address("1.2.3.4");
    ep1.set_port(7777);

    uint32_t  test_address;
    CPPUNIT_ASSERT(inet_pton(AF_INET, "1.2.3.4", &test_address) == 1);
    CPPUNIT_ASSERT(ep1.address() == test_address);
    CPPUNIT_ASSERT(ep1.port() == 7777);

    //
    // Test constructor that takes string representation of an endpoint.
    //

    Ipv4Endpoint  ep2("1.2.3.4:7777");
    CPPUNIT_ASSERT(ep2.address() == test_address);
    CPPUNIT_ASSERT(ep2.port() == ntohs(7777));

    //
    // Test constructor that takes an invalid string representation of an
    // endpoint.
    //

    Ipv4Endpoint  ep3("1.2.3.4,7777");
    CPPUNIT_ASSERT(ep3.address() == 0);
    CPPUNIT_ASSERT(ep3.port() == 0);

    //
    // Test constructor that takes string representation of an address and a
    // port number.
    //

    Ipv4Endpoint  ep4("1.2.3.4", 7777);
    CPPUNIT_ASSERT(ep4.address() == test_address);
    CPPUNIT_ASSERT(ep4.port() == ntohs(7777));

    //
    // Test constructor that takes uint32_t representation of an address and a
    // port number.
    //

    Ipv4Endpoint  ep5(test_address, htons(7777));
    CPPUNIT_ASSERT(ep5.address() == test_address);
    CPPUNIT_ASSERT(ep5.port() == ntohs(7777));

    //
    // Test constructor that takes an Ipv4Address and a port number.
    //

    Ipv4Address   ip_addr("1.2.3.4");
    Ipv4Endpoint  ep6(ip_addr, htons(7777));
    CPPUNIT_ASSERT(ep6.address() == test_address);
    CPPUNIT_ASSERT(ep6.port() == ntohs(7777));

    //
    // Test copy constructor.
    //

    Ipv4Endpoint  ep7(ep6);
    CPPUNIT_ASSERT(ep7.address() == test_address);
    CPPUNIT_ASSERT(ep7.port() == ntohs(7777));
  }

  //==========================================================================
  void TestToString()
  {
    Ipv4Endpoint  ep("1.2.3.4:9999");
    CPPUNIT_ASSERT(ep.ToString() == "1.2.3.4:9999");
  }

  //==========================================================================
  void TestToSockAddr()
  {
    Ipv4Endpoint     ep("1.2.3.4:7777");

    uint32_t  test_address;
    CPPUNIT_ASSERT(inet_pton(AF_INET, "1.2.3.4", &test_address) == 1);

    struct sockaddr  addr;
    ep.ToSockAddr(&addr);

    struct sockaddr_in*  addr_in =
      reinterpret_cast<struct sockaddr_in*>(&addr);
    CPPUNIT_ASSERT(addr_in->sin_addr.s_addr == test_address);
    CPPUNIT_ASSERT(addr_in->sin_port == htons(7777));
  }

  //==========================================================================
  void TestCopyOperator()
  {
    Ipv4Endpoint  ep1("1.2.3.4:9999");
    Ipv4Endpoint  ep2 = ep1;

    CPPUNIT_ASSERT(ep1.address() == ep2.address());
    CPPUNIT_ASSERT(ep1.port() == ep2.port());
    CPPUNIT_ASSERT(ep1.ToString() == ep2.ToString());
  }

private:

};

CPPUNIT_TEST_SUITE_REGISTRATION(Ipv4EndpointTest);
