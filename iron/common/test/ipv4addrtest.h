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
 * File:   ipv4addrtest.h
 * Author: Dabideen
 *
 * Created on Jul 29, 2015, 1:09:16 PM
 */

#ifndef IPv4ADDRTEST_H
#define	IPv4ADDRTEST_H

#include <cppunit/extensions/HelperMacros.h>
#include "ipv4_address.h"

namespace iron
{

class ipv4addrtest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(ipv4addrtest);

    CPPUNIT_TEST(TestIpv4Address);
    CPPUNIT_TEST(TestIpv4Address2);
    CPPUNIT_TEST(TestIpv4Address3);
    CPPUNIT_TEST(TestIpv4Address4);
    CPPUNIT_TEST(TestToString);
    CPPUNIT_TEST(TestGetIpv4Address);
    CPPUNIT_TEST(TestSetAddress);
    CPPUNIT_TEST(TestEquality);
    CPPUNIT_TEST(TestInequality);
    CPPUNIT_TEST(TestAssignment);
    CPPUNIT_TEST(TestCopy);

    CPPUNIT_TEST_SUITE_END();

public:

    ipv4addrtest();
    virtual ~ipv4addrtest();
    void setUp();
    void tearDown();

private:

    void TestIpv4Address();
    void TestIpv4Address2();
    void TestIpv4Address3();
    void TestIpv4Address4();
    void TestToString();
    void TestGetIpv4Address();
    void TestSetAddress();
    void TestEquality();
    void TestInequality();
    void TestAssignment();
    void TestCopy();
    Ipv4Address *ip1_;
    Ipv4Address *ip2_;
    Ipv4Address *ip3_;
    Ipv4Address *ip4_;
    std::string addr_;

};

} // namespace iron

#endif	/* IPv4ADDRTEST_H */
