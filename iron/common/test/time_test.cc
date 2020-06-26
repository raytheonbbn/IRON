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

#include "itime.h"

#include <cstdio>


using ::iron::Time;
using ::std::string;

namespace iron
{

//============================================================================
class TimeTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(TimeTest);

  CPPUNIT_TEST(TestConstructors);
  CPPUNIT_TEST(TestFromSec);
  CPPUNIT_TEST(TestFromMsec);
  CPPUNIT_TEST(TestFromUsec);
  CPPUNIT_TEST(TestMaxAndMinOperators);
  CPPUNIT_TEST(TestToTval);
  CPPUNIT_TEST(TestAdd);
  CPPUNIT_TEST(TestSubtract);
  CPPUNIT_TEST(TestMultiply);
  CPPUNIT_TEST(TestZeroTime);
  CPPUNIT_TEST(TestInfiniteTime);
  CPPUNIT_TEST(TestGetTime);
  CPPUNIT_TEST(TestMonotonic);
  CPPUNIT_TEST(TestOperators);
  CPPUNIT_TEST(TestGetTimeInFormat);

  CPPUNIT_TEST_SUITE_END();

public:

  //==========================================================================
  void setUp()
  {
    // Turn down logging levels for the unit testing.
    Log::SetDefaultLevel("F");
  }

  //==========================================================================
  void tearDown()
  {
    // Restore default logging levels so we don't break other unit tests.
    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestConstructors()
  {
    // Test no-arg constructor.
    Time  t1;
    CPPUNIT_ASSERT(t1.GetTimeInUsec() == 0);

    // Test copy constructor.
    Time  t2(t1);
    CPPUNIT_ASSERT(t2.GetTimeInUsec() == 0);

    // Test constructor from struct timeval.
    struct timeval  tv = {5000, 345678};

    Time  t3(tv);
    CPPUNIT_ASSERT(t3.GetTimeInUsec() == 5000345678);

    // Test constructor from struct timespec.
    struct timespec  ts = {999, 123456};

    Time  t4(ts);
    CPPUNIT_ASSERT(t4.GetTimeInUsec() == 999000123);

    // Test constuctor from seconds.
    Time  t5(static_cast<int>(3));
    CPPUNIT_ASSERT(t5.GetTimeInUsec() == 3000000);

    Time  t6(static_cast<int>(-8));
    CPPUNIT_ASSERT(t6.GetTimeInUsec() == -8000000);

    Time  t7(static_cast<time_t>(3));
    CPPUNIT_ASSERT(t7.GetTimeInUsec() == 3000000);

    Time  t8(static_cast<time_t>(-8));
    CPPUNIT_ASSERT(t8.GetTimeInUsec() == -8000000);

    // Test constructor from seconds and microseconds.
    Time  t9(static_cast<time_t>(4), static_cast<suseconds_t>(987654));
    CPPUNIT_ASSERT(t9.GetTimeInUsec() == 4987654);

    Time  t10(static_cast<time_t>(-7), static_cast<suseconds_t>(777666));
    CPPUNIT_ASSERT(t10.GetTimeInUsec() == -6222334);

    // Test constructor from double.
    Time  t11(4.5);
    CPPUNIT_ASSERT(t11.GetTimeInUsec() == 4500000);

    Time  t12(static_cast<double>(-4.567890));
    CPPUNIT_ASSERT(t12.GetTimeInUsec() == -4567890);
  }

  //==========================================================================
  void TestFromSec()
  {
    Time  t1 = Time::FromSec(10);
    CPPUNIT_ASSERT(t1.GetTimeInUsec() == 10000000);

    Time  t2 = Time::FromSec(-10);
    CPPUNIT_ASSERT(t2.GetTimeInUsec() == -10000000);
  }

  //==========================================================================
  void TestFromMsec()
  {
    Time  t1 = Time::FromMsec(10);
    CPPUNIT_ASSERT(t1.GetTimeInUsec() == 10000);

    Time  t2 = Time::FromMsec(1000);
    CPPUNIT_ASSERT(t2.GetTimeInUsec() == 1000000);

    Time  t3 = Time::FromMsec(-100);
    CPPUNIT_ASSERT(t3.GetTimeInUsec() == -100000);

    Time  t4 = Time::FromMsec(-10400);
    CPPUNIT_ASSERT(t4.GetTimeInUsec() == -10400000);
  }

  //==========================================================================
  void TestFromUsec()
  {
    Time  t1 = Time::FromUsec(10);
    CPPUNIT_ASSERT(t1.GetTimeInUsec() == 10);

    Time  t2 = Time::FromUsec(-10);
    CPPUNIT_ASSERT(t2.GetTimeInUsec() == -10);

    Time  t3 = Time::FromUsec(-4567890);
    CPPUNIT_ASSERT(t3.GetTimeInUsec() == -4567890);
  }

  //==========================================================================
  void TestMaxAndMinOperators()
  {
    Time  t1 = Time::FromSec(1000);
    Time  t2 = Time::FromSec(900);

    Time  t3 = Time::Max(t1, t2);
    CPPUNIT_ASSERT(t3 == t1);

    Time t4 = Time::Min(t1, t2);
    CPPUNIT_ASSERT(t4 == t2);
  }

  //==========================================================================
  void TestToTval()
  {
    Time  t1(1000, 999999);
    CPPUNIT_ASSERT(t1.GetTimeInUsec() == 1000999999);

    timeval  t_val = t1.ToTval();
    CPPUNIT_ASSERT((t_val.tv_sec == 1000) && (t_val.tv_usec == 999999));
  }

  //==========================================================================
  void TestAdd()
  {
    Time  t1 = Time::FromSec(10);
    Time  t2 = Time::FromSec(20);

    CPPUNIT_ASSERT(t1.Add(t2).GetTimeInUsec() == 30000000);
    CPPUNIT_ASSERT(t1.Add(1.5).GetTimeInUsec() == 11500000);

    // Test adding a positive floating point time.
    Time    t3(100, 935261);
    double  fp = 11.638192;
    t3 = t3.Add(fp);
    CPPUNIT_ASSERT(t3.GetTimeInUsec() == 112573453);

    // Test adding zero.
    Time  t4(100, 935261);
    fp = 0.0;
    t4 = t4.Add(fp);
    CPPUNIT_ASSERT(t4.GetTimeInUsec() == 100935261);

    // Test adding a negative floating point time.
    Time  t5(100, 191486);
    fp = -6.729571;
    t5 = t5.Add(fp);
    CPPUNIT_ASSERT(t5.GetTimeInUsec() == 93461915);

    // Test adding a negative floating point time to a negative time.
    Time  t6(-10.9);
    fp = -5.4;
    t6 = t6.Add(fp);
    CPPUNIT_ASSERT(t6.GetTimeInUsec() == -16300000);
  }

  //==========================================================================
  void TestSubtract()
  {
    Time  t1 = Time::FromSec(60);
    Time  t2 = Time::FromSec(20);

    CPPUNIT_ASSERT(t1.Subtract(t2).GetTimeInUsec() == 40000000);

    Time  t3;
    Time  t4 = Time::FromMsec(10700);

    t3 = t3.Subtract(t4);
    CPPUNIT_ASSERT(t3.GetTimeInUsec() == -10700000);
    CPPUNIT_ASSERT(t3.ToString() == "-10.700000s");

    struct timeval  res = t3.ToTval();
    CPPUNIT_ASSERT(res.tv_sec == -11);
    CPPUNIT_ASSERT(res.tv_usec == 300000);

    Time  t5;
    t5 = t5 - t4;

    CPPUNIT_ASSERT(t5.GetTimeInUsec() == -10700000);
    CPPUNIT_ASSERT(t5.ToString() == "-10.700000s");

    res = t5.ToTval();
    CPPUNIT_ASSERT(res.tv_sec == -11);
    CPPUNIT_ASSERT(res.tv_usec == 300000);
  }

  //==========================================================================
  void TestMultiply()
  {
    Time  t1 = Time::FromSec(60);
    CPPUNIT_ASSERT(t1.Multiply(2).GetTimeInUsec() == 120000000);

    Time  t2 = Time::FromMsec(500);
    CPPUNIT_ASSERT(t2.Multiply(3).GetTimeInUsec() == 1500000);

    Time  t3 = Time::FromMsec(100);
    CPPUNIT_ASSERT(t3.Multiply(10.5).GetTimeInUsec() == 1050000);

    Time  t4 = Time::FromMsec(1400);
    CPPUNIT_ASSERT(t4.Multiply(-2).GetTimeInUsec() == -2800000);

    Time  t5 = Time::FromMsec(-1900);
    CPPUNIT_ASSERT(t5.Multiply(5).GetTimeInUsec() == -9500000);

    Time  t6 = Time::FromMsec(-1300);
    CPPUNIT_ASSERT(t6.Multiply(-2).GetTimeInUsec() == 2600000);
  }

  //==========================================================================
  void TestZeroTime()
  {
    Time  t1;
    CPPUNIT_ASSERT(t1.IsZero());

    Time  t2 = Time::FromSec(1);
    CPPUNIT_ASSERT(!t2.IsZero());
  }

  //==========================================================================
  void TestInfiniteTime()
  {
    Time  t1 = Time::Infinite();
    CPPUNIT_ASSERT(t1.IsInfinite());
  }

  //==========================================================================
  void TestGetTime()
  {
    Time  t1 = Time::FromUsec(1000);
    CPPUNIT_ASSERT(t1.GetTimeInSec() == 0);
    CPPUNIT_ASSERT(t1.GetTimeInMsec() == 1);
    CPPUNIT_ASSERT(t1.GetTimeInUsec() == 1000);
  }

  //==========================================================================
  void TestMonotonic()
  {
    Time m_time1;
    CPPUNIT_ASSERT(m_time1.GetNow());
    Time m_time5;
    CPPUNIT_ASSERT(m_time5.GetNow());
    CPPUNIT_ASSERT(m_time1.GetNowInUsec() <=  m_time5.GetNowInUsec());
    timespec t_spec1 = {1000, 123456789};
    Time m_time2(t_spec1);
    CPPUNIT_ASSERT(m_time2.GetTimeInUsec() == 1000123457);
    timespec t_spec2 = {1000, 111111111};
    Time m_time3(t_spec2);
    CPPUNIT_ASSERT(m_time3.GetTimeInUsec() == 1000111111);
    CPPUNIT_ASSERT(m_time3.GetTimeInSec() == 1000);

    Time m_time4;
    CPPUNIT_ASSERT(m_time5.GetNow());
    CPPUNIT_ASSERT(m_time4 <= m_time5);
  }

  //==========================================================================
  void TestOperators()
  {
    timeval t_val1 = {10, 200000};
    timeval t_val2 = {3, 800005};
    Time m_time1 = Time(t_val1);
    Time m_time2 = Time(t_val2);
    m_time1 += m_time2;
    CPPUNIT_ASSERT(m_time1.GetTimeInUsec() == 14000005);

    t_val1.tv_sec = 1000;
    t_val1.tv_usec = 999999;
    m_time1 = Time(t_val1);
    CPPUNIT_ASSERT(m_time1.GetTimeInUsec() == 1000999999);
    m_time2 = Time(t_val1);
    int64_t addTime = (m_time1 + m_time2).GetTimeInUsec();
    CPPUNIT_ASSERT(addTime == 2001999998);
    int64_t subTime = (m_time1 - m_time2).GetTimeInUsec();
    CPPUNIT_ASSERT(subTime == 0);
    CPPUNIT_ASSERT(m_time1 == m_time2);
    CPPUNIT_ASSERT((m_time1 != m_time2) == false);
    CPPUNIT_ASSERT(m_time1 >= m_time2);
    CPPUNIT_ASSERT(m_time1 <= m_time2);
    t_val1.tv_usec = 999998;
    Time m_time3(t_val1);
    CPPUNIT_ASSERT(m_time3 < m_time2);
    CPPUNIT_ASSERT(m_time2 > m_time3);
    Time m_time4;
    CPPUNIT_ASSERT(m_time4.GetNow());
    Time m_time6 = m_time4;
    CPPUNIT_ASSERT(m_time6 == m_time4);
    Time m_time7 = m_time3 + 10;
    CPPUNIT_ASSERT(m_time7.GetTimeInUsec() == 1010999998);
  }

  //==========================================================================
  void TestGetTimeInFormat()
  {
    Time  t1(200, 10);

    char    s1[] = "200.000010s";
    string  s2   = t1.GetTimeInFormat("%H:%M:%us");
    string  s3   = "00:03:000010";
    CPPUNIT_ASSERT(t1.ToString() == s1);
    CPPUNIT_ASSERT(s2 == s3);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(TimeTest);
}
