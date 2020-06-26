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

#include "rng.h"

#include <cstdio>
#include <cstring>

using ::iron::RNG;
using ::std::cout;

namespace iron
{

//============================================================================
class RNGTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(RNGTest);

  CPPUNIT_TEST(testGetRand);
  CPPUNIT_TEST(testGetInt);
  CPPUNIT_TEST(testGetFloat);
  CPPUNIT_TEST(testGetDouble);
  CPPUNIT_TEST(testGetByteSequence);
  CPPUNIT_TEST(testOperations);

  CPPUNIT_TEST_SUITE_END();

public:

  //==========================================================================
  void setUp()
  {
    // Do nothing.
  }

  //==========================================================================
  void tearDown()
  {
    // Do nothing.
  }

  void testGetRand()
  {
    // cout << "GetRand() Test ...\n";
    RNG rng1;
    // cout << rng1.ToString();

    RNG rng2(10);
    // cout << rng2.ToString();

    int  dup_cnt = 0;

    for (int i = 0; i < 1000; i++)
    {
      int32_t  v1 = rng1.GetRand();
      int32_t  v2 = rng2.GetRand();
      // cout << "Next rand 1 " << v1 << "\n";
      // cout << "Next rand 2 " << v2 << "\n";
      CPPUNIT_ASSERT(v1 >= 0);
      CPPUNIT_ASSERT(v2 >= 0);

      // Allow for a single duplicate in 1000 random draws.
      if (v1 == v2)
      {
        dup_cnt++;
      }

      CPPUNIT_ASSERT(dup_cnt <= 1);
    }
    // cout << "...GetRand Done and OK\n";
  }

  void testGetInt()
  {
    // cout << "GetInt() Test ...\n";
    RNG rng(8888);
    // cout << rng.ToString();

    for (int i = 0; i < 1000; i++)
    {
      int32_t  v1 = rng.GetInt(100);
      CPPUNIT_ASSERT(v1 >= 0);
      CPPUNIT_ASSERT(v1 <= 100);
    }
    // cout << "...GetInt Done and OK\n";
  }

  void testGetFloat()
  {
    // cout << "GetFloat() Test ...\n";
    RNG rng;
    // cout << rng.ToString();

    for (int i = 0; i < 1000; i++)
    {
      float  v1 = rng.GetFloat(100.0f);
      CPPUNIT_ASSERT(v1 >= 0.0f);
      CPPUNIT_ASSERT(v1 <= 100.0f);
    }
    // cout << "...GetFloat Done and OK\n";
  }

  void testGetDouble()
  {
    // cout << "GetDouble() Test ...\n";
    RNG rng;
    // cout << rng.ToString();

    for (int i = 0; i < 1000; i++)
    {
      double  v1 = rng.GetDouble(1000.0);
      CPPUNIT_ASSERT(v1 >= 0.0);
      CPPUNIT_ASSERT(v1 <= 1000.0);
    }
    // cout << "...GetDouble Done and OK\n";
  }

  void testGetByteSequence()
  {
    // cout << "GetByteSequence() Test ...\n";
    RNG rng(1234);
    // cout << rng.ToString();

    size_t    len = 1024;
    uint8_t*  seq = new uint8_t[len];

    // Generate a random byte sequence.
    CPPUNIT_ASSERT(rng.GetByteSequence(seq, len) == true);

    // Count the occurance of each possible random byte.
    uint32_t  cnt[256];
    memset(cnt, 0, sizeof(cnt));

    for (size_t i = 0; i < len; i++)
    {
      cnt[seq[i]] += 1;
    }

    // Find the maximum count of all counts.
    uint32_t  max_cnt = 0;

    for (int i = 0; i < 256; i++)
    {
      if (cnt[i] > max_cnt)
      {
        max_cnt = cnt[i];
      }
    }

    // The maximum count should theoretically be 4 when "len" is 1024.
    // However, in practice, it has been observed to be as high as 14.  Add a
    // bit of room.  Note that if "len" above is changed, then the value used
    // in this comparison will also need updated.
    CPPUNIT_ASSERT(max_cnt <= 20);

    delete [] seq;
    // cout << "...GetByteSequence Done and OK\n";
  }

  void testOperations()
  {
    RNG rng1(200);
    RNG rng2(200);

    // cout << "Test same seed --> same numbers ...\n";
    for (int i = 0; i < 20; i++)
    {
      int32_t  v1 = rng1.GetInt(100);
      CPPUNIT_ASSERT(v1 >= 0);
      CPPUNIT_ASSERT(v1 <= 100);
    }

    for (int i = 0; i < 20; i++)
    {
      int32_t  v2 = rng2.GetInt(100);
      CPPUNIT_ASSERT(v2 >= 0);
      CPPUNIT_ASSERT(v2 <= 100);
    }

    CPPUNIT_ASSERT(rng1.GetInt(100) == rng2.GetInt(100));
    // cout << "...Test same seed --> same numbers Done and OK\n";
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(RNGTest);

}
