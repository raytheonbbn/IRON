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

#include "bin_map.h"

#include "config_info.h"
#include "ipv4_address.h"
#include "iron_constants.h"
#include "log.h"

#include <string.h>


using ::iron::BinId;
using ::iron::BinIndex;
using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::DstVec;
using ::iron::Ipv4Address;
using ::iron::kInvalidBinId;
using ::iron::kInvalidBinIndex;
using ::iron::Log;
using ::iron::McastId;


//============================================================================
class BinMapTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(BinMapTest);

  CPPUNIT_TEST(TestInitialize);
  CPPUNIT_TEST(TestInitializeOneId);
  CPPUNIT_TEST(TestIteratorsWithoutIntNodes);
  CPPUNIT_TEST(TestNestedIteratorsWithoutIntNodes);
  CPPUNIT_TEST(TestIteratorsWithIntNodes);
  CPPUNIT_TEST(TestNestedIteratorsWithIntNodes);
  CPPUNIT_TEST(TestBinIndexIsAssigned);
  CPPUNIT_TEST(TestUcastBinIdIsInValidRange);
  CPPUNIT_TEST(TestGetDstBinIndexFromAddress);
  CPPUNIT_TEST(TestGetMcastIdFromAddress);
  CPPUNIT_TEST(TestGetNumIds);
  CPPUNIT_TEST(TestGetPhyBinId);
  CPPUNIT_TEST(TestGetPhyBinIndex);
  CPPUNIT_TEST(TestGetMcastId);
  CPPUNIT_TEST(TestBinIndexIsAssigned2);
  CPPUNIT_TEST(TestMcastAddr);
  CPPUNIT_TEST(TestIsMcastBinIndex);
  CPPUNIT_TEST(TestOffsetAndMaxNums);
  CPPUNIT_TEST(TestDstVecSubtract);
  CPPUNIT_TEST(TestGetIdToLog);

  CPPUNIT_TEST_SUITE_END();

private:

  char*       bin_map_mem_ = NULL;
  BinMap*     bin_map_     = NULL;
  ConfigInfo  config_info_;

public:

  //==========================================================================
  void setUp()
  {
    bin_map_mem_ = new char[sizeof(BinMap)];
    bin_map_     = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));
    Log::SetDefaultLevel("F");

    // The configuration for the majority of the test does not contain
    // interior nodes.  When needed, interior node configuration information
    // will be added to the ConfigInfo object.
    config_info_.Add("BinMap.BinIds", "0,1");
    config_info_.Add("BinMap.BinId.0.HostMasks",
                     "192.168.1.0/24,10.1.1.0/24,1.2.3.4");
    config_info_.Add("BinMap.BinId.1.HostMasks",
                     "192.168.2.0/24,10.2.2.2,5.6.7.8");
    config_info_.Add("BinMap.NumMcastGroups", "2");
    config_info_.Add("BinMap.McastGroup.0.Addr", "224.9.18.27");
    config_info_.Add("BinMap.McastGroup.0.Members", "0,1");
    config_info_.Add("BinMap.McastGroup.1.Addr", "225.9.18.27");
    config_info_.Add("BinMap.McastGroup.1.Members", "0,1");
  }

  //==========================================================================
  void AddDynamicMulticastGroups()
  {
    Ipv4Address  addr1("226.2.4.8");
    bin_map_->AddDstToMcastGroup(addr1, 0);

    Ipv4Address  addr2("227.3.6.9");
    bin_map_->AddDstToMcastGroup(addr2, 1);
  }

  //==========================================================================
  void tearDown()
  {
    delete [] bin_map_mem_;
    bin_map_     = NULL;
    bin_map_mem_ = NULL;

    config_info_.Reset();

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestInitialize()
  {
    // Test the value of initialized() before invoking the Initialize()
    // method.
    CPPUNIT_ASSERT(!bin_map_->initialized());

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);
    CPPUNIT_ASSERT(bin_map_->initialized());
  }

  //==========================================================================
  void TestInitializeOneId()
  {
    // Test the value of initialized() before invoking the Initialize()
    // method.
    CPPUNIT_ASSERT(!bin_map_->initialized());

    ConfigInfo  ci_one_id;
    ci_one_id.Add("BinMap.BinIds", "10");
    ci_one_id.Add("BinMap.BinId.10.HostMasks", "192.168.1.0/24,1.2.3.4");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(ci_one_id) == true);
    CPPUNIT_ASSERT(bin_map_->initialized());
  }

  //==========================================================================
  void TestIteratorsWithoutIntNodes()
  {
    // Tests out the various BinMap iterators when there are no interior nodes
    // in the BinMap configuration.

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_));

    //**************************************************************************
    // Test out GetFirstUcastBinIndex() and GetNextUcastBinIndex().
    //
    // The returned bin indices should be: 0 and 1
    BinIndex  bin_idx = kInvalidBinIndex;
    CPPUNIT_ASSERT(bin_map_->GetFirstUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstIntNodeBinIndex() and GetNextIntNodeBinIndex().
    //
    // There are no interior nodes in this test.
    CPPUNIT_ASSERT(!bin_map_->GetFirstIntNodeBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);
    CPPUNIT_ASSERT(!bin_map_->GetNextIntNodeBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstMcastBinIndex() and GetNextMcastBinIndex().
    //
    // The returned bin indices should be 512, 513, and 514. Note that there
    // is the special multicast address used internally, 224.77.77.77, in
    // addition to the multicast groups identified in the configuration
    // information.
    CPPUNIT_ASSERT(bin_map_->GetFirstMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 513);
    CPPUNIT_ASSERT(bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstDstBinIndex() and GetNextDstBinIndex(). This should
    // iterate over unicast and multicast bin indices.
    //
    // The returned bin indices should be 0, 1, 512, 513, and 514. Note that
    // there is the special multicast address used internally, 224.77.77.77,
    // in addition to the multicast groups identified in the configuration
    // information.
    CPPUNIT_ASSERT(bin_map_->GetFirstDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 513);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstPhyBinIndex() and GetNextPhyBinIndex(). This should
    // iterate over unicast and interior node bin indices.
    //
    // The returned bin indices should be 0 and 1.
    CPPUNIT_ASSERT(bin_map_->GetFirstPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstBinIndex() and GetNextBinIndex().
    //
    // The returned bin indices should be 0, 1, 512, 513, and 514. Note that
    // there is the special multicast address used internally, 224.77.77.77,
    // in addition to the multicast groups identified in the configuration
    // information.
    CPPUNIT_ASSERT(bin_map_->GetFirstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 513);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test iterator operation, mid-iterator.
    bin_idx = 1;
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);

    bin_idx = 513;
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);

    // The following should fail and set bin_idx to kInvalidBinIndex.
    CPPUNIT_ASSERT(!bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out invalid combinations of iterator calls.
    CPPUNIT_ASSERT(bin_map_->GetFirstUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(!bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    CPPUNIT_ASSERT(bin_map_->GetFirstMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(!bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);
  }

  //==========================================================================
  void TestNestedIteratorsWithoutIntNodes()
  {
    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_));

    size_t    outer_cnt     = 0;
    BinIndex  outer_bin_idx = kInvalidBinIndex;
    for (bool  outer_valid = bin_map_->GetFirstBinIndex(outer_bin_idx);
         outer_valid;
         outer_valid = bin_map_->GetNextBinIndex(outer_bin_idx))
    {
      // Check the value of outer_bin_idx. We do this by looking at the
      // current value of outer_cnt. outer_bin_idx should take on the values:
      // 0, 1, 512, 513, and 514.
      if (outer_cnt == 0)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 0);
      }
      else if (outer_cnt == 1)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 1);
      }
      else if (outer_cnt == 2)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 512);
      }
      else if (outer_cnt == 3)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 513);
      }
      else if (outer_cnt == 4)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 514);
      }

      ++outer_cnt;

      size_t    inner_cnt     = 0;
      BinIndex  inner_bin_idx = kInvalidBinIndex;
      for (bool  inner_valid = bin_map_->GetFirstBinIndex(inner_bin_idx);
           inner_valid;
           inner_valid = bin_map_->GetNextBinIndex(inner_bin_idx))
      {
        // Check the value of inner_bin_idx. We do this by looking at the
        // current value of inner_cnt. inner_bin_idx should take on the
        // values: 0, 1, 512, 513, and 514.
        if (inner_cnt == 0)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 0);
        }
        else if (inner_cnt == 1)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 1);
        }
        else if (inner_cnt == 2)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 512);
        }
        else if (inner_cnt == 3)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 513);
        }
        else if (inner_cnt == 4)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 514);
        }

        ++inner_cnt;
      }

      // The inner BinIndex should now be kInvalidBinIndex.
      CPPUNIT_ASSERT(inner_bin_idx == kInvalidBinIndex);
    }

    // The outer BinIndex should now be kInvalidBinIndex.
    CPPUNIT_ASSERT(outer_bin_idx == kInvalidBinIndex);
  }

  //==========================================================================
  void TestIteratorsWithIntNodes()
  {
    // Tests out the various BinMap iterators when there are interior nodes in
    // the BinMap configuration.

    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_));

    // Add dynamic multicast groups to the BinMap.
    AddDynamicMulticastGroups();

    //**************************************************************************
    // Test out GetFirstUcastBinIndex() and GetNextUcastBinIndex().
    //
    // The returned bin indices should be: 0 and 1
    BinIndex  bin_idx = kInvalidBinIndex;
    CPPUNIT_ASSERT(bin_map_->GetFirstUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstIntNodeBinIndex() and GetNextIntNodeBinIndex().
    //
    // The returned bin indices should be 256, 257, 258, 259, and 260.
    CPPUNIT_ASSERT(bin_map_->GetFirstIntNodeBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 256);
    CPPUNIT_ASSERT(bin_map_->GetNextIntNodeBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 257);
    CPPUNIT_ASSERT(bin_map_->GetNextIntNodeBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 258);
    CPPUNIT_ASSERT(bin_map_->GetNextIntNodeBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 259);
    CPPUNIT_ASSERT(bin_map_->GetNextIntNodeBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 260);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstMcastBinIndex() and GetNextMcastBinIndex().
    //
    // The returned bin indices should be 512, 513, 514, 515, and 516. Note
    // that there is the special multicast address used internally,
    // 224.77.77.77, in addition to the multicast groups identified in the
    // configuration information.
    CPPUNIT_ASSERT(bin_map_->GetFirstMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 513);
    CPPUNIT_ASSERT(bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);
    CPPUNIT_ASSERT(bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 515);
    CPPUNIT_ASSERT(bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 516);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstDstBinIndex() and GetNextDstBinIndex(). This should
    // iterate over unicast and multicast bin indices.
    //
    // The returned bin indices should be 0, 1, 512, 513, 514, 515, and 516.
    // Note that there is the special multicast address used internally,
    // 224.77.77.77, in addition to the multicast groups identified in the
    // configuration information.
    CPPUNIT_ASSERT(bin_map_->GetFirstDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 513);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 515);
    CPPUNIT_ASSERT(bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 516);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextDstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstPhyBinIndex() and GetNextPhyBinIndex(). This should
    // iterate over unicast and interior node bin indices.
    //
    // The returned bin indices should be 0, 1, 256, 257, 258, 259, and 260.
    CPPUNIT_ASSERT(bin_map_->GetFirstPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 256);
    CPPUNIT_ASSERT(bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 257);
    CPPUNIT_ASSERT(bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 258);
    CPPUNIT_ASSERT(bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 259);
    CPPUNIT_ASSERT(bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 260);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextPhyBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out GetFirstBinIndex() and GetNextBinIndex().
    //
    // The returned bin indices should be 0, 1, 256, 257, 258, 259, 260, 512,
    // 513, 514, 515, and 516. Note that there is the special multicast
    // address used internally, 224.77.77.77, in addition to the multicast
    // groups identified in the configuration information.
    CPPUNIT_ASSERT(bin_map_->GetFirstBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 256);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 257);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 258);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 259);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 260);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 513);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 515);
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 516);

    // The iteration should now be complete.
    CPPUNIT_ASSERT(!bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test iterator operation, mid-iterator.
    bin_idx = 1;
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 256);

    bin_idx = 513;
    CPPUNIT_ASSERT(bin_map_->GetNextBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 514);

    // The following should fail and set bin_idx to kInvalidBinIndex.
    CPPUNIT_ASSERT(!bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    //**************************************************************************
    // Test out invalid combinations of iterator calls.
    CPPUNIT_ASSERT(bin_map_->GetFirstUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(!bin_map_->GetNextMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);

    CPPUNIT_ASSERT(bin_map_->GetFirstMcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(!bin_map_->GetNextUcastBinIndex(bin_idx));
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);
  }

  //==========================================================================
  void TestNestedIteratorsWithIntNodes()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_));

    // Add dynamic multicast groups to the BinMap.
    AddDynamicMulticastGroups();

    size_t    outer_cnt     = 0;
    BinIndex  outer_bin_idx = kInvalidBinIndex;
    for (bool  outer_valid = bin_map_->GetFirstBinIndex(outer_bin_idx);
         outer_valid;
         outer_valid = bin_map_->GetNextBinIndex(outer_bin_idx))
    {
      // Check the value of outer_bin_idx. We do this by looking at the
      // current value of outer_cnt. outer_bin_idx should take on the values:
      // 0, 1, 256, 257, 258, 259, 260, 512, 513, 514, 515, and 516.
      if (outer_cnt == 0)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 0);
      }
      else if (outer_cnt == 1)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 1);
      }
      else if (outer_cnt == 2)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 256);
      }
      else if (outer_cnt == 3)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 257);
      }
      else if (outer_cnt == 4)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 258);
      }
      else if (outer_cnt == 5)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 259);
      }
      else if (outer_cnt == 6)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 260);
      }
      else if (outer_cnt == 7)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 512);
      }
      else if (outer_cnt == 8)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 513);
      }
      else if (outer_cnt == 9)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 514);
      }
      else if (outer_cnt == 10)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 515);
      }
      else if (outer_cnt == 11)
      {
        CPPUNIT_ASSERT(outer_bin_idx == 516);
      }

      ++outer_cnt;

      size_t    inner_cnt     = 0;
      BinIndex  inner_bin_idx = kInvalidBinIndex;
      for (bool  inner_valid = bin_map_->GetFirstBinIndex(inner_bin_idx);
           inner_valid;
           inner_valid = bin_map_->GetNextBinIndex(inner_bin_idx))
      {
        // Check the value of inner_bin_idx. We do this by looking at the
        // current value of inner_cnt. inner_bin_idx should take on the
        // values: 0, 1, 256, 257, 258, 259, 260, 512, 513, 514, 515, and 516.
        if (inner_cnt == 0)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 0);
        }
        else if (inner_cnt == 1)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 1);
        }
        else if (inner_cnt == 2)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 256);
        }
        else if (inner_cnt == 3)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 257);
        }
        else if (inner_cnt == 4)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 258);
        }
        else if (inner_cnt == 5)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 259);
        }
        else if (inner_cnt == 6)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 260);
        }
        else if (inner_cnt == 7)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 512);
        }
        else if (inner_cnt == 8)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 513);
        }
        else if (inner_cnt == 9)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 514);
        }
        else if (inner_cnt == 10)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 515);
        }
        else if (inner_cnt == 11)
        {
          CPPUNIT_ASSERT(inner_bin_idx == 516);
        }

        ++inner_cnt;
      }

      // The inner BinIndex should now be kInvalidBinIndex.
      CPPUNIT_ASSERT(inner_bin_idx == kInvalidBinIndex);
    }

    // The outer BinIndex should now be kInvalidBinIndex.
    CPPUNIT_ASSERT(outer_bin_idx == kInvalidBinIndex);
  }

  //==========================================================================
  void TestBinIndexIsAssigned()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_));

    // Following are the valid BinIndices given the configuration information:
    //
    // 0, 1, 256, 257, 258, 259, 260, 512, 513, and 514.
    BinIndex  bin_idx = 0;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 1;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 256;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 257;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 258;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 259;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 260;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 512;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 513;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 514;
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(bin_idx));

    // Test some invalid values.
    bin_idx = 3;
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 261;
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(bin_idx));
    bin_idx = 515;
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(bin_idx));
  }

  //==========================================================================
  void TestUcastBinIdIsInValidRange()
  {
    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Test valid unicast (destination) BinId values.
    BinId  bin_id = 0;
    CPPUNIT_ASSERT(bin_map_->UcastBinIdIsInValidRange(bin_id));
    bin_id = 23;
    CPPUNIT_ASSERT(bin_map_->UcastBinIdIsInValidRange(bin_id));

    // Test invalid unicast (destination) BinId value.
    bin_id = 24;
    CPPUNIT_ASSERT(!bin_map_->UcastBinIdIsInValidRange(bin_id));

    // Test valid interior node BinId values.
    bin_id = 0;
    CPPUNIT_ASSERT(bin_map_->IntNodeBinIdIsInValidRange(bin_id));
    bin_id = 254;
    CPPUNIT_ASSERT(bin_map_->IntNodeBinIdIsInValidRange(bin_id));

    // Test invalid interior node BinId value.
    bin_id = 255;
    CPPUNIT_ASSERT(!bin_map_->IntNodeBinIdIsInValidRange(bin_id));
  }

  //==========================================================================
  void TestGetDstBinIndexFromAddress()
  {
    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Add dynamic multicast groups to the BinMap.
    AddDynamicMulticastGroups();

    Ipv4Address  addr("192.168.1.1");
    BinIndex  bin_idx = kInvalidBinIndex;
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 0);

    addr.set_address("192.168.2.1");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 1);

    addr.set_address("10.1.1.2");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 0);

    addr.set_address("10.2.2.2");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 1);

    addr.set_address("224.77.77.77");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 512);
    CPPUNIT_ASSERT(bin_map_->GetMcastId(bin_idx) == addr.address());

    addr.set_address("224.9.18.27");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 513);
    CPPUNIT_ASSERT(bin_map_->GetMcastId(bin_idx) == addr.address());

    addr.set_address("225.9.18.27");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 514);
    CPPUNIT_ASSERT(bin_map_->GetMcastId(bin_idx) == addr.address());

    addr.set_address("226.2.4.8");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 515);
    CPPUNIT_ASSERT(bin_map_->GetMcastId(bin_idx) == addr.address());

    addr.set_address("227.3.6.9");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 516);
    CPPUNIT_ASSERT(bin_map_->GetMcastId(bin_idx) == addr.address());

    addr.set_address("192.168.1.3");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 0);

    addr.set_address("192.168.2.10");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 1);

    addr.set_address("10.1.1.8");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 0);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 0);

    addr.set_address("10.2.2.2");
    bin_idx = bin_map_->GetDstBinIndexFromAddress(addr);
    CPPUNIT_ASSERT(bin_idx == 1);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinId(bin_idx) == 1);
  }

  //==========================================================================
  void TestGetMcastIdFromAddress()
  {
    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    Ipv4Address  addr("224.9.18.27");
    CPPUNIT_ASSERT(bin_map_->GetMcastIdFromAddress(addr) == addr.address());

    addr.set_address("225.9.18.27");
    CPPUNIT_ASSERT(bin_map_->GetMcastIdFromAddress(addr) == addr.address());

    addr.set_address("224.77.77.77");
    CPPUNIT_ASSERT(bin_map_->GetMcastIdFromAddress(addr) == addr.address());
  }

  //==========================================================================
  void TestGetNumIds()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    CPPUNIT_ASSERT(bin_map_->GetNumUcastBinIds() == 2);
    CPPUNIT_ASSERT(bin_map_->GetNumIntNodeBinIds() == 4);
    CPPUNIT_ASSERT(bin_map_->GetNumMcastIds() == 3);

    // Add dynamic multicast groups to the BinMap.
    AddDynamicMulticastGroups();
    CPPUNIT_ASSERT(bin_map_->GetNumMcastIds() == 5);
  }

  //==========================================================================
  void TestGetPhyBinId()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // The following BinIndex values should successfully retrieve BinId
    // values: 0, 1, 256, 257, 258, 259, and 260.
    BinIndex  bin_idx = 0;
    BinId     bin_id  = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == 0);
    bin_idx = 1;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == 1);
    bin_idx = 256;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == 4);
    bin_idx = 257;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == 5);
    bin_idx = 258;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == 6);
    bin_idx = 259;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == 7);
    bin_idx = 260;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == 8);

    // Test with BinIndex values that are not present.
    bin_idx = 2;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == kInvalidBinId);
    bin_idx = 3;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == kInvalidBinId);
    bin_idx = 261;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == kInvalidBinId);
    bin_idx = 262;
    bin_id = bin_map_->GetPhyBinId(bin_idx);
    CPPUNIT_ASSERT(bin_id == kInvalidBinId);
  }

  //==========================================================================
  void TestGetPhyBinIndex()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // The following BinId values should result in a valid BinIndex return
    // value: 0, 1, 4, 5, 6, 7, and 8.
    // The following BinIndex values should be returned for these BinIds:
    // 0, 1, 256, 257, 258, 259, and 260.
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(0) == 0);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(1) == 1);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(4) == 256);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(5) == 257);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(6) == 258);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(7) == 259);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(8) == 260);

    // Test with BinId values that are not present.
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(2) == kInvalidBinIndex);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(3) == kInvalidBinIndex);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(9) == kInvalidBinIndex);
    CPPUNIT_ASSERT(bin_map_->GetPhyBinIndex(10) == kInvalidBinIndex);
  }

  //==========================================================================
  void TestGetMcastId()
  {
    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // The following are the valid multicast BinIndex values: 512, 513, and
    // 514.
    CPPUNIT_ASSERT(bin_map_->GetMcastId(512) ==
                   Ipv4Address("224.77.77.77").address());
    CPPUNIT_ASSERT(bin_map_->GetMcastId(513) ==
                   Ipv4Address("224.9.18.27").address());
    CPPUNIT_ASSERT(bin_map_->GetMcastId(514) ==
                   Ipv4Address("225.9.18.27").address());
  }

  //==========================================================================
  void TestBinIndexIsAssigned2()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Valid BinIndex values are: 0, 1, 256, 257, 258, 259, 260, 512, 513, and
    // 514. Note we won't test with an invalid BinIndex because the BinMap
    // issues a LogF statement when that happens.
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(0));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(1));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(256));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(257));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(258));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(259));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(260));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(512));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(513));
    CPPUNIT_ASSERT(bin_map_->BinIndexIsAssigned(514));

    CPPUNIT_ASSERT(bin_map_->IsUcastBinIndex(0));
    CPPUNIT_ASSERT(bin_map_->IsUcastBinIndex(1));

    CPPUNIT_ASSERT(bin_map_->IsIntNodeBinIndex(256));
    CPPUNIT_ASSERT(bin_map_->IsIntNodeBinIndex(257));
    CPPUNIT_ASSERT(bin_map_->IsIntNodeBinIndex(258));
    CPPUNIT_ASSERT(bin_map_->IsIntNodeBinIndex(259));
    CPPUNIT_ASSERT(bin_map_->IsIntNodeBinIndex(260));

    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(512));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(513));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(514));

    CPPUNIT_ASSERT(bin_map_->IsDstBinIndex(0));
    CPPUNIT_ASSERT(bin_map_->IsDstBinIndex(1));
    CPPUNIT_ASSERT(bin_map_->IsDstBinIndex(512));
    CPPUNIT_ASSERT(bin_map_->IsDstBinIndex(513));
    CPPUNIT_ASSERT(bin_map_->IsDstBinIndex(514));

    CPPUNIT_ASSERT(bin_map_->IsPhyBinIndex(0));
    CPPUNIT_ASSERT(bin_map_->IsPhyBinIndex(1));
    CPPUNIT_ASSERT(bin_map_->IsPhyBinIndex(256));
    CPPUNIT_ASSERT(bin_map_->IsPhyBinIndex(257));
    CPPUNIT_ASSERT(bin_map_->IsPhyBinIndex(258));
    CPPUNIT_ASSERT(bin_map_->IsPhyBinIndex(259));
    CPPUNIT_ASSERT(bin_map_->IsPhyBinIndex(260));

    // Test with BinIndex values that are not present or not the requested
    // type.
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(2));
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(3));
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(261));
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(262));
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(515));
    CPPUNIT_ASSERT(!bin_map_->BinIndexIsAssigned(516));

    CPPUNIT_ASSERT(!bin_map_->IsUcastBinIndex(2));
    CPPUNIT_ASSERT(!bin_map_->IsUcastBinIndex(3));
    CPPUNIT_ASSERT(!bin_map_->IsUcastBinIndex(256));
    CPPUNIT_ASSERT(!bin_map_->IsUcastBinIndex(257));
    CPPUNIT_ASSERT(!bin_map_->IsUcastBinIndex(512));
    CPPUNIT_ASSERT(!bin_map_->IsUcastBinIndex(513));

    CPPUNIT_ASSERT(!bin_map_->IsIntNodeBinIndex(0));
    CPPUNIT_ASSERT(!bin_map_->IsIntNodeBinIndex(1));
    CPPUNIT_ASSERT(!bin_map_->IsIntNodeBinIndex(261));
    CPPUNIT_ASSERT(!bin_map_->IsIntNodeBinIndex(262));
    CPPUNIT_ASSERT(!bin_map_->IsIntNodeBinIndex(512));
    CPPUNIT_ASSERT(!bin_map_->IsIntNodeBinIndex(513));

    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(0));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(1));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(256));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(257));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(515));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(516));

    CPPUNIT_ASSERT(!bin_map_->IsDstBinIndex(2));
    CPPUNIT_ASSERT(!bin_map_->IsDstBinIndex(3));
    CPPUNIT_ASSERT(!bin_map_->IsDstBinIndex(256));
    CPPUNIT_ASSERT(!bin_map_->IsDstBinIndex(257));
    CPPUNIT_ASSERT(!bin_map_->IsDstBinIndex(515));
    CPPUNIT_ASSERT(!bin_map_->IsDstBinIndex(516));

    CPPUNIT_ASSERT(!bin_map_->IsPhyBinIndex(2));
    CPPUNIT_ASSERT(!bin_map_->IsPhyBinIndex(3));
    CPPUNIT_ASSERT(!bin_map_->IsPhyBinIndex(261));
    CPPUNIT_ASSERT(!bin_map_->IsPhyBinIndex(262));
    CPPUNIT_ASSERT(!bin_map_->IsPhyBinIndex(512));
    CPPUNIT_ASSERT(!bin_map_->IsPhyBinIndex(513));
  }

  //==========================================================================
  void TestMcastAddr()
  {
    config_info_.Add("BinMap.NumMcastGroups", "3");
    config_info_.Add("BinMap.McastGroup.2.Addr", "238.0.1.2");
    config_info_.Add("BinMap.McastGroup.2.Members", "0");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Add dynamic multicast groups to the BinMap.
    AddDynamicMulticastGroups();

    // Test that a unicast destination does not have a multicast BinIndex.
    BinIndex  bin_idx_u  = bin_map_->GetPhyBinIndex(1);
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(bin_idx_u));

    // Test that configurated multicast destinations do have valid multicast
    // BinIndex values.
    Ipv4Address  addr("238.0.1.2");
    BinIndex     bin_idx = bin_map_->GetMcastBinIndex(addr.address());
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(bin_idx));

    addr.set_address("224.77.77.77");
    McastId  mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == 512);

    addr.set_address("224.9.18.27");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == 513);

    addr.set_address("225.9.18.27");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == 514);

    addr.set_address("238.0.1.2");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == 515);

    addr.set_address("226.2.4.8");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == 516);

    addr.set_address("227.3.6.9");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == 517);

    // Test that unconfigurated multicast destinations have invalid BinIndex
    // values.
    addr.set_address("224.9.18.26");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == kInvalidBinIndex);

    addr.set_address("225.9.17.27");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == kInvalidBinIndex);

    addr.set_address("238.1.1.2");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == kInvalidBinIndex);

    addr.set_address("227.3.6.1");
    mcast_id = bin_map_->GetMcastIdFromAddress(addr);
    CPPUNIT_ASSERT(mcast_id == addr.address());
    CPPUNIT_ASSERT(bin_map_->GetMcastBinIndex(mcast_id) == kInvalidBinIndex);

    // Test the multicast group management for a static multicast group,
    // 238.0.1.2.  These calls should not have any effect on the group.
    addr.set_address("238.0.1.2");
    bin_idx = bin_map_->GetMcastBinIndex(addr.address());
    CPPUNIT_ASSERT(bin_idx == 515);

    DstVec  init_dst_vec = bin_map_->GetMcastDst(bin_idx);

    bin_map_->AddDstToMcastGroup(addr, 1);
    CPPUNIT_ASSERT(bin_map_->GetMcastDst(bin_idx) == init_dst_vec);

    bin_map_->RemoveDstFromMcastGroup(addr, 0);
    CPPUNIT_ASSERT(bin_map_->GetMcastDst(bin_idx) == init_dst_vec);

    // Test the multicast group management for a dynamic multicast group,
    // 226.2.4.8.  It should start with just BinIndex 0 in the group.  Test
    // adding and then removing BinIndex 1.
    addr.set_address("226.2.4.8");
    bin_idx = bin_map_->GetMcastBinIndex(addr.address());
    CPPUNIT_ASSERT(bin_idx == 516);

    DstVec  tst_dst_vec = 0;
    DstVec  grp_dst_vec = bin_map_->GetMcastDst(bin_idx);
    tst_dst_vec = bin_map_->AddBinToDstVec(tst_dst_vec, 0);
    CPPUNIT_ASSERT(grp_dst_vec == tst_dst_vec);
    CPPUNIT_ASSERT(BinMap::GetNumBinsInDstVec(grp_dst_vec) == 1);
    CPPUNIT_ASSERT(bin_map_->IsBinInDstVec(grp_dst_vec, 0));
    CPPUNIT_ASSERT(!bin_map_->IsBinInDstVec(grp_dst_vec, 1));
    CPPUNIT_ASSERT(bin_map_->IsOnlyBinInDstVec(grp_dst_vec, 0));

    bin_map_->AddDstToMcastGroup(addr, 1);
    grp_dst_vec = bin_map_->GetMcastDst(bin_idx);
    tst_dst_vec = bin_map_->AddBinToDstVec(tst_dst_vec, 1);
    CPPUNIT_ASSERT(grp_dst_vec == tst_dst_vec);
    CPPUNIT_ASSERT(BinMap::GetNumBinsInDstVec(grp_dst_vec) == 2);
    CPPUNIT_ASSERT(bin_map_->IsBinInDstVec(grp_dst_vec, 0));
    CPPUNIT_ASSERT(bin_map_->IsBinInDstVec(grp_dst_vec, 1));
    CPPUNIT_ASSERT(!bin_map_->IsOnlyBinInDstVec(grp_dst_vec, 0));
    CPPUNIT_ASSERT(!bin_map_->IsOnlyBinInDstVec(grp_dst_vec, 1));

    bin_map_->RemoveDstFromMcastGroup(addr, 1);
    grp_dst_vec = bin_map_->GetMcastDst(bin_idx);
    tst_dst_vec = bin_map_->RemoveBinFromDstVec(tst_dst_vec, 1);
    CPPUNIT_ASSERT(grp_dst_vec == tst_dst_vec);
    CPPUNIT_ASSERT(BinMap::GetNumBinsInDstVec(grp_dst_vec) == 1);
    CPPUNIT_ASSERT(bin_map_->IsBinInDstVec(grp_dst_vec, 0));
    CPPUNIT_ASSERT(!bin_map_->IsBinInDstVec(grp_dst_vec, 1));
    CPPUNIT_ASSERT(bin_map_->IsOnlyBinInDstVec(grp_dst_vec, 0));

    // Next, purge BinIndex 0 from all groups.  Group 226.2.4.8 should not
    // have any destinations left.  Group 238.0.1.2 should just have BinIndex
    // 0 left.  Group 224.9.18.27 should just have BinIndex 1 left.
    bin_map_->PurgeDstFromMcastGroups(0);
    grp_dst_vec = bin_map_->GetMcastDst(bin_idx);
    tst_dst_vec = 0;
    CPPUNIT_ASSERT(grp_dst_vec == tst_dst_vec);

    addr.set_address("238.0.1.2");
    bin_idx = bin_map_->GetMcastBinIndex(addr.address());
    grp_dst_vec = bin_map_->GetMcastDst(bin_idx);
    tst_dst_vec = bin_map_->AddBinToDstVec(tst_dst_vec, 0);
    CPPUNIT_ASSERT(grp_dst_vec == tst_dst_vec);

    addr.set_address("224.9.18.27");
    bin_idx = bin_map_->GetMcastBinIndex(addr.address());
    grp_dst_vec = bin_map_->GetMcastDst(bin_idx);
    tst_dst_vec = bin_map_->AddBinToDstVec(tst_dst_vec, 1);
    CPPUNIT_ASSERT(grp_dst_vec == tst_dst_vec);

    // Finally, test GetMcastDst() on an unknown multicast group.
    addr.set_address("224.0.0.7");
    bin_idx = bin_map_->GetMcastBinIndex(addr.address());
    CPPUNIT_ASSERT(bin_idx == kInvalidBinIndex);
    CPPUNIT_ASSERT(bin_map_->GetMcastDst(bin_idx) == 0);
  }

  //==========================================================================
  void TestIsMcastBinIndex()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Tests that should succeed.
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(512));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(513));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(514));

    // Tests that should not succeed.
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(0));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(1));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(256));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(400));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(515));

    // Add dynamic multicast groups to the BinMap.
    AddDynamicMulticastGroups();

    // Tests that should succeed.
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(512));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(513));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(514));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(515));
    CPPUNIT_ASSERT(bin_map_->IsMcastBinIndex(516));

    // Tests that should not succeed.
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(0));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(1));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(256));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(400));
    CPPUNIT_ASSERT(!bin_map_->IsMcastBinIndex(517));
  }

  //==========================================================================
  void TestOffsetAndMaxNums()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Test the offset and maximum number of unicast (destination), interior
    // node, and multicast BinIndex values.
    CPPUNIT_ASSERT(bin_map_->ucast_bin_idx_offset() == 0);
    CPPUNIT_ASSERT(bin_map_->max_num_ucast_bin_idxs() ==
                   ::iron::kDstVecBitsUsed);
    CPPUNIT_ASSERT(bin_map_->max_num_ucast_bin_idxs() ==
                   ::iron::kMaxNumDsts);

    CPPUNIT_ASSERT(bin_map_->int_bin_idx_offset() == 256);
    CPPUNIT_ASSERT(bin_map_->max_num_int_bin_idxs() ==
                   ::iron::kMaxNumIntNodes);

    CPPUNIT_ASSERT(bin_map_->mcast_bin_idx_offset() == 512);
    CPPUNIT_ASSERT(bin_map_->max_num_mcast_bin_idxs() ==
                   ::iron::kMaxNumMcastGroups);
  }

  //==========================================================================
  void TestDstVecSubtract()
  {
    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Original DstVec is:          0000 0000 0000 1011 0100 1101
    // Subtract the DstVec:         0000 0000 0000 1001 0000 1001
    // Resulting DstVec should be:  0000 0000 0000 0010 0100 0100
    DstVec  original = 0x000b4d;
    DstVec  subtract = 0x000909;
    DstVec  result   = BinMap::DstVecSubtract(original, subtract);
    CPPUNIT_ASSERT(result == 0x000244);

    // Original DstVec is:          0000 0000 0000 1011 0100 1101
    // Subtract the DstVec:         0000 0000 0000 0000 0000 0000
    // Resulting DstVec should be:  0000 0000 0000 1011 0100 1101
    original = 0x000b4d;
    subtract = 0x000000;
    result   = BinMap::DstVecSubtract(original, subtract);
    CPPUNIT_ASSERT(result == 0x000b4d);

    // Original DstVec is:          0000 0000 0000 1011 0100 1101
    // Subtract the DstVec:         0000 0000 0000 1011 0100 1101
    // Resulting DstVec should be:  0000 0000 0000 0000 0000 0000
    original = 0x000b4d;
    subtract = 0x000b4d;
    result   = BinMap::DstVecSubtract(original, subtract);
    CPPUNIT_ASSERT(result == 0x000000);
  }

  //==========================================================================
  void TestGetIdToLog()
  {
    // Add interior nodes to the ConfigInfo object created for the test.
    config_info_.Add("BinMap.IntBinIds", "4,5,6,7,8");

    // Initialize the BinMap.
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_) == true);

    // Test valid unicast (destination), interior node, and multicast BinIndex
    // values.
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(0) == "D0");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(1) == "D1");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(256) == "I4");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(257) == "I5");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(258) == "I6");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(259) == "I7");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(260) == "I8");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(512) == "M224.77.77.77");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(513) == "M224.9.18.27");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(514) == "M225.9.18.27");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(512, true) == "224.77.77.77");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(513, true) == "224.9.18.27");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(514, true) == "225.9.18.27");

    // Test invalid BinIndex values.
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(2) == "INVALID BIN");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(3) == "INVALID BIN");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(261) == "INVALID BIN");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(262) == "INVALID BIN");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(515) == "INVALID BIN");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(516) == "INVALID BIN");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(515, true) == "INVALID BIN");
    CPPUNIT_ASSERT(bin_map_->GetIdToLog(516, true) == "INVALID BIN");
  }

};  // end class BinMapTest

CPPUNIT_TEST_SUITE_REGISTRATION(BinMapTest);
