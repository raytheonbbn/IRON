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

#include "packet_history_mgr.h"

#include "bin_map.h"
#include "config_info.h"
#include "log.h"
#include "packet.h"
#include "packet_pool_heap.h"

#include <inttypes.h>

using ::iron::BinId;
using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketHistoryMgr;
using ::iron::PacketPoolHeap;

//============================================================================
class PacketHistoryMgrTester : public PacketHistoryMgr
{
public:
  PacketHistoryMgrTester(BinMap& bin_map, BinId my_bin_id);
  virtual ~PacketHistoryMgrTester();
  bool VerifyNumVisits(Packet* packet,
                       BinId   bin_id,
                       uint32_t expected);
private:
  PacketHistoryMgrTester(const PacketHistoryMgrTester& other);
  PacketHistoryMgrTester operator=(const PacketHistoryMgrTester& other);
};

//============================================================================
PacketHistoryMgrTester::PacketHistoryMgrTester(BinMap& bin_map,
                                               BinId my_bin_id)
    : PacketHistoryMgr(bin_map, my_bin_id)
{}

//============================================================================
PacketHistoryMgrTester::~PacketHistoryMgrTester()
{}

//============================================================================
bool PacketHistoryMgrTester::VerifyNumVisits(Packet* packet,
                                             BinId bin_id,
                                             uint32_t expected)
{
  LogD("Test", __func__, "Looking for %" PRIu32 ", got %" PRIu32 "\n",
       expected, GetNumVisits(packet, bin_id));
  return (GetNumVisits(packet, bin_id) == expected);
}

//============================================================================
class PacketHistoryMgrTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(PacketHistoryMgrTest);
  CPPUNIT_TEST(TestPacketVisitedBin);
  CPPUNIT_TEST(TestNumVisits);
  CPPUNIT_TEST(TestGetAllVisitedBins);

  CPPUNIT_TEST_SUITE_END();

private:
  char* bin_map_mem_ = NULL;
  BinMap* bin_map_   = NULL;

public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FE");

    bin_map_mem_ = new char[sizeof(BinMap)];
    bin_map_     = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));

    ConfigInfo config_info;
    config_info.Add("BinMap.BinIds", "15,10,12,2,3");
    config_info.Add("BinMap.BinId.15.HostMasks",
                    "192.168.1.0/24,10.1.1.0/24,1.2.3.4");
    config_info.Add("BinMap.BinId.10.HostMasks",
                    "192.168.2.0/24,10.2.2.2,5.6.7.8");
    config_info.Add("BinMap.BinId.12.HostMasks",
                    "192.168.3.0/24,10.3.3.3,5.6.7.9");
    config_info.Add("BinMap.BinId.2.HostMasks",
                    "192.168.4.0/24,10.4.2.2,5.6.7.10");
    config_info.Add("BinMap.BinId.3.HostMasks",
                    "192.168.5.0/24,10.5.2.2,5.6.7.11");

    CPPUNIT_ASSERT(bin_map_->Initialize(config_info) == true);
    CPPUNIT_ASSERT(pkt_pool_.Create(8) == true);

    bin_15_ = new PacketHistoryMgrTester(*bin_map_, 15);
    bin_10_ = new PacketHistoryMgrTester(*bin_map_, 10);
    bin_12_ = new PacketHistoryMgrTester(*bin_map_, 12);
    bin_2_  = new PacketHistoryMgrTester(*bin_map_, 2);
    bin_3_  = new PacketHistoryMgrTester(*bin_map_, 3);
    CPPUNIT_ASSERT(bin_15_);
    CPPUNIT_ASSERT(bin_10_);
    CPPUNIT_ASSERT(bin_12_);
    CPPUNIT_ASSERT(bin_2_);
    CPPUNIT_ASSERT(bin_3_);
    pkt1 = pkt_pool_.Get();
    CPPUNIT_ASSERT(pkt1);
    pkt_pool_.AssignPacketId(pkt1);
    pkt2 = pkt_pool_.Get();
    CPPUNIT_ASSERT(pkt2);
    pkt_pool_.AssignPacketId(pkt2);
  }

  //==========================================================================
  void tearDown()
  {
    Log::SetDefaultLevel("FEWI");
    delete bin_2_;
    delete bin_3_;
    delete bin_10_;
    delete bin_12_;
    delete bin_15_;
    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;
    bin_map_     = NULL;
    pkt_pool_.Recycle(pkt1);
    pkt_pool_.Recycle(pkt2);
  }

  //==========================================================================
  void TestPacketVisitedBin()
  {
    // Test a scattering of "packet visited" stats.
    CPPUNIT_ASSERT(!bin_2_->PacketVisitedBin(pkt1, 3));
    CPPUNIT_ASSERT(!bin_2_->PacketVisitedBin(pkt1, 12));
    CPPUNIT_ASSERT(!bin_15_->PacketVisitedBin(pkt1, 3));
    CPPUNIT_ASSERT(!bin_10_->PacketVisitedBin(pkt1, 15));
    CPPUNIT_ASSERT(!bin_10_->PacketVisitedBin(pkt1, 2));
    CPPUNIT_ASSERT(!bin_3_->PacketVisitedBin(pkt1, 10));

    bin_15_->TrackHistory(pkt1, false);
    bin_3_->TrackHistory(pkt1, false);

    // 15 and 3 have now been visited (and all managers should know it)
    CPPUNIT_ASSERT(bin_2_->PacketVisitedBin(pkt1, 3));
    CPPUNIT_ASSERT(!bin_2_->PacketVisitedBin(pkt1, 12));
    CPPUNIT_ASSERT(bin_15_->PacketVisitedBin(pkt1, 3));
    CPPUNIT_ASSERT(bin_10_->PacketVisitedBin(pkt1, 15));
    CPPUNIT_ASSERT(!bin_10_->PacketVisitedBin(pkt1, 2));
    CPPUNIT_ASSERT(!bin_3_->PacketVisitedBin(pkt1, 10));

    bin_10_->TrackHistory(pkt1, false);
    bin_3_->TrackHistory(pkt1, false);

    // pkt2 should not affect pkt1 stats.
    bin_12_->TrackHistory(pkt2, false);
    bin_3_->TrackHistory(pkt2, false);

    // 15, 3, and 10 have now been visited (and all managers should know it)
    CPPUNIT_ASSERT(bin_2_->PacketVisitedBin(pkt1, 3));
    CPPUNIT_ASSERT(!bin_2_->PacketVisitedBin(pkt1, 12));
    CPPUNIT_ASSERT(bin_15_->PacketVisitedBin(pkt1, 3));
    CPPUNIT_ASSERT(bin_10_->PacketVisitedBin(pkt1, 15));
    CPPUNIT_ASSERT(!bin_10_->PacketVisitedBin(pkt1, 2));
    CPPUNIT_ASSERT(bin_3_->PacketVisitedBin(pkt1, 10));
  }

  //==========================================================================
  void TestNumVisits()
  {
    // Check a scattering of "num visits"
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 3, 0));
    CPPUNIT_ASSERT(bin_12_->VerifyNumVisits(pkt1, 3, 0));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 3, 0));
    CPPUNIT_ASSERT(bin_15_->VerifyNumVisits(pkt1, 10, 0));
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 12, 0));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 2, 0));

    bin_15_->TrackHistory(pkt1, false);
    bin_3_->TrackHistory(pkt1, false);

    // pkt 1 visited node 3 once.
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 3, 1));
    CPPUNIT_ASSERT(bin_12_->VerifyNumVisits(pkt1, 3, 1));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 3, 1));
    CPPUNIT_ASSERT(bin_15_->VerifyNumVisits(pkt1, 10, 0));
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 12, 0));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 2, 0));

    bin_10_->TrackHistory(pkt1, false);
    bin_3_->TrackHistory(pkt1, false); // Now we have a cycle

    // pkt2 should not affect pkt1 stats.
    bin_12_->TrackHistory(pkt2, false);
    bin_3_->TrackHistory(pkt2, false); // visited, but no cycle

    // 15, 3, and 10 have now been visited (and all managers should know it)
    // pkt 1 visited node 3 twice and node 10 once.
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 3, 2));
    CPPUNIT_ASSERT(bin_12_->VerifyNumVisits(pkt1, 3, 2));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 3, 2));
    CPPUNIT_ASSERT(bin_15_->VerifyNumVisits(pkt1, 10, 1));
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 12, 0));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 2, 0));

    bin_3_->TrackHistory(pkt1, false); // Now we have 3 visits

    // pkt 1 visited node 3 three times.
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 3, 3));
    CPPUNIT_ASSERT(bin_12_->VerifyNumVisits(pkt1, 3, 3));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 3, 3));
    CPPUNIT_ASSERT(bin_15_->VerifyNumVisits(pkt1, 10, 1));
    CPPUNIT_ASSERT(bin_10_->VerifyNumVisits(pkt1, 12, 0));
    CPPUNIT_ASSERT(bin_3_->VerifyNumVisits(pkt1, 2, 0));
}

  //==========================================================================
  void TestGetAllVisitedBins()
  {
    bin_15_->TrackHistory(pkt1, false);
    bin_3_->TrackHistory(pkt1, false);
    bin_10_->TrackHistory(pkt1, false);
    bin_3_->TrackHistory(pkt1, false);
    bin_3_->TrackHistory(pkt1, false);
    // pkt2 shouldn't affect pkt1.
    bin_12_->TrackHistory(pkt2, false);
    bin_3_->TrackHistory(pkt2, false);

    // Test GetAllVisitedBins
    BinId    visited[iron::kMaxUcastBinId + 1];
    uint32_t num_visited =
      bin_2_->GetAllVisitedBins(pkt1, &(visited[0]),
                                (iron::kMaxUcastBinId + 1));
    CPPUNIT_ASSERT(num_visited == 3);
    bool found15    = false;
    bool found3     = false;
    bool found10    = false;
    bool foundOther = false;
    for (iron::BinIndex idx = 0; idx < num_visited; idx++)
    {
      switch (visited[idx])
      {
        case 15:
          found15 = true;
          break;
        case 3:
          found3 = true;
          break;
        case 10:
          found10 = true;
          break;
        default:
          foundOther = true;
          break;
      }
    }
    CPPUNIT_ASSERT(found15);
    CPPUNIT_ASSERT(found3);
    CPPUNIT_ASSERT(found10);
    CPPUNIT_ASSERT(!foundOther);
  }

private:

  /// Configuration info for the bin map.
  PacketPoolHeap               pkt_pool_;
  PacketHistoryMgrTester*      bin_2_;
  PacketHistoryMgrTester*      bin_3_;
  PacketHistoryMgrTester*      bin_10_;
  PacketHistoryMgrTester*      bin_12_;
  PacketHistoryMgrTester*      bin_15_;
  Packet*                      pkt1;
  Packet*                      pkt2;

}; // end PacketHistoryMgrTest

CPPUNIT_TEST_SUITE_REGISTRATION(PacketHistoryMgrTest);
