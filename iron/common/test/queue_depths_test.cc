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

#include "queue_depths.h"

#include "bin_map.h"
#include "config_info.h"
#include "log.h"
#include "packet.h"
#include "packet_pool_heap.h"

#include <cstring>

using ::iron::BinId;
using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPoolHeap;
using ::iron::QueueDepths;

//============================================================================
class QueueDepthsTest : public CPPUNIT_NS::TestFixture
{
  CPPUNIT_TEST_SUITE(QueueDepthsTest);

  CPPUNIT_TEST(TestGetSetBinDepth);
  CPPUNIT_TEST(TestIncrement);
  CPPUNIT_TEST(TestDecrement);
  CPPUNIT_TEST(TestClearAllBins);
  CPPUNIT_TEST(TestNumQueues);
  CPPUNIT_TEST(TestSerialize);
  CPPUNIT_TEST(TestDeserialize);
  CPPUNIT_TEST(TestToString);

  CPPUNIT_TEST_SUITE_END();

private:
  char* bin_map_mem_ = NULL;
  BinMap* bin_map_   = NULL;
  PacketPoolHeap*  pkt_pool_;

  //============================================================================
  void InitBinMap(BinMap* bin_map)
  {
    ConfigInfo  ci;
    ci.Add("BinMap.BinIds", "2,5,6,7,10");
    ci.Add("BinMap.BinId.2.HostMasks",
           "192.168.2.0/24,10.2.2.2,2.2.2.2");
    ci.Add("BinMap.BinId.5.HostMasks",
           "192.168.5.0/24,10.5.5.5,5.5.5.5");
    ci.Add("BinMap.BinId.6.HostMasks",
           "192.168.6.0/24,10.6.6.6,6.6.6.6");
    ci.Add("BinMap.BinId.7.HostMasks",
           "192.168.7.0/24,10.7.7.7,7.7.7.7");
    ci.Add("BinMap.BinId.10.HostMasks",
           "192.168.10.0/24,10.10.10.10,10.10.10.10");
    CPPUNIT_ASSERT(bin_map->Initialize(ci) == true);
  }

public:

  //==========================================================================
  void setUp()
  {

    bin_map_mem_ = new char[sizeof(BinMap)];
    bin_map_     = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));

    //
    // Turn down logging levels for the unit testing.
    //

    Log::SetDefaultLevel("F");

    CPPUNIT_ASSERT(bin_map_);
    InitBinMap(bin_map_);

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_);
    CPPUNIT_ASSERT(pkt_pool_->Create(8) == true);
  }

  //==========================================================================
  void tearDown()
  {
    //
    // Clean up.
    //

    delete pkt_pool_;
    pkt_pool_ = NULL;
    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;
    bin_map_     = NULL;

    //
    // Restore default logging levels so we don't break other unit tests.
    //

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestGetSetBinDepth()
  {
    QueueDepths     qd(*bin_map_);

    // Test with bin having zero depth.
    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    qd.SetBinDepthByIdx(bidx_6, 0);

    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_6) == 0);

    // Test with bin having non-zero depth.
    iron::BinIndex  bidx_7  = bin_map_->GetPhyBinIndex(7);
    qd.SetBinDepthByIdx(bidx_7, 25);
    qd.SetBinDepthByIdx(bidx_7, 12, iron::LOW_LATENCY);

    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_7) == 25);
    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_7, iron::LOW_LATENCY) == 12);

//    // Test integration with BinQueueMgr class.
//    // Different depths, but same bins defined.
//    CPPUNIT_ASSERT(qd_->GetBinDepthById(3) == 0);
//    CPPUNIT_ASSERT(qd_->GetBinDepthById(7) == 0);
  }

  //==========================================================================
  void TestIncrement()
  {
    QueueDepths     qd(*bin_map_);

    iron::BinIndex  bidx_5  = bin_map_->GetPhyBinIndex(5);

    // Test increment on empty bin.
    qd.Increment(bidx_5, 4);

    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_5) == 4);

    // Test increment on non-empty bin.
    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    qd.SetBinDepthByIdx(bidx_6, 20);
    qd.Increment(bidx_6, 8);

    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_6) == 28);

    qd.Increment(bidx_6, 12, 12);
    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_6) == 40);
    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_6, iron::LOW_LATENCY) == 12);
  }

  //==========================================================================
  void TestDecrement()
  {
    QueueDepths  qd(*bin_map_);

    // Test decrement on empty bin.
    iron::BinIndex  bidx_5  = bin_map_->GetPhyBinIndex(5);
    qd.Decrement(bidx_5, 4);

    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_5) == 0UL);

    // Test decrement on non-empty bin.
    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    qd.SetBinDepthByIdx(bidx_6, 20);
    qd.SetBinDepthByIdx(bidx_6, 12, iron::LOW_LATENCY);
    qd.Decrement(bidx_6, 8);

    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_6) == 12);

    qd.Decrement(bidx_6, 4, 4);
    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_6) == 8);
    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_6, iron::LOW_LATENCY) == 8);
  }

  //==========================================================================
  void TestClearAllBins()
  {
    QueueDepths  qd(*bin_map_);

    iron::BinIndex  bidx_5  = bin_map_->GetPhyBinIndex(5);
    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    iron::BinIndex  bidx_7  = bin_map_->GetPhyBinIndex(7);

    // Set up the QueueDepths object.
    qd.SetBinDepthByIdx(bidx_5, 10);
    qd.SetBinDepthByIdx(bidx_6, 20);
    qd.SetBinDepthByIdx(bidx_7, 30);
    qd.SetBinDepthByIdx(bidx_7, 30, iron::LOW_LATENCY);

    std::string qd_str = qd.StatDump();

    // Check the single line of content.
    std::string search_string = "(Bin 5:10B),(Bin 6:20B),(Bin 7:30B),";
    CPPUNIT_ASSERT(qd_str.find(search_string) != std::string::npos);

    qd.ClearAllBins();

    qd_str = qd.StatDump();

    search_string = "(Bin 5:0B),(Bin 6:0B),(Bin 7:0B),";
    CPPUNIT_ASSERT(qd_str.find(search_string) != std::string::npos);
  
    CPPUNIT_ASSERT(qd.GetBinDepthByIdx(bidx_7, iron::LOW_LATENCY) == 0);
  }

  //==========================================================================
  void TestNumQueues()
  {
    QueueDepths  qd(*bin_map_);
    // There are 5 bins defined in the bin map, plus the bin for the GRAM
    // multicast group.
    CPPUNIT_ASSERT(qd.GetNumQueues() == 6);
    CPPUNIT_ASSERT(qd.GetNumNonZeroQueues() == 0);

    iron::BinIndex  bidx_5  = bin_map_->GetPhyBinIndex(5);
    qd.SetBinDepthByIdx(bidx_5, 0);

    CPPUNIT_ASSERT(qd.GetNumNonZeroQueues() == 0);

    qd.SetBinDepthByIdx(bidx_5, 10);

    CPPUNIT_ASSERT(qd.GetNumNonZeroQueues() == 1);

    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    qd.SetBinDepthByIdx(bidx_6, 0);

    CPPUNIT_ASSERT(qd.GetNumNonZeroQueues() == 1);

    qd.SetBinDepthByIdx(bidx_6, 20);

    CPPUNIT_ASSERT(qd.GetNumNonZeroQueues() == 2);

    qd.SetBinDepthByIdx(bidx_6, 0);

    CPPUNIT_ASSERT(qd.GetNumQueues() == 6);
    CPPUNIT_ASSERT(qd.GetNumNonZeroQueues() == 1);
  }

  //==========================================================================
  void TestSerialize()
  {
    QueueDepths qd(*bin_map_);
    size_t      offset        = 0;
    size_t      len           = 0;
    // Not a BinId type, because we're still using 32 bits in QLAMs.
    uint32_t    bin_id        = 0;
    uint32_t    bin_depth     = 0;
    uint32_t    ls_bin_depth  = 0;
    uint8_t*    buf           = new uint8_t[100];
    ::memset(buf, 0, sizeof(uint8_t) * 100);

    iron::BinIndex  bidx_2  = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex  bidx_5  = bin_map_->GetPhyBinIndex(5);
    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    iron::BinIndex  bidx_7  = bin_map_->GetPhyBinIndex(7);
    iron::BinIndex  bidx_10 = bin_map_->GetPhyBinIndex(10);

    // Set up the QueueDepths object.
    qd.SetBinDepthByIdx(bidx_2, 40);
    qd.SetBinDepthByIdx(bidx_5, 0);
    qd.SetBinDepthByIdx(bidx_6, 20);
    qd.SetBinDepthByIdx(bidx_7, 30, (uint32_t)28);
    qd.SetBinDepthByIdx(bidx_10, 100);

    // Serialize it.  Use a minimal-sized buffer (4 * 9B) (0B queues are not 
    // reported).
    uint8_t num_pairs = 0;
    len = qd.Serialize(buf, 36, num_pairs);

    CPPUNIT_ASSERT(len == 36);
    
    CPPUNIT_ASSERT(num_pairs == 4);

    // Check the first pair (bin 2).
    ::memcpy(&bin_id, &(buf[offset]), sizeof(uint8_t));
    offset += sizeof(uint8_t);
    ::memcpy(&bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);
    ::memcpy(&ls_bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);

    CPPUNIT_ASSERT(bin_id == 2);
    CPPUNIT_ASSERT(ntohl(bin_depth) == 40);
    CPPUNIT_ASSERT(ntohl(ls_bin_depth) == 0);

    // Check the second pair (bin6).
    ::memcpy(&bin_id, &(buf[offset]), sizeof(uint8_t));
    offset += sizeof(uint8_t);
    ::memcpy(&bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);
    ::memcpy(&ls_bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);

    CPPUNIT_ASSERT(bin_id == 6);
    CPPUNIT_ASSERT(ntohl(bin_depth) == 20);
    CPPUNIT_ASSERT(ntohl(ls_bin_depth) == 0);

    // Check the 3rd pair (bin 7).
    ::memcpy(&bin_id, &(buf[offset]), sizeof(uint8_t));
    offset += sizeof(uint8_t);
    ::memcpy(&bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);
    ::memcpy(&ls_bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);

    CPPUNIT_ASSERT(bin_id == 7);
    CPPUNIT_ASSERT(ntohl(bin_depth) == 30);
    CPPUNIT_ASSERT(ntohl(ls_bin_depth) == 28);

    // Check the 4th pair (bin 10).
    ::memcpy(&bin_id, &(buf[offset]), sizeof(uint8_t));
    offset += sizeof(uint8_t);
    ::memcpy(&bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);
    ::memcpy(&ls_bin_depth, &(buf[offset]), sizeof(uint32_t));
    offset += sizeof(uint32_t);

    CPPUNIT_ASSERT(bin_id == 10);
    CPPUNIT_ASSERT(ntohl(bin_depth) == 100);
    CPPUNIT_ASSERT(ntohl(ls_bin_depth) == 0);

    // Test with a buffer that cannot handle 3 (bin,depth, ls_depth) tuples.
    len = qd.Serialize(buf, 20, num_pairs);
    CPPUNIT_ASSERT(len == 0);
   
    // Clean up.
    delete [] buf;
  }

  //==========================================================================
  void TestDeserialize()
  {
    QueueDepths  qd(*bin_map_);
    QueueDepths  qd2(*bin_map_);
    size_t       len = 0;
    uint8_t*     buf = new uint8_t[100];

    iron::BinIndex  bidx_2  = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex  bidx_5  = bin_map_->GetPhyBinIndex(5);
    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    iron::BinIndex  bidx_7  = bin_map_->GetPhyBinIndex(7);
    iron::BinIndex  bidx_10 = bin_map_->GetPhyBinIndex(10);

    // Set up the QueueDepths object.
    qd.SetBinDepthByIdx(bidx_2, 40);
    qd.SetBinDepthByIdx(bidx_5, 0);
    qd.SetBinDepthByIdx(bidx_6, 20);
    qd.SetBinDepthByIdx(bidx_7, 30, (uint32_t) 28);
    qd.SetBinDepthByIdx(bidx_10, 100);

    uint8_t num_pairs = 5;

    // Serialize into the buffer.
    len = qd.Serialize(buf, 100, num_pairs);

    // Expect 4 x (1B + (2 x 4B)) values.
    CPPUNIT_ASSERT(len == 36);

    // Now deserialize and check the results.
    size_t  result = qd2.Deserialize(buf, len, num_pairs);

    CPPUNIT_ASSERT(result == 36);

    // Check that bin 2 has depth 40.
    CPPUNIT_ASSERT(qd2.GetBinDepthByIdx(bidx_2) == 40);

    // Check that bin 5 has depth 0.
    CPPUNIT_ASSERT(qd2.GetBinDepthByIdx(bidx_5) == 0);

    // Check that bin 6 has depth 20.
    CPPUNIT_ASSERT(qd2.GetBinDepthByIdx(bidx_6) == 20);

    // Check that bin 7 has depth 30.
    CPPUNIT_ASSERT(qd2.GetBinDepthByIdx(bidx_7) == 30);

    // Check that bin 7 has LS depth 28.
    CPPUNIT_ASSERT(qd2.GetBinDepthByIdx(bidx_7, iron::LOW_LATENCY) == 28);

    // Check that bin 10 has depth 100.
    CPPUNIT_ASSERT(qd2.GetBinDepthByIdx(bidx_10) == 100);

    // Test deserialize with a length that is too short.
    QueueDepths  qd3(*bin_map_);
    result = qd3.Deserialize(buf, 24, num_pairs);

    CPPUNIT_ASSERT(result == 0);

    // Test deserialize with a length that is vastly too short.
    QueueDepths  qd5(*bin_map_);
    result = qd5.Deserialize(buf, 3, num_pairs);

    CPPUNIT_ASSERT(result == 0);

    // Test deserialize with a length that is 1 byte too short.
    QueueDepths  qd6(*bin_map_);
    result = qd6.Deserialize(buf, len - 1, num_pairs);

    CPPUNIT_ASSERT(result == 0);

    // Clean up.
    delete [] buf;
  }

  //==========================================================================
  void TestToString()
  {
    QueueDepths  qd(*bin_map_);

    iron::BinIndex  bidx_5  = bin_map_->GetPhyBinIndex(5);
    iron::BinIndex  bidx_6  = bin_map_->GetPhyBinIndex(6);
    iron::BinIndex  bidx_7  = bin_map_->GetPhyBinIndex(7);

    // Set up the QueueDepths object.
    qd.SetBinDepthByIdx(bidx_5, 10);
    qd.SetBinDepthByIdx(bidx_6, 20);
    qd.SetBinDepthByIdx(bidx_7, 30);
    qd.SetBinDepthByIdx(bidx_7, 30, iron::LOW_LATENCY);

    std::string qd_str = qd.ToString();

    // Check the 3 lines of content.
    std::string  search_string = "5\t\t|    10\t\t|      0";
    CPPUNIT_ASSERT(qd_str.find(search_string) != std::string::npos);

    search_string = "6\t\t|    20\t\t|      0";
    CPPUNIT_ASSERT(qd_str.find(search_string) != std::string::npos);

    search_string = "7\t\t|    30\t\t|      30";
    CPPUNIT_ASSERT(qd_str.find(search_string) != std::string::npos);

    qd_str = qd.StatDump();

    // Check the single line of content.
    search_string = "(Bin 5:10B),(Bin 6:20B),(Bin 7:30B),";
    CPPUNIT_ASSERT(qd_str.find(search_string) != std::string::npos);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(QueueDepthsTest);
