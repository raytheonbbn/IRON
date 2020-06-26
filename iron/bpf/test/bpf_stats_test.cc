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

#include "bpf_stats.h"
#include "path_controller.h"
#include "sond.h"

#include "bin_map.h"
#include "config_info.h"
#include "log.h"
#include "queue_depths.h"
#include "packet_pool_heap.h"
#include "itime.h"
#include "timer.h"

#include <string>

#include <cmath>
#include <inttypes.h>
#include <unistd.h>

using ::iron::BinMap;
using ::iron::BpfStats;
using ::iron::ConfigInfo;
using ::iron::Ipv4Address;
using ::iron::Log;
using ::iron::PathController;
using ::iron::QueueDepths;
using ::iron::PacketPoolHeap;
using ::iron::Sond;
using ::iron::Time;
using ::iron::Timer;
using ::std::string;

//============================================================================
class BpfStatsTester : public BpfStats
{
 public:

  uint32_t  GetQueueDepthBinIndex(iron::BinIndex bin_idx);
  string    GetBpfPCStatsString(PathController* pc, iron::BinIndex bin_idx,
                                bool tx_dir);
  string    GetBpfProxyStatsString(uint32_t proxy, iron::BinIndex bin_idx,
                                   bool tx_dir);
  string    GetBpfAvgQDStatsString(iron::BinIndex bin_idx);
  uint64_t  GetBpfAvgChannelCapacity(PathController* pc);
  uint64_t  GetBpfAvgTransportCapacity(PathController* pc);

  BpfStatsTester(BinMap& bin_map)
      : BpfStats(bin_map), tester_bin_map_(bin_map) {}
  virtual ~BpfStatsTester() {}

 private:

  BpfStatsTester(const BpfStats& bs);
  BpfStatsTester& operator= (const BpfStatsTester& bs);

  BinMap&  tester_bin_map_;
};

//============================================================================
uint32_t BpfStatsTester::GetQueueDepthBinIndex(iron::BinIndex bin_idx)
{
  // A special queue depth bin index value of zero is used for accessing all
  // unicast queue depth objects.
  uint32_t  qd_idx = 0;

  if (tester_bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd_idx = bin_idx;
  }

  return qd_idx;
}

//============================================================================
string BpfStatsTester::GetBpfPCStatsString(PathController* pc,
                                           iron::BinIndex bin_idx,
                                           bool tx_dir)
{
  CPPUNIT_ASSERT(pc);

  string        rmt_iron_node = CreateRemoteNodeAddrForPC(pc);
  uint32_t      qd_idx        = GetQueueDepthBinIndex(bin_idx);
  QueueDepths*  qd            = NULL;

  if (tx_dir)
  {
    CPPUNIT_ASSERT(pc_data_tx_queue_depths_.find(rmt_iron_node) !=
                   pc_data_tx_queue_depths_.end());
    CPPUNIT_ASSERT(pc_data_tx_queue_depths_[rmt_iron_node].find(qd_idx) !=
                   pc_data_tx_queue_depths_[rmt_iron_node].end());

    qd = pc_data_tx_queue_depths_[rmt_iron_node][qd_idx];
  }
  else
  {
    CPPUNIT_ASSERT(pc_data_rx_queue_depths_.find(rmt_iron_node) !=
                   pc_data_rx_queue_depths_.end());
    CPPUNIT_ASSERT(pc_data_rx_queue_depths_[rmt_iron_node].find(qd_idx) !=
                   pc_data_rx_queue_depths_[rmt_iron_node].end());

    qd = pc_data_rx_queue_depths_[rmt_iron_node][qd_idx];
  }

  CPPUNIT_ASSERT(qd);

  return qd->StatDump();
}

//============================================================================
string BpfStatsTester::GetBpfProxyStatsString(uint32_t protocol,
                                              iron::BinIndex bin_idx,
                                              bool tx_dir)
{
  uint32_t      qd_idx = GetQueueDepthBinIndex(bin_idx);
  QueueDepths*  qd     = NULL;

  if (tx_dir)
  {
    CPPUNIT_ASSERT(proxy_data_tx_queue_depths_.find(protocol) !=
                   proxy_data_tx_queue_depths_.end());
    CPPUNIT_ASSERT(proxy_data_tx_queue_depths_[protocol].find(qd_idx) !=
                   proxy_data_tx_queue_depths_[protocol].end());

    qd = proxy_data_tx_queue_depths_[protocol][qd_idx];
  }
  else
  {
    CPPUNIT_ASSERT(proxy_data_rx_queue_depths_.find(protocol) !=
                   proxy_data_rx_queue_depths_.end());
    CPPUNIT_ASSERT(proxy_data_rx_queue_depths_[protocol].find(qd_idx) !=
                   proxy_data_rx_queue_depths_[protocol].end());

    qd = proxy_data_rx_queue_depths_[protocol][qd_idx];
  }

  CPPUNIT_ASSERT(qd);

  return qd->StatDump();
}

//============================================================================
string BpfStatsTester::GetBpfAvgQDStatsString(iron::BinIndex bin_idx)
{
  uint32_t  qd_idx = GetQueueDepthBinIndex(bin_idx);

  CPPUNIT_ASSERT(avg_queue_depths_.find(qd_idx) != avg_queue_depths_.end());

  QueueDepths*  qd = avg_queue_depths_[qd_idx];

  CPPUNIT_ASSERT(qd);

  return qd->StatDump();
}

//============================================================================
uint64_t BpfStatsTester::GetBpfAvgChannelCapacity(PathController* pc)
{
  CPPUNIT_ASSERT(pc);
  string rmt_iron_node = CreateRemoteNodeAddrForPC(pc);
  return pc_capacity_estimate_[rmt_iron_node].chan_cap_est_bps;
}

//============================================================================
uint64_t BpfStatsTester::GetBpfAvgTransportCapacity(PathController* pc)
{
  CPPUNIT_ASSERT(pc);
  string rmt_iron_node = CreateRemoteNodeAddrForPC(pc);
  return pc_capacity_estimate_[rmt_iron_node].trans_cap_est_bps;
}

//============================================================================
class BpfStatsTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(BpfStatsTest);

  CPPUNIT_TEST(TestBpfStatsToString);
  CPPUNIT_TEST(TestBpfPCStats);
  CPPUNIT_TEST(TestBpfProxyStats);
  CPPUNIT_TEST(TestBpfAvgQueueDepths);
  CPPUNIT_TEST(TestBpfAvgCapacity);

  CPPUNIT_TEST_SUITE_END();

  private:
  BpfStatsTester* stats_;
  PathController* pc1_;
  PathController* pc2_;
  PacketPoolHeap* pkt_pool_;
  BinMap*         bin_map_;
  char*           bin_map_mem_;
  Timer*          timer_;

  //============================================================================
  void InitBinMap(BinMap* bin_map)
  {
    ConfigInfo  ci;
    // Add bin map configuration.
    ci.Add("BinMap.BinIds", "2,3,8");
    ci.Add("BinMap.BinId.2.HostMasks",
           "192.168.2.0/24,10.1.2.0/24,0.0.0.2");
    ci.Add("BinMap.BinId.3.HostMasks", "192.168.3.0/24,10.1.16.0/24");
    ci.Add("BinMap.BinId.8.HostMasks",
           "192.168.20.0/24,10.1.20.0/24,0.0.0.20");
    CPPUNIT_ASSERT(bin_map->Initialize(ci));
  }

  public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");

    timer_ = new Timer();

    bin_map_mem_ = new char[sizeof(BinMap)];
    bin_map_     = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));
    InitBinMap(bin_map_);

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_->Create(8) == true);

    stats_ = new (std::nothrow) BpfStatsTester(*bin_map_);
    pc1_   = new (std::nothrow) Sond(NULL, *pkt_pool_, *timer_);
    pc2_   = new (std::nothrow) Sond(NULL, *pkt_pool_, *timer_);
    pc1_->set_remote_bin_id_idx(2, 0);
    pc2_->set_remote_bin_id_idx(3, 1);
    pc1_->set_label("Alt");
    stats_->StartDump();
    stats_->set_test_override(true);
    stats_->Initialize();
  }

  //==========================================================================
  void tearDown()
  {
    // Cancel all timers.  This protects other BPFwder-based unit tests.
    timer_->CancelAllTimers();

    delete pc1_;
    pc1_         = NULL;
    delete pc2_;
    pc2_         = NULL;
    delete stats_;
    stats_       = NULL;
    delete pkt_pool_;
    pkt_pool_    = NULL;
    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;
    bin_map_     = NULL;
    delete timer_;
    timer_       = NULL;

    Log::SetDefaultLevel("FEW");
  }

  //==========================================================================
  void TestBpfStatsToString()
  {
    iron::BinIndex  bidx_2  = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex  bidx_3  = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex  bidx_8  = bin_map_->GetPhyBinIndex(8);
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnPathCtrl(
                     pc1_, bidx_2, 0));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnPathCtrl(
                     pc2_, bidx_3, 0));

    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnPathCtrl(
                     pc1_, bidx_2, 0));

    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnProxy(
                     IPPROTO_UDP, bidx_2, 0));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnProxy(
                     IPPROTO_TCP, bidx_2, 0));

    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnProxy(
                     IPPROTO_UDP, bidx_2, 0));

    QueueDepths qd(*bin_map_);
    qd.SetBinDepthByIdx(bidx_2, 1000);
    stats_->ReportQueueDepthsForBins(bidx_2, &qd);

    qd.SetBinDepthByIdx(bidx_8, 10000);
    stats_->ReportQueueDepthsForBins(bidx_8, &qd);

    stats_->ReportCapacityUpdateForPC(pc1_, 1000, 800);

    string comp_str = "Stats=(DataBytesSentToBinOnPC:2El),";
    comp_str += "(DataBytesRcvdForBinOnPC:1El),";
    comp_str += "(DataBytesSentToBinOnProxy:2El),";
    comp_str += "(DataBytesRcvdForBinOnProxy:1El),";
    comp_str += "(NumQueues:1El),";
    comp_str += "(PCCapacity:1El)";
    string stat_str = stats_->ToString();

    CPPUNIT_ASSERT(stat_str == comp_str);
  }

  //==========================================================================
  void TestBpfPCStats()
  {
    iron::BinIndex  bidx_2  = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex  bidx_3  = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex  bidx_8  = bin_map_->GetPhyBinIndex(8);
    // Sent bytes.
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnPathCtrl(
                     pc1_, bidx_2, 1000));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnPathCtrl(
                     pc1_, bidx_8, 2000));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnPathCtrl(
                     pc2_, bidx_3, 3000));

    // Received bytes.
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnPathCtrl(
                     pc1_, bidx_2, 1500));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnPathCtrl(
                     pc1_, bidx_8, 2500));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnPathCtrl(
                     pc2_, bidx_3, 3500));

    string stat_str = stats_->GetBpfPCStatsString(pc1_, bidx_2, true);
    string comp_str = "(Bin 2:1000B),(Bin 3:0B),(Bin 8:2000B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    stat_str = stats_->GetBpfPCStatsString(pc2_, bidx_3, true);
    comp_str = "(Bin 2:0B),(Bin 3:3000B),(Bin 8:0B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    stat_str = stats_->GetBpfPCStatsString(pc1_, bidx_8, false);
    comp_str = "(Bin 2:1500B),(Bin 3:0B),(Bin 8:2500B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    stat_str = stats_->GetBpfPCStatsString(pc2_, bidx_2, false);
    comp_str = "(Bin 2:0B),(Bin 3:3500B),(Bin 8:0B)";
    CPPUNIT_ASSERT(stat_str == comp_str);
  }

  //==========================================================================
  void TestBpfProxyStats()
  {
    iron::BinIndex  bidx_2  = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex  bidx_3  = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex  bidx_8  = bin_map_->GetPhyBinIndex(8);
    // Sent bytes.
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnProxy(IPPROTO_UDP,
                                                              bidx_2, 1000));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnProxy(IPPROTO_UDP,
                                                              bidx_8, 2000));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesSentToBinOnProxy(IPPROTO_TCP,
                                                              bidx_3, 3000));

    // Received bytes.
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnProxy(IPPROTO_UDP,
                                                              bidx_2, 1500));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnProxy(IPPROTO_UDP,
                                                              bidx_8, 2500));
    CPPUNIT_ASSERT(stats_->IncrementNumDataBytesRcvdForBinOnProxy(IPPROTO_TCP,
                                                              bidx_3, 3500));

    string stat_str = stats_->GetBpfProxyStatsString(IPPROTO_UDP, bidx_2,
                                                     true);
    string comp_str = "(Bin 2:1000B),(Bin 3:0B),(Bin 8:2000B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    stat_str = stats_->GetBpfProxyStatsString(IPPROTO_TCP, bidx_3, true);
    comp_str = "(Bin 2:0B),(Bin 3:3000B),(Bin 8:0B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    stat_str = stats_->GetBpfProxyStatsString(IPPROTO_UDP, bidx_8, false);
    comp_str = "(Bin 2:1500B),(Bin 3:0B),(Bin 8:2500B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    stat_str = stats_->GetBpfProxyStatsString(IPPROTO_TCP, bidx_2, false);
    comp_str = "(Bin 2:0B),(Bin 3:3500B),(Bin 8:0B)";
    CPPUNIT_ASSERT(stat_str == comp_str);
  }

  //==========================================================================
  void TestBpfAvgQueueDepths()
  {
    iron::BinIndex  bidx_2  = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex  bidx_8  = bin_map_->GetPhyBinIndex(8);

    QueueDepths qd(*bin_map_);
    // Start adding queue depths to be averaged.
    qd.SetBinDepthByIdx(bidx_2, 1000);
    qd.SetBinDepthByIdx(bidx_8, 10000);

    stats_->ReportQueueDepthsForBins(bidx_2, &qd);
    stats_->ReportQueueDepthsForBins(bidx_8, &qd);
    stats_->IncrementNumberOfQueueDepthUpdates();

    string stat_str = stats_->GetBpfAvgQDStatsString(bidx_2);
    string comp_str = "(Bin 2:1000B),(Bin 3:0B),(Bin 8:10000B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    // Add more queue depths.
    qd.SetBinDepthByIdx(bidx_2, 2000);
    qd.SetBinDepthByIdx(bidx_8, 20000);

    stats_->ReportQueueDepthsForBins(bidx_2, &qd);
    stats_->ReportQueueDepthsForBins(bidx_8, &qd);
    stats_->IncrementNumberOfQueueDepthUpdates();

    stat_str = stats_->GetBpfAvgQDStatsString(bidx_2);
    comp_str = "(Bin 2:1500B),(Bin 3:0B),(Bin 8:15000B)";
    CPPUNIT_ASSERT(stat_str == comp_str);

    // Add more queue depths.
    qd.SetBinDepthByIdx(bidx_2, 3000);
    qd.SetBinDepthByIdx(bidx_8, 30000);

    stats_->ReportQueueDepthsForBins(bidx_2, &qd);
    stats_->ReportQueueDepthsForBins(bidx_8, &qd);
    stats_->IncrementNumberOfQueueDepthUpdates();

    stat_str = stats_->GetBpfAvgQDStatsString(bidx_2);
    comp_str = "(Bin 2:2000B),(Bin 3:0B),(Bin 8:20000B)";
    CPPUNIT_ASSERT(stat_str == comp_str);
  }

  //==========================================================================
  void TestBpfAvgCapacity()
  {
    // Report 1000bps then wait 1s.
    stats_->ReportCapacityUpdateForPC(pc1_, 1000, 800);

    sleep(1);

    // Compute the capacity after 1s.
    uint64_t capacity = stats_->GetBpfAvgChannelCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 1000);

    capacity = stats_->GetBpfAvgTransportCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 800);

    sleep(2);

    // Compute the capacity after 3s.
    capacity = stats_->GetBpfAvgChannelCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 1000);

    capacity = stats_->GetBpfAvgTransportCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 800);

    // After 3s of 1,000bps capacity, set to 2,000bps.
    stats_->ReportCapacityUpdateForPC(pc1_, 2000, 1600);

    sleep(3);

    // Compute the capacity after 3s of 1,000bps and 3s of 2,000bps.
    capacity = stats_->GetBpfAvgChannelCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 2000);

    capacity = stats_->GetBpfAvgTransportCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 1600);

    // Make sure the dump stat still keeps the proper state.
    stats_->WriteStats(NULL);

    // The current capacity is 2,000bps after the dump.
    stats_->ReportCapacityUpdateForPC(pc1_, 2000, 1600);

    sleep(1);

    // Compute avg capacity after 1s of 2,000bps.
    capacity = stats_->GetBpfAvgChannelCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 2000);

    capacity = stats_->GetBpfAvgTransportCapacity(pc1_);
    CPPUNIT_ASSERT(capacity == 1600);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(BpfStatsTest);
