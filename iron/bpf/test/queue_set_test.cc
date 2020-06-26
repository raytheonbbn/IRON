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

#include "bin_queue_mgr.h"

#include "bin_indexable_array.h"
#include "bin_map.h"
#include "config_info.h"
#include "itime.h"
#include "log.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "queue_depths.h"

#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using ::iron::BinId;
using ::iron::BinIndex;
using ::iron::BinIndexableArray;
using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::DropPolicy;
using ::iron::LatencyClass;
using ::iron::Log;
using ::iron::McastId;
using ::iron::Packet;
using ::iron::PacketPoolHeap;
using ::iron::Queue;
using ::iron::QueueDepths;
using ::iron::BinQueueMgr;
using ::iron::Time;

//============================================================================
class QSetTest : public CPPUNIT_NS::TestFixture
{
  CPPUNIT_TEST_SUITE(QSetTest);

  CPPUNIT_TEST(TestEnqueue);
  CPPUNIT_TEST(TestMulticastEnqueue);
  CPPUNIT_TEST(TestDequeue);
  CPPUNIT_TEST(TestLatencyFitMethods);
  CPPUNIT_TEST(TestGetDepth);
  CPPUNIT_TEST(TestGetDropPolicy);
  CPPUNIT_TEST(TestMaxDepth);
  CPPUNIT_TEST(TestSetDropPolicy);
  CPPUNIT_TEST(TestMaxBinDepth);

  CPPUNIT_TEST_SUITE_END();

private:

  uint32_t                         num_bin_ids_;
  BinId                            bin_ids_[24];
  uint32_t                         num_mcast_ids_;
  McastId                          mcast_ids_[24];
  struct iphdr                     ip_hdr_;
  PacketPoolHeap*                  pkt_pool_;
  BinMap*                          bin_map_;
  char*                            bin_map_mem_;
  bool                             q_mgrs_init_;
  BinIndexableArray<BinQueueMgr*>  q_mgrs_;

  //============================================================================
  void InitBinMap(ConfigInfo& ci)
  {
    // Set the BinId list to those that will be configured.
    BinId  bin_id_list[12] = {3,5,6,7,8,9,10,11,12,13,14,15};

    num_bin_ids_ = 12;
    memcpy(bin_ids_, bin_id_list, sizeof(bin_id_list));
    num_mcast_ids_ = 0;

    // Set up the BinMap
    ci.Add("Bpf.BinId", "3");

    ci.Add("BinMap.BinIds", "3,5,6,7,8,9,10,11,12,13,14,15");
    ci.Add("BinMap.BinId.3.HostMasks",
           "192.168.3.0/24,10.3.3.3,3.3.3.3");
    ci.Add("BinMap.BinId.5.HostMasks",
           "192.168.5.0/24,10.5.5.5,5.5.5.5");
    ci.Add("BinMap.BinId.6.HostMasks",
           "192.168.6.0/24,10.6.6.6,6.6.6.6");
    ci.Add("BinMap.BinId.7.HostMasks",
           "192.168.7.0/24,10.7.7.7,7.7.7.7");
    ci.Add("BinMap.BinId.8.HostMasks",
           "192.168.8.0/24,10.8.8.8,8.8.8.8");
    ci.Add("BinMap.BinId.9.HostMasks",
           "192.168.9.0/24,10.9.9.9,9.9.9.9");
    ci.Add("BinMap.BinId.10.HostMasks",
           "192.168.10.0/24,10.10.10.10,10.10.10.10");
    ci.Add("BinMap.BinId.11.HostMasks",
           "192.168.11.0/24,10.11.11.11,11.11.11.11");
    ci.Add("BinMap.BinId.12.HostMasks",
           "192.168.12.0/24,10.12.12.12,10.12.12.12");
    ci.Add("BinMap.BinId.13.HostMasks",
           "192.168.13.0/24,10.13.13.13,11.13.13.13");
    ci.Add("BinMap.BinId.14.HostMasks",
           "192.168.14.0/24,10.14.14.14");
    ci.Add("BinMap.BinId.15.HostMasks",
           "192.168.15.0/24,10.15.15.15,11.15.15.15");
  }

  //==========================================================================
  void PrepareTest(ConfigInfo&  ci)
  {
    // Create and initialize the BinMap.
    bin_map_mem_ = new char[sizeof(BinMap)];
    memset(bin_map_mem_, 0, sizeof(BinMap));

    bin_map_ = reinterpret_cast<BinMap*>(bin_map_mem_);
    CPPUNIT_ASSERT(bin_map_);

    CPPUNIT_ASSERT(bin_map_->Initialize(ci) == true);

    // Initialize the bin queue managers array only once with an initialized
    // BinMap.
    if (!q_mgrs_init_)
    {
      CPPUNIT_ASSERT(q_mgrs_.Initialize(*bin_map_));
      q_mgrs_init_ = true;
    }

    // Create BinQueueMgrs for testing.
    BinId      bin_id   = 0;
    McastId    mcast_id = 0;
    BinIndex   bin_idx  = 0;
    in_addr_t  bpf_addr = inet_addr("3.3.3.3");

    for (uint32_t i = 0; i < num_bin_ids_; ++i)
    {
      bin_id  = bin_ids_[i];
      bin_idx = bin_map_->GetPhyBinIndex(bin_id);

      q_mgrs_[bin_idx] = new (std::nothrow) BinQueueMgr(bin_idx, *pkt_pool_,
                                                        *bin_map_);
      CPPUNIT_ASSERT(q_mgrs_[bin_idx]);
      CPPUNIT_ASSERT(q_mgrs_[bin_idx]->Initialize(ci, bpf_addr));
    }

    for (uint32_t i = 0; i < num_mcast_ids_; ++i)
    {
      mcast_id = mcast_ids_[i];
      bin_idx  = bin_map_->GetMcastBinIndex(mcast_id);

      q_mgrs_[bin_idx] = new (std::nothrow) BinQueueMgr(bin_idx, *pkt_pool_,
                                                        *bin_map_);
      CPPUNIT_ASSERT(q_mgrs_[bin_idx]);
      CPPUNIT_ASSERT(q_mgrs_[bin_idx]->Initialize(ci, bpf_addr));
    }
  }

  //==========================================================================
  void CleanUpTest()
  {
    // Free all of the BinQueueMgr objects.
    BinId     bin_id   = 0;
    McastId   mcast_id = 0;
    BinIndex  bin_idx  = 0;

    for (uint32_t i = 0; i < num_bin_ids_; ++i)
    {
      bin_id  = bin_ids_[i];
      bin_idx = bin_map_->GetPhyBinIndex(bin_id);

      delete q_mgrs_[bin_idx];
      q_mgrs_[bin_idx] = NULL;
    }

    for (uint32_t i = 0; i < num_mcast_ids_; ++i)
    {
      mcast_id = mcast_ids_[i];
      bin_idx  = bin_map_->GetMcastBinIndex(mcast_id);

      delete q_mgrs_[bin_idx];
      q_mgrs_[bin_idx] = NULL;
    }

    // Free the BinMap.
    delete [] bin_map_mem_;
    bin_map_     = NULL;
    bin_map_mem_ = NULL;

    // Clear the array of all BinIds and McastIds.
    num_bin_ids_ = 0;
    memset(bin_ids_, 0, sizeof(bin_ids_));
    num_mcast_ids_ = 0;
    memset(mcast_ids_, 0, sizeof(mcast_ids_));
  }

  //==========================================================================
  bool EnqueueToBinId(BinId bin_id, Packet* pkt)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    return q_mgrs_[bin_idx]->Enqueue(pkt);
  }

  //==========================================================================
  bool EnqueueToMcastId(McastId mcast_id, Packet* pkt)
  {
    BinIndex  bin_idx = bin_map_->GetMcastBinIndex(mcast_id);

    return q_mgrs_[bin_idx]->Enqueue(pkt);
  }

  //==========================================================================
  Packet* DequeueFromBinId(BinId bin_id)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    return q_mgrs_[bin_idx]->Dequeue();
  }

  //==========================================================================
  Packet* DequeueFromBinId(BinId bin_id, LatencyClass lat)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    return q_mgrs_[bin_idx]->Dequeue(lat);
  }

  //==========================================================================
  Packet* DequeueFromBinId(BinId bin_id, LatencyClass lat,
                           uint32_t max_size_bytes)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    return q_mgrs_[bin_idx]->Dequeue(lat, max_size_bytes);
  }

  //==========================================================================
  Packet* DequeueFromMcastId(McastId mcast_id)
  {
    BinIndex  bin_idx = bin_map_->GetMcastBinIndex(mcast_id);

    return q_mgrs_[bin_idx]->Dequeue();
  }

  //==========================================================================
  uint32_t GetQMgrDepthPackets(BinId bin_id)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    return q_mgrs_[bin_idx]->depth_packets();
  }

  //==========================================================================
  uint32_t GetQMgrMcastDepthPackets(McastId mcast_id)
  {
    BinIndex  bin_idx = bin_map_->GetMcastBinIndex(mcast_id);

    return q_mgrs_[bin_idx]->depth_packets();
  }

  //==========================================================================
  uint32_t GetQMgrBinDepthBytes(BinId bin_id,
                                LatencyClass lat = iron::NORMAL_LATENCY)
  {
    BinIndex      bin_idx      = bin_map_->GetPhyBinIndex(bin_id);
    QueueDepths*  queue_depths = q_mgrs_[bin_idx]->GetQueueDepths();

    CPPUNIT_ASSERT(queue_depths != NULL);

    return queue_depths->GetBinDepthByIdx(bin_idx, lat);
  }

  //==========================================================================
  uint32_t GetQMgrMcastBinDepthBytes(McastId mcast_id,
                                     LatencyClass lat = iron::NORMAL_LATENCY)
  {
    BinIndex      bin_idx      = bin_map_->GetMcastBinIndex(mcast_id);
    QueueDepths*  queue_depths = q_mgrs_[bin_idx]->GetQueueDepths();

    CPPUNIT_ASSERT(queue_depths != NULL);

    return queue_depths->GetBinDepthByIdx(bin_idx, lat);
  }

  //==========================================================================
  DropPolicy GetQMgrDropPolicy(BinId bin_id)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    return q_mgrs_[bin_idx]->drop_policy();
  }

  //==========================================================================
  DropPolicy GetQMgrDropPolicy(BinId bin_id, LatencyClass lat)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    return q_mgrs_[bin_idx]->drop_policy(lat);
  }

  //==========================================================================
  void SetQMgrDropPolicy(BinId bin_id, DropPolicy policy)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    q_mgrs_[bin_idx]->set_drop_policy(policy);
  }

  //==========================================================================
  void SetQMgrDropPolicy(BinId bin_id, LatencyClass lat, DropPolicy policy)
  {
    BinIndex  bin_idx = bin_map_->GetPhyBinIndex(bin_id);

    q_mgrs_[bin_idx]->set_drop_policy(lat, policy);
  }

public:

  //==========================================================================
  void setUp()
  {
    // Turn down logging levels for the unit testing.
    Log::SetDefaultLevel("F");

    // Clear the array of all BinIds and McastIds.
    num_bin_ids_ = 0;
    memset(bin_ids_, 0, sizeof(bin_ids_));
    num_mcast_ids_ = 0;
    memset(mcast_ids_, 0, sizeof(mcast_ids_));

    // Populate an IP header with some dummy values.
    ip_hdr_.version  = 4;
    ip_hdr_.ihl      = 5;
    ip_hdr_.protocol = IPPROTO_UDP;
    ip_hdr_.saddr    = htonl(1);
    ip_hdr_.daddr    = htonl(2);
    ip_hdr_.tot_len  = htons(sizeof(ip_hdr_));

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_);
    CPPUNIT_ASSERT(pkt_pool_->Create(32) == true);

    q_mgrs_init_ = false;
  }

  //==========================================================================
  void tearDown()
  {
    delete pkt_pool_;
    pkt_pool_ = NULL;

    // Restore default logging levels so we don't break other unit tests.
    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestDequeue()
  {
    ConfigInfo  ci;

    InitBinMap(ci);
    PrepareTest(ci);

    BinId    bin_id             = 0;
    BinId    bin_low            = 5;
    BinId    bin_high           = 15;
    uint8_t  pkt_len_additive_1 = 100;
    uint8_t  pkt_len_additive_2 = 50;
    Packet*  pkt1               = NULL;
    Packet*  pkt2               = NULL;
    Packet*  result             = NULL;

    for (bin_id = bin_low; bin_id <= bin_high; bin_id++)
    {
      // Queue up packets in the bin: a (100 + bin_id) byte packet followed by
      // a (50 + bin_id) byte packet.
      pkt1 = pkt_pool_->Get();
      pkt2 = pkt_pool_->Get();

      pkt1->SetLengthInBytes(pkt_len_additive_1 + bin_id);
      pkt2->SetLengthInBytes(pkt_len_additive_2 + bin_id);

      EnqueueToBinId(bin_id, pkt1);
      EnqueueToBinId(bin_id, pkt2);
    }

    // Dequeue all of the packets from the bin, making sure that their
    // lengths are correct.
    for (bin_id = bin_low; bin_id <= bin_high; bin_id++)
    {
      result = DequeueFromBinId(bin_id);

      CPPUNIT_ASSERT(result != NULL);
      CPPUNIT_ASSERT(result->GetLengthInBytes() ==
                     (pkt_len_additive_1 + bin_id));

      pkt_pool_->Recycle(result);

      LogD("Test", __func__, "%s\n",
           q_mgrs_[bin_map_->GetPhyBinIndex(bin_id)]->GetQueueDepths(
           )->ToString().c_str());
    }

    for (bin_id = bin_low; bin_id <= bin_high; bin_id++)
    {
      result = DequeueFromBinId(bin_id);

      CPPUNIT_ASSERT(result != NULL);
      CPPUNIT_ASSERT(result->GetLengthInBytes() ==
                     (pkt_len_additive_2 + bin_id));

      pkt_pool_->Recycle(result);
    }

    for (bin_id = bin_low; bin_id <= bin_high; bin_id++)
    {
      result = DequeueFromBinId(bin_id);

      CPPUNIT_ASSERT(result == NULL);
    }

    pkt1 = pkt_pool_->Get();
    pkt2 = pkt_pool_->Get();

    // We need to make sure that the Packet objects are IPv4 packets.
    memcpy(pkt1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    memcpy(pkt2->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    pkt1->SetLengthInBytes(100);
    pkt2->SetLengthInBytes(50);
    CPPUNIT_ASSERT(pkt1->SetIpDscp(46));
    pkt2->SetIpDscp(0);

    bin_id = 8;
    EnqueueToBinId(bin_id, pkt1);
    EnqueueToBinId(bin_id, pkt2);

    Packet*  ret_pkt = DequeueFromBinId(bin_id, iron::LOW_LATENCY);
    CPPUNIT_ASSERT(ret_pkt);
    CPPUNIT_ASSERT(ret_pkt->GetLengthInBytes() == 100);

    ret_pkt = DequeueFromBinId(bin_id, iron::LOW_LATENCY);
    CPPUNIT_ASSERT(!ret_pkt);

    ret_pkt = DequeueFromBinId(bin_id, iron::NORMAL_LATENCY);
    CPPUNIT_ASSERT(ret_pkt);
    CPPUNIT_ASSERT(ret_pkt->GetLengthInBytes() == 50);

    pkt1->SetIpDscp(0);
    pkt_pool_->Recycle(pkt1);
    pkt_pool_->Recycle(pkt2);

    // Empty then enqueue LS packets.
    Packet*  pkt10 = NULL;

    while (NULL != (pkt10 = DequeueFromBinId(15)))
    {
      pkt_pool_->Recycle(pkt10);
    }

    pkt10 = pkt_pool_->Get();
    pkt10->SetLengthInBytes(100);
    CPPUNIT_ASSERT(EnqueueToBinId(15, pkt10));
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15) == 100);

    pkt10 = pkt_pool_->Get();
    pkt10->InitIpPacket();
    pkt10->SetIpDscp(iron::DSCP_EF);
    pkt10->SetLengthInBytes(200);
    CPPUNIT_ASSERT(EnqueueToBinId(15, pkt10));
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15) == 300);

    pkt10 = DequeueFromBinId(15, iron::LOW_LATENCY, 2000);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15) == 100);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15, iron::LOW_LATENCY) == 0);
    pkt_pool_->Recycle(pkt10);

    pkt10 = DequeueFromBinId(15);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15, iron::LOW_LATENCY) == 0);
    pkt_pool_->Recycle(pkt10);

    CleanUpTest();
  }

  //==========================================================================
  void TestLatencyFitMethods()
  {
    ConfigInfo  ci;

    InitBinMap(ci);
    PrepareTest(ci);

    BinId    bin_id = 8;
    Packet*  pkt1   = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);
    Packet*  pkt2   = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);

    // We need to make sure that the Packet objects are IPv4 packets.
    memcpy(pkt1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    memcpy(pkt2->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));

    pkt1->SetLengthInBytes(100);
    pkt2->SetLengthInBytes(50);

    CPPUNIT_ASSERT(pkt1->SetIpDscp(46));
    CPPUNIT_ASSERT(pkt2->SetIpDscp(0));
    pkt1->SetTimeToGo(Time(3));
    pkt2->SetTimeToGo(Time(6));

    EnqueueToBinId(bin_id, pkt1);
    EnqueueToBinId(bin_id, pkt2);

    Time ttr(5);

    pkt1->SetIpDscp(0);
    pkt2->SetIpDscp(0);
    pkt_pool_->Recycle(pkt1);
    pkt_pool_->Recycle(pkt2);

    CleanUpTest();
  }

  //==========================================================================
  void TestEnqueue()
  {
    ConfigInfo  ci;

    InitBinMap(ci);
    PrepareTest(ci);

    // First load up all the queues so that we're testing the right minimum
    // queue depth.
    BinId    bin_id   = 0;
    BinId    bin_low  = 5;
    BinId    bin_high = 15;
    Packet*  pkt0     = NULL;

    for (bin_id = bin_low; bin_id <= bin_high; bin_id++)
    {
      pkt0 = pkt_pool_->Get();
      pkt0->SetLengthInBytes(1000);
      EnqueueToBinId(bin_id, pkt0);
    }

    // Use one inactive bin that would otherwise often be the minimum to make
    // sure inactive bins don't affect minimum queue depth.
    pkt0 = pkt_pool_->Get();
    pkt0->SetLengthInBytes(2);
    EnqueueToBinId(3, pkt0);

    // Now dequeue the packet from bin 5 to get an empty queue to start with.
    pkt0 = DequeueFromBinId(5);
    pkt_pool_->Recycle(pkt0);

    // Queue up packets in bin 5: a 100 byte packet followed by a 50 byte
    // packet followed by a 150 byte packet.
    Packet*  pkt1 = pkt_pool_->Get();
    Packet*  pkt2 = pkt_pool_->Get();
    Packet*  pkt3 = pkt_pool_->Get();

    pkt1->SetLengthInBytes(100);
    pkt2->SetLengthInBytes(50);
    pkt3->SetLengthInBytes(150);

    // The number of packets in bin 5 should be 0.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 0);

    CPPUNIT_ASSERT(EnqueueToBinId(5, pkt1));

    // The number of packets in bin 5 should be 1.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 1);

    EnqueueToBinId(5, pkt2);

    // The number of packets in bin 5 should be 2.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 2);

    EnqueueToBinId(5, pkt3);

    // The number of packets in bin 5 should now be 3.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 3);

    // Enqueueing a NULL packet should fail.
    CPPUNIT_ASSERT(EnqueueToBinId(5, NULL) == false);
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 3);

    // Now try enqueuing into a different bin that isn't the minimum, to test
    // minimum depth tracking.
    Packet*  pkt4 = pkt_pool_->Get();

    pkt4->SetLengthInBytes(100);
    EnqueueToBinId(9, pkt4);

    // And change which bin is the minimum
    Packet*  pkt5 = pkt_pool_->Get();

    pkt5->SetLengthInBytes(701);
    EnqueueToBinId(5, pkt5);

    // Empty then enqueue LS packets.
    Packet*  pkt10 = NULL;

    while (NULL != (pkt10 = DequeueFromBinId(15)))
    {
      pkt_pool_->Recycle(pkt10);
    }

    pkt10 = pkt_pool_->Get();
    pkt10->SetLengthInBytes(100);
    CPPUNIT_ASSERT(EnqueueToBinId(15, pkt10));
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15) == 100);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15, iron::LOW_LATENCY) == 0);

    pkt10 = pkt_pool_->Get();
    pkt10->InitIpPacket();
    pkt10->SetIpDscp(iron::DSCP_EF);
    pkt10->SetLengthInBytes(200);
    CPPUNIT_ASSERT(EnqueueToBinId(15, pkt10));
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15) == 300);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(15, iron::LOW_LATENCY) == 200);

    CleanUpTest();
  }

  //==========================================================================
  void TestMulticastEnqueue()
  {
    ConfigInfo  ci;

    InitBinMap(ci);

    // Update the common BinMap configuration with multicast information.
    ci.Add("BinMap.BinIds", "1,2,3,4,5,6");
    ci.Add("BinMap.BinId.1.HostMasks",
           "192.168.1.0/24,10.1.1.1,1.1.1.1");
    ci.Add("BinMap.BinId.2.HostMasks",
           "192.168.2.0/24,10.2.2.2,2.2.2.2");
    ci.Add("BinMap.BinId.4.HostMasks",
           "192.168.4.0/24,10.4.4.4,4.4.4.4");
    ci.Add("BinMap.NumMcastGroups", "1");
    ci.Add("BinMap.McastGroup.0.Addr", "227.7.7.7");
    ci.Add("BinMap.McastGroup.0.Members", "3,4,6");

    // Make the BinId and McastId lists match the BinMap configuration.
    BinId  bin_id_list[6] = {1,2,3,4,5,6};

    num_bin_ids_ = 6;
    memcpy(bin_ids_, bin_id_list, sizeof(bin_id_list));
    num_mcast_ids_ = 1;
    mcast_ids_[0]  = 0x070707e3;  // 227.7.7.7 in network byte order.

    PrepareTest(ci);

    Packet*  pkt0     = pkt_pool_->Get();
    McastId  mcast_id = mcast_ids_[0];
    pkt0->SetLengthInBytes(1000);

    // Bin 7 goes to mcast group 3, 4, and 6.
    iron::DstVec  dst_vec = 0x2C;
    pkt0->set_dst_vec(dst_vec);

    // Enqueue mcast packet on mcast bin 7 with dests 3, 4 and 6.
    // 3: 0B  4: 0B  6: 0B  7: 3,000B
    EnqueueToMcastId(mcast_id, pkt0);

    BinIndex      bin_idx      = bin_map_->GetMcastBinIndex(mcast_id);
    QueueDepths*  queue_depths = q_mgrs_[bin_idx]->GetQueueDepths();

    CPPUNIT_ASSERT(queue_depths != NULL);

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 1);
    CPPUNIT_ASSERT(GetQMgrDepthPackets(3) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 3000);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);

    Packet*  pkt1 = pkt_pool_->Get();
    pkt1->SetLengthInBytes(1000);

    // Bin 7 goes to mcast group 3, 4, and 6, but this packet has already
    // visited 4.
    dst_vec = 0x24;
    pkt1->set_dst_vec(dst_vec);

    // Enqueue mcast packet on mcast bin 7 with dests 3 and 6.
    // 3: 0B  4: 0B  6: 0B  7: 5,000B
    EnqueueToMcastId(mcast_id, pkt1);

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 2);
    CPPUNIT_ASSERT(GetQMgrDepthPackets(3) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 5000);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);

    Packet*  pkt2 = pkt_pool_->Get();
    pkt2->SetLengthInBytes(1000);

    // Bin 7 goes to mcast group 3, 4, and 6, but this packet has already
    // visited 3, 4.
    dst_vec = 0x20;
    pkt2->set_dst_vec(dst_vec);

    // Enqueue mcast packet on mcast bin 7 with dest 6.
    // 3: 0B  4: 0B  6: 0B  7: 6,000B
    EnqueueToMcastId(mcast_id, pkt2);

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 3);
    CPPUNIT_ASSERT(GetQMgrDepthPackets(3) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 6000);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);

    Packet*  pkt3 = pkt_pool_->Get();
    pkt3->InitIpPacket();
    pkt3->SetIpDscp(iron::DSCP_EF);
    pkt3->SetLengthInBytes(1250);

    // Bin 7 goes to mcast group 3, 4, and 6, but this packet has already
    // visited 4.
    dst_vec = 0x24;
    pkt3->set_dst_vec(dst_vec);

    // Enqueue mcast packet on mcast bin 7 with dests 3 and 6.
    EnqueueToMcastId(mcast_id, pkt3);
    //     3: 0B  4: 0B  6: 0B  7: 8,500B
    // LS: 3: 0B  4: 0B  6: 0B  7: 2,500B

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 4);
    CPPUNIT_ASSERT(GetQMgrDepthPackets(3) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 8500);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 2500);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6, iron::LOW_LATENCY) == 0);

    Packet*  pkt4 = pkt_pool_->Get();
    pkt4->SetLengthInBytes(300);
    EnqueueToBinId(3, pkt4);
    //     3: 300B  4: 0B 6:  0B  7: 8,500B
    // LS: 3: 0B    4: 0B 6:  0B  7: 2,500B

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 4);
    CPPUNIT_ASSERT(GetQMgrDepthPackets(3) == 1);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 8500);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 2500);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 300);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6, iron::LOW_LATENCY) == 0);

    // Check that we in fact cannot dequeue a bin that is physically empty.
    //     3: 300B  4: 0B  6: 0B  7: 8,500B
    // LS: 3: 0B    4: 0B  6: 0B  7: 2,500B
    Packet*  pkt = DequeueFromBinId(4);
    CPPUNIT_ASSERT(pkt == NULL);

    // Check that we can dequeue the LS multicast packet.
    pkt = DequeueFromMcastId(mcast_id);
    //     3: 300B  4: 0B  6: 0B  7: 6,000B
    // LS: 3: 0B    4: 0B  6: 0B  7: 0B
    CPPUNIT_ASSERT(pkt == pkt3);
    pkt_pool_->Recycle(pkt);

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 3);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 6000);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 300);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6, iron::LOW_LATENCY) == 0);

    pkt = DequeueFromMcastId(mcast_id);
    CPPUNIT_ASSERT(pkt == pkt0);
    pkt_pool_->Recycle(pkt);

    // Dequeue mcast packet p0 with dests 3, 4, and 6.
    // 3: 300B  4: 0B  6: 0B  7: 3,000B
    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 2);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 3000);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 300);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6, iron::LOW_LATENCY) == 0);

    // Dequeue mcast packet p1 with dests 3, and 6.
    // 3: 300B  4: 0B  6: B  7: 1,000B
    pkt = DequeueFromMcastId(mcast_id);
    CPPUNIT_ASSERT(pkt == pkt1);
    pkt_pool_->Recycle(pkt);

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 1);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 1000);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 300);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6, iron::LOW_LATENCY) == 0);

    // Dequeue mcast packet p2 with dest 6.
    // 3: 300B  4: 0B  6: 0B  7: 0B
    pkt = DequeueFromMcastId(mcast_id);
    CPPUNIT_ASSERT(pkt == pkt2);
    pkt_pool_->Recycle(pkt);

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 300);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6, iron::LOW_LATENCY) == 0);

    // Dequeue ucast packet p4 with dest 3.
    // 3: 0B  4: 0B  6: 0B  7: 0B
    pkt = DequeueFromBinId(3);
    CPPUNIT_ASSERT(pkt == pkt4);
    pkt_pool_->Recycle(pkt);

    CPPUNIT_ASSERT(GetQMgrMcastDepthPackets(mcast_id) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id) == 0);
    CPPUNIT_ASSERT(GetQMgrMcastBinDepthBytes(mcast_id,
                                             iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(3, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(4, iron::LOW_LATENCY) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6) == 0);
    CPPUNIT_ASSERT(GetQMgrBinDepthBytes(6, iron::LOW_LATENCY) == 0);

    CleanUpTest();
  }

  //==========================================================================
  void TestGetDepth()
  {
    ConfigInfo  ci;

    InitBinMap(ci);
    PrepareTest(ci);

    // Queue up packets in bin 5: a 100 byte packet followed by a 50 byte
    // packet followed by a 150 byte packet.
    Packet*  pkt1 = pkt_pool_->Get();
    Packet*  pkt2 = pkt_pool_->Get();
    Packet*  pkt3 = pkt_pool_->Get();

    pkt1->SetLengthInBytes(100);
    pkt2->SetLengthInBytes(50);
    pkt3->SetLengthInBytes(150);

    // The number of packets in bin 5 should be 0.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 0);

    EnqueueToBinId(5, pkt1);

    // The number of packets in bin 5 should be 1.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 1);

    EnqueueToBinId(5, pkt2);

    // The number of packets in bin 5 should be 2.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 2);

    EnqueueToBinId(5, pkt3);

    // The number of packets in bin 5 should now be 3.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 3);

    Packet*  result = DequeueFromBinId(5);
    CPPUNIT_ASSERT(result != NULL);
    pkt_pool_->Recycle(result);

    // The number of packets in bin 5 should be 2.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 2);

    result = DequeueFromBinId(5);
    CPPUNIT_ASSERT(result != NULL);
    pkt_pool_->Recycle(result);

    // The number of packets in bin 5 should be 1.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 1);

    result = DequeueFromBinId(5);
    CPPUNIT_ASSERT(result != NULL);
    pkt_pool_->Recycle(result);

    // The number of packets in bin 5 should be 0.
    CPPUNIT_ASSERT(GetQMgrDepthPackets(5) == 0);

    CleanUpTest();
  }

  //==========================================================================
  void TestGetDropPolicy()
  {
    ConfigInfo  ci;

    InitBinMap(ci);
    PrepareTest(ci);

    DropPolicy  drop_policy = iron::NO_DROP;

    // Enqueue to initialize queue.
    // Leave bin 5 with policy NO_DROP (our default).
    Packet*  pkt1 = pkt_pool_->Get();
    pkt1->SetLengthInBytes(100);
    CPPUNIT_ASSERT(EnqueueToBinId(5, pkt1));
    DropPolicy  result = GetQMgrDropPolicy(5);

    CPPUNIT_ASSERT(result == drop_policy);

    // Set the policy for bin 6 to TAIL.
    drop_policy = iron::TAIL;
    SetQMgrDropPolicy(6, drop_policy);

    result = GetQMgrDropPolicy(6);

    CPPUNIT_ASSERT(result == drop_policy);

    // Set the policy for bin 5 to TAIL for LOW_LATENCY.
    SetQMgrDropPolicy(5, ::iron::LOW_LATENCY, drop_policy);

    result = GetQMgrDropPolicy(5, ::iron::LOW_LATENCY);

    CPPUNIT_ASSERT(result == drop_policy);

    CleanUpTest();
  }

  //==========================================================================
  void TestMaxDepth()
  {
    ConfigInfo  ci;

    InitBinMap(ci);
    PrepareTest(ci);

    uint32_t      depth = 500;
    BinQueueMgr*  iq2   = new (std::nothrow) BinQueueMgr(1, *pkt_pool_,
                                                         *bin_map_);

    // Test the default maximum depth.
    CPPUNIT_ASSERT(iq2->max_bin_depth_pkts() == depth);

    // Test changing the maximum depth.
    depth = 200;
    iq2->set_max_bin_depth_pkts(depth);
    CPPUNIT_ASSERT(iq2->max_bin_depth_pkts() == depth);

    delete iq2;

    CleanUpTest();
  }

  //==========================================================================
  void TestSetDropPolicy()
  {
    ConfigInfo  ci;

    InitBinMap(ci);
    PrepareTest(ci);

    // Enqueue to initialize queue.
    // Leave bin 5 with policy NO_DROP (our default).
    Packet*  pkt1 = pkt_pool_->Get();
    pkt1->SetLengthInBytes(100);
    EnqueueToBinId(5, pkt1);
    CPPUNIT_ASSERT(GetQMgrDropPolicy(5) == iron::NO_DROP);

    // Change bin 5 to TAIL.
    SetQMgrDropPolicy(5, iron::TAIL);

    CPPUNIT_ASSERT(GetQMgrDropPolicy(5) == iron::TAIL);

    CleanUpTest();
  }

  //==========================================================================
  void TestMaxBinDepth()
  {
    ConfigInfo  ci;

    InitBinMap(ci);

    // Set the max_queue_depth before initialization.
    ci.Add("Bpf.BinQueueMgr.MaxBinDepthPkts", "2");
    ci.Add("Bpf.BinQueueMgr.DropPolicy", "HEAD");

    PrepareTest(ci);

    BinId  bin_id   = 0;
    BinId  bin_low  = 5;
    BinId  bin_high = 15;

    for (bin_id = bin_low; bin_id <= bin_high; ++bin_id)
    {
      // Queue up packets in the bin: a (100 + bin_id) byte packet followed by
      // a (50 + bin_id) byte packet.
      Packet*  pkt1 = pkt_pool_->Get();
      Packet*  pkt2 = pkt_pool_->Get();

      CPPUNIT_ASSERT(pkt1);
      CPPUNIT_ASSERT(pkt2);

      pkt1->SetLengthInBytes(100 + bin_id);
      pkt2->SetLengthInBytes(50 + bin_id);

      EnqueueToBinId(bin_id, pkt1);
      EnqueueToBinId(bin_id, pkt2);

      // Verify that each bin has 2 packets.
      CPPUNIT_ASSERT(GetQMgrDepthPackets(bin_id) == 2);
    }

    // Add one more packet to each bin, and verify that the depth is still 2.
    for (bin_id = bin_low; bin_id <= bin_high; ++bin_id)
    {
      Packet*  pkt1 = pkt_pool_->Get();

      CPPUNIT_ASSERT(pkt1);

      EnqueueToBinId(bin_id, pkt1);

      // Verify that each bin still has 2 packets.
      CPPUNIT_ASSERT(GetQMgrDepthPackets(bin_id) == 2);
    }

    CleanUpTest();
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(QSetTest);
