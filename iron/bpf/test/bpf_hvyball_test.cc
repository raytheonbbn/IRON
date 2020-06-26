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

#include "backpressure_fwder.h"
#include "hvyball_bin_queue_mgr.h"
#include "path_controller.h"
#include "queue_store.h"
#include "sond.h"

#include "bin_map.h"
#include "config_info.h"
#include "log.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "queue_depths.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "timer.h"

using ::iron::BinMap;
using ::iron::BPFwder;
using ::iron::ConfigInfo;
using ::iron::HvyballBinQueueMgr;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::PathController;
using ::iron::QueueStore;
using ::iron::QueueDepths;
using ::iron::PseudoSharedMemory;
using ::iron::SharedMemoryIF;
using ::iron::Sond;
using ::iron::Timer;


//============================================================================
class HvyBallTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(HvyBallTest);

  CPPUNIT_TEST(TestHvyBall);

  CPPUNIT_TEST_SUITE_END();

  private:
  struct iphdr        ip_hdr_;
  HvyballBinQueueMgr* hb_;
  PacketPoolHeap*     pkt_pool_;
  BinMap*             bin_map_;
  Timer*              timer_;
  SharedMemoryIF*     weight_qd_shared_memory_;

  //============================================================================
  void InitForTest(HvyballBinQueueMgr* hvy_ball, BinMap* bin_map)
  {
    ConfigInfo  ci;

    ci.Add("Bpf.IpAddr", "1.2.3.4");

    ci.Add("Bpf.Alg.QDMgr", "HvyBall");
    ci.Add("Bpf.HvyBall.Beta", "0.95");
    ci.Add("Bpf.HvyBall.WeightComputationIntervalUsec", "50000000");

    ci.Add("BinMap.BinIds", "1,2");
    ci.Add("BinMap.BinId.1.IronNodeAddr", "1.2.3.4");
    ci.Add("BinMap.BinId.1.HostMasks",
           "192.168.1.0/24,10.1.1.0/24,1.2.3.4");
    ci.Add("BinMap.BinId.2.IronNodeAddr", "5.6.7.8");
    ci.Add("BinMap.BinId.2.HostMasks",
           "192.168.2.0/24,10.2.2.2,5.6.7.8");

    ci.Add("Bpf.Weight.SemKey", "1");
    ci.Add("Bpf.Weight.ShmName", "weights_");

    CPPUNIT_ASSERT(bin_map->Initialize(ci));
    CPPUNIT_ASSERT(hvy_ball->Initialize(ci));
  }

  public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FE");

    timer_ = new Timer();

    bin_map_ = new BinMap();

    weight_qd_shared_memory_ = new PseudoSharedMemory();

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_->Create(8) == true);

    // Populate an IP header with some dummy values.
    ip_hdr_.version  = 4;
    ip_hdr_.ihl      = 5;
    ip_hdr_.tos      = 0;
    ip_hdr_.protocol = IPPROTO_UDP;
    ip_hdr_.check    = 0;
    ip_hdr_.saddr    = htonl(1);
    ip_hdr_.daddr    = htonl(2);
    ip_hdr_.tot_len  = htons(sizeof(ip_hdr_));

    hb_ = new (std::nothrow) HvyballBinQueueMgr(*pkt_pool_, *bin_map_, *timer_,
                                                *weight_qd_shared_memory_);
    InitForTest(hb_, bin_map_);
  }

  //==========================================================================
  void tearDown()
  {
    delete hb_;
    hb_ = NULL;

    delete pkt_pool_;
    pkt_pool_ = NULL;

    delete bin_map_;
    bin_map_ = NULL;

    delete timer_;
    timer_ = NULL;

    delete weight_qd_shared_memory_;
    weight_qd_shared_memory_ = NULL;

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestHvyBall()
  {
    QueueDepths* weights          = hb_->GetDepthsForBpfQlam();
    QueueDepths* current_weights  = hb_->GetQueueDepthsForBpf();

    CPPUNIT_ASSERT(weights->GetBinDepth(2) == 0);
    CPPUNIT_ASSERT(current_weights->GetBinDepth(2) == 0);

    Packet* pkt = pkt_pool_->Get();
    // We need to make sure that the Packet object is an IPv4 packet.
    memcpy(pkt->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    pkt->SetLengthInBytes(1024);
    hb_->Enqueue(2, pkt);

    pkt = pkt_pool_->Get();
    // We need to make sure that the Packet object is an IPv4 packet.
    memcpy(pkt->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    pkt->SetLengthInBytes(1024);
    hb_->Enqueue(2, pkt);

    uint32_t cur_bin_weight = current_weights->GetBinDepth(2);
    CPPUNIT_ASSERT(cur_bin_weight == 2048);

    // Compute the weights:
    // w_1 = w_0 * beta + current_depth.
    // w_1 = 0 * beta + 2048 = 2048.
    hb_->ComputeWeights();

    uint32_t bin_weight = current_weights->GetBinDepth(2);
    CPPUNIT_ASSERT(cur_bin_weight == 2048);
    // At this point, current weights are equal to weights since we have not
    // yet dequeued or enqueued a packet since the last computation.
    CPPUNIT_ASSERT(cur_bin_weight == bin_weight);

    // Enqueue a new packet---current weights should go from 2048 to 3072.
    pkt = pkt_pool_->Get();
    // We need to make sure that the Packet object is an IPv4 packet.
    memcpy(pkt->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    pkt->SetLengthInBytes(1024);

    hb_->Enqueue(2, pkt);

    cur_bin_weight  = current_weights->GetBinDepth(2);
    CPPUNIT_ASSERT(cur_bin_weight == 3072);

    // Compute weights again:
    // w_2 = w_1 * beta + current_depth.
    // w_2 = 2048 * beta + 3072.
    hb_->ComputeWeights();

    cur_bin_weight  = current_weights->GetBinDepth(2);
    bin_weight      = weights->GetBinDepth(2);
    CPPUNIT_ASSERT(cur_bin_weight == 5017);
    // At this point, current weights are equal to weights since we have not
    // yet dequeued or enqueued a packet since the last computation.
    CPPUNIT_ASSERT(cur_bin_weight == bin_weight);

    // Test the nbr queue depths.
    PathController* pathctrl  = new (std::nothrow) Sond(NULL, *pkt_pool_,
                                                        *timer_);
    iron::BinId pc_nbr_bin_id = 1;
    pathctrl->set_remote_bin_id(pc_nbr_bin_id);
    CPPUNIT_ASSERT(!hb_->SetNbrQueueDepths(pc_nbr_bin_id, NULL));
    QueueDepths*    qd        = new (std::nothrow) QueueDepths(*bin_map_);
    qd->SetBinDepth(2, 10000);
    CPPUNIT_ASSERT(hb_->SetNbrQueueDepths(pc_nbr_bin_id, qd));

    CPPUNIT_ASSERT(hb_->PeekNbrQueueDepths(2) == NULL);
    QueueDepths*    qd_get    = hb_->PeekNbrQueueDepths(pc_nbr_bin_id);
    CPPUNIT_ASSERT(qd_get);
    CPPUNIT_ASSERT(qd_get->GetBinDepth(2) == 10000);

    hb_->DeleteNbrQueueDepths(pc_nbr_bin_id);
    CPPUNIT_ASSERT(hb_->PeekNbrQueueDepths(pc_nbr_bin_id) == NULL);

    // Test the nbr virtual queue depths.
    CPPUNIT_ASSERT(!hb_->SetNbrVirtQueueDepths(pc_nbr_bin_id, NULL));
    qd        = new (std::nothrow) QueueDepths(*bin_map_);
    qd->SetBinDepth(2, 20000);
    CPPUNIT_ASSERT(hb_->SetNbrVirtQueueDepths(pc_nbr_bin_id, qd));

    CPPUNIT_ASSERT(hb_->PeekNbrVirtQueueDepths(2) == NULL);
    qd_get    = hb_->PeekNbrVirtQueueDepths(pc_nbr_bin_id);
    CPPUNIT_ASSERT(qd_get);
    CPPUNIT_ASSERT(qd_get->GetBinDepth(2) == 20000);

    hb_->DeleteNbrVirtQueueDepths(pc_nbr_bin_id);
    CPPUNIT_ASSERT(hb_->PeekNbrVirtQueueDepths(pc_nbr_bin_id) == NULL);

    delete   pathctrl;
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(HvyBallTest);
