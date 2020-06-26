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

#include "bin_map.h"
#include "config_info.h"
#include "fd_event.h"
#include "ipv4_address.h"
#include "itime.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "path_controller.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "port_number_mgr.h"
#include "timer.h"
#include "unused.h"

#include <vector>

#include <inttypes.h>

using ::iron::BinId;
using ::iron::BinMap;
using ::iron::BPFwder;
using ::iron::ConfigInfo;
using ::iron::Ipv4Address;
using ::iron::LSA_PACKET;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::PacketType;
using ::iron::PathController;
using ::iron::PseudoFifo;
using ::iron::PseudoSharedMemory;
using ::iron::PortNumberMgr;
using ::iron::SharedMemoryIF;
using ::iron::Time;
using ::iron::Timer;

using ::std::vector;

namespace
{
  const char*  UNUSED(kClassName) = "BpfBroadcastTester";
}

//============================================================================
// A child class of PathController that only tracks the most recent packet
// sent via each function, for the sake of testing the BPF.

class BroadcastTrackerPathCtrl : public PathController
{
public:
  BroadcastTrackerPathCtrl(BPFwder* bpf, PacketPool& packet_pool) :
      PathController(bpf), packet_pool_(packet_pool),
      last_broadcast_packet_(NULL), second_last_bc_packet_(NULL)
  {};

  virtual ~BroadcastTrackerPathCtrl()
  {
    if (last_broadcast_packet_)
    {
      packet_pool_.Recycle(last_broadcast_packet_);
    }
    if (second_last_bc_packet_)
    {
      packet_pool_.Recycle(second_last_bc_packet_);
    }
  };

  inline bool Initialize(const ConfigInfo& config_info, uint32_t config_id)
  {
    return true;
  };

  inline bool ConfigurePddReporting(double thresh, double min_period,
                                    double max_period)
  {
    return true;
  };

  virtual inline uint32_t GetPerQlamOverhead() const
  {
    return 0;
  };

  inline bool SendPacket(Packet* pkt)
  {
    if (pkt == NULL)
    {
      return false;
    }
    PacketType  pkt_type = pkt->GetType();
    if (pkt_type != LSA_PACKET)
    {
      packet_pool_.Recycle(pkt);
      return true;
    }
    if (second_last_bc_packet_)
    {
      packet_pool_.Recycle(second_last_bc_packet_);
    }
    if (last_broadcast_packet_)
    {
      second_last_bc_packet_ = last_broadcast_packet_;
    }
    last_broadcast_packet_ = pkt;
    return true;
  };

  inline Packet* get_last_broadcast_packet()
  {
    return last_broadcast_packet_;
  }

  inline Packet* get_second_last_bc_packet()
  {
    return second_last_bc_packet_;
  }

  inline void ServiceFileDescriptor(int fd, iron::FdEvent event) {};
  inline size_t GetFileDescriptors(iron::FdEventInfo* fd_event_array,
                                   size_t array_size) const { return 0; };
  inline bool GetXmitQueueSize(size_t& size) const
  {
    size = 0;
    return true;
  };
  virtual bool GetSmoothedRTT(Time& smoothed_rtt) const
  {
    smoothed_rtt.Zero();
    return false;
  };

private:
  iron::PacketPool&      packet_pool_;
  Packet*                last_broadcast_packet_;
  Packet*                second_last_bc_packet_;
};


//============================================================================
// A child class of the backpressure forwarder for testing that broadcast
// traffic can be sent via backpressure forwarding.

class BpfBroadcastTester : public BPFwder
{
public:

  BpfBroadcastTester(PacketPool& packet_pool, BinMap& bin_map, Timer& timer,
                     SharedMemoryIF& weight_qd_shared_memory,
                     vector<PseudoFifo*>* fifos, ConfigInfo& config_info);

  virtual ~BpfBroadcastTester();

  /// \brief Function initializes the test, like the BinMap and Path
  /// Controllers.
  void InitForTest(ConfigInfo& config_info);

  /// \brief Returns the last broadcast packet dequeued for the given bin id.
  ///
  /// \param bin_id We want the last broadcast packet sent here over a dummy
  ///        path controller.
  /// \return Packet* The last sent packet, or NULL if none.
  Packet* GetLastBroadcastPacket(BinId bin_id);

  /// \brief Returns the second to last broadcast packet dequeued for the
  /// given bin id.
  ///
  /// \param bin_id We want the second to last broadcast packet sent here over
  ///        a dummy path controller.
  /// \return Packet* The last sent packet, or NULL if none.
  Packet* GetSecondLastBroadcastPacket(BinId bin_id);

  // Method overriding.

  /// \brief Initialize the FIFOs.
  ///
  /// \param  config_info  The configuration information.
  ///
  /// \return  True if the initialization is successful, false otherwise.
  inline bool InitializeFifos() { return true; };

private:

  /// Disallow constructor and = operator
  BpfBroadcastTester(const BpfBroadcastTester& other);
  BpfBroadcastTester& operator=(const BpfBroadcastTester& other);

  PacketPool&         pkt_pool_;
  BinMap&             bin_map_;
  vector<PseudoFifo*>* fifos_;
};

//============================================================================
BpfBroadcastTester::BpfBroadcastTester(
  PacketPool& packet_pool,
  BinMap& bin_map,
  Timer& timer,
  SharedMemoryIF& weight_qd_shared_memory,
  vector<PseudoFifo*>* fifos,
  ConfigInfo& config_info)
    : BPFwder(packet_pool, timer, bin_map, weight_qd_shared_memory,
              BPF_FIFO_ARGS(fifos), config_info),
      pkt_pool_(packet_pool),
      bin_map_(bin_map),
      fifos_(fifos)
{ }

//============================================================================
BpfBroadcastTester::~BpfBroadcastTester()
{
  PseudoFifo::DeleteBpfFifos(fifos_);
}

//============================================================================
void BpfBroadcastTester::InitForTest(ConfigInfo& ci)
{
  // Initialize two dummy path controllers.
  for (uint8_t i = 0; i < 3; i++)
  {
    PathController* path_ctrl = NULL;
    path_ctrl = new (std::nothrow) BroadcastTrackerPathCtrl(this, pkt_pool_);
    CPPUNIT_ASSERT(path_ctrl != NULL);
    num_path_ctrls_++;
    path_ctrls_[i].path_ctrl = path_ctrl;
    path_ctrls_[i].in_timer_callback = false;
    path_ctrls_[i].timer_handle.Clear();
    path_ctrls_[i].bucket_depth_bits = 0.0;
    path_ctrls_[i].link_capacity_bps = 0.0;
    path_ctrls_[i].last_qlam_tx_time.Zero();
    path_ctrls_[i].last_capacity_update_time.Zero();
  }
  // Make sure bin ids match the bin map IP addresses.
  path_ctrls_[0].path_ctrl->set_remote_bin_id_idx(2, 1); // 0.0.0.2
  path_ctrls_[1].path_ctrl->set_remote_bin_id_idx(4, 2); // 10.1.16.104
  path_ctrls_[2].path_ctrl->set_remote_bin_id_idx(6, 3); // 10.1.16.106

  // Note: this MUST be called after setting up the dummy path controllers, or
  // else num_path_ctrls_ passed into the forwarding algorithm will be 0.
  CPPUNIT_ASSERT(this->Initialize());
}

//============================================================================
Packet* BpfBroadcastTester::GetLastBroadcastPacket(BinId bin_id)
{
  uint8_t pc_idx = 0;
  switch (bin_id)
  {
    case 2:
      pc_idx = 0;
      break;
    case 4:
      pc_idx = 1;
      break;
    case 6:
      pc_idx = 2;
      break;
    default:
      return NULL;
  }

  return static_cast<BroadcastTrackerPathCtrl*>(
    path_ctrls_[pc_idx].path_ctrl)->get_last_broadcast_packet();
}

//============================================================================
Packet* BpfBroadcastTester::GetSecondLastBroadcastPacket(BinId bin_id)
{
  uint8_t pc_idx = 0;
  switch (bin_id)
  {
    case 2:
      pc_idx = 0;
      break;
    case 4:
      pc_idx = 1;
      break;
    case 6:
      pc_idx = 2;
      break;
    default:
      return NULL;
  }

  return static_cast<BroadcastTrackerPathCtrl*>(
    path_ctrls_[pc_idx].path_ctrl)->get_second_last_bc_packet();
}

//============================================================================
class BPFBroadcastTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(BPFBroadcastTest);

  CPPUNIT_TEST(TestBPFBroadcast);

  CPPUNIT_TEST_SUITE_END();

private:

  BpfBroadcastTester*    bpfwder_;
  PacketPoolHeap*          pkt_pool_;
  BinMap*                  bin_map_     = NULL;
  char*                    bin_map_mem_ = NULL;
  Timer*                   timer_;
  SharedMemoryIF*          weight_qd_shared_memory_;

public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FE");

    timer_ = new Timer();
    CPPUNIT_ASSERT(timer_ != NULL);

    weight_qd_shared_memory_ = new PseudoSharedMemory();
    CPPUNIT_ASSERT(weight_qd_shared_memory_ != NULL);

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_->Create(16) == true);

    ConfigInfo  config_info;

    // Add BinMap configuration to ConfigInfo.
    config_info.Add("BinMap.BinIds", "1,2,4,6");
    config_info.Add("BinMap.BinId.1.HostMasks",
                    "192.168.1.0/24,10.1.1.0/24,10.1.10.101");
    config_info.Add("BinMap.BinId.2.HostMasks",
                    "192.168.2.0/24,10.2.2.0/24,0.0.0.2");
    config_info.Add("BinMap.BinId.4.HostMasks",
                    "192.168.4.0/24,10.1.14.0/24,10.1.16.104");
    config_info.Add("BinMap.BinId.6.HostMasks",
           "192.168.6.0/24,10.1.16.0/24");

    // Add backpressure forwarder configuration to ConfigInfo.
    config_info.Add("Bpf.BinId", "1");

    // Create and initialize the BinMap.
    bin_map_mem_ = new char[sizeof(BinMap)];
    bin_map_     = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));
    CPPUNIT_ASSERT(bin_map_ != NULL);
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info));

    // Create the backpressure forwarder set up for testing.  Memory reclaimed
    // below.
    bpfwder_ = new (std::nothrow) BpfBroadcastTester(
      *pkt_pool_, *bin_map_, *timer_, *weight_qd_shared_memory_,
      PseudoFifo::BpfFifos(), config_info);
    CPPUNIT_ASSERT(bpfwder_ != NULL);

    bpfwder_->InitForTest(config_info);
  }

  //==========================================================================
  void tearDown()
  {
    // Cancel all timers.  This protects other BPFwder-based unit tests.
    timer_->CancelAllTimers();

    // Clean up.
    delete bpfwder_;
    bpfwder_ = NULL;

    delete pkt_pool_;
    pkt_pool_ = NULL;

    delete [] bin_map_mem_;
    bin_map_ = NULL;

    delete timer_;
    timer_ = NULL;

    delete weight_qd_shared_memory_;
    weight_qd_shared_memory_ = NULL;

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestBPFBroadcast()
  {
    // Fill a broadcast packet.
    //
    // pkt1 from bin 1, seq num 0. Type=LSA_PACKET (because we need a broadcast
    // packet type. It won't actually be a LSA_PACKET).
    // contents: pkt1_contents1 pkt1_contents2 pkt1_contents2
    uint32_t pkt1_contents1 = 12345;
    uint64_t pkt1_contents2 = 987654321987654321;
    uint16_t pkt1_contents3 = 23456;
    size_t   offset1        = 0;
    Packet* pkt1 = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);
    pkt1->PopulateBroadcastPacket(iron::LSA_PACKET, 1,
                                  bpfwder_->GetAndIncrLSASeqNum());
    pkt1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&pkt1_contents1),
                           sizeof(pkt1_contents1));
    offset1 += sizeof(pkt1_contents1);
    pkt1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&pkt1_contents2),
                           sizeof(pkt1_contents2));
    offset1 += sizeof(pkt1_contents2);
    pkt1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&pkt1_contents3),
                           sizeof(pkt1_contents3));
    offset1 += sizeof(pkt1_contents3);
    // And forward it via the BPF.
    bpfwder_->BroadcastPacket(pkt1);

    // Fill a second broadcast packet.
    //
    // pkt2 from bin 1, seq num 1. Type=LSA_PACKET (same comment as above).
    // contents:
    // uint8_t=4
    uint8_t  pkt2_contents1 = 13;
    size_t   offset2        = 0;
    Packet* pkt2 = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);
    pkt2->PopulateBroadcastPacket(iron::LSA_PACKET, 1,
                                  bpfwder_->GetAndIncrLSASeqNum());
    pkt2->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&pkt2_contents1),
                           sizeof(pkt2_contents1));
    offset2 += sizeof(pkt2_contents1);

    // And forward it.
    bpfwder_->BroadcastPacket(pkt2);

    // Run the BPF just until we've processed the packets we added. Give it a
    // 20 iteration limit so we don't have an infinite loop if there are bugs.
    // This should add 6 packets: one of each to each of the other 3 bins.
    bpfwder_->Start(6, 20);

    BinId bins[3] = { 2, 4, 6 };

    for (uint8_t check_idx = 0; check_idx < 3; check_idx++)
    {
      BinId check_bin = bins[check_idx];

      // Now check that the path controllers each got both of the packets.
      Packet* ch_pkt1 = bpfwder_->GetSecondLastBroadcastPacket(check_bin);
      CPPUNIT_ASSERT(ch_pkt1 != NULL);

      bool     parsed;
      BinId    rcvd_src_bin         = 0;
      uint16_t rcvd_seq_num         = 0;
      const uint8_t* rcvd_data;
      size_t   rcvd_data_len        = 0;
      uint32_t rcvd_pkt1_contents1  = 0;
      uint64_t rcvd_pkt1_contents2  = 0;
      uint16_t rcvd_pkt1_contents3  = 0;

      // Check the contents of the packet.
      parsed = ch_pkt1->ParseBroadcastPacket(rcvd_src_bin, rcvd_seq_num,
                                             &rcvd_data, rcvd_data_len);
      CPPUNIT_ASSERT(parsed);
      pkt_pool_->Recycle(ch_pkt1);
      CPPUNIT_ASSERT(rcvd_src_bin == 1);
      CPPUNIT_ASSERT(rcvd_seq_num == 0);
      CPPUNIT_ASSERT(rcvd_data_len == offset1);
      size_t read_offset = 0;
      memcpy(&rcvd_pkt1_contents1, &(rcvd_data[read_offset]),
             sizeof(rcvd_pkt1_contents1));
      CPPUNIT_ASSERT(rcvd_pkt1_contents1 == pkt1_contents1);
      read_offset += sizeof(rcvd_pkt1_contents1);
      memcpy(&rcvd_pkt1_contents2, &(rcvd_data[read_offset]),
             sizeof(rcvd_pkt1_contents2));
      CPPUNIT_ASSERT(rcvd_pkt1_contents2 == pkt1_contents2);
      read_offset += sizeof(rcvd_pkt1_contents2);
      memcpy(&rcvd_pkt1_contents3, &(rcvd_data[read_offset]),
             sizeof(rcvd_pkt1_contents3));
      CPPUNIT_ASSERT(rcvd_pkt1_contents3 == pkt1_contents3);
      read_offset += sizeof(rcvd_pkt1_contents3);

      // And check the most recent packet.
      Packet* ch_pkt2 = bpfwder_->GetLastBroadcastPacket(check_bin);
      CPPUNIT_ASSERT(ch_pkt2 != NULL);

      // Check the contents of the packet.
      uint8_t rcvd_pkt2_contents1  = 0;
      parsed = ch_pkt2->ParseBroadcastPacket(rcvd_src_bin, rcvd_seq_num,
                                             &rcvd_data, rcvd_data_len);
      CPPUNIT_ASSERT(parsed);
      pkt_pool_->Recycle(ch_pkt2);
      CPPUNIT_ASSERT(rcvd_src_bin == 1);
      CPPUNIT_ASSERT(rcvd_seq_num == 1);
      CPPUNIT_ASSERT(rcvd_data_len == offset2);
      read_offset = 0;
      memcpy(&rcvd_pkt2_contents1, &(rcvd_data[read_offset]),
             sizeof(rcvd_pkt2_contents1));
      CPPUNIT_ASSERT(rcvd_pkt2_contents1 == pkt2_contents1);
      read_offset += sizeof(rcvd_pkt2_contents1);
    }
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(BPFBroadcastTest);
