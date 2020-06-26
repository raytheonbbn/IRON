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
#include "gradient.h"
#include "path_controller.h"
#include "queue_store.h"

#include "bin_map.h"
#include "config_info.h"
#include "fifo_if.h"
#include "itime.h"
#include "ipv4_address.h"
#include "iron_types.h"
#include "log.h"
#include "ordered_list.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "queue_depths.h"
#include "bin_queue_mgr.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "packet_creator.h"
#include "port_number_mgr.h"
#include "timer.h"
#include "uber_fwd_alg.h"
#include "unused.h"
#include "zombie.h"
#include "zombie_queue.h"

#include <map>
#include <string>
#include <vector>

#include <netinet/ip.h>
#include <inttypes.h>


using ::iron::BinId;
using ::iron::BPFwder;
using ::iron::ConfigInfo;
using ::iron::FifoIF;
using ::iron::Gradient;
using ::iron::Ipv4Address;
using ::iron::Log;
using ::iron::OrderedList;
using ::iron::PacketCreator;
using ::iron::PACKET_NOW_TIMESTAMP;
using ::iron::PathController;
using ::iron::UberFwdAlg;
using ::iron::Zombie;

using ::std::map;
using ::std::string;
using ::std::vector;


namespace
{
  const char*   UNUSED(kClassName)  = "BpfUberAlgTester";

  const uint8_t kNumSolutions       = 10;
}


//============================================================================
// A child class of the backpressure forwarder for testing the BPF algorithm.
// This class lets a test call a function that sets data and invoke
// FindNextTransmission.  The test is broken into various iterations, intended
// to test different aspects of the algorithm.
// !!!! NOTE: The SetUpBPFAlgTest MUST be called iteratively, that is, do not
// skip any iteration as data builds off of each other.!!!!
// Note: It would take more time / work to break this into separate functions.

// The QueueStore is the default algorithm, which is base (no heavy ball)
// as of 10Feb16.

class BpfAlgTester : public BPFwder, public UberFwdAlg
{
public:

  BpfAlgTester(iron::PacketPool& packet_pool, iron::BinMap& bin_map,
               iron::Timer& timer,
               iron::SharedMemoryIF& weight_qd_shared_memory,
               vector<iron::PseudoFifo*>* fifos, ConfigInfo& config_info);
  virtual ~BpfAlgTester();

  // New methods.

  /// \brief Function initializes the test, like the BinMap and Path
  /// Controllers.
  ///
  /// \param ci The config info object used to initialize the BPF.
  void InitForTest(iron::ConfigInfo& ci);

  /// \brief  Function calls to preseed the virtual queues.
  ///
  /// \param  ci  The config info object to use to configure virtual queues.
  void CallPreseedVirtQueues(iron::ConfigInfo& ci);

  /// \brief Function that directly exposes the protected FindNextTransmission
  ///        function, which is the core of the BP Fwding algorithm.
  ///
  /// \param  solutions The array of transmis solutions to be sent.
  /// \param  num_solutions The number of elements in the solutions array.
  ///
  /// \return true if the outcome is successful and we have a packet to send,
  ///         false otherwise.
  bool CallFindNextTransmission(iron::TxSolution* solutions,
                                uint8_t& num_solutions);

  // Method overriding.

  /// \brief Initialize the FIFOs.
  ///
  /// \param  config_info  The configuration information.
  ///
  /// \return  True if the initialization is successful, false otherwise.
  virtual bool InitializeFifos();

  /// \brief  Get the BinQueueMgr object from the BPF.
  ///
  /// \return A pointer to the queue depth object.
  iron::BinQueueMgr* GetBinQueueMgr(iron::BinIndex bidx);

  /// \brief  Set a latency value on all path controllers.
  ///
  /// \param  node_idx    The node idx where to source the latencies.
  /// \param  latency_us  The latency in microseconds.
  /// \param  num_nbrs    The number of neighbors (size of latency_us) the node
  ///                     has.
  void SetPcLatencies(iron::BinIndex node_idx, uint32_t* latency_us,
    uint8_t num_path_ctrl);

  /// \brief  Call method to get the index and value of the lowest latency path.
  ///
  /// \param  latencies_us    The vector of latencies on each path controller.
  /// \param  num_latencies   The number of latencies in the vector.
  /// \param  path_ctrl_index The index of the lowest-latency path controller.
  /// \param  min_ttr         The latency of the lowest-latency path.
  ///
  /// \return true if results were computed, false for no min (then, must pick
  ///         at random).
  bool CallGetMinLatency(uint32_t* latency_us, size_t num_latencies,
                         size_t& min_path_ctrl_index, iron::Time& min_ttr);

  /// \brief  Call method to determine if a packet is in history-constrained
  ///         mode.
  ///
  /// \param  pkt           A pointer to the packet.
  /// \param  ttg           The packet's time-to-go.
  /// \param  latencies_us  The vector of latencies on each path controller.
  /// \param  num_latencies   The number of latencies in the vector.
  ///
  /// \return true if the packet is in history-constrained mode, false if still
  ///         in gradient mode.
  bool CallIsHistoryConstrained(iron::Packet* pkt, iron::Time& ttg,
                                uint32_t* latencies_us, size_t num_latencies);

  /// \brief  Match a gradient to a packet inside a particular queue.
  ///
  /// \param  gradient          A reference to the gradient to match.
  /// \param  q_mgr             A pointer to the bin queue mgr object.
  /// \param  ttype             The traffic type of the queue to look in.
  /// \param  method_start      The start of the caller method to have
  ///                           consistent timestamps.
  /// \param  consider_latency  Boolean indicating whether to consider latency.
  /// \param  candidates        The list of candidates.
  /// \param  max_bytes         The maximum number of bytes to send.
  /// \return True if match found, false otherwise.
  bool CallFindUcastPacketsForGradient(const iron::Gradient& gradient,
                       iron::LatencyClass& ttype,
                       iron::Time& method_start,
                       bool consider_latency,
                       OrderedList<TransmitCandidate, iron::Time>& candidates,
                       uint32_t max_bytes);

  /// \brief  Set the queue depth for a nbr or self, including virtual.
  ///
  /// \param  dst_bidx     The index of the destination bin for which to set
  ///                      depth.
  /// \param  pc_index     The index of the path controller for whose distant
  ///                      nbr this method is setting queue depth.
  /// \param  num_bytes    The number of bytes to set as queue depth.
  /// \param  for_virtual  True for virtual queue depths, false otherwise.
  void SetQueueDepth(iron::BinIndex dst_bidx, int8_t pc_index,
    uint32_t num_bytes, bool for_virtual = false);

  /// \brief Get my virtual queue depth for a given bin id.
  ///
  /// \param  bin_id  The bin id for which to get my virtual queue.
  ///
  /// \return My virtual queue depth for the bin id, in bytes.
  uint32_t  GetMyVirtualBinDepth(iron::BinIndex bin_idx);

  /// \brief Get the virtual queue depth for a neighbor, for a given bin id.
  ///
  /// \param  nbr_bin_id  The bin id of the neighbor.
  /// \param  bin_id    The bin id for which to get my virtual queue.
  ///
  /// \return My virtual queue depth for the bin id, in bytes.
  uint32_t  GetNbrVirtualBinDepth(iron::BinIndex nbr_bin_idx,
    iron::BinIndex dst_bin_idx);

  /// \brief  Increase the xmit buffer of a particular path controller to a
  ///         given number of bytes.
  ///
  /// \param  path_ctrl_idx The index of the path controller.
  /// \param  num_bytes     The number of bytes we want in the buffer.
  ///
  /// \return true if success, false otherwise.
  bool IncrPathCtrlXmitBuffer(uint8_t path_ctrl_idx, uint32_t num_bytes);

  /// \brief  Get the size of the path controller xmit buffer.
  ///
  /// \param  path_ctrl_idx The index of the path controller.
  ///
  /// \return The number of bytes in the buffer.
  size_t GetPathCtrlXmitBuffer(uint8_t path_ctrl_idx);

  /// \brief  Get the queue depth for latency sensitive or normal zombies.
  ///
  /// This function is defined here simply because it's something the tests
  /// need to access quite often, so defining it saves the trouble of
  /// repeating a complicated queue depths call from all over the unit
  /// tests. We used to have a GetZombieDepthBytes function in BinQueueMgr, but
  /// that is very inprecise about which zombie types should be included and
  /// is never used outside of the unit tests.
  ///
  /// \param  bin_idx  Bin index for which we want the depth.
  /// \param  ls       True if we want LS zombies, false for normal.
  ///
  /// \return The number of bytes of zombies.
  uint32_t GetZombieDepthBytes(iron::BinIndex bin_idx, bool ls);

  /// \brief  Get the queue depth for normal latency packets.
  ///
  /// This function is defined here simply because it's something the tests
  /// need to access quite often, so defining it saves the trouble of
  /// repeating a complicated queue depths call from all over the unit
  /// tests. We used to have a GetNonZombieDepthBytes function in BinQueueMgr,
  /// but that is very inprecise about which types should be included and
  /// is never used outside of the unit tests.
  ///
  /// \param  binid    Bin for which we want the depth.
  ///
  /// \return The number of bytes of normal latency packets in the queue.
  uint32_t GetNormalLatencyDepthBytes(iron::BinIndex bin_idx);

  // \brief Method to overwrite UpdateVirtualQueues.
  virtual void UpdateVirtQueues();

private:

  /// Disallow constructor and = operator
  BpfAlgTester(const BpfAlgTester& other);
  BpfAlgTester& operator=(const BpfAlgTester& other);

  iron::QueueStore*           queue_store_;
  iron::PacketPool&           pkt_pool_;
  iron::BinMap&               bin_map_;
  char*                       bin_map_mem_;
  vector<iron::PseudoFifo*>*  fifos_;
};

//============================================================================
BpfAlgTester::BpfAlgTester(iron::PacketPool& packet_pool, iron::BinMap& bin_map,
                           iron::Timer& timer,
                           iron::SharedMemoryIF& weight_qd_shared_memory,
                           vector<iron::PseudoFifo*>* fifos, ConfigInfo& ci)
  : BPFwder(packet_pool, timer, bin_map, weight_qd_shared_memory,
            BPF_FIFO_ARGS(fifos), ci),
    UberFwdAlg(*this, packet_pool, bin_map, BPFwder::queue_store_,
               BPFwder::packet_history_mgr_,
               BPFwder::num_path_ctrls_, BPFwder::path_ctrls_),
    queue_store_(BPFwder::queue_store_),
    pkt_pool_(packet_pool),
    bin_map_(bin_map),
    fifos_(fifos)
{ }

//============================================================================
BpfAlgTester::~BpfAlgTester()
{
  iron::PseudoFifo::DeleteBpfFifos(fifos_);
}

//============================================================================
void BpfAlgTester::InitForTest(iron::ConfigInfo& ci)
{
  CPPUNIT_ASSERT(BPFwder::Initialize());
  UberFwdAlg::queue_store_  = BPFwder::queue_store_;
  UberFwdAlg::Initialize(ci);
  UberFwdAlg::packet_history_mgr_ = BPFwder::packet_history_mgr_;
  bpf_fwd_alg_->set_xmit_buf_max_thresh(3000);

  iron::BinIndex bidx_2 = bin_map_.GetPhyBinIndex(2);
  iron::BinIndex bidx_3 = bin_map_.GetPhyBinIndex(3);
  iron::BinIndex bidx_4 = bin_map_.GetPhyBinIndex(4);

  // Reverse the list so as to possibly exercise destination not recognized
  // later.
  for (ssize_t i = (BPFwder::num_path_ctrls_ - 1); i >= 0; --i)
  {
    PathController*  pctl = BPFwder::path_ctrls_[i].path_ctrl;

    if (pctl == NULL)
    {
      continue;
    }

    if (pctl->path_controller_number() == 0)
    {
      pctl->set_remote_bin_id_idx(2, bidx_2); // 10.1.2.100
    }
    else if (pctl->path_controller_number() == 1)
    {
      pctl->set_remote_bin_id_idx(3, bidx_3); // 10.1.3.100
    }
    else if (pctl->path_controller_number() == 2)
    {
      pctl->set_remote_bin_id_idx(4, bidx_4); // 10.1.4.100
    }
  }

  bpf_fwd_alg_->set_hysteresis(10);
}

//============================================================================
iron::BinQueueMgr* BpfAlgTester::GetBinQueueMgr(iron::BinIndex bidx)
{
  return BPFwder::queue_store_->GetBinQueueMgr(bidx);
}

//============================================================================
void BpfAlgTester::CallPreseedVirtQueues(iron::ConfigInfo& ci)
{
  BPFwder::PreseedVirtQueues(ci);
}

//============================================================================
void BpfAlgTester::SetPcLatencies(iron::BinIndex node_idx, uint32_t* latency_us,
                                  uint8_t num_nbrs)
{
  NodeRecord* node_record = AccessOrAllocateNodeRecord(node_idx);

  for (uint8_t nbr_index = 0; nbr_index < num_nbrs; ++nbr_index)
  {
    node_record->records_[nbr_index].nbr_lat_mean_ = latency_us[nbr_index];

    if (my_bin_idx_ == node_idx)
    {
      LogD(kClassName, __func__,
           "Setting pc latencies for self, must update path ctrl info %" PRIu8 
           " to %" PRIu32 ".\n",
           nbr_index + 1, latency_us[nbr_index]);
      // The path controller number is the nbr index + 1.
      BPFwder::path_ctrls_[nbr_index].pdd_mean_sec =
        latency_us[nbr_index+1] / 1e6;
    }
  }

  // Reset cache.
  ClearLatencyCache();
  PrintNodeRecords();
}

//============================================================================
bool BpfAlgTester::CallGetMinLatency(uint32_t* latency_us, size_t num_latencies,
                                 size_t& min_path_ctrl_index,
                                 iron::Time& min_ttr)
{
  return this->bpf_fwd_alg_->GetMinLatencyPath(latency_us, num_latencies,
    min_path_ctrl_index, min_ttr);
}

//============================================================================
bool BpfAlgTester::CallIsHistoryConstrained(iron::Packet* pkt, iron::Time& ttg,
                                            uint32_t* latencies_us,
                                            size_t num_latencies)
{
  return UberFwdAlg::IsHistoryConstrained(pkt, ttg, latencies_us,
    num_latencies);
}

//============================================================================
bool BpfAlgTester::CallFindUcastPacketsForGradient(
  const iron::Gradient& gradient,
  iron::LatencyClass& ttype, iron::Time& method_start, bool consider_latency,
  OrderedList<TransmitCandidate, iron::Time>& candidates,
  uint32_t max_bytes)
{
  return UberFwdAlg::FindUcastPacketsForGradient(gradient, ttype, method_start,
    consider_latency, candidates, max_bytes);
}

//============================================================================
void BpfAlgTester::SetQueueDepth(iron::BinIndex dst_bidx, int8_t pc_index,
  uint32_t num_bytes, bool for_virtual)
{
  iron::BinIndex  nbr_bidx  = iron::kInvalidBinIndex;

  if (pc_index >= 0)
  {
    PathController*  pctl = BPFwder::path_ctrls_[pc_index].path_ctrl;
    CPPUNIT_ASSERT(pctl);

    nbr_bidx  = pctl->remote_bin_idx();
  }

  iron::QueueDepths*  queue_depths  = NULL;
  bool                local_alloc   = false;

  if (nbr_bidx == iron::kInvalidBinIndex)
  {
    // Get local queue depths to dst_bidx group.
    if (!for_virtual)
    {
      // Get local queue depths to dst_bidx group.
      queue_depths  = BPFwder::queue_store_->GetQueueDepthsForBpf(dst_bidx);
    }
    else
    {
      // Get local virtual queue depths to dst_bidx group.
      queue_depths  = BPFwder::queue_store_->GetVirtQueueDepths();
    }
  }
  else
  {
    // Get nbr queue depths to dst_bidx group.
    if (!for_virtual)
    {
      queue_depths  = BPFwder::queue_store_->PeekNbrQueueDepths(dst_bidx,
        nbr_bidx);
    }
    else
    {
      // Get nbr virtual queue depths to dst_bidx group.
      queue_depths  = BPFwder::queue_store_->PeekNbrVirtQueueDepths(nbr_bidx);
      if (!queue_depths)
      {
        queue_depths  = new (std::nothrow) iron::QueueDepths(bin_map_);
        local_alloc   = true;
      }
    }
  }

  CPPUNIT_ASSERT(queue_depths);
  queue_depths->SetBinDepthByIdx(dst_bidx, num_bytes);

  if (local_alloc)
  {
    delete queue_depths;
    queue_depths = NULL;
  }
}

//============================================================================
bool BpfAlgTester::CallFindNextTransmission(iron::TxSolution* solutions,
                                            uint8_t& num_solutions)
{
  solutions[0].bin_idx          = 0;
  solutions[0].path_ctrl_index  = 0;

  num_solutions                 =
    bpf_fwd_alg_->FindNextTransmission(solutions, num_solutions);

  return num_solutions > 0;
}

//============================================================================
// Override function so the FIFOs are not intialized for tests.
bool BpfAlgTester::InitializeFifos()
{
  return true;
}

//============================================================================
// Override function so the VirtQueues are not intialized for tests.
void BpfAlgTester::UpdateVirtQueues()
{
  return;
}

//============================================================================
size_t BpfAlgTester::GetPathCtrlXmitBuffer(uint8_t path_ctrl_index)
{
  iron::PathController* pctl  = BPFwder::path_ctrls_[path_ctrl_index].path_ctrl;

  if (!pctl)
  {
    return 0;
  }
  size_t  xmit_queue_size = 0;
  pctl->GetXmitQueueSize(xmit_queue_size);
  LogD(kClassName, __func__,
       "Path Ctrl %" PRIu8 " to %" PRIBinId " has %zuB.\n",
       path_ctrl_index, pctl->remote_bin_id(), xmit_queue_size);
  return xmit_queue_size;
}

//============================================================================
uint32_t BpfAlgTester::GetMyVirtualBinDepth(iron::BinIndex bin_idx)
{
  return BPFwder::queue_store_->GetVirtQueueDepths()->GetBinDepthByIdx(bin_idx);
}

//============================================================================
uint32_t BpfAlgTester::GetNbrVirtualBinDepth(iron::BinIndex nbr_bin_idx,
  iron::BinIndex dst_bin_idx)
{
  for (size_t i = 0; i < BPFwder::num_path_ctrls_; ++i)
  {
    iron::PathController* pctl = BPFwder::path_ctrls_[i].path_ctrl;

    if (pctl == NULL)
    {
      continue;
    }

    if (!pctl->ready())
    {
      continue;
    }

    iron::QueueDepths*  nbr_queue_depths =
      BPFwder::queue_store_->PeekNbrVirtQueueDepths(nbr_bin_idx);

    if (nbr_queue_depths)
    {
      return nbr_queue_depths->GetBinDepthByIdx(dst_bin_idx);
    }
  }
  return 0;
}

//============================================================================
bool BpfAlgTester::IncrPathCtrlXmitBuffer(uint8_t path_ctrl_index,
                                         uint32_t num_bytes)
{
  iron::PathController* pctl  = BPFwder::path_ctrls_[path_ctrl_index].path_ctrl;

  if (!pctl)
  {
    return false;
  }
  size_t  xmit_queue_size = 0;
  pctl->GetXmitQueueSize(xmit_queue_size);
  LogD(kClassName, __func__,
       "Before setting, path ctrl %" PRIu8 " is %zdB.\n",
       path_ctrl_index, xmit_queue_size);

  size_t pkt_size = 2000;
  while (xmit_queue_size < num_bytes && pkt_size > 0)
  {
    while (num_bytes - xmit_queue_size >= pkt_size)
    {
      iron::Packet* p = pkt_pool_.Get(PACKET_NOW_TIMESTAMP);
      p->InitIpPacket();
      p->SetLengthInBytes(pkt_size);

      CPPUNIT_ASSERT(pctl->SendPacket(p));
      pctl->GetXmitQueueSize(xmit_queue_size);
      LogD(kClassName, __func__,
           "After adding %zd bytes, path ctrl %" PRIu8 " is %zdB.\n",
           pkt_size, path_ctrl_index, xmit_queue_size);
    }
    pkt_size = pkt_size / 2;
  }

  pctl->GetXmitQueueSize(xmit_queue_size);
  LogD(kClassName, __func__,
       "Set path ctrl %" PRIu8 " to %zdB.\n",
       path_ctrl_index, xmit_queue_size);
  return (xmit_queue_size == num_bytes);
}

//============================================================================
uint32_t BpfAlgTester::GetZombieDepthBytes(iron::BinIndex bin_idx, bool ls)
{
  iron::BinQueueMgr* q_mgr = GetBinQueueMgr(bin_idx);
  CPPUNIT_ASSERT(q_mgr);

  if (ls)
  {
    iron::LatencyClass  ttype_to_get[]  = {iron::HIGH_LATENCY_EXP,
      iron::HIGH_LATENCY_ZLR_LS};
    return q_mgr->GetTtypeDepthBytes(bin_idx, ttype_to_get, 2);
  }
  else
  {
    iron::LatencyClass  ttype_to_get[]  = {iron::HIGH_LATENCY_RCVD,
      iron::HIGH_LATENCY_NPLB, iron::HIGH_LATENCY_ZLR};
    return q_mgr->GetTtypeDepthBytes(bin_idx, ttype_to_get, 2);
  }

}

//============================================================================
uint32_t BpfAlgTester::GetNormalLatencyDepthBytes(iron::BinIndex bin_idx)
{
  iron::BinQueueMgr* q_mgr = GetBinQueueMgr(bin_idx);
  CPPUNIT_ASSERT(q_mgr);

  iron::LatencyClass  ttype_to_get[]  = {iron::NORMAL_LATENCY};

  return q_mgr->GetTtypeDepthBytes(bin_idx, ttype_to_get, 1);
}

class BPFAlgTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(BPFAlgTest);

  CPPUNIT_TEST(TestPreseedVirtualGradient);
  CPPUNIT_TEST(TestGetMinLatencyPath);
  CPPUNIT_TEST(TestIsHistoryConstrained);
  CPPUNIT_TEST(TestFindPacketsForGradient);
  CPPUNIT_TEST(TestZombification);
  CPPUNIT_TEST(TestCriticalization);
  CPPUNIT_TEST(TestBase);
  CPPUNIT_TEST(TestHeuristicLatencyAware);
  CPPUNIT_TEST(TestConditionalLatencyAware);
  CPPUNIT_TEST(TestZombieQueueProcessing);
  CPPUNIT_TEST(TestZombieQueueProcessingMultiDequeue);

  CPPUNIT_TEST_SUITE_END();

private:

  BpfAlgTester*         bpfwder_;
  iron::PacketPoolHeap* pkt_pool_;
  iron::BinMap*         bin_map_;
  char*                 bin_map_mem_;
  iron::Timer*          timer_;
  iron::SharedMemoryIF* weight_qd_shared_memory_;
  struct iphdr          ip_hdr_;
  ConfigInfo            config_info_;

public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");

    timer_ = new (std::nothrow) iron::Timer();
    CPPUNIT_ASSERT(timer_);

    // Prepare the ConfigInfo object for the test.
    config_info_.Reset();

    iron::PortNumberMgr&  port_mgr = iron::PortNumberMgr::GetInstance();
    string                ep_str;

    // Add bin map configuration.
    config_info_.Add("BinMap.BinIds", "1,2,3,4");
    config_info_.Add("BinMap.BinId.1.HostMasks", "10.1.1.0/24");
    config_info_.Add("BinMap.BinId.2.HostMasks", "10.1.2.0/24");
    config_info_.Add("BinMap.BinId.3.HostMasks", "10.1.3.0/24");
    config_info_.Add("BinMap.BinId.4.HostMasks", "10.1.4.0/24");

    config_info_.Add("Bpf.SendGrams", "false");

    // Add backpressure forwarder configuration.
    config_info_.Add("Bpf.BinId", "1");
    config_info_.Add("Bpf.Alg.Fwder", "LatencyAware");
    config_info_.Add("Bpf.Alg.AntiCirculation", "HeuristicDAG");
    config_info_.Add("Bpf.Alg.QueueSearchDepth", "5000");
    config_info_.Add("Bpf.Alg.MultiDeq", "false");
    config_info_.Add("Bpf.Alg.EFOrdering", "Ttg");
    config_info_.Add("LinkStateLatency", "true");

    // Add Path Controller configuration.
    config_info_.Add("Bpf.NumPathControllers", "3");

    ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() + "->127.0.0.1:20010";
    config_info_.Add("PathController.0.Type", "Sond");
    config_info_.Add("PathController.0.Endpoints", ep_str);
    config_info_.Add("PathController.0.MaxLineRateKbps", "0");

    ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() + "->127.0.0.1:20011";
    config_info_.Add("PathController.1.Type", "Sond");
    config_info_.Add("PathController.1.Endpoints", ep_str);
    config_info_.Add("PathController.1.MaxLineRateKbps", "0");

    ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() + "->127.0.0.1:20012";
    config_info_.Add("PathController.2.Type", "Sond");
    config_info_.Add("PathController.2.Endpoints", ep_str);
    config_info_.Add("PathController.2.MaxLineRateKbps", "0");

    config_info_.Add("Bpf.Weight.SemKey", "1");
    config_info_.Add("Bpf.Weight.ShmName", "weights_");

    config_info_.Add("Bpf.XmitQueueThreshBytes", "3000");
    config_info_.Add("Bpf.XmitBufFreeThreshBytes", "3000");

    config_info_.Add("Bpf.QueueDelayWeight", "0");

    // Create and initialize the BinMap.
    bin_map_mem_       = new char[sizeof(iron::BinMap)];
    bin_map_           = reinterpret_cast<iron::BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(iron::BinMap));
    CPPUNIT_ASSERT(bin_map_);
    CPPUNIT_ASSERT(bin_map_->Initialize(config_info_));

    weight_qd_shared_memory_  = new (std::nothrow) iron::PseudoSharedMemory();
    CPPUNIT_ASSERT(weight_qd_shared_memory_);

    pkt_pool_ = new (std::nothrow) iron::PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_);
    CPPUNIT_ASSERT(pkt_pool_->Create(32) == true);

    // Create the backpressure forwarder set up for testing.
    // Memory reclaimed below
    bpfwder_ = new (std::nothrow) BpfAlgTester(*pkt_pool_, *bin_map_,
                                               *timer_,
                                               *weight_qd_shared_memory_,
                                               iron::PseudoFifo::BpfFifos(),
                                               config_info_);
    CPPUNIT_ASSERT(bpfwder_);

    // Populate an IP header with some dummy values.
    ip_hdr_.version  = 4;
    ip_hdr_.ihl      = 5;
    ip_hdr_.tos      = 0;
    ip_hdr_.protocol = IPPROTO_UDP;
    ip_hdr_.check    = 0;
    ip_hdr_.saddr    = htonl(1);
    ip_hdr_.daddr    = htonl(2);
    ip_hdr_.tos      = 0;
    ip_hdr_.tot_len  = htons(sizeof(ip_hdr_));

    bpfwder_->InitForTest(config_info_);
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
    bin_map_mem_ = NULL;
    bin_map_ = NULL;

    delete timer_;
    timer_ = NULL;

    delete weight_qd_shared_memory_;
    weight_qd_shared_memory_ = NULL;

    Log::SetDefaultLevel("FE");
  }

  //==========================================================================
  void TestPreseedVirtualGradient()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    iron::BinIndex  bidx_1  = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex  bidx_2  = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex  bidx_3  = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex  bidx_4  = bin_map_->GetPhyBinIndex(4);

    config_info_.Add("Bpf.VirtQueueDepths.Multiplier", "100");
    config_info_.Add("Bpf.VirtQueueDepths.1.Hops", "2:12,3:13");
    config_info_.Add("Bpf.VirtQueueDepths.2.Hops", "1:21,3:23");
    config_info_.Add("Bpf.VirtQueueDepths.3.Hops", "1:31,2:32,4:34");
    config_info_.Add("Bpf.VirtQueueDepths.4.Hops", "2:42,4:44");
    bpfwder_->CallPreseedVirtQueues(config_info_);

    CPPUNIT_ASSERT (bpfwder_->GetMyVirtualBinDepth(bidx_1) == 0);
    CPPUNIT_ASSERT (bpfwder_->GetMyVirtualBinDepth(bidx_2) == 2100);
    CPPUNIT_ASSERT (bpfwder_->GetMyVirtualBinDepth(bidx_3) == 3100);
    CPPUNIT_ASSERT (bpfwder_->GetMyVirtualBinDepth(bidx_4) == 0);

    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_2, bidx_1) == 1200);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_3, bidx_1) == 1300);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_4, bidx_1) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_2, bidx_2) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_3, bidx_2) == 2300);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_4, bidx_2) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_2, bidx_3) == 3200);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_4, bidx_3) == 3400);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_2, bidx_4) == 4200);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_3, bidx_4) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetNbrVirtualBinDepth(bidx_4, bidx_4) == 4400);
  }

  //==========================================================================
  void TestGetMinLatencyPath()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    const size_t  num_latencies = 10;
    uint32_t      latency_us[num_latencies] = {50, 22, 100, 999999, 3, 23, 3,
                                               18, 19, 20};
    size_t        min_path_ctrl_index       = num_latencies + 1;
    iron::Time    min_ttr;
    min_ttr.SetInfinite();

    LogD(kClassName, __func__, "Testing min latency path search.\n");

    CPPUNIT_ASSERT(bpfwder_->CallGetMinLatency(latency_us, num_latencies,
      min_path_ctrl_index, min_ttr));

    CPPUNIT_ASSERT(min_path_ctrl_index == 4);
    CPPUNIT_ASSERT(min_ttr == iron::Time(0.000003));
  }

  //==========================================================================
  void TestIsHistoryConstrained()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    iron::Packet* p = pkt_pool_->Get();
    CPPUNIT_ASSERT(p);
    p->SetLengthInBytes(1500);

    iron::PacketHistoryMgr* packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 3);

    packet_history_mgr_->TrackHistory(p, false);

    delete packet_history_mgr_;

    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 2);

    packet_history_mgr_->TrackHistory(p, false);

    delete packet_history_mgr_;

    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 1);

    packet_history_mgr_->TrackHistory(p, false);

    delete packet_history_mgr_;

    uint32_t    latencies_us[4] = {5, 5, 5, 5};
    iron::Time  ttg             = iron::Time(1.0);
    CPPUNIT_ASSERT(!bpfwder_->CallIsHistoryConstrained(p, ttg,
      (uint32_t*)latencies_us, 4));

    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 4);

    packet_history_mgr_->TrackHistory(p, false);

    delete packet_history_mgr_;

    CPPUNIT_ASSERT(bpfwder_->CallIsHistoryConstrained(p, ttg,
      (uint32_t*)latencies_us, 4));

    pkt_pool_->Recycle(p);
  }

  //==========================================================================
  void TestZombification()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex bidx_4 = bin_map_->GetPhyBinIndex(4);

    // Create two packets in EF queue.  One will eventually not be able to make
    // it and turn to a Zombie.

    // Create the packet destined to become a Zombie.
    iron::Packet* zp  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(zp);
    memcpy(zp->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    zp->SetLengthInBytes(1500);

    iron::Time  ttg = iron::Time::FromMsec(500);
    zp->SetTimeToGo(ttg);
    zp->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(zp);

    // Create a second packet.
    iron::Packet* p = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p);
    memcpy(p->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p->SetLengthInBytes(1500);

    ttg = iron::Time::FromMsec(3000);
    p->SetTimeToGo(ttg);
    p->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p);

    // At first, all packets can make it.
    // Note: latency array size must be 5 due to indexing in SetPcLatencies()!
    uint32_t        latencies[5]  = {0, 10, 10, 10, 0};
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    for (uint8_t pc_index = 0; pc_index < 3; ++pc_index)
    {
      bpfwder_->SetQueueDepth(bidx_1, pc_index, 0);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, 0);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, 0);
      bpfwder_->SetQueueDepth(bidx_4, pc_index, 0);

      bpfwder_->SetQueueDepth(bidx_1, pc_index, 0, true);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, 0, true);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, 0, true);
      bpfwder_->SetQueueDepth(bidx_4, pc_index, 0, true);
    }

    iron::TxSolution  solutions[kNumSolutions];
    memset(solutions, 0, sizeof(solutions));
    uint8_t num_solutions = kNumSolutions;
    bpfwder_->CallFindNextTransmission(solutions, num_solutions);

    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, true) == 0);
    CPPUNIT_ASSERT(solutions[0].pkt == zp);

    // The FindNextTransmission would have dequeued zp, re-enqueue.
    q_mgr->Enqueue(solutions[0].pkt);

    // But latency conditions change and one packet is Zombified.
    latencies[1]  = 1000000;
    latencies[2]  = 1000000;
    latencies[3]  = 1000000;
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    num_solutions = kNumSolutions;
    bpfwder_->CallFindNextTransmission(solutions, num_solutions);

    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, true)
                   == zp->virtual_length());

    // Recycle packet that was taken out by FindNextTransmission.
    pkt_pool_->Recycle(solutions[0].pkt);
  }

  //==========================================================================
  void TestCriticalization()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex bidx_4 = bin_map_->GetPhyBinIndex(4);

    // Create two packets in EF queue.  One will eventually not be able to make
    // it and turn to a critical packet.

    // Create the packet destined to become a critical packet.
    iron::Packet* cp  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(cp);
    memcpy(cp->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    cp->SetLengthInBytes(1500);

    iron::Time  ttg = iron::Time::FromMsec(100);
    cp->SetTimeToGo(ttg);
    cp->SetIpDscp(iron::DSCP_EF);

    LogD(kClassName, __func__,
         "Packet %p is destined to be critical.\n", cp);

    iron::PacketHistoryMgr* packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 3);

    packet_history_mgr_->TrackHistory(cp, false);

    delete packet_history_mgr_;

    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 2);

    packet_history_mgr_->TrackHistory(cp, false);

    delete packet_history_mgr_;

    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 1);

    packet_history_mgr_->TrackHistory(cp, false);

    delete packet_history_mgr_;

    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 4);

    packet_history_mgr_->TrackHistory(cp, false);

    delete packet_history_mgr_;

    // Enqueue.
    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(cp);

    // Create a second packet.
    iron::Packet* p = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p);
    memcpy(p->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p->SetLengthInBytes(1500);

    LogD(kClassName, __func__,
         "Packet %p has not visited any neighbor.\n", p);

    ttg = iron::Time::FromMsec(100);
    p->SetTimeToGo(ttg);
    p->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p);

    // Note: latency array size must be 5 due to indexing in SetPcLatencies()!
    uint32_t  latencies[5]  = {0, 10, 10, 10, 0};
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    for (uint8_t pc_index = 0; pc_index < 3; ++pc_index)
    {
      bpfwder_->SetQueueDepth(bidx_1, pc_index, 0);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, 0);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, 0);
      bpfwder_->SetQueueDepth(bidx_4, pc_index, 0);
    }

    // There is no criticalization in non-heuristic dag algs.
    config_info_.Add("Bpf.Alg.AntiCirculation", "ConditionalDAG");
    bpfwder_->BPFwder::ResetFwdingAlg();

    iron::TxSolution  solutions[kNumSolutions];
    memset(solutions, 0, sizeof(solutions));
    uint8_t num_solutions = kNumSolutions;
    bpfwder_->CallFindNextTransmission(solutions, num_solutions);

    // Peek(3, iron::CRITICAL_LATENCY);
    CPPUNIT_ASSERT(!q_mgr->Peek(iron::CRITICAL_LATENCY));

    q_mgr->Enqueue(solutions[0].pkt);

    // However, in heuristic dag alg, packet would be history-constrained.
    config_info_.Add("Bpf.Alg.AntiCirculation", "HeuristicDAG");
    bpfwder_->BPFwder::ResetFwdingAlg();

    latencies[1]  = 550000;
    latencies[2]  = 100;
    latencies[3]  = 550000;
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    CPPUNIT_ASSERT(bpfwder_->IncrPathCtrlXmitBuffer(1, 3000));

    cp->SetTimeToGo(ttg);

    num_solutions = kNumSolutions;
    bpfwder_->CallFindNextTransmission(solutions, num_solutions);
    // cp should now be critical.

    // Peek(3, iron::CRITICAL_LATENCY);
    CPPUNIT_ASSERT(cp == q_mgr->Peek(iron::CRITICAL_LATENCY));
  }

  //==========================================================================
  void TestFindPacketsForGradient()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);

    iron::Gradient  gradient;

    gradient.value            = 4000;
    gradient.bin_idx          = bidx_3;
    gradient.path_ctrl_index  = 1;
    gradient.is_dst           = false;

    iron::LatencyClass  ttype = iron::LOW_LATENCY;

    iron::Time          now   = iron::Time::Now();

    OrderedList<UberFwdAlg::TransmitCandidate, iron::Time>
      candidates(iron::LIST_INCREASING);

    int32_t max_bytes = 10000;

    LogD(kClassName, __func__,
         "** Test single packet, no latency consideration. **\n");
    // Create a packet.
    iron::Packet* p0  = pkt_pool_->Get();
    CPPUNIT_ASSERT(p0);
    memcpy(p0->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p0->SetLengthInBytes(1500);

    iron::Time  ttg = iron::Time::FromMsec(500);
    p0->SetTimeToGo(ttg);
    p0->SetOrderTime(ttg);
    p0->set_recv_time(now);
    p0->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(p0);

    // Set path latencies to be very large.
    // Note: latency array size must be 5 due to indexing in SetPcLatencies()!
    uint32_t  latencies[5]  = {0, 10000000, 10000000, 10000000, 0};
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    // We expect to find the packet if we have no latency considerations.
    // Match p0 (bin 3, ttg = 500,000us) to gradient bin 3, pc 1.
    CPPUNIT_ASSERT(bpfwder_->CallFindUcastPacketsForGradient(gradient,
      ttype, now, false, candidates, static_cast<uint32_t>(max_bytes)));

    UberFwdAlg::TransmitCandidate cand;
    CPPUNIT_ASSERT(candidates.size() == 1);
    CPPUNIT_ASSERT(candidates.Peek(cand));
    CPPUNIT_ASSERT(cand.pkt == p0);

    candidates.Clear();

    LogD(kClassName, __func__,
         "** Test 2 packets in same queue, no latency consideration. **\n");
    // Create a second packet.
    iron::Packet* p1  = pkt_pool_->Get();
    CPPUNIT_ASSERT(p1);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p1->SetLengthInBytes(1500);

    ttg = iron::Time::FromMsec(300);
    p1->SetTimeToGo(ttg);
    p1->SetOrderTime(ttg);
    p1->set_recv_time(now);
    p1->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p1);

    gradient.is_dst  = true;

    // We expect to find the first packet only: both are completely equivalent,
    // but removing latency considerations lets us stop at the first.  The
    // packet in candidates is first replaced by itself now that the gradient
    // is indicating path ctrl to dst.  Then second packet added because the
    // two are equivalent.
    // Match p0 (bin 3, ttg = 500,000us), p1 (bin 3, ttg = 300,000us) to gradient
    // bin 3, pc 1.
    CPPUNIT_ASSERT(bpfwder_->CallFindUcastPacketsForGradient(gradient,
      ttype, now, false, candidates, static_cast<uint32_t>(max_bytes)));

    CPPUNIT_ASSERT(candidates.size() == 2);


    candidates.Clear();

    LogD(kClassName, __func__,
         "** Test 2 packets with latency consideration, no viable path. **\n");
    // We expect to find no packet: all latencies inifinity.
    CPPUNIT_ASSERT(!bpfwder_->CallFindUcastPacketsForGradient(gradient,
      ttype, now, true, candidates, static_cast<uint32_t>(max_bytes)));

    CPPUNIT_ASSERT(candidates.size() == 0);

    candidates.Clear();

    LogD(kClassName, __func__,
         "** Test 2 packets with latency consideration, one viable path. **\n");
    latencies[0]  = 0;
    latencies[1]  = 10;
    latencies[2]  = 10;
    latencies[3]  = 10;
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    // We expect to find one packet.
    // Match p0 (bin 3, ttg = 500,000us), p1 (bin 3, ttg = 300,000) to gradient
    // bin 3, pc 1.
    CPPUNIT_ASSERT(bpfwder_->CallFindUcastPacketsForGradient(gradient,
      ttype, now, true, candidates, static_cast<uint32_t>(max_bytes)));

    CPPUNIT_ASSERT(candidates.size() == 2);
    CPPUNIT_ASSERT(candidates.Peek(cand));
    CPPUNIT_ASSERT(cand.pkt == p1);

    LogD(kClassName, __func__,
         "** Test 3 packets, 2 with equivalent ttg, two viable path. **\n");
    // Create a third packet.
    iron::Packet* p2  = pkt_pool_->Get();
    CPPUNIT_ASSERT(p2);
    memcpy(p2->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p2->SetLengthInBytes(1500);

    ttg = iron::Time::FromMsec(300);
    p2->SetTimeToGo(ttg);
    p2->SetOrderTime(ttg);
    p2->set_recv_time(now);
    p2->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_2);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(p2);
    candidates.Clear();

    gradient.bin_idx          = bidx_2;
    gradient.path_ctrl_index  = 0;

    // There are two packets with the same ttg (although different dst bins).
    // Match p0 (bin 3, ttg = 500,000us), p1 (bin 3, ttg = 300,000) and p2 (bin
    // 2, ttg 300,000us) to gradients (bin 3, pc 1), (bin 2, pc 0).
    CPPUNIT_ASSERT(bpfwder_->CallFindUcastPacketsForGradient(gradient,
      ttype, now, true, candidates, static_cast<uint32_t>(max_bytes)));

    CPPUNIT_ASSERT(candidates.size() == 1);

    candidates.Clear();

    LogD(kClassName, __func__,
         "** Test 3 packets, 1 with lowest ttg, two viable path. **\n");
    // p2 now has very low ttg: it should be selected.
    p2->SetTimeToGo(iron::Time::FromMsec(100));
    p2->SetOrderTime(ttg);

    // There are two packets with the same ttg (although different dst bins).
    // Match p0 (bin 3, ttg = 500,000us), p1 (bin 3, ttg = 300,000) and p2 (bin
    // 2, ttg 300,000us) to gradient (bin 2, pc 0).
    CPPUNIT_ASSERT(bpfwder_->CallFindUcastPacketsForGradient(gradient,
      ttype, now, true, candidates, static_cast<uint32_t>(max_bytes)));

    CPPUNIT_ASSERT(candidates.size() == 1);
    CPPUNIT_ASSERT(candidates.Peek(cand));
    CPPUNIT_ASSERT(cand.pkt == p2);

    candidates.Clear();

    LogD(kClassName, __func__,
         "** Test 3 packets, 2 to dst bin, one with history-block. **\n");

    gradient.bin_idx          = bidx_3;
    gradient.path_ctrl_index  = 1;

    // p0 has visited bin 3.  Will not be eligible to be sent.
    iron::PacketHistoryMgr* packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 3);

    packet_history_mgr_->TrackHistory(p0, false);

    delete packet_history_mgr_;

    CPPUNIT_ASSERT(bpfwder_->CallFindUcastPacketsForGradient(gradient,
      ttype, now, true, candidates, static_cast<uint32_t>(max_bytes)));

    CPPUNIT_ASSERT(candidates.size() == 1);
    CPPUNIT_ASSERT(candidates.Peek(cand));
    CPPUNIT_ASSERT(cand.pkt == p1);
  }

  //==========================================================================
  void TestBase()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    config_info_.Add("Bpf.Alg.Fwder", "Base");
    bpfwder_->BPFwder::ResetFwdingAlg();

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex bidx_4 = bin_map_->GetPhyBinIndex(4);

    for (uint8_t pc_index = 0; pc_index < 3; ++pc_index)
    {
      // Set neighbor queue depths to create a gradient gap for multiple
      // dequeues.
      uint16_t  queue_depth = 1500;

      if (pc_index == 1)
      {
        queue_depth = 0;
      }

      bpfwder_->SetQueueDepth(bidx_1, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_4, pc_index, queue_depth);
      // PC0: Bin 1: 1,500B
      // PC0: Bin 2: 1,500B
      // PC0: Bin 3: 1,500B
      // PC0: Bin 4: 1,500B
      // PC1: Bin 1: 0B
      // PC1: Bin 2: 0B
      // PC1: Bin 3: 0B
      // PC1: Bin 4: 0B
      // PC2: Bin 1: 1,500B
      // PC2: Bin 2: 1,500B
      // PC2: Bin 3: 1,500B
      // PC2: Bin 4: 1,500B

      bpfwder_->SetQueueDepth(bidx_1, pc_index, queue_depth, true);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, queue_depth, true);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, queue_depth, true);
      bpfwder_->SetQueueDepth(bidx_4, pc_index, queue_depth, true);
    }

    // Set path latencies to 100ms.
    // Note: latency array size must be 5 due to indexing in SetPcLatencies()!
    uint32_t  latencies[5]  = {0, 100000, 100000, 100000, 0};
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    // Create the packet destined to bin 3.
    iron::Packet* p0  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p0);
    memcpy(p0->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p0->SetLengthInBytes(1500);

    // p0 has ttg 50ms.
    iron::Time  ttg = iron::Time::FromMsec(50);
    p0->SetTimeToGo(ttg);
    p0->SetOrderTime(ttg);
    p0->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(p0);
    // Bin 3: EF 50ms, 1,500B, p0 (1,500B)

    iron::TxSolution  solutions[kNumSolutions];
    memset(solutions, 0, sizeof(solutions));
    uint8_t num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 1));

    p0->SetTimeToGo(ttg);
    p0->SetOrderTime(ttg);
    p0->SetIpDscp(iron::DSCP_EF);
    q_mgr->Enqueue(solutions[0].pkt);
    // Bin 3: 1,500B, p0 (1,500B)

    // Create the packet destined to bin 2.
    iron::Packet* p1  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p1);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p1->SetLengthInBytes(2000);

    ttg.SetInfinite();
    p1->SetTimeToGo(ttg);
    p1->SetOrderTime(ttg);
    p1->SetIpDscp(iron::DSCP_DEFAULT);

    // Enqueue.
    q_mgr->Enqueue(p1);
    // Bin 3: 3,500B, p0 (1,500B), p1 (2,000B)

    latencies[2]  = 10000;
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 1));

    q_mgr->Enqueue(solutions[0].pkt);
    // Bin 3: 3,500B, p0 (1,500B), p1 (2,000B)

    // Create the packet destined to bin 2.
    iron::Packet* p2  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p2);
    memcpy(p2->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p2->SetLengthInBytes(2000);

    ttg.SetInfinite();
    p2->SetTimeToGo(ttg);
    p2->SetOrderTime(ttg);
    p2->SetIpDscp(iron::DSCP_DEFAULT);

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_2);
    q_mgr->Enqueue(p2);
    // Bin 2: 2,000B, p2 (2,000B)
    // Bin 3: 3,500B, p0 (1,500B), p1 (2,000B)

    num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p1) &&
      (solutions[0].path_ctrl_index == 1));

    pkt_pool_->Recycle(solutions[0].pkt);
    // Bin 2: 2,000B, p2 (2,000B)
    // Bin 3: 3,500B, p0 (1,500B)

    num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p2) &&
      (solutions[0].path_ctrl_index == 0));

    pkt_pool_->Recycle(solutions[0].pkt);
    // Bin 2: 0B
    // Bin 3: 3,500B, p0 (1,500B)

    num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 1));

    pkt_pool_->Recycle(solutions[0].pkt);
    // Bin 2: 0B
    // Bin 3: 0B

    //
    // Test Multi-Dequeues.
    //
    config_info_.Add("Bpf.Alg.MultiDeq", "true");
    bpfwder_->BPFwder::ResetFwdingAlg();

    // Create a 500B packet destined to bin 3.
    iron::Packet* p10  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p10);
    memcpy(p10->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p10->SetLengthInBytes(500);

    // p10 has ttg 50ms.
    ttg = iron::Time::FromMsec(50);
    p10->SetTimeToGo(ttg);
    p10->SetOrderTime(ttg);
    p10->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    q_mgr->Enqueue(p10);
    // Bin 2: 0B
    // Bin 3: 500B, p10 (500B)

    // Create a 500B packet destined to bin 3.
    iron::Packet* p11  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p11);
    memcpy(p11->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p11->SetLengthInBytes(500);

    // p11 has ttg 50ms.
    ttg = iron::Time::FromMsec(50);
    p11->SetTimeToGo(ttg);
    p11->SetOrderTime(ttg);
    p11->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p11);
    // Bin 2: 0B
    // Bin 3: 1,000B, p10 (500B), p11 (500B)

    // Create a 500B packet destined to bin 3.
    iron::Packet* p12  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p12);
    memcpy(p12->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p12->SetLengthInBytes(500);

    // p12 has ttg 50ms.
    ttg = iron::Time::FromMsec(50);
    p12->SetTimeToGo(ttg);
    p12->SetOrderTime(ttg);
    p12->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p12);
    // Bin 2: 0B
    // Bin 3: 1,500B, p10 (500B), p11 (500B), p12 (500B)

    num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT(num_solutions == 3);
    CPPUNIT_ASSERT((solutions[0].pkt->GetLengthInBytes() == 500) &&
      (solutions[1].pkt->GetLengthInBytes() == 500) &&
      (solutions[2].pkt->GetLengthInBytes() == 500));

    q_mgr->Enqueue(p10);
    q_mgr->Enqueue(p11);
    q_mgr->Enqueue(p12);
    // Bin 2: 0B
    // Bin 3: 1,500B, p10 (500B), p11 (500B), p12 (500B)

    // Create a 800B packet destined to bin 4.
    iron::Packet* p13  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p13);
    memcpy(p13->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p13->SetLengthInBytes(800);

    // p13 has ttg 50ms.
    ttg = iron::Time::FromMsec(50);
    p13->SetTimeToGo(ttg);
    p13->SetOrderTime(ttg);
    p13->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    q_mgr->Enqueue(p13);
    // Bin 2: 0B
    // Bin 3: 1,500B, p10 (500B), p11 (500B), p12 (500B)
    // Bin 4: 800B, p13 (800B)

    num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT(num_solutions == 3);
    CPPUNIT_ASSERT((solutions[0].pkt->GetLengthInBytes() == 500) &&
      (solutions[1].pkt->GetLengthInBytes() == 500) &&
      (solutions[2].pkt->GetLengthInBytes() == 500));

    pkt_pool_->Recycle(solutions[0].pkt);
    pkt_pool_->Recycle(solutions[1].pkt);
    pkt_pool_->Recycle(solutions[2].pkt);
    // Bin 2: 0B
    // Bin 4: 800B, p13 (800B)

    num_solutions = kNumSolutions;

    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT(num_solutions == 1);
    CPPUNIT_ASSERT(solutions[0].pkt->GetLengthInBytes() == 800);

    pkt_pool_->Recycle(solutions[0].pkt);

    num_solutions = kNumSolutions;
    // Bin 2: 0B
    // Bin 4: 800B, p13 (800B)

    CPPUNIT_ASSERT(!bpfwder_->CallFindNextTransmission(solutions, num_solutions));
  }

  //==========================================================================
  void TestHeuristicLatencyAware()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex bidx_4 = bin_map_->GetPhyBinIndex(4);

    for (uint8_t pc_index = 0; pc_index < 3; ++pc_index)
    {
      // Set neighbor queue depths to create a gradient gap for multiple
      // dequeues.
      uint16_t  queue_depth = 500;

      if (pc_index == 1)
      {
        queue_depth = 0;
      }

      bpfwder_->SetQueueDepth(bidx_1, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_4, pc_index, queue_depth);
    }
    // PC0: Bin 1: 500B
    // PC0: Bin 2: 500B
    // PC0: Bin 3: 500B
    // PC0: Bin 4: 500B
    // PC1: Bin 1: 0B
    // PC1: Bin 2: 0B
    // PC1: Bin 3: 0B
    // PC1: Bin 4: 0B
    // PC2: Bin 1: 500B
    // PC2: Bin 2: 500B
    // PC2: Bin 3: 500B
    // PC2: Bin 4: 500B

    // Create a latency-insensitive packet destined to bin 3.
    iron::Packet* p0  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p0);
    memcpy(p0->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p0->SetLengthInBytes(1500);

    // p0 has infinite ttg.
    iron::Time  ttg;
    ttg.SetInfinite();
    p0->SetTimeToGo(ttg);
    p0->SetOrderTime(ttg);
    p0->SetIpDscp(iron::DSCP_DEFAULT);
    p0->set_dst_vec(0);

    // Enqueue.
    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(p0);
    // Bin 3:
    //  p0  non-EF, 1,500B

    // Set path latencies to 100ms.
    // Note: latency array size must be 5 due to indexing in SetPcLatencies()!
    uint32_t  latencies[5]  = {0, 10000, 1000000, 10000, 0};
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    latencies[0]  = 10000;
    latencies[1]  = 0;
    latencies[2]  = UINT32_MAX;
    latencies[3]  = UINT32_MAX;
    bpfwder_->SetPcLatencies(bidx_2, latencies, 4);

    latencies[0]  = 1000000;
    latencies[1]  = UINT32_MAX;
    latencies[2]  = 0;
    latencies[3]  = 10000;
    bpfwder_->SetPcLatencies(bidx_3, latencies, 4);

    latencies[0]  = 1000000;
    latencies[1]  = UINT32_MAX;
    latencies[2]  = 10000;
    latencies[3]  = 0;
    bpfwder_->SetPcLatencies(bidx_4, latencies, 4);

    iron::TxSolution  solutions[kNumSolutions];
    memset(solutions, 0, sizeof(solutions));
    uint8_t num_solutions = kNumSolutions;

    // In absence of other traffic, latency-insensitive packet is selected to
    // nbr bin 3.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 1));

    q_mgr->Enqueue(solutions[0].pkt);

    // Create a low-latency packet destined to bin 3.
    iron::Packet* p1  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p1);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p1->SetLengthInBytes(1500);

    // p1 has ttg 500ms.
    ttg = iron::Time::FromMsec(500);
    p1->SetTimeToGo(ttg);
    p1->SetOrderTime(ttg);
    p1->SetIpDscp(iron::DSCP_EF);
    p1->set_dst_vec(0);

    // Enqueue.
    q_mgr->Enqueue(p1);
    // Bin 3:
    //  p0  non-EF, 1,500B
    //  p1  EF 500ms, 1,500B

    num_solutions = kNumSolutions;

    // Low-latency traffic is selected to be nbr bin 4 (latency 20ms).
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p1) &&
      (solutions[0].path_ctrl_index == 2));

    // Mark p1 as having visited bin 4 already, leaving it no active path to
    // bin 3.
    iron::PacketHistoryMgr* packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 4);

    packet_history_mgr_->TrackHistory(p1, false);

    delete packet_history_mgr_;

    q_mgr->Enqueue(solutions[0].pkt);
    // Bin 3:
    //  p0  non-EF, 1,500B
    //  p1  EF 500ms, 1,500B

    num_solutions = kNumSolutions;

    // The low-latency packet is history-constrained, must be sent on path ctrl
    // 2.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p1) &&
      (solutions[0].path_ctrl_index == 2));

    p1->SetTimeToGo(ttg);
    p1->SetOrderTime(ttg);
    q_mgr->Enqueue(p1);

    // Create a low-latency packet destined to bin 4.
    iron::Packet* p2  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p2);
    memcpy(p2->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p2->SetLengthInBytes(1500);

    // p2 has ttg 450ms.
    ttg = iron::Time::FromMsec(450);
    p2->SetTimeToGo(ttg);
    p2->SetOrderTime(ttg);
    p2->SetIpDscp(iron::DSCP_EF);

    // Mark p2 as having visited bin 4 already (which is technically not
    // possible since bin 4 is the destination, but done for purposes of
    // testing), leaving it no active path to bin 4.
    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 4);

    packet_history_mgr_->TrackHistory(p2, false);

    delete packet_history_mgr_;

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    q_mgr->Enqueue(p2);

    num_solutions = kNumSolutions;

    // The low-latency packet is history-constrained, must be sent on path ctrl
    // 2.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p2) &&
      (solutions[0].path_ctrl_index == 2));

    p2->SetTimeToGo(ttg);
    p2->SetOrderTime(ttg);
    q_mgr->Enqueue(p2);

    // Create another low-latency packet destined to bin 3.
    iron::Packet* p3  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p3);
    memcpy(p3->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p3->SetLengthInBytes(1500);

    // p3 has ttg 300ms.
    ttg = iron::Time::FromMsec(300);
    p3->SetTimeToGo(ttg);
    p3->SetOrderTime(ttg);
    p3->SetIpDscp(iron::DSCP_EF);

    // Mark p3 as having visited bin 4 already, leaving it no active path to
    // bin 3.
    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 4);

    packet_history_mgr_->TrackHistory(p3, false);

    delete packet_history_mgr_;

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    q_mgr->Enqueue(p3);

    num_solutions = kNumSolutions;

    // The low-latency packet p3 is history-constrained, has tighest deadline,
    // must be sent on path ctrl 2.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p3) &&
      (solutions[0].path_ctrl_index == 2));

    pkt_pool_->Recycle(solutions[0].pkt);

    num_solutions = kNumSolutions;

    // The low-latency packet p2 is history-constrained, has next tightest
    // deadline, must be sent on available path ctrl 2.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p2) &&
      (solutions[0].path_ctrl_index == 2));

    pkt_pool_->Recycle(solutions[0].pkt);

    num_solutions = kNumSolutions;

    // The low-latency packet p1 is history-constrained, has next tightest
    // deadline, must be sent on available path ctrl 2.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p1) &&
      (solutions[0].path_ctrl_index == 2));

    num_solutions = kNumSolutions;

    pkt_pool_->Recycle(solutions[0].pkt);

    // The low-latency packet p0 is history-constrained, has next tightest
    // deadline, must be sent on available path ctrl 1.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 1));

    pkt_pool_->Recycle(solutions[0].pkt);

    // Create a low-latency packet destined to bin 3.
    iron::Packet* p10  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p10);
    memcpy(p10->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p10->SetLengthInBytes(1500);

    // p10 has ttg 1.2s.
    ttg = iron::Time::FromMsec(1200);
    p10->SetTimeToGo(ttg);
    p10->SetOrderTime(ttg);
    p10->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p10);

    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 4);

    packet_history_mgr_->TrackHistory(p10, false);

    delete packet_history_mgr_;

    num_solutions = kNumSolutions;

    // The low-latency packet p10 is in gradient mode, has next tightest
    // deadline, must be sent on available path ctrl 1.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p10) &&
      (solutions[0].path_ctrl_index == 1));

    q_mgr->Enqueue(p10);

    // Create a low-latency packet destined to bin 3.
    iron::Packet* p11  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p11);
    memcpy(p11->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p11->SetLengthInBytes(1500);

    // p11 has ttg 500ms.
    ttg = iron::Time::FromMsec(500);
    p11->SetTimeToGo(ttg);
    p11->SetOrderTime(ttg);
    p11->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p11);

    num_solutions = kNumSolutions;

    // The low-latency packet p11 is in gradient mode, has next tightest
    // deadline, must be sent on available path ctrl 2.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p10) &&
      (solutions[0].path_ctrl_index == 1));

    pkt_pool_->Recycle(solutions[0].pkt);

    //
    // Test Multi-Dequeues.
    //
    config_info_.Add("Bpf.Alg.MultiDeq", "true");
    bpfwder_->BPFwder::ResetFwdingAlg();

    // Create a low-latency packet destined to bin 3.
    iron::Packet* p12  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p12);
    memcpy(p12->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p12->SetLengthInBytes(1500);

    // p12 has ttg 500ms.
    ttg = iron::Time::FromMsec(600);
    p12->SetTimeToGo(ttg);
    p12->SetOrderTime(ttg);
    p12->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p12);

    num_solutions = kNumSolutions;

    // The low-latency packets p10 & p11 are in gradient mode, has next tightest
    // deadline, must be sent on available path ctrl 2.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 2) &&
      (solutions[0].pkt == p11) && (solutions[1].pkt == p12) &&
      (solutions[0].path_ctrl_index == 2));

    pkt_pool_->Recycle(solutions[0].pkt);
    pkt_pool_->Recycle(solutions[1].pkt);
  }

  //==========================================================================
  void TestConditionalLatencyAware()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    // There is no criticalization in non-heuristic dag algs.
    config_info_.Add("Bpf.Alg.AntiCirculation", "ConditionalDAG");
    bpfwder_->BPFwder::ResetFwdingAlg();

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex bidx_4 = bin_map_->GetPhyBinIndex(4);

    CPPUNIT_ASSERT(bpfwder_->GetPathCtrlXmitBuffer(0) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetPathCtrlXmitBuffer(1) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetPathCtrlXmitBuffer(2) == 0);

    CPPUNIT_ASSERT(bpfwder_->IncrPathCtrlXmitBuffer(2, 3000));

    for (uint8_t pc_index = 0; pc_index < 2; ++pc_index)
    {
      // Set neighbor queue depths to create a gradient gap for multiple
      // dequeues.
      uint32_t  queue_depth = 3000;

      if (pc_index == 1)
      {
        queue_depth = 0;
      }

      bpfwder_->SetQueueDepth(bidx_1, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, queue_depth);
    }

    iron::Time  now = iron::Time::Now();

    // Create a latency-insensitive packet destined to bin 3.
    iron::Packet* p0  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p0);
    memcpy(p0->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p0->SetLengthInBytes(1500);

    // p0 has infinite ttg.
    iron::Time  ttg;
    ttg.SetInfinite();
    p0->SetTimeToGo(ttg);
    p0->SetOrderTime(ttg);
    p0->SetIpDscp(iron::DSCP_DEFAULT);

    // Enqueue.
    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(p0);

    // Set path latencies.
    // Note: latency array size must be 5 due to indexing in SetPcLatencies()!
    uint32_t  latencies[5]  = {0, 1000000, 10000, UINT32_MAX, 0};
    bpfwder_->SetPcLatencies(bidx_1, latencies, 4);

    latencies[0]  = 1000000;
    latencies[1]  = 0;
    latencies[2]  = 12000;
    latencies[3]  = 15000;
    bpfwder_->SetPcLatencies(bidx_2, latencies, 4);

    latencies[0]  = 10000;
    latencies[1]  = 12000;
    latencies[2]  = 0;
    latencies[3]  = 15000;
    bpfwder_->SetPcLatencies(bidx_3, latencies, 4);

    latencies[0]  = UINT32_MAX;
    latencies[1]  = 15000;
    latencies[2]  = 15000;
    latencies[3]  = 0;
    bpfwder_->SetPcLatencies(bidx_4, latencies, 4);

    iron::TxSolution  solutions[kNumSolutions];
    memset(solutions, 0, sizeof(solutions));
    uint8_t num_solutions = kNumSolutions;

    // Test simple non-EF.
    // In absence of other traffic, latency-insensitive packet is selected to
    // nbr bin 2, over the first available path controller (ignoring latency).
    // Bin 3:
    // Bin 4:
    //    p0 non-EF, 1500B
    LogD(kClassName, __func__, "Simple non-EF test.\n");
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 0));

    iron::PacketHistoryMgr* packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 2);

    packet_history_mgr_->TrackHistory(p0, false);

    delete packet_history_mgr_;

    q_mgr->Enqueue(solutions[0].pkt);

    num_solutions = kNumSolutions;

    // Test non-EF with some history constraints.
    // In absence of other traffic, latency-insensitive packet is selected to
    // nbr bin 2 over the first available path controller (ignoring latency and
    // history).
    // Bin 3:
    // Bin 4:
    //    p0 non-EF, 1500B
    LogD(kClassName, __func__, "Non-EF with history constraints test.\n");
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 0));

    q_mgr->Enqueue(p0);

    // Test simple EF.
    // Create a latency-insensitive packet destined to bin 4, demonstrate use
    // of possible route.
    LogD(kClassName, __func__, "Simple EF test.\n");
    iron::Packet* p1  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p1);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p1->SetLengthInBytes(1500);

    // p1 has ttg 900ms.
    ttg = iron::Time::FromMsec(900);
    p1->SetTimeToGo(ttg);
    p1->SetOrderTime(ttg);
    p1->SetIpDscp(iron::DSCP_EF);

    q_mgr->Enqueue(p1);

    num_solutions = kNumSolutions;

    // EF p1 is selected first to go out on pc 1 can accommodate the packet.
    // Bin 3:
    // Bin 4:
    //    p0 non-EF, 1500B
    //    p1 EF 900ms, 1500B
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p1) &&
      (solutions[0].path_ctrl_index == 1));

    // Test EF with looser deadlines.
    LogD(kClassName, __func__, "EF with looser deadlines test.\n");
    ttg = iron::Time::FromMsec(1500);
    p1->SetTimeToGo(ttg);
    p1->SetOrderTime(ttg);

#if 0 // We no longer send along fastest route because of multiple dequeues.
    q_mgr->Enqueue(4, p1);

    // EF p1 is selected first to go out on pc 1 since pc 1 is faster than pc 0.
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p1) &&
      (solutions[0].path_ctrl_index == 1));
#endif

    // Test EF with looser deadline and one fewer available path due to history.
    packet_history_mgr_ =
      new (std::nothrow) iron::PacketHistoryMgr(*bin_map_, 3);

    packet_history_mgr_->TrackHistory(p1, false);

    delete packet_history_mgr_;

    q_mgr->Enqueue(p1);

    num_solutions = kNumSolutions;

    // EF p1 is selected first to go out on pc 0 since it is available and
    // viable.
    // Bin 3:
    // Bin 4:
    //    p0 non-EF, 1500B
    //    p1 EF 1500ms, 1500B
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p1) &&
      (solutions[0].path_ctrl_index == 0));

    ttg = iron::Time::FromMsec(900);
    p1->SetTimeToGo(ttg);
    p1->SetOrderTime(ttg);
    size_t p1_len = p1->virtual_length();

    q_mgr->Enqueue(p1);

    num_solutions = kNumSolutions;

    // Test EF with no viable path.
    // EF p1 is turned into a Zombie.
    // Bin 3:
    // Bin 4:
    //    p0 non-EF, 1500B
    //    p1 EF->Zombie, 1500B
    LogD(kClassName, __func__, "EF with no viable path test.\n");
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) == 0);
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT(solutions[0].path_ctrl_index == 0);
    // Multi-dequeue is false, so we should get one zombie packet of size
    // kZombieSingleDequeueLenBytes.
    if (q_mgr->IsPktlessZQueue(iron::HIGH_LATENCY_RCVD))
    {
      CPPUNIT_ASSERT(
        solutions[0].pkt->virtual_length() == kZombieSingleDequeueLenBytes);
      CPPUNIT_ASSERT(solutions[0].pkt->GetType() == iron::ZOMBIE_PACKET);
      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) ==
                     (p1_len - kZombieSingleDequeueLenBytes));
    }
    else
    {
      CPPUNIT_ASSERT(solutions[0].pkt == p1);
      CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == 0);
    }

    iron::Packet* z0  = solutions[0].pkt;

    // Dequeued Zombies are marked with HIGH_LATENCY_RCVD, set to EXP.
    z0->MakeZombie(iron::HIGH_LATENCY_EXP);

    num_solutions = kNumSolutions;

    // Test EF with no viable path.
    // Bin 3:
    // Bin 4:
    //    p0 non-EF, 1500B
    //    p1 Zombie, 1500B - kZombieSingleDequeueLenBytes
    LogD(kClassName, __func__, "EF with no viable path test 2.\n");
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));

    CPPUNIT_ASSERT(solutions[0].path_ctrl_index == 0);
    // Multi-dequeue is false, so we should get one zombie packet of size
    // kZombieSingleDequeueLenBytes.
    if (q_mgr->IsPktlessZQueue(iron::HIGH_LATENCY_EXP))
    {
      CPPUNIT_ASSERT(solutions[0].pkt->virtual_length() == p1_len -
          kZombieSingleDequeueLenBytes);
      CPPUNIT_ASSERT(solutions[0].pkt->GetType() == iron::ZOMBIE_PACKET);
      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) == 0);
    }
    else
    {
      CPPUNIT_ASSERT(solutions[0].pkt == p1);
      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) == 0);
    }

    iron::Packet* z1  = solutions[0].pkt;

    // Dequeued Zombies are marked with HIGH_LATENCY_RCVD, set to EXP.
    z1->MakeZombie(iron::HIGH_LATENCY_EXP);

    num_solutions = kNumSolutions;

    // Test EF with no viable path.
    // Bin 3:
    // Bin 4:
    //    p0 non-EF, 1500B
    LogD(kClassName, __func__, "EF with no viable path test 3.\n");
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p0) &&
      (solutions[0].path_ctrl_index == 0));
    pkt_pool_->Recycle(solutions[0].pkt);

    // Put the Zombie(s) back in.
    q_mgr->Enqueue(z0);
    q_mgr->Enqueue(z1);

    // Test EF with various deadlines.
    LogD(kClassName, __func__, "EF with various deadlines test.\n");
    iron::Packet* p2  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p2);
    memcpy(p2->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p2->SetLengthInBytes(1500);

    // p2 has ttg 500ms.
    ttg = iron::Time::FromMsec(500);
    p2->SetTimeToGo(ttg);
    p2->SetOrderTime(ttg);
    p2->set_recv_time(now);
    p2->SetIpDscp(iron::DSCP_EF);

    q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    q_mgr->Enqueue(p2);

    // Create EF packet with 500ms deadline to go to bin 3.
    iron::Packet* p3  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p3);
    memcpy(p3->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p3->SetLengthInBytes(1500);

    // p3 has ttg 450ms.
    ttg = iron::Time::FromMsec(450);
    p3->SetTimeToGo(ttg);
    p3->SetOrderTime(ttg);
    p3->set_recv_time(now);
    p3->SetIpDscp(iron::DSCP_EF);

    q_mgr->Enqueue(p3);

    // Create EF packet with 450ms deadline to go to bin 4.
    iron::Packet* p4  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p4);
    memcpy(p4->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p4->SetLengthInBytes(1500);

    // p4 has ttg 450ms.
    ttg = iron::Time::FromMsec(450);
    p4->SetTimeToGo(ttg);
    p4->SetOrderTime(ttg);
    p4->set_recv_time(now);
    p4->SetIpDscp(iron::DSCP_EF);

    q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    q_mgr->Enqueue(p4);

    num_solutions = kNumSolutions;

    // EF p3 is selected first to go out on pc 1 since it has tightest
    // deadline and direct link to dest.
    // Bin 3:
    //    p2 EF 500ms, 1500B
    //    p3 EF 450ms, 1500B
    // Bin 4:
    //    p1 LS Zombie, 1500B
    //    p4 EF 450ms, 1500B
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p3) &&
      (solutions[0].path_ctrl_index == 1));

    pkt_pool_->Recycle(p3);

    num_solutions = kNumSolutions;

    // EF p4 is selected to go out on pc 1 since it has tightest deadline,
    // greatest gradient.
    // Bin 3:
    //    p2 EF 500ms, 1500B
    // Bin 4:
    //    p1 LS Zombie, 1500B
    //    p4 EF 450ms, 1500B
    // With hierarchical forwarding, Bin 3 has the same gradient as Bin 4 for
    // LS, and therefore p2 is selected (even though it has lower deadline but
    // pc1 is to destination directly).
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p4) &&
      (solutions[0].path_ctrl_index == 1));

    pkt_pool_->Recycle(solutions[0].pkt);

    num_solutions = kNumSolutions;

    // EF p2 is selected to go out on pc 1 since it has tightest
    // availability.
    // Bin 3:
    //    p2 EF 500ms, 1500B
    // Bin 4:
    //    p1 Zombie, 1500B
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((solutions[0].pkt == p2) &&
      (solutions[0].path_ctrl_index == 1));

    pkt_pool_->Recycle(solutions[0].pkt);

    num_solutions = kNumSolutions;

    // Zombie p1 is selected to go out on pc 0.
    // Bin 3:
    // Bin 4:
    //    p1 Zombie, 1500B
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) == p1_len);
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    // Multi-dequeue is false, so we should get one zombie packet of size
    // kZombieSingleDequeueLenBytes.
    if (q_mgr->IsPktlessZQueue(iron::HIGH_LATENCY_EXP))
    {
      CPPUNIT_ASSERT(
        solutions[0].pkt->virtual_length() == kZombieSingleDequeueLenBytes);
      CPPUNIT_ASSERT(solutions[0].pkt->GetType() == iron::ZOMBIE_PACKET);
      CPPUNIT_ASSERT(solutions[0].path_ctrl_index == 0);
      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) ==
                     (p1_len - kZombieSingleDequeueLenBytes));
    }
    else
    {
      CPPUNIT_ASSERT(solutions[0].pkt == p1);
      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) == 0);
    }
    CPPUNIT_ASSERT(solutions[0].path_ctrl_index == 0);

    pkt_pool_->Recycle(solutions[0].pkt);

    //
    // Test Multi-Dequeues.
    //
    LogD(kClassName, __func__, "Multi-dequeue test.\n");
    config_info_.Add("Bpf.Alg.MultiDeq", "true");
    bpfwder_->BPFwder::ResetFwdingAlg();

    // Create a low-latency packet destined to bin 3.
    iron::Packet* p10  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p10);
    memcpy(p10->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p10->SetLengthInBytes(1400);

    // p10 has ttg 500ms.
    ttg = iron::Time::FromMsec(400);
    p10->SetTimeToGo(ttg);
    p10->SetOrderTime(ttg);
    p10->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    q_mgr->Enqueue(p10);

    // Create a low-latency packet destined to bin 3.
    iron::Packet* p11  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p11);
    memcpy(p11->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p11->SetLengthInBytes(1400);

    // p11 has ttg 500ms.
    ttg = iron::Time::FromMsec(500);
    p11->SetTimeToGo(ttg);
    p11->SetOrderTime(ttg);
    p11->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p11);

    // Create a low-latency packet destined to bin 3.
    iron::Packet* p12  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p12);
    memcpy(p12->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p12->SetLengthInBytes(1400);

    // p12 has ttg 500ms.
    ttg = iron::Time::FromMsec(600);
    p12->SetTimeToGo(ttg);
    p12->SetOrderTime(ttg);
    p12->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr->Enqueue(p12);

    // Create a low-latency packet destined to bin 4.
    iron::Packet* p13  = pkt_pool_->Get(PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p13);
    memcpy(p13->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_), sizeof(ip_hdr_));
    p13->SetLengthInBytes(500);

    // p13 has ttg 500ms.
    ttg = iron::Time::FromMsec(600);
    p13->SetTimeToGo(ttg);
    p13->SetOrderTime(ttg);
    p13->SetIpDscp(iron::DSCP_EF);

    // Enqueue.
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    q_mgr->Enqueue(p13);

    num_solutions = kNumSolutions;

    // Bin 3:
    //    p10 EF 400ms, 1400B
    //    p11 EF 500ms, 1400B
    //    p12 EF 600ms, 1400B
    // Bin 4:
    //    p13 EF 600ms, 500B
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 3) &&
      (solutions[0].pkt == p10) && (solutions[1].pkt == p11) &&
      (solutions[2].pkt == p12));

    pkt_pool_->Recycle(p10);
    pkt_pool_->Recycle(p11);
    pkt_pool_->Recycle(p12);

    num_solutions = kNumSolutions;

    // Bin 3:
    // Bin 4:
    //    p13 EF 600ms, 500B
    CPPUNIT_ASSERT(bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT((num_solutions == 1) && (solutions[0].pkt == p13));

    pkt_pool_->Recycle(p13);
  }

  //==========================================================================
  void TestZombieQueueProcessing()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex bidx_4 = bin_map_->GetPhyBinIndex(4);

    // This tests the following:
    // 1. If there are normal latency packets and zombies for the same bin,
    // the normal latency packets are sent first.
    // 2. If there are normal latency packets for one bin and zombie packets
    // for another bin, and the zombie gradient is higher, the zombies will be
    // sent.
    // 3. If multi dequeue is disabled, we'll send approximately one packet
    // worth of zombie data (when appropriate to send a zombie).
    // 3b. If not enough zombie data is available, we'll send what is
    // available.
    // There is no criticalization in non-heuristic dag algs.
    config_info_.Add("Bpf.Alg.AntiCirculation", "ConditionalDAG");
    // Don't include a hysteresis - too hard to empty the queues between
    // tests.
    config_info_.Add("Bpf.Alg.HysteresisBytes", "0");
    bpfwder_->BPFwder::ResetFwdingAlg();
    CPPUNIT_ASSERT(bpfwder_->IncrPathCtrlXmitBuffer(2, 3000));

    for (uint8_t pc_index = 0; pc_index < 2; ++pc_index)
    {
      bpfwder_->SetQueueDepth(bidx_1, pc_index, 0);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, 0);
    }

    iron::Time  now      = iron::Time::Now();
    iron::Time  infinite = iron::Time::Infinite();

    // ----------------------------------------------------------------------
    // 1. If there are normal latency packets and zombies for the same bin,
    // the normal latency packets are sent first.

    // Create 1 latency-insensitive packet and 1 zombie packet.
    iron::Packet* norm0  = PacketCreator::CreateUdpPacket(
      *pkt_pool_, NULL, 1001);
    CPPUNIT_ASSERT(norm0);
    size_t norm0_len = norm0->GetLengthInBytes();
    norm0->SetTimeToGo(infinite);
    norm0->SetIpDscp(iron::DSCP_DEFAULT);

    iron::Packet* z0  = PacketCreator::CreateUdpPacket(
      *pkt_pool_, NULL, 994);
    CPPUNIT_ASSERT(z0);
    z0->SetTimeToGo(infinite);
    z0->SetIpDscp(iron::DSCP_DEFAULT);
    Zombie::ZombifyExistingPacket(z0);
    size_t z0_len = z0->virtual_length();

    iron::Packet* z1  = PacketCreator::CreateUdpPacket(
      *pkt_pool_, NULL, 996);
    CPPUNIT_ASSERT(z1);
    z1->SetTimeToGo(infinite);
    z1->SetIpDscp(iron::DSCP_DEFAULT);
    Zombie::ZombifyExistingPacket(z1);
    size_t z1_len = z1->virtual_length();

    z1->MakeZombie(iron::HIGH_LATENCY_RCVD);

    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    CPPUNIT_ASSERT(q_mgr);

    // Enqueue both to bin 4.
    q_mgr->Enqueue(z0);
    q_mgr->Enqueue(z1);
    q_mgr->Enqueue(norm0);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) == z0_len);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, false) == z1_len);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == norm0_len);

    // With LS Zombies implementation, LS Zombies are dequeued first, then
    // normal packets, then non-LS Zombie.
    iron::TxSolution  solutions[kNumSolutions];
    memset(solutions, 0, sizeof(solutions));
    uint8_t num_solutions = kNumSolutions;

    // Bin 4:
    //    z0 LS Zombie, 994B
    //    norm0 EF 450ms, 1001B
    //    z1 Zombie, 996B
    CPPUNIT_ASSERT(
      bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT(num_solutions == 1);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, true) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, false) == z1_len);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == norm0_len);
    pkt_pool_->Recycle(solutions[0].pkt);

    num_solutions = kNumSolutions;

    // Bin 4:
    //    norm0 EF 450ms, 1001B
    //    z1 Zombie, 996B
    CPPUNIT_ASSERT(
      bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT(num_solutions == 1);
    CPPUNIT_ASSERT(solutions[0].pkt == norm0);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, false) == z1_len);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == 0);
    pkt_pool_->Recycle(norm0);

    num_solutions = kNumSolutions;

    // Empty the queues to get ready for the next test.
    // Bin 4:
    //    z1 Zombie, 996B
    CPPUNIT_ASSERT(
      bpfwder_->CallFindNextTransmission(solutions, num_solutions));
    CPPUNIT_ASSERT(num_solutions == 1);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, false) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == 0);
    pkt_pool_->Recycle(solutions[0].pkt);

    // Empty the queues to get ready for the next test.
    bool result = true;
    while (num_solutions != 0 && result)
    {
      num_solutions = kNumSolutions;
      result = bpfwder_->CallFindNextTransmission(solutions, num_solutions);
      for (int i = 0; i < num_solutions; i++)
      {
        pkt_pool_->Recycle(solutions[i].pkt);
      }
    }

    // ----------------------------------------------------------------------
    // 2. If there are normal latency packets for one bin and zombie packets
    // for another bin, and the zombie gradient is higher, the zombies will be
    // sent.
    // AND
    // 3. If multi dequeue is disabled, we'll send approximately one packet
    // worth of zombie data (when appropriate to send a zombie).

    // Create 1 smaller latency-insensitive packet and 1 larger zombie packet.
    norm0  = PacketCreator::CreateUdpPacket(*pkt_pool_, NULL, 1101);
    CPPUNIT_ASSERT(norm0);
    norm0_len = norm0->GetLengthInBytes();
    norm0->SetTimeToGo(infinite);
    norm0->SetIpDscp(iron::DSCP_DEFAULT);

    z0  = PacketCreator::CreateUdpPacket(*pkt_pool_, NULL, 1203);
    CPPUNIT_ASSERT(z0);
    z0->SetTimeToGo(infinite);
    z0->SetIpDscp(iron::DSCP_DEFAULT);
    Zombie::ZombifyExistingPacket(z0);
    z0_len = z0->virtual_length();

    // Enqueue the normal latency packet to bin 4 and the zombie to bin 3.
    q_mgr->Enqueue(norm0);
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    q_mgr->Enqueue(z0);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, true) == z0_len);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == norm0_len);

    // Make sure the zombie packet is dequeued first because it should have
    // the higher gradient, and make sure it has the correct length for multi
    // dequeue = false.
    memset(solutions, 0, sizeof(solutions));
    num_solutions = kNumSolutions;
    CPPUNIT_ASSERT(
      bpfwder_->CallFindNextTransmission(solutions, num_solutions));

    if (q_mgr->IsPktlessZQueue(iron::HIGH_LATENCY_EXP))
    {
      CPPUNIT_ASSERT(
        solutions[0].pkt->virtual_length() == kZombieSingleDequeueLenBytes);
      CPPUNIT_ASSERT(solutions[0].pkt->GetType() == iron::ZOMBIE_PACKET);
      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, true) ==
                     (z0_len - kZombieSingleDequeueLenBytes));
    }
    else
    {
      CPPUNIT_ASSERT(solutions[0].pkt == z0);
      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, true) == 0);
    }
    pkt_pool_->Recycle(solutions[0].pkt);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == norm0_len);

    // Empty the queues to get ready for the next test.
    result = true;
    while (num_solutions != 0 && result)
    {
      num_solutions = kNumSolutions;
      result = bpfwder_->CallFindNextTransmission(solutions, num_solutions);
      for (int i = 0; i < num_solutions; i++)
      {
        pkt_pool_->Recycle(solutions[i].pkt);
      }
    }

    // ----------------------------------------------------------------------
    // 3b. If not enough zombie data is available, we'll send what is
    // available.

    // Create 1 smaller zombie packet.
    z0  = PacketCreator::CreateUdpPacket(*pkt_pool_, NULL, 50);
    CPPUNIT_ASSERT(z0);
    z0->SetTimeToGo(infinite);
    z0->SetIpDscp(iron::DSCP_DEFAULT);
    Zombie::ZombifyExistingPacket(z0);
    z0_len = z0->virtual_length();

    // Enqueue the zombie to bin 3.
    q_mgr->Enqueue(z0);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, true) == z0_len);

    // Make sure the dequeued packet has the right length.
    memset(solutions, 0, sizeof(solutions));
    num_solutions = kNumSolutions;
    CPPUNIT_ASSERT(
      bpfwder_->CallFindNextTransmission(solutions, num_solutions));

    if (q_mgr->IsPktlessZQueue(iron::HIGH_LATENCY_RCVD))
    {
      CPPUNIT_ASSERT(
        solutions[0].pkt->virtual_length() == z0_len);
      CPPUNIT_ASSERT(solutions[0].pkt->GetType() == iron::ZOMBIE_PACKET);
    }
    else
    {
      CPPUNIT_ASSERT(solutions[0].pkt == z0);
    }
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, true) == 0);
    pkt_pool_->Recycle(solutions[0].pkt);
  }

  //==========================================================================
  void TestZombieQueueProcessingMultiDequeue()
  {
    LogA(kClassName, __func__, "Start %s----------\n", __func__);

    // This tests the following:
    // 4. If multi dequeue is enabled, we'll send enough zombie packets to
    // fill the min of the gradient differential and the cat available space.
    // There is no criticalization in non-heuristic dag algs.
    config_info_.Add("Bpf.Alg.AntiCirculation", "ConditionalDAG");
    // Don't include a hysteresis - too hard to empty the queues between
    // tests.
    config_info_.Add("Bpf.Alg.HysteresisBytes", "0");
    // Enable multi-dequeue
    config_info_.Add("Bpf.Alg.MultiDeq", "true");
    bpfwder_->BPFwder::ResetFwdingAlg();
    CPPUNIT_ASSERT(bpfwder_->IncrPathCtrlXmitBuffer(2, 3000));

    iron::BinIndex bidx_1 = bin_map_->GetPhyBinIndex(1);
    iron::BinIndex bidx_2 = bin_map_->GetPhyBinIndex(2);
    iron::BinIndex bidx_3 = bin_map_->GetPhyBinIndex(3);
    iron::BinIndex bidx_4 = bin_map_->GetPhyBinIndex(4);

    for (uint8_t pc_index = 0; pc_index < 2; ++pc_index)
    {
      uint16_t  queue_depth = 3000;

      if (pc_index == 1)
      {
        queue_depth = 0;
      }

      bpfwder_->SetQueueDepth(bidx_1, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_2, pc_index, queue_depth);
      bpfwder_->SetQueueDepth(bidx_3, pc_index, queue_depth);
    }
    iron::BinQueueMgr* q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
    CPPUNIT_ASSERT(q_mgr);
    // This test isn't particularly interesting if we have a queue of real
    // packets. In that case, zombie processing is identical to normal
    // processing, which we already tested.
    if (!q_mgr->IsPktlessZQueue(iron::HIGH_LATENCY_RCVD))
    {
      return;
    }

    q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    CPPUNIT_ASSERT(q_mgr);
    // This test isn't particularly interesting if we have a queue of real
    // packets. In that case, zombie processing is identical to normal
    // processing, which we already tested.
    if (!q_mgr->IsPktlessZQueue(iron::HIGH_LATENCY_RCVD))
    {
      return;
    }

    iron::Time  now      = iron::Time::Now();
    iron::Time  infinite = iron::Time::Infinite();

    // This tests the following:
    // If multi dequeue is enabled, we'll send enough zombie packets to
    // fill the min of the gradient differential and the cat available space.

    // Create 2 normal latency packets and 5 zombies of varying sizes.
    // Enqueue the normal packets to bin 4 and the zombies to bin 3.
    size_t norm_len = 0;
    iron::Packet* norm0  = PacketCreator::CreateUdpPacket(
      *pkt_pool_, NULL, 800);
    CPPUNIT_ASSERT(norm0);
    norm_len += norm0->GetLengthInBytes();
    norm0->SetTimeToGo(infinite);
    norm0->SetIpDscp(iron::DSCP_DEFAULT);
    q_mgr = bpfwder_->GetBinQueueMgr(bidx_4);
    CPPUNIT_ASSERT(q_mgr);
    q_mgr->Enqueue(norm0);

    iron::Packet* norm1  = PacketCreator::CreateUdpPacket(
      *pkt_pool_, NULL, 900);
    CPPUNIT_ASSERT(norm1);
    norm_len += norm1->GetLengthInBytes();
    norm1->SetTimeToGo(infinite);
    norm1->SetIpDscp(iron::DSCP_DEFAULT);
    q_mgr->Enqueue(norm1);

    iron::Packet* zombies[5];
    size_t total_zombie_len = 0;
    for (int i = 0; i < 5; i++)
    {
      zombies[i]  = PacketCreator::CreateUdpPacket(
        *pkt_pool_, NULL, (1000 + (5*i)));
      CPPUNIT_ASSERT(zombies[i]);
      zombies[i]->SetTimeToGo(infinite);
      zombies[i]->SetIpDscp(iron::DSCP_DEFAULT);
      Zombie::ZombifyExistingPacket(zombies[i]);
      zombies[i]->MakeZombie(iron::HIGH_LATENCY_RCVD);
      total_zombie_len += zombies[i]->virtual_length();
      q_mgr = bpfwder_->GetBinQueueMgr(bidx_3);
      CPPUNIT_ASSERT(q_mgr);
      q_mgr->Enqueue(zombies[i]);
    }

    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, false) == total_zombie_len);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_4) == norm_len);
    CPPUNIT_ASSERT(bpfwder_->GetNormalLatencyDepthBytes(bidx_3) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_4, false) == 0);

    // The difference between the largest gradients is
    // total_zombie_len - norm_len. Path controller buffer is 3000 Bytes.

    iron::TxSolution  solutions[kNumSolutions];
    memset(solutions, 0, sizeof(solutions));
    uint8_t num_solutions = kNumSolutions;

    size_t expected_len = 0;
    while (total_zombie_len >= norm_len)
    {
      if (total_zombie_len == norm_len)
      {
        // The next gradient is equal, we send 1024B of Zombie.
        expected_len  = kZombieSingleDequeueLenBytes;
      }
      else
      {
        expected_len = total_zombie_len;
      }
      size_t pc_space = bpfwder_->GetPathCtrlXmitBuffer(1);
      if (pc_space >= 3000)
      {
        // Can't dequeue any more zombies.
        LogD(kClassName, __func__, "pc_space = %zu\n", pc_space);
        break;
      }
      else
      {
        pc_space = 3000 - pc_space;
        if (pc_space < expected_len)
        {
          expected_len = pc_space;
        }
      }
      if (!iron::kDefaultZombieCompression &&
          (expected_len < sizeof(struct iphdr)))
      {
        expected_len = sizeof(struct iphdr);
      }

      // Make sure the dequeued packet has the right length. Should be a
      // zombie of length expected_len.
      memset(solutions, 0, sizeof(solutions));
      num_solutions = kNumSolutions;
      CPPUNIT_ASSERT(
        bpfwder_->CallFindNextTransmission(solutions, num_solutions));

      CPPUNIT_ASSERT(solutions[0].pkt->GetType() == iron::ZOMBIE_PACKET);

      size_t  dequeued_size = 0;
      for (uint8_t i = 0; i < num_solutions; ++i)
      {
        CPPUNIT_ASSERT(solutions[i].pkt);
        dequeued_size += solutions[i].pkt->virtual_length();
        pkt_pool_->Recycle(solutions[i].pkt);
      }

      CPPUNIT_ASSERT(expected_len == dequeued_size);
      total_zombie_len -= dequeued_size;

      CPPUNIT_ASSERT(bpfwder_->GetZombieDepthBytes(bidx_3, false) == total_zombie_len);
    }
    // Now that we've hit a stop condition on zombies, we should get a normal
    // latency packet.
    size_t pc_space = bpfwder_->GetPathCtrlXmitBuffer(1);
    if (pc_space < 3000)
    {
      memset(solutions, 0, sizeof(solutions));
      num_solutions = kNumSolutions;
      CPPUNIT_ASSERT(
        bpfwder_->CallFindNextTransmission(solutions, num_solutions));
      CPPUNIT_ASSERT(solutions[0].pkt == norm0);
      pkt_pool_->Recycle(solutions[0].pkt);
      // and recycle any other results.
      for (int i = 1; i < num_solutions; i++)
      {
        pkt_pool_->Recycle(solutions[i].pkt);
      }
    }
    // Empty the queues to avoid a packet leak.
    num_solutions = kNumSolutions;
    bool result = true;
    while (num_solutions != 0 && result)
    {
      result = bpfwder_->CallFindNextTransmission(solutions, num_solutions);
      for (int i = 0; i < num_solutions; i++)
      {
        pkt_pool_->Recycle(solutions[i].pkt);
      }
    }
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(BPFAlgTest);
