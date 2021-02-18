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
#include "backpressure_fwder.h"
#include "fifo_if.h"
#include "ipv4_address.h"
#include "iron_types.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "port_number_mgr.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "queue_depths.h"
#include "shared_memory_if.h"
#include "sond.h"
#include "timer.h"
#include "unused.h"

#include <cmath>

#include <limits>
#include <vector>

using iron::BinId;
using iron::BinIndex;
using iron::BinMap;
using iron::ConfigInfo;
using ::iron::FifoIF;
using iron::Log;
using iron::Packet;
using iron::PacketPool;
using iron::PacketPoolHeap;
using iron::PseudoFifo;
using iron::PseudoSharedMemory;
using iron::SharedMemoryIF;
using iron::Timer;

using ::std::vector;

namespace
{
  const char* UNUSED(kClassName)  = "BpfLinkStateTester";
}

//============================================================================
class LinkStateTester : public iron::BPFwder
{
public:
  /// Constructor.
  LinkStateTester(PacketPool& packet_pool, BinMap& bin_map, Timer& timer,
                  SharedMemoryIF& weight_qd_shared_memory,
                  vector<PseudoFifo*>* fifos,
                  ConfigInfo& config_info)
    : BPFwder(packet_pool, timer, bin_map, weight_qd_shared_memory,
              BPF_FIFO_ARGS(fifos), config_info),
      queue_depths_6_(NULL),
      queue_depths_7_(NULL),
      bidx_6_(iron::kInvalidBinIndex),
      bidx_7_(iron::kInvalidBinIndex),
      fifos_(fifos)
  { };

  /// Destructor.
  virtual ~LinkStateTester()
  {
    PseudoFifo::DeleteBpfFifos(fifos_);
  };

  /// Initialize for the tests.
  void InitForTest(iron::BinMap& bin_map);

  /// Set the remote iron node address at the end of a path controller.
  void SetRemoteIronAddr(uint8_t path_ctrl_num, iron::Ipv4Address addr);

  /// Toggle including the queue delays.
  inline void IncludeQueueDelays(bool include)
  {
    incl_queue_delays_  = include;
  }

  /// Add a latency record as if coming from an LSA.
  void AddRecord(BinId node_id,
    std::vector<std::pair<BinId, uint32_t> > nbr_lat_mean,
    std::vector<std::pair<BinId, uint64_t> > nbr_lat_var,
    uint32_t* queue_delays = NULL, size_t num_queue_delays = 0);

  /// Clear the variance measure on all path controllers.  Used for
  /// non-variance tests.
  void ClearVariance();

  /// Get the latency from the records for a source to a neighbor, by bin id.
  uint32_t GetLatencyRecord(BinId node_id, BinId nbr_id);

  /// Invoke the method to print the node records.
  void PrintRecords()
  {
    PrintNodeRecords();
  }

  /// Send a dummy LSA as if from node 0.
  void SendDummyLsa(Packet* lsa, PacketPool& pkt_pool, bool include_var = false);

  /// Call the FindNextTransmission method.
  ///
  /// \param  bin The id of the bin to send.
  /// \param  nbr The path controller on which to send.
  ///
  /// \return true if found a packet to send, false otherwise.
  bool FindNextTransmissionTest(BinId& bin, iron::PathController*& nbr);

  /// Do no broadcasting.
  virtual void BroadcastPacket(Packet* packet,
    iron::Ipv4Address nbr_to_omit = iron::Ipv4Address())
  { }

  /// Place arbitrary values in the matrix.
  void FillMatrixWithArbitraryValues(BinMap* bin_map);

  /// Place specific values in the matrix.
  void FillMatrixWithValues(const uint32_t (*lat_mean_matrix)[7],
                            const uint64_t (*lat_var_matrix)[7]);

  /// Clear the list of nodes to exclude.
  void ClearNodesToExclude();

  /// Add a node to the list of nodes to exclude.
  void AddNodeToExclude(BinIndex bin_idx);

  /// Invoke the method to convert the latency records to a matrix.
  void ConvertRecords();

  /// Get a value from the latency mean matrix.
  uint32_t GetMatrix(BinIndex dest, BinIndex nbr);

  /// Invoke the method to find the shortest path.
  void ShortestPath(BinIndex dest_bin_idx);

  /// Invoke the method to find the shortest path.
  void GetShortestPathResults(uint32_t* min_lat_mean, uint64_t* min_lat_var,
                              uint32_t* next_hop);

  /// Invoke the method to enqueue a packet.
  bool EnqueuePacket(Packet* packet, BinId bin_id);

  /// \brief Function sets up test of BP Fwding algorithm.
  ///
  /// \param i  The iteration of the sequential test starting at 0, which tells
  ///           the function what test parameters to change.
  ///           This function must be called with increasing i's: 0, 1, 2, ...
  void SetUpBPFLowLatAlgTest(uint8_t i);

private:
  LinkStateTester(const LinkStateTester& other);

  LinkStateTester& operator= (const LinkStateTester& other);

  iron::QueueDepths*  queue_depths_6_;
  iron::QueueDepths*  queue_depths_7_;
  BinIndex            bidx_6_;
  BinIndex            bidx_7_;
  vector<PseudoFifo*>* fifos_;

};

//============================================================================
void LinkStateTester::InitForTest(iron::BinMap& bin_map)
{
  CPPUNIT_ASSERT(this->Initialize());

  SetRemoteIronAddr(0, iron::Ipv4Address("10.1.10.102"));
  SetRemoteIronAddr(1, iron::Ipv4Address("10.1.10.103"));
  SetRemoteIronAddr(2, iron::Ipv4Address("10.1.10.104"));
  SetRemoteIronAddr(3, iron::Ipv4Address("10.1.10.104"));

  bidx_6_         = bin_map_shm_.GetPhyBinIndex(6);
  bidx_7_         = bin_map_shm_.GetPhyBinIndex(7);

  queue_depths_6_ =
    queue_store_->GetBinQueueMgr(bidx_6_)->GetQueueDepthsForBpf();
  queue_depths_7_ =
    queue_store_->GetBinQueueMgr(bidx_7_)->GetQueueDepthsForBpf();

  for (uint8_t i = 0; i < num_path_ctrls_; ++i)
  {
    iron::PathController* pctl  = path_ctrls_[i].path_ctrl;
    CPPUNIT_ASSERT(pctl);

    switch (i)
    {
      case 0: path_ctrls_[i].pdd_mean_sec       = 0.002;
              path_ctrls_[i].pdd_variance_secsq = 0.;
              break;
      case 1: path_ctrls_[i].pdd_mean_sec       = 0.001;
              path_ctrls_[i].pdd_variance_secsq = 1e-9;
              break;
      case 2: path_ctrls_[i].pdd_mean_sec       = 0.001;
              path_ctrls_[i].pdd_variance_secsq = 1e-8;
              break;
      case 3: path_ctrls_[i].pdd_mean_sec       = 0.010;
              path_ctrls_[i].pdd_variance_secsq = 1e-8;
              break;
      default: LogF(kClassName, __func__, "Wrong path controller %u.\n", i);
    }
  }

  bpf_dequeue_alg_->set_hysteresis(10);
}

//============================================================================
void LinkStateTester::SetRemoteIronAddr(uint8_t path_ctrl_num,
  iron::Ipv4Address addr)
{
  CPPUNIT_ASSERT(path_ctrl_num < num_path_ctrls_);

  BinIndex  bin_idx = bin_map_shm_.GetDstBinIndexFromAddress(addr);
  BinId     bin_id  = bin_map_shm_.GetPhyBinId(bin_idx);

  path_ctrls_[path_ctrl_num].path_ctrl->set_remote_bin_id_idx(bin_id,
                                                              bin_idx);
}

//============================================================================
void LinkStateTester::AddRecord(BinId node_id,
    std::vector<std::pair<BinId, uint32_t> > nbr_lat,
    std::vector<std::pair<BinId, uint64_t> > nbr_var,
    uint32_t* queue_delays, size_t num_queue_delays)
{
  std::vector<std::pair<BinId, uint32_t> >::iterator itr;
  std::vector<std::pair<BinId, uint64_t> >::iterator var_itr  =
    nbr_var.begin();

  BinIndex    bin_idx     = bin_map_shm_.GetPhyBinIndex(node_id);
  NodeRecord* node_record = AccessOrAllocateNodeRecord(bin_idx);

  for (itr = nbr_lat.begin(); itr != nbr_lat.end(); ++itr)
  {
    BinIndex nbr_idx = bin_map_shm_.GetPhyBinIndex((*itr).first);
    node_record->records_[nbr_idx].nbr_lat_mean_ = (*itr).second;

    if ((*itr).first == (*var_itr).first)
    {
      node_record->records_[nbr_idx].nbr_lat_var_ = (*var_itr).second;
    }
    ++var_itr;
  }

  if (queue_delays)
  {
    for (bin_idx = 0; bin_idx < num_queue_delays; ++bin_idx)
    {
      node_record->records_[bin_idx].queue_delay_ = queue_delays[bin_idx];
    }
  }
}

//============================================================================
void LinkStateTester::ClearVariance()
{
  for (uint8_t i = 0; i < num_path_ctrls_; ++i)
  {
    path_ctrls_[i].pdd_variance_secsq = 0.;
  }
}

//============================================================================
uint32_t LinkStateTester::GetLatencyRecord(BinId node_id, BinId nbr_id)
{
  BinIndex    bin_idx     = bin_map_shm_.GetPhyBinIndex(node_id);
  BinIndex    nbr_idx     = bin_map_shm_.GetPhyBinIndex(nbr_id);
  NodeRecord* node_record = AccessOrAllocateNodeRecord(bin_idx);

  CPPUNIT_ASSERT(node_record);
  return node_record->records_[nbr_idx].nbr_lat_mean_;
}

//============================================================================
void LinkStateTester::SendDummyLsa(Packet* lsa, PacketPool& packet_pool,
                                   bool include_var)
{
  CPPUNIT_ASSERT(lsa);

  uint8_t*  buffer  = lsa->GetBuffer();

  // Packet type.
  *buffer = static_cast<uint8_t>(iron::LSA_PACKET);
  ++buffer;

  // My node id.
  BinId  my_node_id = 4;
  *buffer           = my_node_id;
  ++buffer;

  // The sequence number.
  uint16_t lsa_seq_num_nbo  = htons(2);
  memcpy(buffer, &lsa_seq_num_nbo, sizeof(lsa_seq_num_nbo));
  buffer += sizeof(lsa_seq_num_nbo);

  // Number of neighbors listed in LSA.
  uint8_t num_nbrs  = 3;
  *buffer           = num_nbrs;
  ++buffer;
  *buffer           = 0;
  buffer           += 3; // num neighbors + 3 bytes padding

  // Neighbor list with latency.
  BinId     nbr_id        = 1;
  uint16_t  nbr_lat_mean  = htons(100);

  *buffer                 = nbr_id;
  ++buffer;

  memcpy(buffer, &nbr_lat_mean, sizeof(nbr_lat_mean));
  buffer       += sizeof(nbr_lat_mean);

  uint16_t  nbr_lat_sd  = 0;
  if (include_var)
  {
    nbr_lat_sd  = htons(1);
  }
  memcpy(buffer, &nbr_lat_sd, sizeof(nbr_lat_sd));
  buffer       += sizeof(nbr_lat_sd);

  nbr_id        = 6;
  nbr_lat_mean  = htons(70);
  nbr_lat_sd    = 0;

  if (include_var)
  {
    nbr_lat_sd  = htons(1);
  }

  *buffer       = nbr_id;
  ++buffer;

  memcpy(buffer, &nbr_lat_mean, sizeof(nbr_lat_mean));
  buffer       += sizeof(nbr_lat_mean);

  memcpy(buffer, &nbr_lat_sd, sizeof(nbr_lat_sd));
  buffer       += sizeof(nbr_lat_sd);

  nbr_id        = 7;
  nbr_lat_mean  = htons(100);
  nbr_lat_sd    = 0;

  if (include_var)
  {
    nbr_lat_sd  = htons(1);
  }

  *buffer       = nbr_id;
  ++buffer;

  memcpy(buffer, &nbr_lat_mean, sizeof(nbr_lat_mean));
  buffer       += sizeof(nbr_lat_mean);

  memcpy(buffer, &nbr_lat_sd, sizeof(nbr_lat_sd));
  buffer       += sizeof(nbr_lat_sd);

  // Set the length, in bytes, of the packet that was just generated.
  size_t  packet_size = sizeof(uint8_t) + sizeof(num_nbrs) +
    sizeof(my_node_id) + sizeof(lsa_seq_num_nbo) +
    num_nbrs * (sizeof(nbr_id) + sizeof(nbr_lat_mean) + sizeof(nbr_lat_sd));
  lsa->SetLengthInBytes(packet_size);
}

//============================================================================
bool LinkStateTester::FindNextTransmissionTest(BinId& bin,
  iron::PathController*& nbr)
{
  iron::TxSolution  unused_solutions[10];
  memset(unused_solutions, 0, sizeof(unused_solutions));
  uint8_t num_solutions = 10;
  bool    result        =
    this->bpf_dequeue_alg_->FindNextTransmission(
      unused_solutions, num_solutions);

  if (num_solutions > 0)
  {
    BinIndex bin_idx = unused_solutions[0].bin_idx;
    // MCAST TODO: can we return bin index instead to avoid this line?
    bin = bin_map_shm_.GetPhyBinId(bin_idx);
    queue_store_->GetBinQueueMgr(bin_idx)->Enqueue(unused_solutions[0].pkt);
  }
  nbr = path_ctrls_[unused_solutions[0].path_ctrl_index].path_ctrl;
  return result;
}

//============================================================================
void LinkStateTester::FillMatrixWithArbitraryValues(BinMap* bin_map)
{
  // Place arbitrary values in the matrix.
  BinIndex  bin_idx     = 0;
  BinIndex  nbr_bin_idx = 0;

  for (bool m1 = bin_map->GetFirstPhyBinIndex(bin_idx); m1;
       m1 = bin_map->GetNextPhyBinIndex(bin_idx))
  {
    for (bool m2 = bin_map->GetFirstPhyBinIndex(nbr_bin_idx); m2;
         m2 = bin_map->GetNextPhyBinIndex(nbr_bin_idx))
    {
      path_info_.LatMean(bin_idx, nbr_bin_idx) = (bin_idx + nbr_bin_idx);
      path_info_.LatVar(bin_idx, nbr_bin_idx)  = 0;
    }
  }
}

//============================================================================
void LinkStateTester::FillMatrixWithValues(
  const uint32_t (*lat_mean_matrix)[7], const uint64_t (*lat_var_matrix)[7])
{
  for (BinIndex i = 0; i < 7; ++i)
  {
    for (BinIndex j = 0; j < 7; ++j)
    {
      path_info_.LatMean(i, j) = lat_mean_matrix[i][j];
      path_info_.LatVar(i, j)  = lat_var_matrix[i][j];
    }
  }
}

//============================================================================
void LinkStateTester::ClearNodesToExclude()
{
  path_info_.num_nodes_to_exclude_ = 0;
}

//============================================================================
void LinkStateTester::AddNodeToExclude(BinIndex bin_idx)
{
  path_info_.ExcludeNode(bin_idx);
}

//============================================================================
void LinkStateTester::ConvertRecords()
{
  ConvertNodeRecordsToMatrix();
}

//============================================================================
uint32_t LinkStateTester::GetMatrix(BinIndex dest, BinIndex nbr)
{
  return path_info_.LatMean(dest, nbr);
}

//============================================================================
void LinkStateTester::ShortestPath(BinIndex dest_bin_idx)
{
  FindMinimumLatencyPath(dest_bin_idx);
}

//============================================================================
void LinkStateTester::GetShortestPathResults(uint32_t* min_lat_mean,
                                             uint64_t* min_lat_var,
                                             uint32_t* next_hop)
{
  for (BinIndex i = 0; i < 7; ++i)
  {
    min_lat_mean[i] = path_info_.MinLatMean(i);
    min_lat_var[i]  = path_info_.MinLatVar(i);
    next_hop[i]     = path_info_.NextHop(i);
  }
}

//============================================================================
bool LinkStateTester::EnqueuePacket(Packet* packet, BinId bin_id)
{
  return queue_store_->GetBinQueueMgr(
    bin_map_shm_.GetPhyBinIndex(bin_id))->Enqueue(packet);
}

//============================================================================
void LinkStateTester::SetUpBPFLowLatAlgTest(uint8_t iteration)
{
  if (iteration == 0)
  {
    // Test behavior when one bin has a low-latency packet and 6ms ttg.
    // Self:                  Bin6: 100   Bin7: 120
    // Self Virt:             Bin6: 0     Bin7: 0
    // NbrId 2:               Bin6: 0     Bin7: 0
    // NbrId 2 Virt:          Bin6: 0     Bin7: 0
    // NbrId 2 Delay:         Bin6: 6     Bin7: 5
    // NbrId 3:               Bin6: 10    Bin7: 0
    // NbrId 3 Virt:          Bin6: 0     Bin7: 0
    // NbrId 3 Delay:         Bin6: 5     Bin7: 2
    // Greatest Delta: (Bin7, Nbr3) 120, but pick DSCP 0 packet (Bin6, Nbr3).

    // Add actual packet to queue for low-lat algorithm to operate on.
    queue_depths_6_->SetBinDepthByIdx(bidx_6_, 100);
    queue_depths_7_->SetBinDepthByIdx(bidx_7_, 120);
    LogD(kClassName, __func__,
      "Set bin 6 (idx %" PRIBinIndex ") depth to 100B.\n", bidx_6_);
    LogD(kClassName, __func__,
      "Set bin 7 (idx %" PRIBinIndex ") depth to 120B.\n", bidx_7_);

    iron::PathController* pctl = path_ctrls_[1].path_ctrl;
    CPPUNIT_ASSERT(pctl);

    iron::QueueDepths*  queue_depths  =
      queue_store_->PeekNbrQueueDepths(bidx_6_, pctl->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths);
    queue_depths->SetBinDepthByIdx(bidx_6_, 0);
    queue_depths  = queue_store_->PeekNbrQueueDepths(bidx_7_,
      pctl->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths);
    queue_depths->SetBinDepthByIdx(bidx_7_, 0);

    LogD(kClassName, __func__,
         "NbrId 2 set bin 6 and 7 depths to 0 and virtual depths to 0.\n");

    pctl = path_ctrls_[2].path_ctrl;
    CPPUNIT_ASSERT(pctl);

    queue_depths  = queue_store_->PeekNbrQueueDepths(bidx_6_,
      pctl->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths);
    queue_depths->SetBinDepthByIdx(bidx_6_, 0);
    queue_depths  = queue_store_->PeekNbrQueueDepths(bidx_7_,
      pctl->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths);
    queue_depths->SetBinDepthByIdx(bidx_7_, 0);

    LogD(kClassName, __func__,
         "NbrId 3 set bin 6 depth to 10, bin 7 depth to 0 and virtual depths to"
         " 0.\n");
  }
}

//============================================================================
class LinkStateTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(LinkStateTest);

  CPPUNIT_TEST(TestProcessLsa);
  CPPUNIT_TEST(TestLsaConnectivityConversion);
  CPPUNIT_TEST(TestLsaConnectivityConversionWQueueDelays);
  CPPUNIT_TEST(TestFindShortestPath);
  CPPUNIT_TEST(TestFindShortestPathWVar);
  CPPUNIT_TEST(TestGetPerPcLatencyToDst);
  CPPUNIT_TEST(TestGetPerPcLatencyToDstWQueueDelay);
  CPPUNIT_TEST(TestGetPerPcLatencyToDstWVar);
  CPPUNIT_TEST(TestBPFAlg);

  CPPUNIT_TEST_SUITE_END();

private:
  LinkStateTester*        bpfwder_;
  iron::PacketPoolHeap*   pkt_pool_;
  iron::BinMap*           bin_map_ = NULL;
  char*                   bin_map_mem_ = NULL;
  iron::Timer*            timer_;
  SharedMemoryIF*         weight_qd_shared_memory_;

public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");

    timer_    = new (std::nothrow) Timer();
    CPPUNIT_ASSERT(timer_);

    weight_qd_shared_memory_  = new PseudoSharedMemory();

    pkt_pool_ = new (std::nothrow) PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_);
    CPPUNIT_ASSERT(pkt_pool_->Create(8) == true);

    ConfigInfo            ci;
    iron::PortNumberMgr&  port_mgr = iron::PortNumberMgr::GetInstance();
    std::string           ep_str;

    ci.Add("Bpf.BinId", "1");
    ci.Add("Bpf.Alg.Fwder", "LatencyAware");
    ci.Add("Bpf.Alg.MultiDeq", "false");
    ci.Add("LinkStateLatency", "true");
    ci.Add("Bpf.Laf.IncludeQueuingDelays", "false");

    // Minimal BinMap config to prevent errors duing initialization
    ci.Add("BinMap.BinIds", "1,2,3,4,5,6,7");
    ci.Add("BinMap.BinId.1.HostMasks",
           "192.168.1.0/24,10.1.1.0/24,10.1.10.101");
    ci.Add("BinMap.BinId.2.HostMasks",
           "192.168.2.0/24,10.1.2.0/24,10.1.10.102");
    ci.Add("BinMap.BinId.3.HostMasks",
           "192.168.3.0/24,10.1.3.0/24,10.1.10.103");
    ci.Add("BinMap.BinId.4.HostMasks",
           "192.168.4.0/24,10.1.4.0/24,10.1.10.104");
    ci.Add("BinMap.BinId.5.HostMasks",
           "192.168.5.0/24,10.1.5.0/24,10.1.10.105");
    ci.Add("BinMap.BinId.6.HostMasks",
           "192.168.6.0/24,10.1.6.0/24,10.1.10.106");
    ci.Add("BinMap.BinId.7.HostMasks",
           "192.168.7.0/24,10.1.7.0/24,10.1.10.107");

    // Add Path Controller configuration.
    ci.Add("Bpf.NumPathControllers", "4");

    ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() + "->127.0.0.1:20010";
    ci.Add("PathController.0.Type", "Sond");
    ci.Add("PathController.0.Endpoints", ep_str);
    ci.Add("PathController.0.MaxLineRateKbps", "0");

    ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() + "->127.0.0.1:20011";
    ci.Add("PathController.1.Type", "Sond");
    ci.Add("PathController.1.Endpoints", ep_str);
    ci.Add("PathController.1.MaxLineRateKbps", "0");

    ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() + "->127.0.0.1:20012";
    ci.Add("PathController.2.Type", "Sond");
    ci.Add("PathController.2.Endpoints", ep_str);
    ci.Add("PathController.2.MaxLineRateKbps", "0");

    ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() + "->127.0.0.1:20013";
    ci.Add("PathController.3.Type", "Sond");
    ci.Add("PathController.3.Endpoints", ep_str);
    ci.Add("PathController.3.MaxLineRateKbps", "0");

    // Create and initialize the BinMap.
    bin_map_mem_ = new char[sizeof(BinMap)];
    bin_map_     = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));
    CPPUNIT_ASSERT(bin_map_);
    CPPUNIT_ASSERT(bin_map_->Initialize(ci));

    // Create the backpressure forwarder set up for testing. Memory reclaimed
    // below.
    bpfwder_ = new (std::nothrow) LinkStateTester(*pkt_pool_, *bin_map_,
                                                  *timer_,
                                                  *weight_qd_shared_memory_,
                                                  PseudoFifo::BpfFifos(),
                                                  ci);
    CPPUNIT_ASSERT(bpfwder_);

    bpfwder_->InitForTest(*bin_map_);
  }

  //==========================================================================
  void tearDown()
  {
    timer_->CancelAllTimers();

    // Clean up.
    delete bpfwder_;
    bpfwder_ = NULL;

    delete pkt_pool_;
    pkt_pool_ = NULL;

    delete [] bin_map_mem_;
    bin_map_     = NULL;
    bin_map_mem_ = NULL;

    delete timer_;
    timer_ = NULL;

    delete weight_qd_shared_memory_;
    weight_qd_shared_memory_ = NULL;

    //
    // Restore the default log levels so we don't break any other unit tests.
    //
    Log::SetDefaultLevel("FEW");
  }

  //============================================================================
  void TestProcessLsa()
  {
    // Create spoof lsa packet.
    Packet* lsa = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);

    bpfwder_->SendDummyLsa(lsa, *pkt_pool_);

    // Create a dummy path controller on which the LSA could have come.
    iron::PathController* pc  = new (std::nothrow) iron::Sond(bpfwder_,
      *pkt_pool_, *timer_);
    CPPUNIT_ASSERT(pc);

    // Process it.
    bpfwder_->ProcessRcvdPacket(lsa, pc);

    delete pc;

    // Make sure we got the correct info.
    CPPUNIT_ASSERT(bpfwder_->GetLatencyRecord(4, 1) == 10000);
    CPPUNIT_ASSERT(bpfwder_->GetLatencyRecord(4, 6) == 7000);
    CPPUNIT_ASSERT(bpfwder_->GetLatencyRecord(4, 7) == 10000);
    pkt_pool_->Recycle(lsa);
  }

  //============================================================================
  void TestLsaConnectivityConversion()
  {
    std::vector<std::pair<BinId, uint32_t> > nbr_list;
    std::vector<std::pair<BinId, uint64_t> > var_list;
    bin_map_->Print();
    /*
    //          (0)
    //          /|\
    //        2/1| \1,10/10,10
    //        /  |  \
    //      (1) (2) (3)
    //         3/5\ /7\1,10
    //         /   v   \
    //       (4)  (5)--(6)
    //               3
    */

    // Get the bin indicies based on the bin ids.
    BinIndex  bix1 = bin_map_->GetPhyBinIndex(1);
    BinIndex  bix2 = bin_map_->GetPhyBinIndex(2);
    BinIndex  bix3 = bin_map_->GetPhyBinIndex(3);
    BinIndex  bix4 = bin_map_->GetPhyBinIndex(4);
    BinIndex  bix5 = bin_map_->GetPhyBinIndex(5);
    BinIndex  bix6 = bin_map_->GetPhyBinIndex(6);
    BinIndex  bix7 = bin_map_->GetPhyBinIndex(7);

    // Add records as if received from LSAs. These use Bin Ids (which will be
    // internally converted to BinIndexes for storage).
    // Neighbor list data is:  (src_bin_id, cost)
    // Variance list data is:  (src_bin_id, variance)
    nbr_list.push_back(std::pair<BinId, uint32_t> (2, 2));
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1));
    var_list.push_back(std::pair<BinId, uint64_t> (2, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    bpfwder_->AddRecord(1, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 2));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    bpfwder_->AddRecord(2, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (5, 3));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 5));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (5, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    bpfwder_->AddRecord(3, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 7));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 1));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    bpfwder_->AddRecord(4, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 3));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    bpfwder_->AddRecord(5, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 5));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 7));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 3));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    bpfwder_->AddRecord(6, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 3));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    bpfwder_->AddRecord(7, nbr_list, var_list);

    bpfwder_->PrintRecords();

    bpfwder_->FillMatrixWithArbitraryValues(bin_map_);

    // Convert the records to a connection matrix.
    LogD(kClassName, __func__, "Convert to connection matrix, no exclusion.\n");
    bpfwder_->ClearNodesToExclude();
    bpfwder_->ConvertRecords();

    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix1) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix2) == 2);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix3) == 1);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix4) == 1);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix5) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix6) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix7) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix2) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix3) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix4) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix5) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix6) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix7) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix3) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix4) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix5) == 3);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix6) == 5);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix7) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix4) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix5) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix6) == 7);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix7) == 1);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix5,bix5) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix5,bix6) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix5,bix7) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix6) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix7) == 3);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix5) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix7) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix6) == 3);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix4) == 1);

    // Convert the records to a connection matrix excluding some nodes.
    bpfwder_->ClearNodesToExclude();
    bpfwder_->AddNodeToExclude(bix3);
    bpfwder_->AddNodeToExclude(bix6);
    LogD(kClassName, __func__,
         "Convert to connection matrix, excluding 2 and 5.\n");
    bpfwder_->ConvertRecords();

    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix1) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix6) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix3) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix4) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix7) == 1);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix5,bix5) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix5,bix7) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix6) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix5) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix7) == 0);
  }

  //============================================================================
  void TestLsaConnectivityConversionWQueueDelays()
  {
    bpfwder_->IncludeQueueDelays(true);
    std::vector<std::pair<BinId, uint32_t> > nbr_list;
    std::vector<std::pair<BinId, uint64_t> > var_list;

    // Queue delays for dest node id 5 and 6 at 1: 100 and 200.

    /*
    //          (0)
    //          /|\
    //        2/1| \1,10/10,10
    //        /  |  \
    //      (1) (2) (3)
    //         3/5\ /7\1,10
    //         /   v   \
    //       (4)  (5)--(6)
    //               3
    */

    // Get the bin indicies based on the BinId. Note that the
    // GRAM multicast group will take a much larger bin index.
    BinIndex  bix1 = bin_map_->GetPhyBinIndex(1);
    BinIndex  bix2 = bin_map_->GetPhyBinIndex(2);
    BinIndex  bix3 = bin_map_->GetPhyBinIndex(3);
    BinIndex  bix4 = bin_map_->GetPhyBinIndex(4);
    BinIndex  bix5 = bin_map_->GetPhyBinIndex(5);
    BinIndex  bix6 = bin_map_->GetPhyBinIndex(6);
    BinIndex  bix7 = bin_map_->GetPhyBinIndex(7);

    // Add records as if received from LSAs. These use Bin Ids (which will be
    // internally converted to BinIndexes for storage).
    // Neighbor list data is:  (src_bin_id, cost)
    // Variance list data is:  (src_bin_id, variance)
    nbr_list.push_back(std::pair<BinId, uint32_t> (2, 2));
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1));
    var_list.push_back(std::pair<BinId, uint64_t> (2, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    uint32_t  queue_delays[8];
    memset(queue_delays, 0, sizeof(queue_delays));
    queue_delays[bix6] = 100;
    queue_delays[bix7] = 200;
    bpfwder_->AddRecord(1, nbr_list, var_list, queue_delays, 8);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 2));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    queue_delays[bix6] = 0;
    queue_delays[bix7] = 0;
    bpfwder_->AddRecord(2, nbr_list, var_list, queue_delays, 8);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (5, 3));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 5));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (5, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    queue_delays[bix6] = 40;
    queue_delays[bix7] = 80;
    bpfwder_->AddRecord(3, nbr_list, var_list, queue_delays, 8);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 7));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 1));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    queue_delays[bix6] = 0;
    queue_delays[bix7] = 0;
    bpfwder_->AddRecord(4, nbr_list, var_list, queue_delays, 8);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 3));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    queue_delays[bix6] = 30;
    queue_delays[bix7] = 0;
    bpfwder_->AddRecord(5, nbr_list, var_list, queue_delays, 8);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 5));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 7));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 3));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    queue_delays[bix6] = 0;
    queue_delays[bix7] = 60;
    bpfwder_->AddRecord(6, nbr_list, var_list, queue_delays, 8);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 3));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    queue_delays[bix6] = 0;
    queue_delays[bix7] = 0;
    bpfwder_->AddRecord(7, nbr_list, var_list, queue_delays, 8);

    bpfwder_->PrintRecords();

    bpfwder_->FillMatrixWithArbitraryValues(bin_map_);

    // Convert the records to a connection matrix.
    LogD(kClassName, __func__, "Convert to connection matrix, no exclusion.\n");
    bpfwder_->ClearNodesToExclude();
    bpfwder_->ConvertRecords();

    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix1) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix5) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix2) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix3) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix6) == 45);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix4) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix6) == 7);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix5,bix5) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix4) == 7);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix6) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix7) == 63);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix7) == 0);

    // Convert the records to a connection matrix excluding some nodes.
    bpfwder_->ClearNodesToExclude();
    bpfwder_->AddNodeToExclude(bix3);
    bpfwder_->AddNodeToExclude(bix6);
    LogD(kClassName, __func__,
         "Convert to connection matrix, excluding 2 and 5.\n");
    bpfwder_->ConvertRecords();

    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix1) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix1,bix5) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix2,bix2) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix3) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix3,bix6) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix4) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix4,bix6) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix5,bix5) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix4) == UINT32_MAX);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix6,bix6) == 0);
    CPPUNIT_ASSERT(bpfwder_->GetMatrix(bix7,bix7) == 0);
  }

  //===========================================================================
  void TestFindShortestPath()
  {
    uint32_t  i = UINT32_MAX;

    const uint32_t  connect_matrix[7][7] = {{0, 2, 1, 1, i, i, i},
                                            {2, 0, i, i, i, i, i},
                                            {1, i, 0, i, 3, 5, i},
                                            {1, i, i, 0, i, 7, 1},
                                            {i, i, 3, i, 0, i, i},
                                            {i, i, 5, 7, i, 0, 3},
                                            {i, i, i, 1, i, 3, 0}};

    const uint64_t  var_matrix[7][7]     = {{0, 0, 0, 0, 0, 0, 0},
                                            {0, 0, 0, 0, 0, 0, 0},
                                            {0, 0, 0, 0, 0, 0, 0},
                                            {0, 0, 0, 0, 0, 0, 0},
                                            {0, 0, 0, 0, 0, 0, 0},
                                            {0, 0, 0, 0, 0, 0, 0},
                                            {0, 0, 0, 0, 0, 0, 0}};

    uint32_t  min_cost[7];
    uint64_t  min_var[7];
    uint32_t  next_hop[7];

    bpfwder_->FillMatrixWithValues(connect_matrix, var_matrix);

    // Find the set of shortest paths from node id 0.
    bpfwder_->ShortestPath(0);
    bpfwder_->GetShortestPathResults(min_cost, min_var, next_hop);
    LogD(kClassName, __func__,
         "Cost from 5 to 0: %" PRIu32 "ms through node %" PRIu32 ".\n",
         min_cost[5], next_hop[5]);

    CPPUNIT_ASSERT((min_cost[1] == 2) && (next_hop[1] == 0));
    CPPUNIT_ASSERT((min_cost[2] == 1) && (next_hop[2] == 0));
    CPPUNIT_ASSERT((min_cost[3] == 1) && (next_hop[3] == 0));
    CPPUNIT_ASSERT((min_cost[4] == 4) && (next_hop[4] == 2));
    CPPUNIT_ASSERT((min_cost[5] == 5) && (next_hop[5] == 6));
    CPPUNIT_ASSERT((min_cost[6] == 2) && (next_hop[6] == 3));

    // Find the set of shortest paths from node id 6.
    bpfwder_->ShortestPath(6);
    bpfwder_->GetShortestPathResults(min_cost, min_var, next_hop);
    LogD(kClassName, __func__,
         "Cost from 2 to 6: %" PRIu32 "ms through node %" PRIu32 ".\n",
         min_cost[2], next_hop[2]);

    CPPUNIT_ASSERT((min_cost[0] == 2) && (next_hop[0] == 3));
    CPPUNIT_ASSERT((min_cost[1] == 4) && (next_hop[1] == 0));
    CPPUNIT_ASSERT((min_cost[2] == 3) && (next_hop[2] == 0));
    CPPUNIT_ASSERT((min_cost[3] == 1) && (next_hop[3] == 6));
    CPPUNIT_ASSERT((min_cost[4] == 6) && (next_hop[4] == 2));
    CPPUNIT_ASSERT((min_cost[5] == 3) && (next_hop[5] == 6));
    CPPUNIT_ASSERT((min_cost[6] == 0) && (next_hop[6] == 6));
  }

  //===========================================================================
  void TestFindShortestPathWVar()
  {
    uint32_t  i = UINT32_MAX;

    const uint32_t  connect_matrix[7][7] = {{0, 2, 1, 1, i, i, i},
                                            {2, 0, i, i, i, i, i},
                                            {1, i, 0, i, 3, 5, i},
                                            {1, i, i, 0, i, 7, 1},
                                            {i, i, 3, i, 0, i, i},
                                            {i, i, 5, 7, i, 0, 3},
                                            {i, i, i, 1, i, 3, 0}};

    const uint64_t  var_matrix[7][7]     = {{ 0, 0, 1, 10, 0,  0,  0},
                                            { 0, 0, 0,  0, 0,  0,  0},
                                            { 1, 0, 0,  0, 0,  1,  0},
                                            {10, 0, 0,  0, 0, 10, 10},
                                            { 0, 0, 0,  0, 0,  0,  0},
                                            { 0, 0, 1, 10, 0,  0, 10},
                                            { 0, 0, 0, 10, 0, 10,  0}};

    uint32_t  min_cost[7];
    uint64_t  min_var[7];
    uint32_t  next_hop[7];

    bpfwder_->FillMatrixWithValues(connect_matrix, var_matrix);

    // Find the set of shortest paths from node id 0.
    bpfwder_->ShortestPath(0);
    bpfwder_->GetShortestPathResults(min_cost, min_var, next_hop);
    LogD(kClassName, __func__,
         "Cost from 5 to 0: %" PRIu32 "us (var: %" PRIu32 "us2) through node %"
         PRIu32".\n",
         min_cost[5], min_var[5], next_hop[5]);

    CPPUNIT_ASSERT((min_cost[1] == 2) && (min_var[1] == 0) &&
      (next_hop[1] == 0));
    CPPUNIT_ASSERT((min_cost[2] == 1) && (min_var[2] == 1) &&
      (next_hop[2] == 0));
    CPPUNIT_ASSERT((min_cost[3] == 1) && (min_var[3] == 10) &&
      (next_hop[3] == 0));
    CPPUNIT_ASSERT((min_cost[4] == 4) && (min_var[4] == 1) &&
      (next_hop[4] == 2));
    CPPUNIT_ASSERT((min_cost[5] == 6) && (min_var[5] == 2) &&
      (next_hop[5] == 2));
    CPPUNIT_ASSERT((min_cost[6] == 2) && (min_var[6] == 20) &&
      (next_hop[6] == 3));

    // Find the set of shortest paths from node id 6.
    bpfwder_->ShortestPath(6);
    bpfwder_->GetShortestPathResults(min_cost, min_var, next_hop);
    LogD(kClassName, __func__,
         "Cost from 2 to 6: %" PRIu32 "ms through node %" PRIu32 ".\n",
         min_cost[2], next_hop[2]);

    CPPUNIT_ASSERT((min_cost[1] == 4) && (min_var[1] == 20) &&
      (next_hop[1] == 0));
    CPPUNIT_ASSERT((min_cost[2] == 3) && (min_var[2] == 21) &&
      (next_hop[2] == 0));
    CPPUNIT_ASSERT((min_cost[3] == 1) && (min_var[3] == 10) &&
      (next_hop[3] == 6));
    CPPUNIT_ASSERT((min_cost[4] == 6) && (min_var[4] == 21) &&
      (next_hop[4] == 2));
    CPPUNIT_ASSERT((min_cost[5] == 3) && (min_var[5] == 10) &&
      (next_hop[5] == 6));
    CPPUNIT_ASSERT((min_cost[6] == 0) && (min_var[6] == 0) &&
      (next_hop[6] == 6));
  }

  //===========================================================================
  void TestGetPerPcLatencyToDst()
  {
    for (uint8_t i = 0; i < 4; ++i)
    {
      bpfwder_->ClearVariance();
    }

    std::vector<std::pair<BinId, uint32_t> > nbr_list;
    std::vector<std::pair<BinId, uint64_t> > var_list;

    // Add records as if received from LSAs. These take BinIds, as if they
    // came off the wire.
    // Neighbor list data is:  (src_bin_id, cost)
    // Variance list data is:  (src_bin_id, variance)
    nbr_list.push_back(std::pair<BinId, uint32_t> (2, 2000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (2, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    bpfwder_->AddRecord(1, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 2000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    bpfwder_->AddRecord(2, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (5, 3000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 5000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (5, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    bpfwder_->AddRecord(3, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    bpfwder_->AddRecord(4, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    bpfwder_->AddRecord(5, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 5000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    bpfwder_->AddRecord(6, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    bpfwder_->AddRecord(7, nbr_list, var_list);

    bpfwder_->PrintRecords();

    // Make sure that method rejects bad input destination bin id
    // kInvalidBinIndex.
    CPPUNIT_ASSERT(!bpfwder_->GetPerPcLatencyToDst(
                     iron::kInvalidBinIndex, (uint32_t*)NULL, false));

    // There are 3 path controllers.  Get latency to dest 5 (bin id 6) through
    // all controllers.
    uint32_t  latency_us[4];
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 6 is %" PRIu32
         "ms.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 6000);
    CPPUNIT_ASSERT(latency_us[2] == 5000);
    CPPUNIT_ASSERT(latency_us[3] == 14000);

    // Make sure the cache is working.
    std::memset(latency_us, 0, sizeof(latency_us));
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 6000);
    CPPUNIT_ASSERT(latency_us[2] == 5000);
    CPPUNIT_ASSERT(latency_us[3] == 14000);

    // There are 4 path controllers.  Get latency to dest 1 (bin id 2) through
    // all controllers.
    std::memset(latency_us, 0, sizeof(latency_us));
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(2), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 2 is %" PRIu32
         "ms.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == 2000);
    CPPUNIT_ASSERT(latency_us[1] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[2] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[3] == UINT32_MAX);

    // Simulate receiving an LSA, and check the new results.
    // Create spoof lsa packet.
    Packet* lsa = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);

    bpfwder_->SendDummyLsa(lsa, *pkt_pool_);

    // Create a dummy path controller on which the LSA could have come.
    iron::PathController* pc  = new (std::nothrow) iron::Sond(
      bpfwder_, *pkt_pool_, *timer_);
    CPPUNIT_ASSERT(pc);

    // Process it.
    bpfwder_->ProcessRcvdPacket(lsa, pc);

    delete pc;

    // There are 4 path controllers.  Get latency to dest 5 (bin id 6) through
    // all controllers.
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 6 is %" PRIu32
         "us.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 6000);
    CPPUNIT_ASSERT(latency_us[2] == 8000);
    CPPUNIT_ASSERT(latency_us[3] == 17000);

    pkt_pool_->Recycle(lsa);
  }

  //===========================================================================
  void TestGetPerPcLatencyToDstWVar()
  {
    std::vector<std::pair<BinId, uint32_t> > nbr_list;
    std::vector<std::pair<BinId, uint64_t> > var_list;

    // Add records as if received from LSAs. These take BinIds, as if they
    // came off the wire.
    // Neighbor list data is:  (src_bin_id, cost)
    // Variance list data is:  (src_bin_id, variance)
    nbr_list.push_back(std::pair<BinId, uint32_t> (2, 2000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (2, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 10000));
    bpfwder_->AddRecord(1, nbr_list, var_list);

    nbr_list.clear();
    var_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 2000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    bpfwder_->AddRecord(2, nbr_list, var_list);

    nbr_list.clear();
    var_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (5, 3000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 5000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (5, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 1000));
    bpfwder_->AddRecord(3, nbr_list, var_list);

    nbr_list.clear();
    var_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 10000));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 10000));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 10000));
    bpfwder_->AddRecord(4, nbr_list, var_list);

    nbr_list.clear();
    var_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    bpfwder_->AddRecord(5, nbr_list, var_list);

    nbr_list.clear();
    var_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 5000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 10000));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 10000));
    bpfwder_->AddRecord(6, nbr_list, var_list);

    nbr_list.clear();
    var_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 10000));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 10000));
    bpfwder_->AddRecord(7, nbr_list, var_list);

    // Make sure that method rejects bad input destination bin id
    // kInvalidBinIndex.
    CPPUNIT_ASSERT(!bpfwder_->GetPerPcLatencyToDst(
                     iron::kInvalidBinIndex, NULL, false));

    // There are 3 path controllers.  Get latency to dest 5 (bin id 6) through
    // all controllers.
    uint32_t  latency_us[4];
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 6 is %" PRIu32
         "ms.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 6098);
    CPPUNIT_ASSERT(latency_us[2] == 5381);
    CPPUNIT_ASSERT(latency_us[3] == 14381);

    // Make sure the cache is working.
    std::memset(latency_us, 0, sizeof(latency_us));
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 6098);
    CPPUNIT_ASSERT(latency_us[2] == 5381);
    CPPUNIT_ASSERT(latency_us[3] == 14381);

    // There are 4 path controllers.  Get latency to dest 1 (bin id 2) through
    // all controllers.
    std::memset(latency_us, 0, sizeof(latency_us));
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(2), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 1 is %" PRIu32
         "ms.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == 2000);
    CPPUNIT_ASSERT(latency_us[1] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[2] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[3] == UINT32_MAX);

    // Simulate receiving an LSA, and check the new results.
    // Create spoof lsa packet.
    Packet* lsa = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);

    bpfwder_->SendDummyLsa(lsa, *pkt_pool_, true);

    // Create a dummy path controller on which the LSA could have come.
    iron::PathController* pc  = new (std::nothrow) iron::Sond(
      bpfwder_, *pkt_pool_, *timer_);
    CPPUNIT_ASSERT(pc);

    // Process it.
    bpfwder_->ProcessRcvdPacket(lsa, pc);

    delete pc;

    // There are 4 path controllers.  Get latency to dest 5 (bin id 6) through
    // all controllers.
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 6 is %" PRIu32
         "us.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 6098);
    CPPUNIT_ASSERT(latency_us[2] == 8311);
    CPPUNIT_ASSERT(latency_us[3] == 17311);

    pkt_pool_->Recycle(lsa);
  }

  //===========================================================================
  void TestGetPerPcLatencyToDstWQueueDelay()
  {
    bpfwder_->IncludeQueueDelays(true);
    bpfwder_->ClearVariance();
    std::vector<std::pair<BinId, uint32_t> > nbr_list;
    std::vector<std::pair<BinId, uint64_t> > var_list;

    // Add records as if received from LSAs. These take BinIds, as if they
    // came off the wire.
    // Neighbor list data is:  (src_bin_id, cost)
    // Variance list data is:  (src_bin_id, variance)
    nbr_list.push_back(std::pair<BinId, uint32_t> (2, 2000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (2, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    uint32_t  queue_delays[7];
    memset(queue_delays, 0, sizeof(queue_delays));
    queue_delays[bin_map_->GetPhyBinIndex(6)]  = 10000;
    queue_delays[bin_map_->GetPhyBinIndex(7)]  = 20000;
    bpfwder_->AddRecord(1, nbr_list, var_list, queue_delays, 7);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 2000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    queue_delays[bin_map_->GetPhyBinIndex(6)]  = 0;
    queue_delays[bin_map_->GetPhyBinIndex(7)]  = 0;
    bpfwder_->AddRecord(2, nbr_list, var_list, queue_delays, 7);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (5, 3000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 5000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (5, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    queue_delays[bin_map_->GetPhyBinIndex(6)]  = 4000;
    queue_delays[bin_map_->GetPhyBinIndex(7)]  = 8000;
    bpfwder_->AddRecord(3, nbr_list, var_list, queue_delays, 7);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    queue_delays[bin_map_->GetPhyBinIndex(6)]  = 0;
    queue_delays[bin_map_->GetPhyBinIndex(7)]  = 0;
    bpfwder_->AddRecord(4, nbr_list, var_list, queue_delays, 7);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    queue_delays[bin_map_->GetPhyBinIndex(6)]  = 3000;
    queue_delays[bin_map_->GetPhyBinIndex(7)]  = 0;
    bpfwder_->AddRecord(5, nbr_list, var_list, queue_delays, 7);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 5000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    queue_delays[bin_map_->GetPhyBinIndex(6)]  = 0;
    queue_delays[bin_map_->GetPhyBinIndex(7)]  = 6000;
    bpfwder_->AddRecord(6, nbr_list, var_list, queue_delays, 7);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    queue_delays[bin_map_->GetPhyBinIndex(6)]  = 0;
    queue_delays[bin_map_->GetPhyBinIndex(7)]  = 0;
    bpfwder_->AddRecord(7, nbr_list, var_list, queue_delays, 7);

    bpfwder_->PrintRecords();

    // Make sure that method rejects bad input destination bin id
    // kInvalidBinIndex.
    CPPUNIT_ASSERT(!bpfwder_->GetPerPcLatencyToDst(
                     iron::kInvalidBinIndex, NULL, false));

    // There are 3 path controllers.  Get latency to dest 5 (bin id 6) through
    // all controllers.
    uint32_t  latency_us[4];
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 6 is %" PRIu32
         "ms.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);

    CPPUNIT_ASSERT(latency_us[1] == 10000);
    CPPUNIT_ASSERT(latency_us[2] == 5000);
    CPPUNIT_ASSERT(latency_us[3] == 14000);

    // Make sure the cache is working.
    std::memset(latency_us, 0, sizeof(latency_us));
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 10000);
    CPPUNIT_ASSERT(latency_us[2] == 5000);
    CPPUNIT_ASSERT(latency_us[3] == 14000);

    // Add the local queue delay.
    std::memset(latency_us, 0, sizeof(latency_us));
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, true));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 6 is %" PRIu32
         "ms.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 10000 + (10000 & 0xFFFFFF00));
    CPPUNIT_ASSERT(latency_us[2] == 5000 + (10000 & 0xFFFFFF00));
    CPPUNIT_ASSERT(latency_us[3] == 14000 + (10000 & 0xFFFFFF00));

    // There are 4 path controllers.  Get latency to dest 1 (bin id 2) through
    // all controllers.
    std::memset(latency_us, 0, sizeof(latency_us));
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(2), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 1 is %" PRIu32
         "ms.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == 2000);
    CPPUNIT_ASSERT(latency_us[1] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[2] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[3] == UINT32_MAX);

    // Simulate receiving an LSA, and check the new results.
    // Create spoof lsa packet.
    Packet* lsa = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);

    bpfwder_->SendDummyLsa(lsa, *pkt_pool_);

    // Create a dummy path controller on which the LSA could have come.
    iron::PathController* pc  = new (std::nothrow) iron::Sond(
      bpfwder_, *pkt_pool_, *timer_);
    CPPUNIT_ASSERT(pc);

    // Process it.
    bpfwder_->ProcessRcvdPacket(lsa, pc);

    delete pc;

    bpfwder_->PrintRecords();

    // There are 4 path controllers.  Get latency to dest 5 (bin id 6) through
    // all controllers.
    CPPUNIT_ASSERT(bpfwder_->GetPerPcLatencyToDst(
                     bin_map_->GetPhyBinIndex(6), latency_us, false));
    LogD(kClassName, __func__,
         "Latency from path controller 1 to destination bin id 6 is %" PRIu32
         "us.\n",
         latency_us[1]);

    CPPUNIT_ASSERT(latency_us[0] == UINT32_MAX);
    CPPUNIT_ASSERT(latency_us[1] == 10000);
    CPPUNIT_ASSERT(latency_us[2] == 8000);
    CPPUNIT_ASSERT(latency_us[3] == 17000);

    pkt_pool_->Recycle(lsa);
  }

  //==========================================================================
  void TestBPFAlg()
  {
    BinId                 bin  = 0;
    iron::PathController* nbr  = NULL;

    std::vector<std::pair<BinId, uint32_t> > nbr_list;
    std::vector<std::pair<BinId, uint64_t> > var_list;

    // Add records as if received from LSAs.
    // Neighbor list data is:  (src_bin_id, cost)
    // Variance list data is:  (src_bin_id, variance)
    nbr_list.push_back(std::pair<BinId, uint32_t> (2, 2000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (2, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    bpfwder_->AddRecord(1, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 2000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    bpfwder_->AddRecord(2, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (5, 3000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 5000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (5, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    bpfwder_->AddRecord(3, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (1, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 1000));
    var_list.push_back(std::pair<BinId, uint64_t> (1, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    bpfwder_->AddRecord(4, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    bpfwder_->AddRecord(5, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (3, 5000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 7000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (7, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (3, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (7, 0));
    bpfwder_->AddRecord(6, nbr_list, var_list);

    nbr_list.clear();
    nbr_list.push_back(std::pair<BinId, uint32_t> (4, 1000));
    nbr_list.push_back(std::pair<BinId, uint32_t> (6, 3000));
    var_list.push_back(std::pair<BinId, uint64_t> (4, 0));
    var_list.push_back(std::pair<BinId, uint64_t> (6, 0));
    bpfwder_->AddRecord(7, nbr_list, var_list);

    // Test the operation of the BPF algorithm when a Low-Latency packet
    // (DSCP 0) is present.
    Packet* p = pkt_pool_->Get(iron::PACKET_NOW_TIMESTAMP);
    CPPUNIT_ASSERT(p);
    p->SetLengthInBytes(100);

    // We need to make sure that the Packet object is an IPv4 packet.
    struct iphdr  ip_hdr;
    // Populate an IP header with some dummy values.
    memset(&ip_hdr, 0, sizeof(ip_hdr));
    ip_hdr.version  = 4;
    ip_hdr.ihl      = 5;
    ip_hdr.tos      = 0;
    ip_hdr.id       = 16;
    ip_hdr.frag_off = 0;
    ip_hdr.ttl      = 16;
    ip_hdr.protocol = IPPROTO_TCP;
    ip_hdr.check    = 0;
    ip_hdr.saddr    = htonl(1);
    ip_hdr.daddr    = htonl(2);
    ip_hdr.tot_len  = htons(sizeof(ip_hdr));

    memcpy(p->GetBuffer(), reinterpret_cast<void*>(&ip_hdr), sizeof(ip_hdr));

    CPPUNIT_ASSERT(p->SetIpDscp(46));
    p->SetTimeToGo(iron::Time(0, 5500000));
    CPPUNIT_ASSERT(bpfwder_->EnqueuePacket(p, 6));

    LogD(kClassName, __func__,
         "*** Test DSCP 0 Pkt ***\n");
    bpfwder_->SetUpBPFLowLatAlgTest(0);
    bpfwder_->FindNextTransmissionTest(bin, nbr);
    CPPUNIT_ASSERT(bin == 6);
    CPPUNIT_ASSERT(nbr->remote_bin_id() == 3);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(LinkStateTest);
