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
#include "path_controller.h"
#include "sond.h"

#include "bin_map.h"
#include "callback.h"
#include "config_info.h"
#include "fifo_if.h"
#include "ipv4_address.h"
#include "itime.h"
#include "log.h"
#include "shared_memory.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "port_number_mgr.h"
#include "queue_depths.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "timer.h"

#include "iron_types.h"
#include <cstring>
#include <list>

using ::iron::BinId;
using ::iron::BinIndex;
using ::iron::BinMap;
using ::iron::BPFwder;
using ::iron::CallbackNoArg;
using ::iron::ConfigInfo;
using ::iron::FifoIF;
using ::iron::Ipv4Address;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::PathController;
using ::iron::PortNumberMgr;
using ::iron::QueueStore;
using ::iron::QueueDepths;
using ::iron::PseudoFifo;
using ::iron::PseudoSharedMemory;
using ::iron::SharedMemoryIF;
using ::iron::Sond;
using ::iron::Time;
using ::iron::Timer;

using ::std::list;
using ::std::string;
using ::std::vector;

const char  kClassName[]  = "SondTester";

// The QueueStore is the default algorithm, which is base (no heavy ball)
// as of 10Feb16.

//============================================================================
// A child class of the backpressure forwarder for testing SONDs.  This class
// acts as either the SOND source or the SOND sink.
class SondTester : public BPFwder
{
public:

  SondTester(PacketPool& packet_pool, BinMap& bin_map, Timer& timer,
             SharedMemoryIF& weight_qd_shared_memory,
             vector<PseudoFifo*>* fifos, ConfigInfo& config_info);
  virtual ~SondTester();

  // New methods.
  void InitForTest(int node_id, string node1_port, string node2_port, ConfigInfo& ci);
  int GetSondSendRateKbps();
  int GetSondCount();
  int GetDataQueueLengthInBytes();
  void SendTestPackets(int num_qlams, int num_pkts, int* pkt_len_bytes,
                       int& qlam_pkt_queued_bytes);
  void SetShutdownTime(uint32_t sec);
  void Shutdown();
  void GetSendStats(int& data_pkt_cnt, int& data_pkt_bytes,
                    int& qlam_pkt_cnt, int& qlam_pkt_bytes);
  void GetRecvStats(int& data_pkt_cnt, int& data_pkt_bytes,
                    int& qlam_pkt_cnt, int& qlam_pkt_bytes);
  double ComputeRecvRateBitsPerSecond();
  bool CheckQlamIntervalCalc();

  // Method overriding.
  virtual void ProcessRcvdPacket(Packet* packet, PathController* sond = NULL);
  virtual void SendQlamToPathCtrl(uint32_t path_ctrl_num, uint32_t sn);
  virtual void SendNewLsa();
  virtual bool InitializeBinMap(const ConfigInfo& config_info);
  virtual bool InitializeFifos();

private:

  SondTester(const SondTester& other);
  SondTester& operator=(const SondTester& other);

  PacketPool&          pkt_pool_;
  BinMap&              bin_map_;
  Timer&               timer_;
  vector<PseudoFifo*>* fifos_;
  iron::Timer::Handle  shutdown_handle_;
  int                  node_id_;
  int                  sond_send_rate_kbps_;
  int                  send_data_cnt_;
  int                  send_data_bytes_;
  int                  send_qlam_cnt_;
  int                  send_qlam_bytes_;
  int                  recv_data_cnt_;
  int                  recv_data_bytes_;
  int                  recv_qlam_cnt_;
  int                  recv_qlam_bytes_;
  int                  rate_comp_bytes_;
  int                  first_recv_bytes_;
  uint64_t             start_time_usec_;
  uint64_t             end_time_usec_;
};

//============================================================================
SondTester::SondTester(PacketPool& packet_pool, BinMap& bin_map, Timer& timer,
                       SharedMemoryIF& weight_qd_shared_memory,
                       vector<PseudoFifo*>* fifos, ConfigInfo& config_info)
    : BPFwder(packet_pool, timer, bin_map, weight_qd_shared_memory,
              BPF_FIFO_ARGS(fifos), config_info),
      pkt_pool_(packet_pool), bin_map_(bin_map), timer_(timer), fifos_(fifos),
      shutdown_handle_(), node_id_(0), sond_send_rate_kbps_(1),
      send_data_cnt_(0), send_data_bytes_(0), send_qlam_cnt_(0),
      send_qlam_bytes_(0), recv_data_cnt_(0), recv_data_bytes_(0),
      recv_qlam_cnt_(0), recv_qlam_bytes_(0), rate_comp_bytes_(0),
      first_recv_bytes_(0), start_time_usec_(0), end_time_usec_(0)
{ }

//============================================================================
SondTester::~SondTester()
{
  // Cancel any timer.
  timer_.CancelTimer(shutdown_handle_);

  // Clean up the timer callback object pools.
  CallbackNoArg<SondTester>::EmptyPool();
  PseudoFifo::DeleteBpfFifos(fifos_);
}

//============================================================================
void SondTester::InitForTest(int node_id, string node1_port,
                             string node2_port, ConfigInfo& ci)
{
  // Store the node ID.
  node_id_ = node_id;

  if (node_id == 1)
  {
    sond_send_rate_kbps_ = 8;  // Must match maxLineRate setting below!
  }
  else
  {
    sond_send_rate_kbps_ = 16;  // Must match maxLineRate setting below!
  }

  CPPUNIT_ASSERT(this->Initialize());

  // Set up queue depths for the QLAM packets.
  // Bin 5: 20B.
  iron::BinIndex  bidx  = bin_map_.GetPhyBinIndex(5);
  QueueDepths* qd =
    queue_store_->GetBinQueueMgr(bidx)->GetQueueDepthsForBpfQlam();
  qd    = queue_store_->GetBinQueueMgr(bidx)->GetQueueDepthsForBpfQlam();
  CPPUNIT_ASSERT(qd);
  qd->SetBinDepthByIdx(bidx, 20);

  // Bin 10: 10B.
  bidx  = bin_map_.GetPhyBinIndex(10);
  qd    = queue_store_->GetBinQueueMgr(bidx)->GetQueueDepthsForBpfQlam();
  CPPUNIT_ASSERT(qd);
  qd->SetBinDepthByIdx(bidx, 10);

  // Bin 1: 100B.
  bidx  = bin_map_.GetPhyBinIndex(1);
  qd    = queue_store_->GetBinQueueMgr(bidx)->GetQueueDepthsForBpfQlam();
  CPPUNIT_ASSERT(qd);
  qd->SetBinDepthByIdx(bidx, 100);

  // Bin 2: 100B.
  bidx  = bin_map_.GetPhyBinIndex(2);
  qd    = queue_store_->GetBinQueueMgr(bidx)->GetQueueDepthsForBpfQlam();
  CPPUNIT_ASSERT(qd);
  qd->SetBinDepthByIdx(bidx, 100);
}

//============================================================================
int SondTester::GetSondSendRateKbps()
{
  return sond_send_rate_kbps_;
}

//============================================================================
int SondTester::GetSondCount()
{
  return num_path_ctrls_;
}

//============================================================================
int SondTester::GetDataQueueLengthInBytes()
{
  CPPUNIT_ASSERT(num_path_ctrls_ == 1);

  PathController*  sond   = path_ctrls_[0].path_ctrl;
  size_t           q_size = 0;

  CPPUNIT_ASSERT(sond->GetXmitQueueSize(q_size));

  return (int)q_size;
}

//============================================================================
void SondTester::SendTestPackets(int num_qlams, int num_pkts,
                                 int* pkt_len_bytes,
                                 int& qlam_pkt_queued_bytes)
{
  CPPUNIT_ASSERT(num_path_ctrls_ == 1);

  PathController*  sond = path_ctrls_[0].path_ctrl;

  // Send QLAMs.
  for (int i = 0; i < num_qlams; ++i)
  {
    Packet*  qlam = pkt_pool_.Get();
    ::memset(qlam->GetBuffer(), 0, qlam->GetMaxLengthInBytes());
    BinId  dest_bin_id = 0;
    if (node_id_ == 1)
    {
      dest_bin_id = 2;
    }
    else
    {
      dest_bin_id = 1;
    }
    BinIndex  dest_bin_idx = bin_map_shm_.GetPhyBinIndex(dest_bin_id);
    CPPUNIT_ASSERT(GenerateQlam(qlam, dest_bin_idx,
                                Time::Now().GetTimeInUsec()));
    int  qlam_len = (int)qlam->GetLengthInBytes();
    sond->SendPacket(qlam);
    send_qlam_cnt_   += 1;
    send_qlam_bytes_ += qlam_len;

    if (i != 0)
    {
      // The SOND will send the first QLAM packet immediately, so it will not be
      // in the queue when we check later.  Additionally, the SOND only can
      // queue a single QLAM packet at a time.  Account for this in the total
      // number of queued QLAM packet bytes passed back to the test jig.
      qlam_pkt_queued_bytes = qlam_len;
    }
  }

  // Create a data packet template.
  unsigned char   my_msg[] = " SOND unit test packet";
  Packet*         data_pkt = pkt_pool_.Get();
  data_pkt->SetLengthInBytes(data_pkt->GetMaxLengthInBytes());
  ::memset(data_pkt->GetBuffer(), 0, data_pkt->GetMaxLengthInBytes());
  ::memcpy(data_pkt->GetBuffer(), &(my_msg[0]), sizeof(my_msg));
  uint8_t*  tmp_buf = data_pkt->GetBuffer();
  tmp_buf[0] = 0x45;

  // Send data packets.
  for (int j = 0; j < num_pkts; ++j)
  {
    Packet*  pkt = pkt_pool_.Get();
    *pkt = *data_pkt;
    pkt->SetLengthInBytes(pkt_len_bytes[j]);
    int  pkt_len = (int)pkt->GetLengthInBytes();
    CPPUNIT_ASSERT(sond->SendPacket(pkt));
    send_data_cnt_   += 1;
    send_data_bytes_ += pkt_len;
  }

  // Free the data packet template.
  pkt_pool_.Recycle(data_pkt);
}

//============================================================================
void SondTester::SetShutdownTime(uint32_t sec)
{
  CallbackNoArg<SondTester>  cb(this, &SondTester::Shutdown);
  Time                       delta_time = Time::FromSec(sec);

  CPPUNIT_ASSERT(timer_.StartTimer(delta_time, &cb,
                                   shutdown_handle_) == true);
}

//============================================================================
void SondTester::Shutdown()
{
  CPPUNIT_ASSERT(running_ == true);

  running_ = false;
}

//============================================================================
void SondTester::GetSendStats(int& data_pkt_cnt, int& data_pkt_bytes,
                              int& qlam_pkt_cnt, int& qlam_pkt_bytes)
{
  data_pkt_cnt   = send_data_cnt_;
  data_pkt_bytes = send_data_bytes_;
  qlam_pkt_cnt   = send_qlam_cnt_;
  qlam_pkt_bytes = send_qlam_bytes_;
}

//============================================================================
void SondTester::GetRecvStats(int& data_pkt_cnt, int& data_pkt_bytes,
                              int& qlam_pkt_cnt, int& qlam_pkt_bytes)
{
  data_pkt_cnt   = recv_data_cnt_;
  data_pkt_bytes = recv_data_bytes_;
  qlam_pkt_cnt   = recv_qlam_cnt_;
  qlam_pkt_bytes = recv_qlam_bytes_;
}

//============================================================================
double SondTester::ComputeRecvRateBitsPerSecond()
{
  CPPUNIT_ASSERT(end_time_usec_ > start_time_usec_);

  // Compute the rate in kbps.  Recall that we need to ignore the first packet
  // received due to the packet transmission delays -- we cannot tell when the
  // first packet was actually transmitted.
  return (((double)(rate_comp_bytes_ - first_recv_bytes_) * 8000.0) /
          (double)(end_time_usec_ - start_time_usec_));
}

//============================================================================
bool SondTester::CheckQlamIntervalCalc()
{
  // Set the minimum allowable capacity estimate to 1000 bits per second for
  // these tests.
  min_path_ctrl_cap_est_bps_ = 1000;

  // Add a new SOND to the BPFwder.
  CPPUNIT_ASSERT(path_ctrls_[1].path_ctrl == NULL);

  Sond*           sond     = new (std::nothrow) Sond(this, pkt_pool_, timer_);
  PortNumberMgr&  port_mgr = PortNumberMgr::GetInstance();
  ConfigInfo      ci;

  ci.Add("PathController.1.Type", "Sond");

  string  ep_str = "127.0.0.1:" + port_mgr.NextAvailableStr() +
    "->127.0.0.1:" + port_mgr.NextAvailableStr();

  ci.Add("PathController.1.Endpoints", ep_str);
  ci.Add("PathController.1.MaxLineRateKbps", "8");

  path_ctrls_[1].path_ctrl = sond;
  num_path_ctrls_          = 2;
  CPPUNIT_ASSERT(sond->Initialize(ci, 1));

  // Test case when capacity is 10000, QLAMs 64B
  last_qlam_size_bits_        = 512;
  uint64_t new_chan_capacity  = 10000;
  uint64_t new_trans_capacity = 8000;
  // Set the capacity, do not check the qlam interval---it will have bucketed
  // an unknown number of bits already, so predicting the correct answer is not
  // straighforward
  ProcessCapacityUpdate(sond, new_chan_capacity, new_trans_capacity);

  Time  t;
  path_ctrls_[1].bucket_depth_bits = 0.0;
  CPPUNIT_ASSERT(ComputeNextQlamTimer(path_ctrls_[1], t));
  uint64_t time_intv_usec = t.GetTimeInUsec();
  // Answer should be: 1e6*64*8 / (1e4*0.01): 5.1200000, but rounding / casting
  // errors give 5.1200001:
  uint64_t mask = -2;
  CPPUNIT_ASSERT((time_intv_usec & mask) ==
                 static_cast<uint64_t>(
                   1000000.0 *
                   static_cast<double>(last_qlam_size_bits_)
                   / (static_cast<double>(new_chan_capacity) * 0.01)));

  // Test what happens when the bucket is not 0:
  uint32_t bucket = last_qlam_size_bits_ - 10;
  path_ctrls_[1].bucket_depth_bits = static_cast<double>(bucket);
  CPPUNIT_ASSERT(ComputeNextQlamTimer(path_ctrls_[1], t));
  time_intv_usec = t.GetTimeInUsec();
  // Answer should be: (1e6*10) / (1e4*0.01): 0.100000:
  mask = -2;
  CPPUNIT_ASSERT((time_intv_usec & mask) ==
                 static_cast<uint64_t>(
                   1000000.0 *
                   static_cast<double>(last_qlam_size_bits_ - bucket)
                   / (static_cast<double>(new_chan_capacity) * 0.01)));

  // Test what happens when the bucket is already filled:
  bucket = new_chan_capacity;
  path_ctrls_[1].bucket_depth_bits = static_cast<double>(bucket);
  CPPUNIT_ASSERT(ComputeNextQlamTimer(path_ctrls_[1], t));
  time_intv_usec = t.GetTimeInUsec();
  // Answer should be: 0 (go out now)
  CPPUNIT_ASSERT(time_intv_usec == 0);

  // Test what happens when the rate is 0:
  // * ComputeNextQlamTimer sets the rate to 1000bps, so the answer should be:
  //    1e6*64*8 / (1e3*0.01): 51.2s.
  // * Deprecated:  ComputeNextQlamTimer returns 0 and sets tv to the largest
  //                allowed (1hr in us): 3600000000.
  new_chan_capacity = 0;
  path_ctrls_[1].bucket_depth_bits = 0.0;
  ProcessCapacityUpdate(sond, new_chan_capacity, new_trans_capacity);
  path_ctrls_[1].bucket_depth_bits = 0.0;
  CPPUNIT_ASSERT(ComputeNextQlamTimer(path_ctrls_[1], t));
  time_intv_usec = t.GetTimeInUsec();
  CPPUNIT_ASSERT((time_intv_usec & mask) ==
                 static_cast<uint64_t>(
                   1000000.0 * static_cast<double>(last_qlam_size_bits_)
                   / (1000.0 * 0.01)));

  return true;
}

//============================================================================
void SondTester::ProcessRcvdPacket(Packet* packet, PathController* sond)
{
  Time           now;
  struct iphdr*  ip_hdr;
  int            pkt_len = packet->GetLengthInBytes();

  CPPUNIT_ASSERT(packet != NULL);
  ip_hdr = reinterpret_cast<struct iphdr*>(packet->GetBuffer(0));
  CPPUNIT_ASSERT(ip_hdr != NULL);

  // Note that the IP header version will be 4 for data packets.
  if (ip_hdr->version == 4)
  {
    // Data packet.
    recv_data_cnt_   += 1;
    recv_data_bytes_ += pkt_len;
  }
  else
  {
    // Verify the QLAM packet.
    CPPUNIT_ASSERT(packet->GetType() == iron::QLAM_PACKET);
    LogD(kClassName, __func__, "Parsing QLAM.\n");

    // Skip over the 1-byte type in the QLAM packet.
    int  offset = sizeof(uint8_t);

    // Verify the source bin id.
    BinId  src_bin_id = *(packet->GetBuffer(offset));
    LogD(kClassName, __func__,
         "Received QLAM from src %" PRIBinId ".\n",
         src_bin_id);
    iron::BinId  nbr_bin_id = 0;
    if (node_id_ == 1)
    {
      CPPUNIT_ASSERT(src_bin_id == 2);
      nbr_bin_id  = 2;
    }
    else
    {
      CPPUNIT_ASSERT(src_bin_id == 1);
      nbr_bin_id  = 1;
    }
    offset += 1;

    // Skip Sequence Number.
    offset += 4;

    if (!sond->ready())
    {
      BinIndex  nbr_bin_idx = bin_map_shm_.GetPhyBinIndex(nbr_bin_id);
      sond->set_remote_bin_id_idx(nbr_bin_id, nbr_bin_idx);
    }

    // Read and check the number of groups.
    uint16_t num_groups = 0;
    memcpy(&num_groups, packet->GetBuffer(offset), sizeof(num_groups));
    num_groups = ntohs(num_groups);
    LogD(kClassName, __func__, "There are %" PRIu16 " groups.\n", num_groups);
    offset += 2;
    CPPUNIT_ASSERT(num_groups == 1);

    // Read and check the group ID.
    uint32_t  group_id  = 1;
    memcpy(&group_id, packet->GetBuffer(offset), sizeof(group_id));
    LogD(kClassName, __func__,
         "Will read queue depths for group id %s.\n",
         bin_map_.GetIdToLog(ntohl(group_id)).c_str());

    offset += sizeof(group_id);
    CPPUNIT_ASSERT(group_id == 0);

    // Read and check the number of pairs.
    uint8_t num_pairs = *packet->GetBuffer(offset);
    LogD(kClassName, __func__,
         "Will read %" PRIu8 " pairs.\n", num_pairs);
    ++offset;
    CPPUNIT_ASSERT(num_pairs == 4);

    for (uint8_t i = 0; i < num_pairs; ++i)
    {
      BinId         bin_id        = *packet->GetBuffer(offset);
      // Do not increment the offset since will be read by Deserialize method.
      BinIndex      bidx          = bin_map_.GetPhyBinIndex(bin_id);

      QueueDepths*  queue_depths  = queue_store_->PeekNbrQueueDepths(bidx,
        sond->remote_bin_idx());

      size_t        num_dser_bytes=
        queue_depths->Deserialize(packet->GetBuffer(offset), pkt_len - offset,
          1);
      CPPUNIT_ASSERT(num_dser_bytes == 9);
      LogD(kClassName, __func__,
           "Read %zdB for dest bin id %" PRIBinId ".\n",
           num_dser_bytes, bin_id);
      offset += num_dser_bytes;
    }

    BinIndex      bidx          = bin_map_.GetPhyBinIndex(5);
    QueueDepths*  queue_depths  = queue_store_->PeekNbrQueueDepths(bidx,
      sond->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths->GetBinDepthByIdx(bidx) == 20);

    bidx          = bin_map_.GetPhyBinIndex(10);
    queue_depths  = queue_store_->PeekNbrQueueDepths(bidx,
      sond->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths->GetBinDepthByIdx(bidx) == 10);

    bidx          = bin_map_.GetPhyBinIndex(1);
    queue_depths  = queue_store_->PeekNbrQueueDepths(bidx,
      sond->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths->GetBinDepthByIdx(bidx) == 100);

    bidx          = bin_map_.GetPhyBinIndex(2);
    queue_depths  = queue_store_->PeekNbrQueueDepths(bidx,
      sond->remote_bin_idx());
    CPPUNIT_ASSERT(queue_depths->GetBinDepthByIdx(bidx) == 100);

    // QLAM packet.
    recv_qlam_cnt_   += 1;
    recv_qlam_bytes_ += pkt_len;
  }

  CPPUNIT_ASSERT(now.GetNow());
  // Update the reception times and received byte counts.  Note that the SOND
  // waits for a packet's transmission delay *before* the packet is actually
  // sent.  For this reason, the first packet received by this code cannot be
  // counted when computing the receive rate.
  if (start_time_usec_ == 0)
  {
    start_time_usec_ = now.GetTimeInUsec();
  }

  end_time_usec_ = now.GetTimeInUsec();

  rate_comp_bytes_ += pkt_len;

  if (first_recv_bytes_ == 0)
  {
    first_recv_bytes_ = pkt_len;
  }

  // Free the packet's memory.
  pkt_pool_.Recycle(packet);
}

//============================================================================
void SondTester::SendQlamToPathCtrl(uint32_t path_ctrl_num, uint32_t sn)
{
  // Disable the BPF from sending its own QLAMs.
  return;
}

//============================================================================
void SondTester::SendNewLsa()
{
  // Disable the BPF from sending LSAs.
  return;
}

//============================================================================
bool SondTester::InitializeBinMap(const ConfigInfo& config_info)
{
  // Return true even if initialization fails, so that this unit test can
  // Initialize two separate BPFwders without failing on the BinMap re-init.
  bin_map_.Initialize(config_info);
  return true;
}

//============================================================================
// Override function so the FIFOs are not intialized for tests.
bool SondTester::InitializeFifos()
{
  return true;
}

//============================================================================
class SondTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(SondTest);

  CPPUNIT_TEST(TestSonds);

  CPPUNIT_TEST_SUITE_END();

private:

  SondTester*      node1_;
  SondTester*      node2_;
  PacketPoolHeap*  pkt_pool_;
  BinMap*          bin_map1_;
  BinMap*          bin_map2_;
  char*            bin_map1_mem_;
  char*            bin_map2_mem_;
  Timer*           timer_;
  SharedMemoryIF*  weight_qd_shared_memory_1_;
  SharedMemoryIF*  weight_qd_shared_memory_2_;

public:

  //==========================================================================
  void InitializeConfigInfo(int node_id, string node1_port, string node2_port,
                            ConfigInfo& ci)
  {
    PortNumberMgr&  port_mgr = PortNumberMgr::GetInstance();
    string          ep_str;

    // Add backpressure forwarder configuration.
    if (node_id == 1)
    {
      ci.Add("Bpf.BinId", "1");
    }
    else
    {
      ci.Add("Bpf.BinId", "2");
    }

    ci.Add("Bpf.QlamOverheadRatio", "0.01");
    ci.Add("Bpf.Fwder", "Base");
    ci.Add("Bpf.ZombieLatencyReduction", "false");
    ci.Add("Bpf.QueueDelayWeight", "0");

    // Add SOND configuration.  Use localhost IP address.
    if (node_id == 1)
    {
      ci.Add("Bpf.NumPathControllers",  "1");
      ci.Add("PathController.0.Type", "Sond");

      ep_str = "127.0.0.1:" + node1_port + "->127.0.0.1:" + node2_port;
      ci.Add("PathController.0.Endpoints", ep_str);

      ci.Add("PathController.0.MaxLineRateKbps", "8");

      ci.Add("Bpf.RemoteControl.Port", port_mgr.NextAvailableStr());

      ci.Add("Bpf.Weight.SemKey", "11");
      ci.Add("Bpf.Weight.ShmName", "weights_1");
    }
    else
    {
      ci.Add("Bpf.NumPathControllers", "1");
      ci.Add("PathController.0.Type", "Sond");

      ep_str = "127.0.0.1:" + node2_port + "->127.0.0.1:" + node1_port;
      ci.Add("PathController.0.Endpoints", ep_str);

      ci.Add("PathController.0.MaxLineRateKbps", "16");

      ci.Add("Bpf.RemoteControl.Port", port_mgr.NextAvailableStr());

      ci.Add("Bpf.Weight.SemKey", "21");
      ci.Add("Bpf.Weight.ShmName", "weights_2");
    }

    ci.Add("Bpf.Alg.McastAgg", "false");
    ci.Add("Bpf.SendGrams", "false");

    ci.Add("BinMap.BinIds", "1,2,5,10");
    ci.Add("BinMap.BinId.1.HostMasks",
           "192.168.1.0/24,10.1.1.0/24,1.2.3.4");
    ci.Add("BinMap.BinId.2.HostMasks",
           "192.168.2.0/24,10.2.2.2,5.6.7.8");
    ci.Add("BinMap.BinId.5.HostMasks",
           "192.168.3.0/24,10.3.3.3,9.10.11.12");
    ci.Add("BinMap.BinId.10.HostMasks",
           "192.168.4.0/24,10.4.4.4,13.14.15.16");
  }

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");
    timer_ = new Timer();

    weight_qd_shared_memory_1_ = new PseudoSharedMemory();
    weight_qd_shared_memory_2_ = new PseudoSharedMemory();

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_->Create(16) == true);

    PortNumberMgr& port_mgr = PortNumberMgr::GetInstance();
    string node1_port = port_mgr.NextAvailableStr();
    string node2_port = port_mgr.NextAvailableStr();

    // Create and initialize the ConfigInfo objects.
    ConfigInfo  ci1;
    ConfigInfo  ci2;
    InitializeConfigInfo(1, node1_port, node2_port, ci1);
    InitializeConfigInfo(2, node1_port, node2_port, ci2);

    // Create and initialize the BinMap objects.
    bin_map1_mem_ = new char[sizeof(BinMap)];
    bin_map1_     = reinterpret_cast<BinMap*>(bin_map1_mem_);
    memset(bin_map1_mem_, 0, sizeof(BinMap));
    CPPUNIT_ASSERT(bin_map1_->Initialize(ci1));

    bin_map2_mem_ = new char[sizeof(BinMap)];
    bin_map2_     = reinterpret_cast<BinMap*>(bin_map2_mem_);
    memset(bin_map2_mem_, 0, sizeof(BinMap));
    CPPUNIT_ASSERT(bin_map2_->Initialize(ci2));

    // Create the two backpressure forwarders set up for testing.
    node1_ = new (std::nothrow) SondTester(*pkt_pool_, *bin_map1_, *timer_,
                                           *weight_qd_shared_memory_1_,
                                           PseudoFifo::BpfFifos(), ci1);
    node2_ = new (std::nothrow) SondTester(*pkt_pool_, *bin_map2_, *timer_,
                                           *weight_qd_shared_memory_2_,
                                           PseudoFifo::BpfFifos(), ci2);
    node1_->InitForTest(1, node1_port, node2_port, ci1);
    node2_->InitForTest(2, node1_port, node2_port, ci2);
  }

  //==========================================================================
  void tearDown()
  {
    // Cancel all timers.  This protects other BPFwder-based unit tests.
    timer_->CancelAllTimers();

    // Clean up.
    delete node1_;
    delete node2_;
    node1_        = NULL;
    node2_        = NULL;
    delete pkt_pool_;
    pkt_pool_     = NULL;
    delete [] bin_map1_mem_;
    delete [] bin_map2_mem_;
    bin_map1_mem_ = NULL;
    bin_map2_mem_ = NULL;
    bin_map1_     = NULL;
    bin_map2_     = NULL;
    delete timer_;
    timer_        = NULL;

    delete weight_qd_shared_memory_1_;
    weight_qd_shared_memory_1_ = NULL;

    delete weight_qd_shared_memory_2_;
    weight_qd_shared_memory_2_ = NULL;

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestSonds()
  {
    int     num_qlam_pkts         = 1;
    int     num_data_pkts         = 10;
    int     data_pkt_bytes[10]    = { 1024, 1500,  252,  128, 1396,
                                       496,  872,  640, 1480,  924 };
    int     data_pkt_total_bytes  = 0;
    int     qlam_pkt_queued_bytes = 0;
    int     send_data_cnt, send_data_len, send_qlam_cnt, send_qlam_len;
    int     recv_data_cnt, recv_data_len, recv_qlam_cnt, recv_qlam_len;
    double  recv_rate;
    for (int i = 0; i < num_data_pkts; ++i)
    {
      data_pkt_total_bytes += data_pkt_bytes[i];
    }

    // -----------------------------------------------------------------------
    // First, use node 1 as the source and node 2 as the sink.

    // Check the SOND count and queue lengths at the source and sink.
    CPPUNIT_ASSERT(node1_->GetSondCount() == 1);
    CPPUNIT_ASSERT(node2_->GetSondCount() == 1);
    CPPUNIT_ASSERT(node1_->GetDataQueueLengthInBytes() == 0);
    CPPUNIT_ASSERT(node2_->GetDataQueueLengthInBytes() == 0);

    // Queue QLAM and data packets at the source.
    node1_->SendTestPackets(num_qlam_pkts, num_data_pkts, data_pkt_bytes,
                            qlam_pkt_queued_bytes);

    // Check the queue lengths at the source.  This counts data packets and
    // QLAM packets.
    CPPUNIT_ASSERT(node1_->GetDataQueueLengthInBytes() ==
                   (data_pkt_total_bytes + qlam_pkt_queued_bytes));

    // Set a time to stop the sink.
    node2_->SetShutdownTime((data_pkt_total_bytes /
                             (node1_->GetSondSendRateKbps() * 1000/8)) + 3);

    // Call Start() on the sink.  This will cause it to receive packets until
    // the stop timer goes off.
    node2_->Start();

    // Verify the packets received by the sink.
    node1_->GetSendStats(send_data_cnt, send_data_len,
                         send_qlam_cnt, send_qlam_len);
    node2_->GetRecvStats(recv_data_cnt, recv_data_len,
                         recv_qlam_cnt, recv_qlam_len);
    CPPUNIT_ASSERT(send_data_cnt == recv_data_cnt);
    CPPUNIT_ASSERT(send_data_len == recv_data_len);
    CPPUNIT_ASSERT(send_qlam_cnt == recv_qlam_cnt);
    CPPUNIT_ASSERT(send_qlam_len == recv_qlam_len);

    // Verify the receive rate.  Should be +/- 2%.
    recv_rate = node2_->ComputeRecvRateBitsPerSecond();
    CPPUNIT_ASSERT(recv_rate < ((double)node1_->GetSondSendRateKbps() * 1.02));
    CPPUNIT_ASSERT(recv_rate > ((double)node1_->GetSondSendRateKbps() * 0.98));

    // -----------------------------------------------------------------------
    // Next, use node 2 as the source and node 1 as the sink.

    // Check the SOND count and queue lengths at the source and sink.
    CPPUNIT_ASSERT(node1_->GetSondCount() == 1);
    CPPUNIT_ASSERT(node2_->GetSondCount() == 1);
    CPPUNIT_ASSERT(node1_->GetDataQueueLengthInBytes() == 0);
    CPPUNIT_ASSERT(node2_->GetDataQueueLengthInBytes() == 0);

    // Queue QLAM and data packets at the source.
    node2_->SendTestPackets(num_qlam_pkts, num_data_pkts, data_pkt_bytes,
                            qlam_pkt_queued_bytes);

    // Check the queue lengths at the source.  This only counts data packets.
    // (There is no API available for checking the QLAM packet queue length!)
    CPPUNIT_ASSERT(node2_->GetDataQueueLengthInBytes() ==
                   (data_pkt_total_bytes + qlam_pkt_queued_bytes));

    // Set a time to stop the sink.
    node1_->SetShutdownTime((data_pkt_total_bytes /
                             (node2_->GetSondSendRateKbps() * 1000/8)) + 3);

    // Call Start() on the sink.  This will cause it to receive packets until
    // the stop timer goes off.
    node1_->Start();

    // Verify the packets received by the sink.
    node2_->GetSendStats(send_data_cnt, send_data_len,
                         send_qlam_cnt, send_qlam_len);
    node1_->GetRecvStats(recv_data_cnt, recv_data_len,
                         recv_qlam_cnt, recv_qlam_len);
    CPPUNIT_ASSERT(send_data_cnt == recv_data_cnt);
    CPPUNIT_ASSERT(send_data_len == recv_data_len);
    CPPUNIT_ASSERT(send_qlam_cnt == recv_qlam_cnt);
    CPPUNIT_ASSERT(send_qlam_len == recv_qlam_len);

    // Verify the receive rate.  Should be +/- 2%.
    recv_rate = node1_->ComputeRecvRateBitsPerSecond();
    CPPUNIT_ASSERT(recv_rate < ((double)node2_->GetSondSendRateKbps() *
                                1.02));
    CPPUNIT_ASSERT(recv_rate > ((double)node2_->GetSondSendRateKbps() *
                                0.98));

    // Check the QLAM transmission interval calculations.
    node1_->CheckQlamIntervalCalc();
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(SondTest);
