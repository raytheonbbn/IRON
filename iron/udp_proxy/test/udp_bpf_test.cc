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

#include "udp_proxy.h"

#include "backpressure_fwder.h"

#include "bin_map.h"
#include "callback.h"
#include "config_info.h"
#include "fec_state_pool.h"
#include "failing_edge_if.h"
#include "fifo_if.h"
#include "iron_constants.h"
#include "itime.h"
#include "log.h"
#include "queue_depths.h"
#include "packet_pool_heap.h"
#include "port_number_mgr.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "timer.h"
#include "unused.h"
#include "virtual_edge_if.h"

using ::iron::BinId;
using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::CallbackNoArg;
using ::iron::FailingEdgeIf;
using ::iron::FifoIF;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::PseudoFifo;
using ::iron::PseudoSharedMemory;
using ::iron::SharedMemoryIF;
using ::iron::Timer;
using ::iron::VirtualEdgeIf;

namespace
{
  const char* UNUSED(kClassName)  = "UdpBpfTester";
}

//============================================================================
// A child class of the backpressure forwarder for testing UDP proxy
// interactions with the BPF.  This BPF is only used in a very lightweight
// manner: in these tests, we do not enter the Start method of the BPF.
// This class becomes in effect the source of the data.
class BpfTester : public iron::BPFwder
{
  public:
  BpfTester(PacketPool& packet_pool, BinMap& bin_map, Timer& timer,
            SharedMemoryIF& weight_qd_shared_memory,
            FifoIF* bpf_to_udp_pkt_fifo,
            FifoIF* bpf_to_tcp_pkt_fifo,
            FifoIF* udp_to_bpf_pkt_fifo,
            FifoIF* tcp_to_bpf_pkt_fifo,
            ConfigInfo& config_info)
    : BPFwder(packet_pool, timer, bin_map, weight_qd_shared_memory,
              bpf_to_udp_pkt_fifo, bpf_to_tcp_pkt_fifo, udp_to_bpf_pkt_fifo,
              tcp_to_bpf_pkt_fifo, config_info) {}
  virtual ~BpfTester() {}

  // New methods.
  // Add config info and some bin depths.
  void InitForTest(const char* weight_shm_name, const char* weight_shm_key,
                   ConfigInfo& ci);
  // Copy the queue depth objects in the shared memory.
  bool CopyQueueDepths();
  // Get a pointer to the (weight) queue depths.
  iron::QueueDepths*  GetLocalQueueDepths();

  private:
  BpfTester(const BpfTester& other);
  BpfTester& operator=(const BpfTester& other);
};

//============================================================================
void BpfTester::InitForTest(const char* weight_shm_name,
                            const char* weight_shm_key,
                            ConfigInfo& ci)
{

  CPPUNIT_ASSERT(this->Initialize());

  // Set up queue depths for sharing with the UDP proxy.
  iron::QueueDepths* qd = queue_store_->GetWQueueDepths();
  qd->SetBinDepthByIdx(1, 20);
  qd->SetBinDepthByIdx(2, 10);
  qd->SetBinDepthByIdx(0, 100);
}

//============================================================================
bool BpfTester::CopyQueueDepths()
{
  CPPUNIT_ASSERT(queue_store_);
  return queue_store_->PublishWQueueDepthsToShm();
}

//============================================================================
iron::QueueDepths*  BpfTester::GetLocalQueueDepths()
{
  CPPUNIT_ASSERT(queue_store_);
  return queue_store_->GetWQueueDepths();
}

//============================================================================
// A child class of the FEC Gateway for testing.
// This lets a unit test configure the FEC Gateway without using actual
// sockets (i.e., this uses a dummy virtual IF) so that we can test the basic
// functionality without needing a full system.
// In effect, this object acts as the destination of the data.
class UdpProxyTester : public UdpProxy
{
public:
  UdpProxyTester(PacketPool& packet_pool, BinMap& bin_map,
                 FecStatePool& fecstate_pool, Timer& timer,
                 VirtualEdgeIf& edge_if,
                 SharedMemoryIF& weight_qd_shared_memory,
                 FifoIF* bpf_to_udp_pkt_fifo,
                 FifoIF* udp_to_bpf_pkt_fifo)
    : UdpProxy(packet_pool, edge_if, bin_map, fecstate_pool,
               timer, weight_qd_shared_memory, bpf_to_udp_pkt_fifo,
               udp_to_bpf_pkt_fifo, true),
      timer_(timer), back_stop_handle_()
  {
  }

  virtual ~UdpProxyTester(); 

  // New methods.
  // Get a pointer to the (weight) queue depths.
  iron::QueueDepths* GetLocalQueueDepths();
  // Attach to the shared memory segment.
  void AttachShm(const char* weight_shm_name, const char* weight_shm_key);
  // Set a timer to stop the proxy and fail in one second in case the UDP Proxy
  // Tester does not receive the Low Queue Msg from the BPF object.  A
  // successful receive should cancel this back stop.
  void SetBackStop();

  // Overridden methods.
  virtual bool initSockets();
  virtual void Stop();
  virtual int Select(int nfds, fd_set* readfs, struct timeval* timeout);

private:
  UdpProxyTester(const UdpProxyTester& other);
  UdpProxyTester& operator=(const UdpProxyTester& other);
  Timer& timer_;
  iron::Timer::Handle  back_stop_handle_;
};

//============================================================================
UdpProxyTester::~UdpProxyTester()
{
  // Cancel any timer.
  timer_.CancelTimer(back_stop_handle_);

  // Clean up the timer callback object pools.
  CallbackNoArg<UdpProxyTester>::EmptyPool();
}

//============================================================================
bool UdpProxyTester::initSockets()
{
  return true;
}

//============================================================================
iron::QueueDepths* UdpProxyTester::GetLocalQueueDepths()
{
  return &local_queue_depths_;
}

//============================================================================
void UdpProxyTester::AttachShm(const char* weight_shm_name,
                               const char* weight_shm_key)
{
  iron::ConfigInfo ci;

  ci.Add("Udp.Weight.SemKey", weight_shm_key);
  ci.Add("Udp.Weight.ShmName", weight_shm_name);

  CPPUNIT_ASSERT(AttachSharedMemory(ci));
}

//============================================================================
int UdpProxyTester::Select(int nfds, fd_set* readfs, struct timeval* timeout)
{
  // always say something is ready to read.
  return 1;
}

//============================================================================
void UdpProxyTester::SetBackStop()
{
  CallbackNoArg<UdpProxyTester> cb(this, &UdpProxyTester::Stop);
  iron::Time                    delta_time = iron::Time::FromSec(1);

  CPPUNIT_ASSERT(timer_.StartTimer(delta_time, &cb,
                                   back_stop_handle_) == 1);
}

//============================================================================
void UdpProxyTester::Stop()
{
  running_  = false;
  CPPUNIT_ASSERT(false);
}

//============================================================================
class UdpBpfTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(UdpBpfTest);
  CPPUNIT_TEST(TestReadQueueDepths);
  CPPUNIT_TEST_SUITE_END();

private:
  BpfTester*       bpf_;
  UdpProxyTester*  udp_proxy_;
  PacketPoolHeap*  pkt_pool_;
  BinMap*          bin_map_;
  char*             bin_map_mem_;
  FecStatePool*    fecstate_pool_;
  Timer*           timer_;
  VirtualEdgeIf*   edge_if_;
  SharedMemoryIF*   weight_qd_shared_memory_;
  FifoIF*          bpf_to_udp_pkt_fifo_;
  FifoIF*          bpf_to_tcp_pkt_fifo_;
  FifoIF*          udp_to_bpf_pkt_fifo_;
  FifoIF*          tcp_to_bpf_pkt_fifo_;

public:
  //==========================================================================
  void setUp()
  {
    iron::Log::SetDefaultLevel("F");

    edge_if_ = new FailingEdgeIf(true);

    timer_ = new Timer();

    weight_qd_shared_memory_ = new PseudoSharedMemory();

    bpf_to_udp_pkt_fifo_ = new PseudoFifo();
    bpf_to_tcp_pkt_fifo_ = new PseudoFifo();
    udp_to_bpf_pkt_fifo_ = new PseudoFifo();
    tcp_to_bpf_pkt_fifo_ = new PseudoFifo();

    bin_map_mem_       = new char[sizeof(BinMap)];
    bin_map_           = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_->Create(8) == true);

    fecstate_pool_ = new FecStatePool(*pkt_pool_);

    ConfigInfo ci;

    ci.Add("Bpf.BinId", "1");
    ci.Add("Bpf.QlamOverheadRatio", "0.01");

    ci.Add("Bpf.Weight.SemKey", "1");
    ci.Add("Bpf.Weight.ShmName", "weight_1");

    ci.Add("BinMap.BinIds", "1,5,10");
    ci.Add("BinMap.BinId.1.HostMasks",
           "192.168.1.0/24,10.1.1.0/24,1.2.3.4");
    ci.Add("BinMap.BinId.5.HostMasks",
           "192.168.3.0/24,10.3.3.3,9.10.11.12");
    ci.Add("BinMap.BinId.10.HostMasks",
           "192.168.4.0/24,10.4.4.4,13.14.15.16");

    // Disable features that affect queue depths.
    ci.Add("Bpf.ZombieLatencyReduction", "false");
    ci.Add("Bpf.QueueDelayWeight", "0");

    iron::PortNumberMgr&  port_mgr = iron::PortNumberMgr::GetInstance();
    ci.Add("Bpf.RemoteControl.Port", port_mgr.NextAvailableStr());

    CPPUNIT_ASSERT(bin_map_->Initialize(ci));

    // Create and init a Bpf for testing.
    bpf_  = new (std::nothrow) BpfTester(*pkt_pool_, *bin_map_, *timer_,
                                         *weight_qd_shared_memory_,
                                         bpf_to_udp_pkt_fifo_,
                                         bpf_to_tcp_pkt_fifo_,
                                         udp_to_bpf_pkt_fifo_,
                                         tcp_to_bpf_pkt_fifo_, ci);
    CPPUNIT_ASSERT(bpf_);
    bpf_->InitForTest("weight_1", "1", ci);

    // Create the UDP Proxy to test, attach to shared memory segment.
    udp_proxy_ = new (std::nothrow) UdpProxyTester(*pkt_pool_, *bin_map_,
                                                   *fecstate_pool_,
                                                   *timer_, *edge_if_,
                                                   *weight_qd_shared_memory_,
                                                   bpf_to_udp_pkt_fifo_,
                                                   udp_to_bpf_pkt_fifo_);

    CPPUNIT_ASSERT(udp_proxy_);
    udp_proxy_->AttachShm("weight_1", "1");
  }

  //==========================================================================
  void tearDown()
  {
    // Cancel all timers.  This protects other BPFwder-based unit tests.
    timer_->CancelAllTimers();

    // Clean up.
    delete bpf_;
    delete udp_proxy_;

    delete fecstate_pool_;
    fecstate_pool_ = NULL;

    delete pkt_pool_;
    pkt_pool_ = NULL;

    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;
    bin_map_ = NULL;

    delete timer_;
    timer_ = NULL;

    delete edge_if_;
    edge_if_ = NULL;

    delete weight_qd_shared_memory_;
    weight_qd_shared_memory_ = NULL;

    delete bpf_to_udp_pkt_fifo_;
    bpf_to_udp_pkt_fifo_ = NULL;

    delete bpf_to_tcp_pkt_fifo_;
    bpf_to_tcp_pkt_fifo_ = NULL;

    delete udp_to_bpf_pkt_fifo_;
    udp_to_bpf_pkt_fifo_ = NULL;

    delete tcp_to_bpf_pkt_fifo_;
    tcp_to_bpf_pkt_fifo_ = NULL;

    iron::Log::SetDefaultLevel("FE");
  }

  //==========================================================================
  void TestReadQueueDepths()
  {
    // Copy the queue depths from BPF into the shared memory.
    CPPUNIT_ASSERT(bpf_);
    CPPUNIT_ASSERT(bpf_->CopyQueueDepths());
    iron::QueueDepths*  bpf_local_qd  = bpf_->GetLocalQueueDepths();

    // Read the queue depths from shared memory into the UDP Proxy.
    CPPUNIT_ASSERT(udp_proxy_);
    iron::QueueDepths*  udp_local_qd  = udp_proxy_->GetLocalQueueDepths();

    // Check the two queue depths match...
    CPPUNIT_ASSERT(bpf_local_qd->GetBinDepthByIdx(0)  == udp_local_qd->GetBinDepthByIdx(0));
    CPPUNIT_ASSERT(bpf_local_qd->GetBinDepthByIdx(1)  == udp_local_qd->GetBinDepthByIdx(1));
    CPPUNIT_ASSERT(bpf_local_qd->GetBinDepthByIdx(2)  == udp_local_qd->GetBinDepthByIdx(2));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(UdpBpfTest);
