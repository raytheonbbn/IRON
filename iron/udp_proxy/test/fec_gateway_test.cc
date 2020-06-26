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

#include "bin_map.h"
#include "config_info.h"
#include "failing_edge_if.h"
#include "fifo_if.h"
#include "list.h"
#include "log.h"
#include "itime.h"
#include "fec_state_pool.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "string_utils.h"
#include "timer.h"
#include "unused.h"
#include "virtual_edge_if.h"

#include <string>

using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::FailingEdgeIf;
using ::iron::FifoIF;
using ::iron::FourTuple;
using ::iron::List;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::PseudoFifo;
using ::iron::PseudoSharedMemory;
using ::iron::SharedMemoryIF;
using ::iron::StringUtils;
using ::iron::Timer;
using ::iron::VirtualEdgeIf;
using ::std::string;

namespace
{
  const char*  UNUSED(kClassName) = "FECGatewayTester";
}


//============================================================================
// A child class of the FEC Gateway for testing.
// This lets a unit test configure the FEC Gateway without using actual
// sockets (i.e., this uses a dummy virtual IF) so that we can test the basic
// functionality without needing a full system.

class UdpProxyAppTester : public UdpProxy
{
public:

  UdpProxyAppTester(PacketPool& packet_pool, BinMap& bin_map,
                    FecStatePool& fecstate_pool, Timer& timer,
                    VirtualEdgeIf& edge_if,
                    SharedMemoryIF& weight_qd_shared_memory,
                    FifoIF* bpf_to_udp_pkt_fifo,
                    FifoIF* udp_to_bpf_pkt_fifo);

  virtual ~UdpProxyAppTester();

  // New methods.

  /// \brief Function initializes the gateway for testing, including setting
  /// up and using configuration info.
  void InitForTest();
  bool CheckKVal(uint64_t value);
  void HasMatchingContext(FECContext& context);
  bool TestModService(FECContext* context);
  void SetFlow(FourTuple four_tuple, std::string flow_defn);
  void CheckFlowDefn(FourTuple four_tuple, std::string flow_defn);
  void AddEncodingState(FourTuple four_tuple);
  void CheckStats(FourTuple four_tuple);

  // Method overriding.
  virtual size_t EdgeIfSend(const Packet* pkt) const;
  virtual bool initSockets();
  virtual bool plumb();
  virtual bool unplumb();
  virtual void UpdateQueueDepths();

private:

  /// Disallow constructor and = operator
  UdpProxyAppTester(const UdpProxyAppTester& other);
  UdpProxyAppTester& operator=(const UdpProxyAppTester& other);
};

//============================================================================
UdpProxyAppTester::UdpProxyAppTester(PacketPool& packet_pool, BinMap& bin_map,
                                     FecStatePool& fecstate_pool, Timer& timer,
                                     VirtualEdgeIf& edge_if,
                                     SharedMemoryIF& weight_qd_shared_memory,
                                     FifoIF* bpf_to_udp_pkt_fifo,
                                     FifoIF* udp_to_bpf_pkt_fifo)
  : UdpProxy(packet_pool, edge_if, bin_map, fecstate_pool, timer,
             weight_qd_shared_memory, bpf_to_udp_pkt_fifo,
             udp_to_bpf_pkt_fifo, false)
{
}

//============================================================================
UdpProxyAppTester::~UdpProxyAppTester()
{
}

//============================================================================
void UdpProxyAppTester::InitForTest()
{
  ConfigInfo  ci;

  ci.Add("KVal", "6.5e8");

  // We can use defaults for most configuration values. There is no default
  // Service, though, so this defines a couple that may be useful for testing.
  ci.Add("Service0", "30000-39999;1/1;1500;0;0;120;0;type=LOG:a=10:b=1:"
         "m=250000:p=5:label=log_service;");
  ci.Add("Service1", "40000-49999;1/1;1500;0;0;120;5000000;type=TRAP:"
         "b=12000:m=10000:p=10:delta=0.90:avgint=30000:stepint=50000:"
         "nsteps=8:resint=6000000:label=trap_service;dscp=46");
  ci.Add("defaultService", "1-65535;1/1;1500;0;0;120;0;type=LOG:a=10:"
         "m=200000:p=1:label=default_service;");
  ci.Add("InboundDevName", "lo");

  LogD(kClassName, __func__, "Done with initialization.\n");
  CPPUNIT_ASSERT(this->Configure(ci, "unused"));
}

//============================================================================
bool UdpProxyAppTester::CheckKVal(uint64_t value)
{
  LogD(kClassName, __func__, "k_val = %" PRIu64 ", expecting %" PRIu64 ".\n",
       k_val().GetValue(), value);
  return k_val().GetValue() == value;
}

//============================================================================
void UdpProxyAppTester::HasMatchingContext(FECContext& context)
{

  uint32_t sport_nbo = htons(context.lo_port());
  uint32_t dport_nbo = htons(context.hi_port());
  uint32_t saddr_nbo = htonl(
    (uint32_t)(iron::StringUtils::GetIpAddr("192.178.1.1").address()));
  uint32_t daddr_nbo = htonl(
    (uint32_t)(iron::StringUtils::GetIpAddr("192.178.1.2").address()));
  FourTuple four_tuple(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);

  FECContext  ref_context;
  CPPUNIT_ASSERT(GetContext(four_tuple, ref_context));
  LogD(kClassName, __func__,
       "Found reference context for ports %" PRId32 " - %" PRId32 ".\n",
       context.lo_port(), context.hi_port());
  CPPUNIT_ASSERT(context.max_chunk_sz() == ref_context.max_chunk_sz());
  CPPUNIT_ASSERT(context.util_fn_defn() == ref_context.util_fn_defn());
  CPPUNIT_ASSERT(context.dscp() == ref_context.dscp());
}

//============================================================================
bool UdpProxyAppTester::TestModService(FECContext* context)
{
  return ModService(context);
}

//============================================================================
void UdpProxyAppTester::SetFlow(FourTuple four_tuple, std::string flow_defn)
{
  char flow_def[flow_defn.length() + 1];
  strcpy(flow_def, flow_defn.c_str());
  FECContext* context = ParseService(flow_def, FECModAction, true);
  SetFlowDefn(four_tuple, context);
}

//============================================================================
void UdpProxyAppTester::CheckFlowDefn(FourTuple four_tuple,
                                      std::string flow_defn)
{
  // Check that we have the flow definition already.
  CPPUNIT_ASSERT(HasFlowDefn(four_tuple));
  // Check that we recognize when we do not have a definition already.
  uint32_t sport_nbo = htons(30000);
  uint32_t dport_nbo = htons(30000);
  uint64_t saddr_nbo = htonl(
    (uint64_t)(iron::StringUtils::GetIpAddr("192.178.1.1").address()));
  uint64_t daddr_nbo = htonl(
    (uint64_t)(iron::StringUtils::GetIpAddr("192.178.1.2").address()));
  FourTuple alt_four_tuple(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);
  CPPUNIT_ASSERT(!HasFlowDefn(alt_four_tuple));

  // Retrieve the flow definition. 
  FECContext* found_context = NULL;

  CPPUNIT_ASSERT(GetFlowDefn(four_tuple, found_context));

  CPPUNIT_ASSERT(found_context != NULL);

  List<string>  tokens;
  string        token;
  StringUtils::Tokenize(flow_defn, ";", tokens);
  CPPUNIT_ASSERT(tokens.size() == 12);
  // Check that the dscp token in the flow definition string is the
  // same as that in the found context.
  List<string>  dscp_tokens;
  string        dscp_token;

  CPPUNIT_ASSERT(tokens.PopBack(token));
  StringUtils::Tokenize(token, "=", dscp_tokens);
  CPPUNIT_ASSERT(dscp_tokens.PeekBack(dscp_token));
  CPPUNIT_ASSERT(StringUtils::GetInt(dscp_token) == 
    found_context->dscp()); 
  // Check that the utility function in the flow definition string is
  // the same as that in the found context.
  CPPUNIT_ASSERT(tokens.PopBack(token));
  CPPUNIT_ASSERT(token == found_context->util_fn_defn());

  // Delete the flow definition.
  DelFlowDefn(four_tuple);
  // Check that we have the flow definition already.
  CPPUNIT_ASSERT(!HasFlowDefn(four_tuple));
}

//============================================================================
void UdpProxyAppTester::AddEncodingState(FourTuple four_tuple)
{
  EncodingState*  state = NULL;
  CPPUNIT_ASSERT(GetEncodingState(1, four_tuple, state));
}

//============================================================================
void UdpProxyAppTester::CheckStats(FourTuple four_tuple)
{
  EncodingState*  encoding_state;
  CPPUNIT_ASSERT(GetEncodingState(1, four_tuple, encoding_state));

  encoding_state->AccumulatePacketInfo(1000);
  encoding_state->AccumulatePacketInfo(1000);
  encoding_state->AccumulatePacketInfo(1000);
  encoding_state->AccumulatePacketInfo(1000);

  CPPUNIT_ASSERT(encoding_state->dump_pkt_number() == 4);
  CPPUNIT_ASSERT(encoding_state->dump_byte_number() == 4000);
  encoding_state->ClearDumpStats();
  CPPUNIT_ASSERT(encoding_state->dump_pkt_number() == 0);
}

//============================================================================
size_t UdpProxyAppTester::EdgeIfSend(const Packet* pkt) const
{
  // Do not actually send.
  return pkt->GetLengthInBytes();
}

//============================================================================
bool UdpProxyAppTester::initSockets()
{
  LogD(kClassName, __func__, "InitSockets is doing nothing.\n");
  // Do nothing. We don't want to test with real sockets.
  return true;
}

//============================================================================
bool UdpProxyAppTester::plumb()
{
  LogD(kClassName, __func__, "Plumb is doing nothing.\n");
  // Do nothing. We don't want to test with real interactions.
  return true;
}

//============================================================================
bool UdpProxyAppTester::unplumb()
{
  LogD(kClassName, __func__, "Unplumb is doing nothing.\n");
  // Do nothing. We don't want to test with real interactions.
  return true;
}

//============================================================================
void UdpProxyAppTester::UpdateQueueDepths()
{
  LogD(kClassName, __func__, "UpdateQueueDepths is doing nothing.\n");
  // Do nothing. We don't want to test with shared memory.
}

//============================================================================
class FECGatewayTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(FECGatewayTest);

  CPPUNIT_TEST(TestInitialization);
  CPPUNIT_TEST(TestModService);
  CPPUNIT_TEST(TestFlowDefn);
  CPPUNIT_TEST(TestStats);

  CPPUNIT_TEST_SUITE_END();

  private:

  UdpProxyAppTester*  udp_proxy_;
  PacketPoolHeap*     pkt_pool_;
  char*               bin_map_mem_;
  BinMap*             bin_map_;
  FecStatePool*       fecstate_pool_;
  Timer*              timer_;
  SharedMemoryIF*     weight_qd_shared_memory_;
  VirtualEdgeIf*      edge_if_;
  FifoIF*             bpf_to_udp_pkt_fifo_;
  FifoIF*             udp_to_bpf_pkt_fifo_;

  public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FE");

    edge_if_ = new FailingEdgeIf(true);

    timer_ = new Timer();

    bin_map_mem_       = new char[sizeof(BinMap)];
    bin_map_           = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));

    weight_qd_shared_memory_ = new PseudoSharedMemory();

    bpf_to_udp_pkt_fifo_ = new PseudoFifo();
    udp_to_bpf_pkt_fifo_ = new PseudoFifo();

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_->Create(8) == true);

    fecstate_pool_ = new FecStatePool(*pkt_pool_);

    ConfigInfo  ci;

    // Add bin map configuration.
    ci.Add("BinMap.BinIds", "8,3,13,1,10");
    ci.Add("BinMap.BinId.8.HostMasks",
         "192.168.20.0/24,10.1.20.0/24,0.0.0.20");
    ci.Add("BinMap.BinId.3.HostMasks",
           "192.168.3.0/24,10.1.16.0/24,10.1.16.101");
    ci.Add("BinMap.BinId.13.HostMasks",
           "192.168.40.0/24,10.1.40.0/24,0.0.0.40");
    ci.Add("BinMap.BinId.1.HostMasks",
           "192.168.1.0/24,10.1.1.0/24,0.0.0.1");
    ci.Add("BinMap.BinId.10.HostMasks",
           "192.168.1.0/24,10.1.1.0/24,10.1.10.101");

    CPPUNIT_ASSERT(bin_map_->Initialize(ci) == true);

    // Create the backpressure forwarder set up for testing.
    // Memory reclaimed below
    udp_proxy_ =
      new (std::nothrow) UdpProxyAppTester(*pkt_pool_, *bin_map_,
                                           *fecstate_pool_,
                                           *timer_, *edge_if_,
                                           *weight_qd_shared_memory_,
                                           bpf_to_udp_pkt_fifo_,
                                           udp_to_bpf_pkt_fifo_);
    udp_proxy_->InitForTest();
  }

  //==========================================================================
  void tearDown()
  {
    // Clean up.
    delete udp_proxy_;
    udp_proxy_ = NULL;

    delete fecstate_pool_;
    fecstate_pool_ = NULL;

    delete pkt_pool_;
    pkt_pool_ = NULL;

    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;
    bin_map_     = NULL;

    delete timer_;
    timer_ = NULL;

    delete weight_qd_shared_memory_;
    weight_qd_shared_memory_ = NULL;

    delete edge_if_;
    edge_if_ = NULL;

    delete bpf_to_udp_pkt_fifo_;
    bpf_to_udp_pkt_fifo_ = NULL;

    delete udp_to_bpf_pkt_fifo_;
    udp_to_bpf_pkt_fifo_ = NULL;

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestInitialization()
  {
    LogD("FECGatewayTest", __func__, "Testing.\n");
    CPPUNIT_ASSERT(udp_proxy_->CheckKVal(650000000));
  }

  //==========================================================================
  void TestModService()
  {
    struct timeval  hold_tv = {.tv_sec = 0, .tv_usec  = 0};
    iron::Time  reorder_time(0);

    // Check that init already added a context.
    FECContext  init_context(30000, 39999, 1, 1, 1500, hold_tv, 0, 120,
                             iron::Time(0.), true,
                             "type=LOG:a=10:b=1:m=250000:p=5:label=log_service",
                             -1, reorder_time, 0);
    udp_proxy_->HasMatchingContext(init_context);

    FECContext  context(3000, 3001, 1, 1, 1500, hold_tv, 0, 120, iron::Time(0.),
                        true, "utility function", -1, reorder_time, 0);
    // Add the service.
    CPPUNIT_ASSERT(udp_proxy_->TestModService(&context));
    // Check that it was adding correctly. 
    udp_proxy_->HasMatchingContext(context);

    // Modify the service.
    context.set_max_chunk_sz(2000);
    CPPUNIT_ASSERT(udp_proxy_->TestModService(&context));
    // Check that it was modified correctly.
    udp_proxy_->HasMatchingContext(context);
  }

  //==========================================================================
  void TestFlowDefn()
  {
    // Add a first flow.
    uint32_t sport_nbo = htons(30000);
    uint32_t dport_nbo = htons(39999);
    uint64_t saddr_nbo = htonl(
      (uint64_t)(iron::StringUtils::GetIpAddr("192.178.1.1").address()));
    uint64_t daddr_nbo = htonl(
      (uint64_t)(iron::StringUtils::GetIpAddr("192.178.1.2").address()));

    FourTuple four_tuple0(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);

    std::string flow_defn = 
      "1;2;3;0.0.0.4;1/1;1500;0;0;120;40000;type=STRAP:p=10:b=1:label=f1;dscp=46";
    udp_proxy_->SetFlow(four_tuple0, flow_defn);

    // Add a second flow.
    FourTuple four_tuple1(saddr_nbo, sport_nbo, daddr_nbo+1, dport_nbo);
    udp_proxy_->SetFlow(four_tuple1, flow_defn);

    udp_proxy_->CheckFlowDefn(four_tuple0, flow_defn);
  }

  //==========================================================================
  void TestStats()
  {
    // Add a first flow.
    uint32_t sport_nbo = htons(30000);
    uint32_t dport_nbo = htons(39999);
    uint64_t saddr_nbo = htonl(
      (uint64_t)(iron::StringUtils::GetIpAddr("192.168.1.1").address()));
    uint64_t daddr_nbo = htonl(
      (uint64_t)(iron::StringUtils::GetIpAddr("192.168.1.2").address()));

    FourTuple four_tuple(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);
    udp_proxy_->AddEncodingState(four_tuple);
    
    udp_proxy_->CheckStats(four_tuple);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(FECGatewayTest);
