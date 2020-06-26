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

#include "tcp_proxy.h"

#include "bin_map.h"
#include "config_info.h"
#include "log.h"
#include "failing_edge_if.h"
#include "fifo_if.h"
#include "itime.h"
#include "iron_constants.h"
#include "packet.h"
#include "packet_pool.h"
#include "packet_pool_heap.h"
#include "string_utils.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "unused.h"
#include "virtual_edge_if.h"

#include <string>

using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::FourTuple;
using ::iron::FifoIF;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::StringUtils;
using ::iron::FailingEdgeIf;
using ::iron::PseudoFifo;
using ::iron::PseudoSharedMemory;
using ::iron::RemoteControlServer;
using ::iron::SharedMemoryIF;
using ::iron::Time;
using ::iron::VirtualEdgeIf;
using ::std::string;

namespace
{
  const char*   UNUSED(kClassName) = "TcpProxyTester";

  const char*   kTestKValue = "1.5e12";

  const char*   kTestMtuBytes = "1000";

  const string  kTestDefaultUtilityDef =
    "type=LOG:a=10:b=11500:m=25000000:p=1:label=default";

  const string  kTestService0 = "22-22;type=LOG:a=10:b=11500:"
    "m=20000000:p=1:label=ssh_flow;";

  const string  kTestService1 = "29778-29778;type=LOG:a=10:b=11500:"
    "m=25000000:p=1:label=mgen_flow_1;";

  const string  kTestService2 = "29779-29779;type=LOG:a=10:b=11500:"
    "m=25000000:p=5:label=mgen_flow_2;";

  const string  kTestService3 = "29780-29780;type=LOGa=10:b=11500:"
    "m=25000000:p=5:label=mgen_flow_3;";

  const int kPoolSize = 100;
}

//============================================================================
// A child class of the TCP Proxy for unit testing the TCP Proxy.
class TcpProxyTester : public TcpProxy
{
  public:

  TcpProxyTester(TcpProxyConfig& proxy_config, PacketPool& packet_pool,
                 VirtualEdgeIf& edge_if,
                 BinMap& bin_map,
                 SharedMemoryIF& weight_qd_shared_memory,
                 FifoIF* bpf_to_tcp_pkt_fifo,
                 FifoIF* tcp_to_bpf_pkt_fifo,
                 RemoteControlServer& remote_control_server);
  virtual ~TcpProxyTester();

  // New methods.
  void InitForTest();
  void CheckInitialize();
  void TestServiceDefUpdate();
  void TestFlowDefUpdate();

  // Method overriding.
  virtual bool AttachSharedMemory(const ConfigInfo& config_info);

  private:

  TcpProxyTester(const TcpProxyTester& other);
  TcpProxyTester& operator=(const TcpProxyTester& other);

  TcpProxyConfig&  proxy_config_; 
};

//============================================================================
TcpProxyTester::TcpProxyTester(TcpProxyConfig& proxy_config,
                               PacketPool& packet_pool,
                               VirtualEdgeIf& edge_if,
                               BinMap& bin_map,
                               SharedMemoryIF& weight_qd_shared_memory,
                               FifoIF* bpf_to_tcp_pkt_fifo,
                               FifoIF* tcp_to_bpf_pkt_fifo,
                               RemoteControlServer& remote_control_server)
  : TcpProxy(proxy_config, packet_pool, edge_if, bin_map, weight_qd_shared_memory,
             bpf_to_tcp_pkt_fifo, tcp_to_bpf_pkt_fifo, remote_control_server),
    proxy_config_(proxy_config)
{
}

//============================================================================
TcpProxyTester::~TcpProxyTester()
{
}

//============================================================================
void TcpProxyTester::InitForTest()
{
  ConfigInfo  ci;

  ci.Add("KVal", kTestKValue);

  ci.Add("MtuBytes", kTestMtuBytes);

  ci.Add("Service0", kTestService0);
  ci.Add("Service1", kTestService1);
  ci.Add("Service2", kTestService2);
  ci.Add("Service3", kTestService3);
  ci.Add("DefaultUtilityDef", kTestDefaultUtilityDef);

  proxy_config_.Initialize(ci);
  CPPUNIT_ASSERT(this->Initialize(ci));
}

//============================================================================
void TcpProxyTester::CheckInitialize()
{
  // Test that the value provided in the configuration file have been
  // correctly extracted.

  // Check K value.
  CPPUNIT_ASSERT(k_val().GetValue() == StringUtils::GetDouble(kTestKValue));

  CPPUNIT_ASSERT(proxy_config_.GetIfMtu(LAN) ==
                 StringUtils::GetInt(kTestMtuBytes));
}

//============================================================================
// \todo Create some real JSON messages and test this with the real TCP Proxy
// methods to process messages from AMP. This will be done in round 2 of the
// unit test development.
void TcpProxyTester::TestServiceDefUpdate()
{
  // Test out the modificiation of an existing Service Definition. We'll
  // modify Service0 (change the priority to 10).
  string  utility_def1 =
    "type=LOG:a=10:b=11500:m=20000000:p=10:label=ssh_flow";
  TcpContext*  new_context1 = new (std::nothrow)
    TcpContext(22, 22, utility_def1, -1);
  CPPUNIT_ASSERT(new_context1);
  CPPUNIT_ASSERT(ModService(new_context1));
  delete new_context1;

  // The Utility Function is the only thing in the Service Definition, so
  // verify that the modification works by ensuring that the Utility Functions
  // match.
  CPPUNIT_ASSERT(GetUtilityFnDef(22) == utility_def1);

  // Test out the addition of a new Service Definition.
  string  utility_def2 =
    "type=LOG:a=10:b=11500:m=20000000:p=7:label=ssh_flow";
  TcpContext*  new_context2 =
    new (std::nothrow) TcpContext(30000, 30100, utility_def2, -1);
  CPPUNIT_ASSERT(new_context2);
  CPPUNIT_ASSERT(ModService(new_context2));
  delete new_context2;

  // The Utility Function is the only thing in the Service Definition, so
  // verify that the modification work by ensuring that the Utility Functions
  // match.
  CPPUNIT_ASSERT(GetUtilityFnDef(30000) == utility_def2);
}

//============================================================================
// \todo Create some real JSON messages and test this with the real TCP Proxy
// methods to process messages from AMP. This will be done in round 2 of the
// unit test development.
void TcpProxyTester::TestFlowDefUpdate()
{
  // Create a four-tuple for the test.
  uint16_t  sport_nbo = htons(30000);
  uint16_t  dport_nbo = htons(39999);
  uint32_t  saddr_nbo = htonl(
    iron::StringUtils::GetIpAddr("172.24.1.1").address());
  uint32_t  daddr_nbo = htonl(
    iron::StringUtils::GetIpAddr("172.24.2.1").address());

  FourTuple  four_tuple(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);

  // First, we will test the addition of a flow definition.
  //
  // There currently should be no flow definitions in the TCP
  // Proxy. Initially, verify that this is the case.
  CPPUNIT_ASSERT(HasFlowUtilityFnDef(four_tuple) == false);

  // Next, add a flow definition and verify that it can be retrieved for test
  // four-tuple.
  string flow_utility_func_def =
    "type=LOG:a=10:b=1:m=250000:p=8:label=flow_utility_func_def";

  flow_utility_def_cache_.Insert(four_tuple, flow_utility_func_def);

  CPPUNIT_ASSERT(HasFlowUtilityFnDef(four_tuple));

  string  utility_func;
  CPPUNIT_ASSERT(GetFlowUtilityFnDef(four_tuple, utility_func));
  CPPUNIT_ASSERT(utility_func == flow_utility_func_def);
}

//============================================================================
bool TcpProxyTester::AttachSharedMemory(const ConfigInfo& config_info)
{
  // We don't attach to any shared memory segment for the unit test.
  return true;
}

//============================================================================
class TcpProxyTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(TcpProxyTest);

  CPPUNIT_TEST(TestInitialize);
  CPPUNIT_TEST(TestGetUtilityFnDef);
  CPPUNIT_TEST(TestServiceDefUpdate);
  CPPUNIT_TEST(TestFlowDefUpdate);

  CPPUNIT_TEST_SUITE_END();

  private:

  TcpProxyTester*       tcp_proxy_;
  TcpProxyConfig*       tcp_proxy_config_;
  PacketPoolHeap*       packet_pool_;
  VirtualEdgeIf*        edge_if_;
  SharedMemoryIF*       weight_qd_shared_memory_;
  BinMap*          bin_map_;
  char*            bin_map_mem_;
  FifoIF*               bpf_to_tcp_pkt_fifo_;
  FifoIF*               tcp_to_bpf_pkt_fifo_;
  RemoteControlServer*  remote_control_server_;

  public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");

    edge_if_          = new FailingEdgeIf(true);
    tcp_proxy_config_ = new TcpProxyConfig();

    packet_pool_ = new PacketPoolHeap();
    packet_pool_->Create(kPoolSize);

    bin_map_mem_       = new char[sizeof(BinMap)];
    bin_map_           = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));

    weight_qd_shared_memory_ = new PseudoSharedMemory();

    bpf_to_tcp_pkt_fifo_   = new PseudoFifo();
    tcp_to_bpf_pkt_fifo_   = new PseudoFifo();
    remote_control_server_ = new RemoteControlServer();

    ConfigInfo  ci;
    // Add bin map configuration.
    ci.Add("BinMap.BinIds", "1,2,3");
    ci.Add("BinMap.BinId.1.IronNodeAddr", "172.24.1.2");
    ci.Add("BinMap.BinId.1.HostMasks", "172.24.1.0/24");
    ci.Add("BinMap.BinId.2.IronNodeAddr", "172.24.2.2");
    ci.Add("BinMap.BinId.2.HostMasks", "172.24.2.0/24");
    ci.Add("BinMap.BinId.3.IronNodeAddr", "172.24.3.2");
    ci.Add("BinMap.BinId.3.HostMasks", "172.24.3.0/24");

    bin_map_->Initialize(ci);

    // Create the TCP Proxy for testing.
    tcp_proxy_ = new (std::nothrow) TcpProxyTester(*tcp_proxy_config_,
                                                   *packet_pool_,
                                                   *edge_if_,
                                                   *bin_map_,
                                                   *weight_qd_shared_memory_,
                                                   bpf_to_tcp_pkt_fifo_,
                                                   tcp_to_bpf_pkt_fifo_,
                                                   *remote_control_server_);

    CPPUNIT_ASSERT(tcp_proxy_);
    tcp_proxy_->InitForTest();
  }

  //==========================================================================
  void tearDown()
  {
    // Clean up.
    delete tcp_proxy_;
    tcp_proxy_ = NULL;

    delete tcp_proxy_config_;
    tcp_proxy_config_ = NULL;

    delete edge_if_;
    edge_if_ = NULL;

    delete packet_pool_;
    packet_pool_ = NULL;

    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;

    delete weight_qd_shared_memory_;
    weight_qd_shared_memory_ = NULL;

    delete bpf_to_tcp_pkt_fifo_;
    bpf_to_tcp_pkt_fifo_ = NULL;

    delete tcp_to_bpf_pkt_fifo_;
    tcp_to_bpf_pkt_fifo_ = NULL;

    delete remote_control_server_;
    remote_control_server_ = NULL;

    Log::SetDefaultLevel("FEW");
  }

  //==========================================================================
  void TestInitialize()
  {
    tcp_proxy_->CheckInitialize();
  }

  //==========================================================================
  void TestGetUtilityFnDef()
  {
    // The Service Defintion saved in the TCP Proxy strips off the 'xx-xx;'
    // portion of the Service Definition string (for the port range) and the
    // terminating ';' character.

    // Ensure that the Utility Function Definitions match for the Services
    // configured at the start of the test, ports 22, 29778, 29779, and
    // 29780.
    CPPUNIT_ASSERT(tcp_proxy_->GetUtilityFnDef(22) ==
                   kTestService0.substr(kTestService0.find(';') + 1,
                                        kTestService0.rfind(';') -
                                        kTestService0.find(';') - 1));
    CPPUNIT_ASSERT(tcp_proxy_->GetUtilityFnDef(29778) ==
                   kTestService1.substr(kTestService1.find(';') + 1,
                                        kTestService1.rfind(';') -
                                        kTestService1.find(';') - 1));
    CPPUNIT_ASSERT(tcp_proxy_->GetUtilityFnDef(29779) ==
                   kTestService2.substr(kTestService2.find(';') + 1,
                                        kTestService2.rfind(';') -
                                        kTestService2.find(';') - 1));

    CPPUNIT_ASSERT(tcp_proxy_->GetUtilityFnDef(29780) ==
                   kTestService3.substr(kTestService3.find(';') + 1,
                                        kTestService3.rfind(';') -
                                        kTestService3.find(';') - 1));

    // We didn't provide a Service Definition for port 29781, so the Utility
    // Function Definition should be the Default Utility Definition.
    CPPUNIT_ASSERT(tcp_proxy_->GetUtilityFnDef(29781) ==
                   kTestDefaultUtilityDef.substr(
                     0, kTestDefaultUtilityDef.rfind(';') - 1));
  }

  //==========================================================================
  void TestServiceDefUpdate()
  {
    tcp_proxy_->TestServiceDefUpdate();
  }

  //==========================================================================
  void TestFlowDefUpdate()
  {
    tcp_proxy_->TestFlowDefUpdate();
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(TcpProxyTest);
