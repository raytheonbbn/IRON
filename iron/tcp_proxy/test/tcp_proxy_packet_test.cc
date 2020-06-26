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

// Test cases that involve sending packets through the tcp proxy.

#include <cppunit/extensions/HelperMacros.h>

#include "tcp_proxy.h"

#include "bin_map.h"
#include "config_info.h"
#include "log.h"
#include "fifo_if.h"
#include "itime.h"
#include "iron_constants.h"
#include "packet.h"
#include "packet_pool.h"
#include "packet_pool_heap.h"
#include "string_utils.h"
#include "pseudo_edge_if.h"
#include "pseudo_fifo.h"
#include "pseudo_shared_memory.h"
#include "shared_memory_if.h"
#include "unused.h"
#include "virtual_edge_if.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string>

using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::FourTuple;
using ::iron::FifoIF;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::PktMemIndex;
using ::iron::PseudoEdgeIf;
using ::iron::PseudoFifo;
using ::iron::PseudoSharedMemory;
using ::iron::RemoteControlServer;
using ::iron::SharedMemoryIF;
using ::iron::Time;
using ::iron::VirtualEdgeIf;
using ::std::string;

namespace
{
  const char*   UNUSED(kClassName) = "TcpProxyPacketTest";

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

  const char*    kSomeIpAddr = "192.168.0.123";
  const char*    kSomeOtherIpAddr = "172.24.3.2";
  const uint16_t kSomePort = 2343;
  const uint16_t kSomeOtherPort = 2345;

  const int kPoolSize = 100;
}

//============================================================================
class RemoteControlServerTester : public RemoteControlServer
{
  public:
  RemoteControlServerTester() : RemoteControlServer() { }
  virtual ~RemoteControlServerTester () { };

  protected:
    bool InSet(int socket, fd_set& fds)
    {
      // never say the socket is ready to read.
      return false;
    }
};

//============================================================================
class TcpProxyPacketTester : public TcpProxy
{
  public:
  TcpProxyPacketTester(TcpProxyConfig& proxy_config, PacketPool& packet_pool,
                       VirtualEdgeIf& edge_if,
                       BinMap& bin_map,
                       SharedMemoryIF& weight_qd_shared_memory,
                       FifoIF* bpf_to_tcp_pkt_fifo,
                       FifoIF* tcp_to_bpf_pkt_fifo,
                       RemoteControlServerTester& remote_control_server)
  : TcpProxy(proxy_config, packet_pool, edge_if, bin_map,
             weight_qd_shared_memory, bpf_to_tcp_pkt_fifo,
             tcp_to_bpf_pkt_fifo, remote_control_server)
  {
  }

  virtual ~TcpProxyPacketTester ()
  {
  }

  int Select(int nfds, fd_set* readfs, struct timeval* timeout)
  {
    // always say something is ready to read.
    return 1;
  };

  void MainLoop()
  {
    TcpProxy::MainLoop();
  };
};

//============================================================================
class TcpProxyPacketTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(TcpProxyPacketTest);

  CPPUNIT_TEST(Test_RstPacketFromLanIF_NoExistingSocket_SentToBpf);

  CPPUNIT_TEST_SUITE_END();

  private:

  TcpProxyPacketTester*       tcp_proxy_;
  RemoteControlServerTester*  remote_control_server_;
  TcpProxyConfig*             tcp_proxy_config_;
  PacketPoolHeap*             packet_pool_;
  PseudoEdgeIf*               edge_if_;
  SharedMemoryIF*             weight_qd_shared_memory_;
  PseudoFifo*                 bpf_to_tcp_pkt_fifo_;
  PseudoFifo*                 tcp_to_bpf_pkt_fifo_;
  Packet*                     created_pkts_[kPoolSize];
  int                         created_pkt_count_;
  BinMap* bin_map_;
  char* bin_map_mem_;

  public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");

    remote_control_server_ = new RemoteControlServerTester();
    tcp_proxy_config_ = new TcpProxyConfig();
    packet_pool_ = new PacketPoolHeap();
    packet_pool_->Create(kPoolSize);

    edge_if_ = new PseudoEdgeIf(*packet_pool_, false);

    weight_qd_shared_memory_ = new PseudoSharedMemory();

    bpf_to_tcp_pkt_fifo_ = new PseudoFifo();
    tcp_to_bpf_pkt_fifo_ = new PseudoFifo();

    bin_map_mem_       = new char[sizeof(BinMap)];
    bin_map_           = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));

    ConfigInfo  ci;

    // Add bin map configuration.
    ci.Add("BinMap.BinIds", "1,2,3");
    ci.Add("BinMap.BinId.1.IronNodeAddr", "172.24.1.2");
    ci.Add("BinMap.BinId.1.HostMasks", "172.24.1.0/24");
    ci.Add("BinMap.BinId.1.BinningRule", "ALL");
    ci.Add("BinMap.BinId.2.IronNodeAddr", "172.24.2.2");
    ci.Add("BinMap.BinId.2.HostMasks", "172.24.2.0/24");
    ci.Add("BinMap.BinId.2.BinningRule", "ALL");
    ci.Add("BinMap.BinId.3.IronNodeAddr", "172.24.3.2");
    ci.Add("BinMap.BinId.3.HostMasks", "172.24.3.0/24");
    ci.Add("BinMap.BinId.3.BinningRule", "ALL");

    bin_map_->Initialize(ci);

    // Create the TCP Proxy for testing.
    tcp_proxy_ = new (std::nothrow) TcpProxyPacketTester(*tcp_proxy_config_,
                      *packet_pool_, *edge_if_, *bin_map_,
                      *weight_qd_shared_memory_, bpf_to_tcp_pkt_fifo_,
                      tcp_to_bpf_pkt_fifo_, *remote_control_server_);

    CPPUNIT_ASSERT(tcp_proxy_);

    InitProxy();
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

    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;
    bin_map_     = NULL;

    for (int i = 0; i < created_pkt_count_; i++)
    {
      packet_pool_->Recycle(created_pkts_[i]);
    }
    created_pkt_count_ = 0;

    delete packet_pool_;
    packet_pool_ = NULL;

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

  void TrackPacket(Packet* pkt)
  {
    created_pkts_[created_pkt_count_] = pkt;
    created_pkt_count_++;
  }

  void AssertSamePacket(Packet* sent_pkt, Packet* recv_pkt)
  {
    CPPUNIT_ASSERT_EQUAL(sent_pkt->GetLengthInBytes(),
      recv_pkt->GetLengthInBytes());
    struct iphdr* sent_ip = (struct iphdr*)sent_pkt->GetBuffer();
    struct iphdr* recv_ip = (struct iphdr*)recv_pkt->GetBuffer();
    CPPUNIT_ASSERT_EQUAL(sent_ip->saddr, recv_ip->saddr);
    CPPUNIT_ASSERT_EQUAL(sent_ip->daddr, recv_ip->daddr);
    CPPUNIT_ASSERT_EQUAL(sent_ip->daddr, recv_ip->daddr);
  }

  //==========================================================================
  void Test_RstPacketFromLanIF_NoExistingSocket_SentToBpf()
  {
    // make reset packet
    Packet* pkt = packet_pool_->Get();
    TrackPacket(pkt);
    pkt->SetLengthInBytes(sizeof(struct iphdr) + sizeof(struct tcphdr));
    memset(pkt->GetBuffer(), 0, pkt->GetLengthInBytes());
    struct iphdr* ip = (struct iphdr*)pkt->GetBuffer();
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = pkt->GetLengthInBytes();
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(kSomeIpAddr);
    ip->daddr = inet_addr(kSomeOtherIpAddr);
    struct tcphdr* tcp = (struct tcphdr*)pkt->GetBuffer(sizeof(struct iphdr));
    tcp->th_flags = TH_RST;
    tcp->source = kSomePort;
    tcp->dest = kSomeOtherPort;

    // Place in raw socket.
    edge_if_->packets_to_recv.push(pkt);

    tcp_proxy_->MainLoop();

    CPPUNIT_ASSERT_MESSAGE("packet fifo received a message",
     tcp_to_bpf_pkt_fifo_->sent_messages.size() == 0);
  }

  //============================================================================
  void InitProxy()
  {
    ConfigInfo  ci;

    ci.Add("KVal", kTestKValue);

    ci.Add("MtuBytes", kTestMtuBytes);

    ci.Add("Service0", kTestService0);
    ci.Add("Service1", kTestService1);
    ci.Add("Service2", kTestService2);
    ci.Add("Service3", kTestService3);
    ci.Add("DefaultUtilityDef", kTestDefaultUtilityDef);

    CPPUNIT_ASSERT(tcp_proxy_->Initialize(ci));
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(TcpProxyPacketTest);
