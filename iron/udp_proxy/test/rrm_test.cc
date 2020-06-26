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

#include "rrm.h"

#include "four_tuple.h"
#include "log.h"
#include "packet_pool_heap.h"
#include "unused.h"

using ::iron::Log;
using ::iron::Rrm;

namespace
{
    const char* UNUSED(kClassName)  = "RrmTester";
}

//============================================================================
class RrmTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(RrmTest);

  CPPUNIT_TEST(TestRrmCreation);
  CPPUNIT_TEST(TestRrmFill);
  CPPUNIT_TEST(TestRrmGetFlowFourTuple);
  CPPUNIT_TEST(TestRrmGetFlowDstPort);

  CPPUNIT_TEST_SUITE_END();

private:
  
  iron::PacketPoolHeap  pkt_pool_;
  iron::Packet*         rrm_;
  iron::FourTuple       four_tuple_;

public:
  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FEWIA");

    CPPUNIT_ASSERT(pkt_pool_.Create(8));

    uint32_t  saddr = htonl(10);
    uint32_t  daddr = htonl(100);

    uint16_t  sport = htons(4500);
    uint16_t  dport = htons(5500);

    four_tuple_.Set(saddr, sport, daddr, dport);
    rrm_  = Rrm::CreateNewRrm(pkt_pool_, four_tuple_);
  }

  //==========================================================================
  void tearDown()
  {
    pkt_pool_.Recycle(rrm_);

    Log::SetDefaultLevel("FE");
  }

  //==========================================================================
  void TestRrmCreation()
  {
    LogD(kClassName, __func__,
         "Testing RRM creation.\n");

    CPPUNIT_ASSERT(rrm_->GetLengthInBytes() == sizeof(struct iphdr) +
      sizeof(struct udphdr) + 4);

    // Check the src/dst addresses are flipped in RRM.
    uint32_t  addr;
    rrm_->GetIpSrcAddr(addr);
    CPPUNIT_ASSERT(addr == four_tuple_.dst_addr_nbo());
    
    rrm_->GetIpDstAddr(addr);
    CPPUNIT_ASSERT(addr == four_tuple_.src_addr_nbo());
    
    uint16_t  port;
    rrm_->GetSrcPort(port);
    CPPUNIT_ASSERT(port == four_tuple_.src_port_nbo());

    rrm_->GetDstPort(port);
    CPPUNIT_ASSERT(port == htons(Rrm::kDefaultRrmPort));

    uint8_t*  buf = rrm_->GetBuffer(rrm_->GetIpPayloadOffset());
    
    memcpy(&port, buf, sizeof(port));
    CPPUNIT_ASSERT(port == four_tuple_.dst_port_nbo());
  }

  //==========================================================================
  void TestRrmFill()
  {
    LogD(kClassName, __func__,
         "Testing RRM fill.\n");

    CPPUNIT_ASSERT(rrm_->GetLengthInBytes() == sizeof(struct iphdr) +
      sizeof(struct udphdr) + 4);

    uint64_t  tot_bytes = 100000;
    uint64_t  rel_bytes = 2000;
    uint32_t  tot_pkts  = 300;
    uint32_t  rel_pkts  = 3;
    uint32_t  loss_rate = 5;

    Rrm::FillReport(rrm_, tot_bytes, tot_pkts, rel_bytes, rel_pkts, loss_rate);

    uint64_t  this_tot_bytes;
    uint64_t  this_rel_bytes;
    uint32_t  this_tot_pkts;
    uint32_t  this_rel_pkts;
    uint32_t  this_loss_rate;

    Rrm::GetReport(rrm_, this_tot_bytes, this_tot_pkts, this_rel_bytes,
      this_rel_pkts, this_loss_rate);

    CPPUNIT_ASSERT(this_tot_bytes == tot_bytes);
    CPPUNIT_ASSERT(this_rel_bytes == rel_bytes);
    CPPUNIT_ASSERT(this_tot_pkts == tot_pkts);
    CPPUNIT_ASSERT(this_rel_pkts == rel_pkts);
    CPPUNIT_ASSERT(this_loss_rate == loss_rate);
  }

  //==========================================================================
  void TestRrmGetFlowFourTuple()
  {
    LogD(kClassName, __func__,
         "Testing RRM getting flow four tuple.\n");

    iron::FourTuple four_tuple(0, 0, 0, 0);
    Rrm::GetFlowFourTuple(rrm_, four_tuple);
    CPPUNIT_ASSERT(four_tuple == four_tuple_);
  }

  //==========================================================================
  void TestRrmGetFlowDstPort()
  {
    LogD(kClassName, __func__,
         "Testing RRM getting dst port.\n");

    uint16_t  flow_dst_port = 0;

    flow_dst_port = ntohs(Rrm::GetFlowDstPort(rrm_));
    CPPUNIT_ASSERT(flow_dst_port == 5500);
  } 
};

CPPUNIT_TEST_SUITE_REGISTRATION(RrmTest);
