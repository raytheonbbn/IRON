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

/// \brief   Tests the packetless ZombieQueue implementation.

#include <cppunit/extensions/HelperMacros.h>

#include "zombie_queue.h"

#include "bin_map.h"
#include "config_info.h"
#include "four_tuple.h"
#include "ipv4_address.h"
#include "log.h"
#include "packet.h"
#include "packet_pool.h"
#include "packet_pool_heap.h"
#include "zombie.h"

#include "packet_creator.h"

using ::iron::BinIndex;
using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::Ipv4Address;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketCreator;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::Zombie;
using ::iron::ZombieQueue;

//============================================================================
// Main test class.
class ZombieQueueTest : public CPPUNIT_NS::TestFixture
{
  CPPUNIT_TEST_SUITE(ZombieQueueTest);

  CPPUNIT_TEST(TestEnqueueDequeue);
  CPPUNIT_TEST(TestPurge);

  CPPUNIT_TEST_SUITE_END();

private:

  char*            bin_map_mem_ = NULL;
  BinMap*          bin_map_     = NULL;
  ZombieQueue*     zq_;
  PacketPool*      pkt_pool_;
  BinIndex         src_bin_idx_;
  Ipv4Address      dst_addr_;

  //============================================================================
  void InitBinMap(BinMap* bin_map)
  {
    ConfigInfo  ci;
    ci.Add("BinMap.BinIds", "2,5,6,7,10");
    ci.Add("BinMap.BinId.2.HostMasks",
           "192.168.2.0/24,10.2.2.2,2.2.2.2");
    ci.Add("BinMap.BinId.5.HostMasks",
           "192.168.5.0/24,10.5.5.5,5.5.5.5");
    ci.Add("BinMap.BinId.6.HostMasks",
           "192.168.6.0/24,10.6.6.6,6.6.6.6");
    ci.Add("BinMap.BinId.7.HostMasks",
           "192.168.7.0/24,10.7.7.7,7.7.7.7");
    ci.Add("BinMap.BinId.10.HostMasks",
           "192.168.10.0/24,10.10.10.10,10.10.10.10");
    CPPUNIT_ASSERT(bin_map->Initialize(ci) == true);
  }
public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");
    bin_map_mem_ = new char[sizeof(BinMap)];
    bin_map_     = reinterpret_cast<BinMap*>(bin_map_mem_);
    memset(bin_map_mem_, 0, sizeof(BinMap));

    CPPUNIT_ASSERT(bin_map_);
    InitBinMap(bin_map_);

    src_bin_idx_ = bin_map_->GetPhyBinIndex(5);
    dst_addr_    = Ipv4Address("10.2.2.2");

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(
      static_cast<PacketPoolHeap*>(pkt_pool_)->Create(10) == true);

    // Create a packet queue.
    zq_ = new ZombieQueue(*pkt_pool_, *bin_map_, false, iron::NORMAL_LATENCY,
      src_bin_idx_, dst_addr_);
  }

  //==========================================================================
  void tearDown()
  {
    // Delete the packet queue.
    delete zq_;
    zq_ = NULL;

    delete pkt_pool_;
    pkt_pool_ = NULL;

    delete [] bin_map_mem_;
    bin_map_mem_ = NULL;
    bin_map_     = NULL;
    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestEnqueueDequeue()
  {
    CPPUNIT_ASSERT(zq_->GetSize() == 0);
    CPPUNIT_ASSERT(zq_->GetCount() == 0);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == 0);

    uint32_t orig_src_addr = Ipv4Address("10.3.3.3").address();
    uint32_t orig_dst_addr = Ipv4Address("10.4.4.4").address();

    Packet* pkt1 = Zombie::CreateNewZombie(
      *pkt_pool_, orig_src_addr, orig_dst_addr, 500, iron::HIGH_LATENCY_NPLB);
    CPPUNIT_ASSERT(pkt1);
    zq_->Enqueue(pkt1);
    size_t qlen = 500;

    // The length of a compressed zombie is exactly the length we passed into
    // CreateNewZombie.
    CPPUNIT_ASSERT(zq_->GetSize() == 500);
    CPPUNIT_ASSERT(zq_->GetCount() > 0);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == 500);


    iron::FourTuple ft;
    ft.Set(orig_src_addr, htons(1), orig_dst_addr, htons(2));
    Packet* pkt2 = PacketCreator::CreateUdpPacket(*pkt_pool_, &ft, 893);
    CPPUNIT_ASSERT(pkt2);
    // Length includes the 893 bytes of data plus headers.
    qlen += pkt2->GetLengthInBytes();
    Zombie::ZombifyExistingPacket(pkt2);
    zq_->Enqueue(pkt2);

    CPPUNIT_ASSERT(zq_->GetSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetCount() > 0);
    CPPUNIT_ASSERT(zq_->GetTotalDequeueSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == kMaxZombieLenBytes);

    Packet* dequeue1 = zq_->Dequeue(100);
    qlen -= 100;

    CPPUNIT_ASSERT(dequeue1 != NULL);
    CPPUNIT_ASSERT(dequeue1->virtual_length() == 100);
    size_t phys_zombie_len = 0;
    if (iron::kDefaultZombieCompression)
    {
      phys_zombie_len = sizeof(struct iphdr) + sizeof(uint32_t);
    }
    else
    {
      phys_zombie_len = 100;
    }
    CPPUNIT_ASSERT(dequeue1->GetLengthInBytes() == phys_zombie_len);
    CPPUNIT_ASSERT(zq_->GetSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetCount() > 0);
    CPPUNIT_ASSERT(zq_->GetTotalDequeueSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == kMaxZombieLenBytes);
    pkt_pool_->Recycle(dequeue1);

    Packet* dequeue2 = zq_->Dequeue(1000);
    qlen -= 1000;

    CPPUNIT_ASSERT(dequeue2 != NULL);
    CPPUNIT_ASSERT(dequeue2->virtual_length() == 1000);

    CPPUNIT_ASSERT(zq_->GetSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetCount() > 0);
    CPPUNIT_ASSERT(zq_->GetTotalDequeueSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == qlen);
    pkt_pool_->Recycle(dequeue2);

    // qlen should now be less then 1000, so this packet will be the rest of
    // the zombie bytes.
    Packet* dequeue3 = zq_->Dequeue(1000);

    CPPUNIT_ASSERT(dequeue3 != NULL);
    CPPUNIT_ASSERT(dequeue3->virtual_length() == qlen);

    CPPUNIT_ASSERT(zq_->GetSize() == 0);
    CPPUNIT_ASSERT(zq_->GetCount() == 0);
    CPPUNIT_ASSERT(zq_->GetTotalDequeueSize() == 0);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == 0);
    pkt_pool_->Recycle(dequeue3);
  }

  //==========================================================================
  void TestPurge()
  {

    uint32_t orig_src_addr = Ipv4Address("10.3.3.3").address();
    uint32_t orig_dst_addr = Ipv4Address("10.4.4.4").address();

    Packet* pkt1 = Zombie::CreateNewZombie(
      *pkt_pool_, orig_src_addr, orig_dst_addr, 500, iron::HIGH_LATENCY_NPLB);
    CPPUNIT_ASSERT(pkt1);
    zq_->Enqueue(pkt1);
    size_t qlen = 500;

    // The length of a compressed zombie is exactly the length we passed into
    // CreateNewZombie.
    CPPUNIT_ASSERT(zq_->GetSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetCount() > 0);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == qlen);


    iron::FourTuple ft;
    ft.Set(orig_src_addr, htons(1), orig_dst_addr, htons(2));
    Packet* pkt2 = PacketCreator::CreateUdpPacket(*pkt_pool_, &ft, 893);
    CPPUNIT_ASSERT(pkt2);
    // Length includes the 893 bytes of data plus headers.
    qlen += pkt2->virtual_length();
    Zombie::ZombifyExistingPacket(pkt2);
    zq_->Enqueue(pkt2);

    CPPUNIT_ASSERT(zq_->GetSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetCount() > 0);
    CPPUNIT_ASSERT(zq_->GetTotalDequeueSize() == qlen);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == kMaxZombieLenBytes);

    zq_->Purge();

    CPPUNIT_ASSERT(zq_->GetSize() == 0);
    CPPUNIT_ASSERT(zq_->GetCount() == 0);
    CPPUNIT_ASSERT(zq_->GetNextDequeueSize() == 0);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(ZombieQueueTest);
