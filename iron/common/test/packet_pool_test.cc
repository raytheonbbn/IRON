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

#include "itime.h"
#include "packet.h"
#include "packet_pool_shm.h"
#include "random_shared_memory.h"

#include <cstdio>
#include <cstring>
#include <iostream>

using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPoolShm;
using ::iron::Time;
using std::string;

class CircularBufferToTest : public PacketPoolShm::LocalPPCircBuf
{
public:
  CircularBufferToTest();
  virtual ~CircularBufferToTest();
};

//============================================================================
CircularBufferToTest::CircularBufferToTest()
    : PacketPoolShm::LocalPPCircBuf()
{
}

//============================================================================
// Destructor
CircularBufferToTest::~CircularBufferToTest()
{
}

//============================================================================
class PacketPoolTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(PacketPoolTest);

  CPPUNIT_TEST(TestCircularBuffer);
  CPPUNIT_TEST(TestGetRecycle);
  CPPUNIT_TEST(TestGetSize);
  CPPUNIT_TEST(TestClone);
  CPPUNIT_TEST(TestCloneHeaderOnly);

  CPPUNIT_TEST_SUITE_END();

private:

  struct iphdr    ip_hdr_;
  struct udphdr   udp_hdr_;
  key_t pkt_pool_key_;
  char pkt_pool_name_[kRandomShmNameSize];

public:
  //==========================================================================
  void setUp()
  {
    // Populate an IP header with some dummy values.
    ip_hdr_.version  = 4;
    ip_hdr_.ihl      = 5;
    ip_hdr_.protocol = IPPROTO_UDP;
    ip_hdr_.saddr    = htonl(1);
    ip_hdr_.daddr    = htonl(2);
    ip_hdr_.tot_len  = htons(sizeof(ip_hdr_));

    // Populate a UDP header with some dummy values.
    udp_hdr_.source = htons(4444);
    udp_hdr_.dest   = htons(9999);

    // Set the shared memory key and name.
    iron::RandomShmNameAndKey("pkt_pool_test", pkt_pool_name_,
                              kRandomShmNameSize, pkt_pool_key_);

    Log::SetDefaultLevel("FE");
  }

  //==========================================================================
  void tearDown()
  {
    Log::SetDefaultLevel("FE");
  }

  //==========================================================================
  void TestCircularBuffer()
  {
    CircularBufferToTest buf;
    iron::PktMemIndex val = 0;
    CPPUNIT_ASSERT(buf.Put(1));
    CPPUNIT_ASSERT(buf.Put(2));
    CPPUNIT_ASSERT(buf.Get(val));
    CPPUNIT_ASSERT(val == 1);
    CPPUNIT_ASSERT(buf.Get(val));
    CPPUNIT_ASSERT(val == 2);

    // Fill it up. The last couple should circle around because of the
    // above Puts.
    for (iron::PktMemIndex i = 0; i < iron::kLocalPPNumPkts; i++)
    {
      CPPUNIT_ASSERT(buf.Put(i * 10));
    }

    // Next put should fail (it is full).
    CPPUNIT_ASSERT(buf.Put(100) == false);

    // Check the first few values
    CPPUNIT_ASSERT(buf.Get(val));
    CPPUNIT_ASSERT(val == 0);
    CPPUNIT_ASSERT(buf.Get(val));
    CPPUNIT_ASSERT(val == 10);
    CPPUNIT_ASSERT(buf.Get(val));
    CPPUNIT_ASSERT(val == 20);
    CPPUNIT_ASSERT(buf.Get(val));
    CPPUNIT_ASSERT(val == 30);

    // Replace the 5 values we removed to fill it up again.
    for (iron::PktMemIndex i = 0; i < 4; i++)
    {
      CPPUNIT_ASSERT(buf.Put(i * 100));
    }

    // Next put should fail (it is full).
    CPPUNIT_ASSERT(buf.Put(100) == false);

    // Now empty it (without checking values this time)
    for (iron::PktMemIndex i = 0; i < iron::kLocalPPNumPkts; i++)
    {
      CPPUNIT_ASSERT(buf.Get(val));
    }

    // Buffer should be empty. Get should fail.
    CPPUNIT_ASSERT(buf.Get(val) == false);
  }

  //==========================================================================
  void TestGetRecycle()
  {
    PacketPoolShm pkt_pool;
    pkt_pool.Create(pkt_pool_key_, pkt_pool_name_);

    Packet* p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == 0);
    CPPUNIT_ASSERT(p1->MaxPacketSizeInBytes() == 2048);
    p1->SetLengthInBytes(500);
    // Create other packets to test purge and LIFO pool
    Packet* p2 = pkt_pool.Get();
    p2->SetLengthInBytes(1500);
    Packet* p3 = pkt_pool.Get();
    p3->SetLengthInBytes(750);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == 500);

    size_t empty_size = pkt_pool.GetSize();

    pkt_pool.Recycle(p3);
    pkt_pool.Recycle(p2);
    pkt_pool.Recycle(p1);

    CPPUNIT_ASSERT(empty_size == pkt_pool.GetSize() - 3);
  }

  //==========================================================================
  void TestGetSize()
  {
    PacketPoolShm pkt_pool;
    pkt_pool.Create(pkt_pool_key_, pkt_pool_name_);

    CPPUNIT_ASSERT(pkt_pool.GetSize() >= 3);
  }

  //==========================================================================
  void TestClone()
  {
    PacketPoolShm pkt_pool;
    pkt_pool.Create(pkt_pool_key_, pkt_pool_name_);
    char    test_string[]   = "Test Clone payload...";
    size_t  test_string_len = (strlen(test_string) + 1);

    Packet* p1 = pkt_pool.Get(iron::PACKET_NOW_TIMESTAMP);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    // Add the payload to the packet. For this test, don't worry about adding
    // a valid UDP header. We will however, ensure there is sufficient room in
    // the Packet for the UDP header.
    memcpy(p1->GetBuffer(sizeof(ip_hdr_) + sizeof(udp_hdr_)),
           reinterpret_cast<void*>(&test_string[0]), test_string_len);
    p1->SetLengthInBytes(sizeof(ip_hdr_) + sizeof(udp_hdr_) + test_string_len);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() ==
                   (sizeof(ip_hdr_) + sizeof(udp_hdr_) + test_string_len));

    Packet* p2 = pkt_pool.Clone(p1, false, iron::PACKET_NO_TIMESTAMP);
    CPPUNIT_ASSERT(p2 != NULL);
    CPPUNIT_ASSERT(p2->recv_time().GetTimeInUsec() == 0);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == p2->GetLengthInBytes());

    Packet* p3 = pkt_pool.Clone(p1, false, iron::PACKET_NOW_TIMESTAMP);
    Time now = Time::Now();
    // Check that the timestamp in the packet was set when we got the
    // packet (not 0, or a stale timestamp).
    CPPUNIT_ASSERT(now.GetTimeInUsec() -
                 p3->recv_time().GetTimeInUsec() < 1000);

    Packet* p4 = pkt_pool.Clone(p1, false, iron::PACKET_COPY_TIMESTAMP);
    CPPUNIT_ASSERT(p1->recv_time().GetTimeInUsec() ==
           p4->recv_time().GetTimeInUsec());

    char  p1_payload_str[64];
    char  p2_payload_str[64];

    memset(p1_payload_str, '\0', sizeof(p1_payload_str));
    memcpy(&p1_payload_str[0], p1->GetBuffer(sizeof(ip_hdr_) +
                                             sizeof(udp_hdr_)),
           (p1->GetLengthInBytes() - sizeof(ip_hdr_) - sizeof(udp_hdr_)));
    memset(p2_payload_str, '\0', sizeof(p2_payload_str));
    memcpy(&p2_payload_str[0], p2->GetBuffer(sizeof(ip_hdr_) +
                                             sizeof(udp_hdr_)),
           (p2->GetLengthInBytes() - sizeof(ip_hdr_) - sizeof(udp_hdr_)));

    string  string_from_packet_p1 = p1_payload_str;
    string  string_from_packet_p2 = p2_payload_str;
    CPPUNIT_ASSERT(string_from_packet_p1 == string_from_packet_p2);

    pkt_pool.Recycle(p1);
    pkt_pool.Recycle(p2);
    pkt_pool.Recycle(p3);
    pkt_pool.Recycle(p4);
  }

  //==========================================================================
  void TestCloneHeaderOnly()
  {
    PacketPoolShm pkt_pool;
    pkt_pool.Create(pkt_pool_key_, pkt_pool_name_);

    Packet* p1 = pkt_pool.Get(iron::PACKET_NOW_TIMESTAMP);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    // Create a clone of the Packet.
    Packet*  p2 = pkt_pool.Clone(p1, false, iron::PACKET_NO_TIMESTAMP);

    CPPUNIT_ASSERT(p1->GetLengthInBytes() == p2->GetLengthInBytes());
    CPPUNIT_ASSERT(p1->GetMaxLengthInBytes() == p2->GetMaxLengthInBytes());
    CPPUNIT_ASSERT(p2->recv_time().GetTimeInUsec() == 0);

    Packet* p3 = pkt_pool.Clone(p1, false, iron::PACKET_NOW_TIMESTAMP);
    Time now = Time::Now();
    // Check that the timestamp in the packet was set when we got the
    // packet (not 0, or a stale timestamp).
    CPPUNIT_ASSERT(now.GetTimeInUsec() -
                 p3->recv_time().GetTimeInUsec() < 1000);

    Packet* p4 = pkt_pool.Clone(p1, false, iron::PACKET_COPY_TIMESTAMP);
    CPPUNIT_ASSERT(p1->recv_time().GetTimeInUsec() ==
           p4->recv_time().GetTimeInUsec());

    struct udphdr*  udp_hdr_p1 =
      reinterpret_cast<struct udphdr*>(p1->GetBuffer(sizeof(ip_hdr_)));
    struct udphdr*  udp_hdr_p2 =
      reinterpret_cast<struct udphdr*>(p2->GetBuffer(sizeof(ip_hdr_)));

    CPPUNIT_ASSERT(udp_hdr_p1->source == udp_hdr_p2->source);
    CPPUNIT_ASSERT(udp_hdr_p1->dest == udp_hdr_p2->dest);

    pkt_pool.Recycle(p1);
    pkt_pool.Recycle(p2);
    pkt_pool.Recycle(p3);
    pkt_pool.Recycle(p4);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(PacketPoolTest);
