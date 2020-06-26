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

#include "iron_types.h"
#include "itime.h"
#include "log.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "udp_fec_trailer.h"

#include <cstdio>
#include <cstring>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include <string>
#include <unistd.h>

using ::iron::BinId;
using ::iron::Log;
using ::iron::LSA_PACKET;
using ::iron::Packet;
using ::iron::PacketPoolHeap;
using ::iron::QLAM_PACKET;
using ::iron::Time;
using ::iron::UNKNOWN_PACKET;
using std::string;


//============================================================================
class PacketTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(PacketTest);

  CPPUNIT_TEST(TestAssignmentOperator);
  CPPUNIT_TEST(TestRefCnt);
  CPPUNIT_TEST(TestShallowCopy);
  CPPUNIT_TEST(TestGetBuffer);
  CPPUNIT_TEST(TestSetLengthInBytes);
  CPPUNIT_TEST(TestMaxPacketSizeInBytes);
  CPPUNIT_TEST(TestRemoveBytesFromBeginning);
  CPPUNIT_TEST(TestAddBytesToBeginning);
  CPPUNIT_TEST(TestAppendBlockToEnd);
  CPPUNIT_TEST(TestRemoveBlockFromEnd);
  CPPUNIT_TEST(TestCopyBlockFromEnd);
  CPPUNIT_TEST(TestGetType);
  CPPUNIT_TEST(TestIpHdrMethods);
  CPPUNIT_TEST(TestGetHdr);
  CPPUNIT_TEST(TestGetIpDscp);
  CPPUNIT_TEST(TestGetIpPayloadOffset);
  CPPUNIT_TEST(TestGetIpPayloadLengthInBytes);
  CPPUNIT_TEST(TestTransportHeaderMethods);
  CPPUNIT_TEST(TestUpdateAndTrimIpLen);
  CPPUNIT_TEST(TestUpdateChecksums);
  CPPUNIT_TEST(TestZeroChecksums);
  CPPUNIT_TEST(TestGetFiveTuple);
  CPPUNIT_TEST(TestRecvTimeAccessors);
  CPPUNIT_TEST(TestTtgMethods);
  CPPUNIT_TEST(TestMgenGets);
  CPPUNIT_TEST(TestToString);
  CPPUNIT_TEST(TestConstructors);
  CPPUNIT_TEST(TestReset);
  CPPUNIT_TEST(TestBroadcastPacket);
  CPPUNIT_TEST(TestHistory);

  CPPUNIT_TEST_SUITE_END();

private:

  struct iphdr    ip_hdr_;
  struct udphdr   udp_hdr_;
  struct Packet::MgenHdr  mgen_hdr_;

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

    // Populate an MGEN header with some dummy values.
    mgen_hdr_.version             = 2;
    mgen_hdr_.messageSize         = htons(1222);
    mgen_hdr_.sequenceNumber      = htonl(10);
    mgen_hdr_.txTimeSeconds       = htonl(999);
    mgen_hdr_.txTimeMicroseconds  = htonl(1001);

    Log::SetDefaultLevel("FE");
  }

  //==========================================================================
  void tearDown()
  {
    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestAssignmentOperator()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet*  p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1);

    char    p1_str[] = "Test assignment operator...";
    size_t  p1_str_len = (strlen(p1_str) + 1);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(p1_str), p1_str_len);
    p1->SetLengthInBytes(p1_str_len);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == p1_str_len);

    Packet*  p2 = pkt_pool.Get();
    CPPUNIT_ASSERT(p2);
    *p2 = *p1;
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == p2->GetLengthInBytes());
    CPPUNIT_ASSERT(p1->GetMaxLengthInBytes() == p2->GetMaxLengthInBytes());

    string  p1_string = reinterpret_cast<char*>(p1->GetBuffer());
    string  p2_string = reinterpret_cast<char*>(p2->GetBuffer());
    CPPUNIT_ASSERT(p1_string == p2_string);

    pkt_pool.Recycle(p1);
    pkt_pool.Recycle(p2);
  }

  //==========================================================================
  void TestRefCnt()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet*  p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1->ref_cnt() == 1);
    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestShallowCopy()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet*  p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1->ref_cnt() == 1);

    pkt_pool.PacketShallowCopy(p1);
    CPPUNIT_ASSERT(p1->ref_cnt() == 2);

    pkt_pool.Recycle(p1);
    CPPUNIT_ASSERT(p1->ref_cnt() == 1);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestGetBuffer()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);
    char    test_string[]   = "Test GetBuffer()...";
    size_t  test_string_len = (strlen(test_string) + 1);

    Packet* p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1);

    // Test GetBuffer.
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&test_string[0]),
           test_string_len);
    p1->SetLengthInBytes(test_string_len);

    string  string_from_packet_p1 = reinterpret_cast<char*>(p1->GetBuffer());
    CPPUNIT_ASSERT(test_string == string_from_packet_p1);

    // Test GetBuffer with an offset.
    Packet* p2 = pkt_pool.Get();
    CPPUNIT_ASSERT(p2);
    uint8_t offset = 10;

    memset(p2->GetBuffer(), '\0', offset);
    memcpy(p2->GetBuffer(offset), reinterpret_cast<void*>(&test_string[0]),
           test_string_len);
    p2->SetLengthInBytes(test_string_len);

    string  string_from_packet_p2 =
      reinterpret_cast<char*>(p2->GetBuffer(offset));
    CPPUNIT_ASSERT(test_string == string_from_packet_p2);

    string  string_from_packet_p2_no_offset =
      reinterpret_cast<char*>(p2->GetBuffer());

    CPPUNIT_ASSERT(test_string != string_from_packet_p2_no_offset);

    pkt_pool.Recycle(p1);
    pkt_pool.Recycle(p2);
  }

  //==========================================================================
  void TestSetLengthInBytes()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();

    p1->SetLengthInBytes(200);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == 200);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestMaxPacketSizeInBytes()
  {
    CPPUNIT_ASSERT(Packet::MaxPacketSizeInBytes() == 2048);
  }

  //==========================================================================
  void TestRemoveBytesFromBeginning()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    uint8_t*  buffer = p1->GetBuffer(sizeof(ip_hdr_));
    *buffer = static_cast<uint8_t>(QLAM_PACKET);
    p1->SetLengthInBytes(sizeof(ip_hdr_) + sizeof(uint8_t));

    p1->RemoveBytesFromBeginning(sizeof(ip_hdr_));
    CPPUNIT_ASSERT(p1->GetType() == QLAM_PACKET);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestAddBytesToBeginning()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet*  p1 = pkt_pool.Get();

    // Eliminate any start offset in the packet.
    bool  rv = true;
    do
    {
      rv = p1->AddBytesToBeginning(1);
    }
    while (rv);
    p1->SetLengthInBytes(0);

    size_t    offset = 20;
    uint8_t*  buffer = p1->GetBuffer(offset);
    *buffer = static_cast<uint8_t>(QLAM_PACKET);
    p1->SetLengthInBytes(sizeof(uint8_t) + offset);

    // We need to remove bytes from the beginning before we can try to add
    // them to the beginning. This will ensure that the Packet private start_
    // member variable is correct.
    p1->RemoveBytesFromBeginning(offset);

    // Try to add more bytes than are available. This should fail.
    CPPUNIT_ASSERT(p1->AddBytesToBeginning(offset * 2) == false);

    // Add a number of bytes that should succeed.
    CPPUNIT_ASSERT(p1->AddBytesToBeginning(offset / 2) == true);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() ==
                   (sizeof(uint8_t) + (offset / 2)));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestAppendBlockToEnd()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() ==
                   (sizeof(ip_hdr_) + sizeof(udp_hdr_)));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestRemoveBlockFromEnd()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    // Now remove the UDP header from the Packet.
    struct udphdr  udp_hdr;

    CPPUNIT_ASSERT(p1->RemoveBlockFromEnd(reinterpret_cast<uint8_t*>(&udp_hdr),
                                          sizeof(udp_hdr)) == true);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == sizeof(ip_hdr_));
    CPPUNIT_ASSERT(udp_hdr.source == htons(4444));
    CPPUNIT_ASSERT(udp_hdr.dest   == htons(9999));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestCopyBlockFromEnd()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    // Now copy the UDP header from the Packet.
    struct udphdr  udp_hdr;

    CPPUNIT_ASSERT(p1->CopyBlockFromEnd(reinterpret_cast<uint8_t*>(&udp_hdr),
                                        sizeof(udp_hdr)) == true);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() ==
                   (sizeof(ip_hdr_) + sizeof(udp_hdr_)));
    CPPUNIT_ASSERT(udp_hdr.source == htons(4444));
    CPPUNIT_ASSERT(udp_hdr.dest   == htons(9999));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestGetType()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet*  p1 = pkt_pool.Get();
    *(p1->GetBuffer()) = static_cast<uint8_t>(LSA_PACKET);
    p1->SetLengthInBytes(sizeof(uint8_t));

    CPPUNIT_ASSERT(p1->GetType() == LSA_PACKET);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestIpHdrMethods()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    // Create a Packet that contains the IP header.
    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Test the source and destination address accessors.
    uint32_t  src_addr = 0;
    uint32_t  dst_addr = 0;

    CPPUNIT_ASSERT(p1->GetIpSrcAddr(src_addr) == true);
    CPPUNIT_ASSERT(p1->GetIpDstAddr(dst_addr) == true);
    CPPUNIT_ASSERT(ntohl(src_addr) == 1);
    CPPUNIT_ASSERT(ntohl(dst_addr) == 2);

    // Test the protocol accessor.
    uint8_t  protocol = 0;
    CPPUNIT_ASSERT(p1->GetIpProtocol(protocol) == true);
    CPPUNIT_ASSERT(protocol == IPPROTO_UDP);

    // Test the method to get the IP header length.
    size_t  ip_len = 0;

    CPPUNIT_ASSERT(p1->GetIpLen(ip_len) == true);
    CPPUNIT_ASSERT(ip_len == sizeof(ip_hdr_));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestGetHdr()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p = pkt_pool.Get();
    memcpy(p->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p->SetLengthInBytes(sizeof(ip_hdr_));

    struct iphdr* ip_hdr  = p->GetIpHdr();
    CPPUNIT_ASSERT(ip_hdr);
    CPPUNIT_ASSERT(ip_hdr->version == ip_hdr_.version);

    memcpy(p->GetBuffer(sizeof(ip_hdr_)), reinterpret_cast<void*>(&udp_hdr_),
           sizeof(udp_hdr_));
    p->SetLengthInBytes(sizeof(ip_hdr_) + sizeof(udp_hdr_));

    struct udphdr*  udp_hdr = p->GetUdpHdr();
    CPPUNIT_ASSERT(udp_hdr);
    CPPUNIT_ASSERT(udp_hdr->source == udp_hdr_.source);

    pkt_pool.Recycle(p);
  }

  //==========================================================================
  void TestGetIpDscp()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Should not be able to set as high a DSCP value.
    CPPUNIT_ASSERT(!p1->SetIpDscp(0xC0));

    // Set 0x2A.
    CPPUNIT_ASSERT(p1->SetIpDscp(0x2A));

    uint8_t dscp = 0;
    CPPUNIT_ASSERT(p1->GetIpDscp(dscp));
    // Make sure we can read 0x2A.
    CPPUNIT_ASSERT(dscp == 0x2A);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestGetIpPayloadOffset()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    CPPUNIT_ASSERT(p1->GetIpPayloadOffset() ==
                   (sizeof(ip_hdr_) + sizeof(udp_hdr_)));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestGetIpPayloadLengthInBytes()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    char    test_string[]   = "Test GetIpPayloadLengthInBytes payload...";
    size_t  test_string_len = (strlen(test_string) + 1);
    Packet* p1 = pkt_pool.Get();
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

    CPPUNIT_ASSERT(p1->GetIpPayloadLengthInBytes() == test_string_len);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestTransportHeaderMethods()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    // Create a Packet that contains the IP header.
    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Test the source and destination port methods.
    uint16_t  src_port_nbo = 0;
    uint16_t  dst_port_nbo = 0;

    // The following should fail as we have only added an IP header to the
    // packet.
    CPPUNIT_ASSERT(p1->GetSrcPort(src_port_nbo) == false);
    CPPUNIT_ASSERT(p1->GetSrcPort(dst_port_nbo) == false);

    // Now we will add an empty UDP header to the packet,
    struct udphdr  udp_hdr;
    memcpy(p1->GetBuffer(sizeof(ip_hdr_)), &udp_hdr, sizeof(udp_hdr));
    p1->SetLengthInBytes(sizeof(ip_hdr_) + sizeof(udp_hdr));

    // set the source and destination ports in the UDP header,
    uint16_t  sport_nbo = htons(5555);
    uint16_t  dport_nbo = htons(7777);

    CPPUNIT_ASSERT(p1->SetSrcPort(sport_nbo) == true);
    CPPUNIT_ASSERT(p1->SetDstPort(dport_nbo) == true);

    // and make sure that we can extract them.
    CPPUNIT_ASSERT(p1->GetSrcPort(src_port_nbo) == true);
    CPPUNIT_ASSERT(p1->GetDstPort(dst_port_nbo) == true);
    CPPUNIT_ASSERT(src_port_nbo == sport_nbo);
    CPPUNIT_ASSERT(dst_port_nbo == dport_nbo);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestUpdateAndTrimIpLen()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);
    char          test_string[]   = "Test TrimIPLen payload...";
    size_t        test_string_len = (::strlen(test_string) + 1);

    // Create a Packet that contains the IP header.
    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Add the payload to the packet. For this test, don't worry about adding
    // a valid UDP header. We will however, ensure there is sufficient room in
    // the Packet for the UDP header.
    memcpy(p1->GetBuffer(sizeof(ip_hdr_) + sizeof(udp_hdr_)),
           reinterpret_cast<void*>(&test_string[0]), test_string_len);
    p1->SetLengthInBytes(sizeof(ip_hdr_) + sizeof(udp_hdr_) + test_string_len);
    p1->UpdateIpLen();

    size_t  ip_len = 0;

    CPPUNIT_ASSERT(p1->GetIpLen(ip_len) == true);
    CPPUNIT_ASSERT(ip_len == (sizeof(ip_hdr_) + sizeof(udp_hdr_) +
                              test_string_len));

    // Trim 3 bytes from the Packet. The 3 bytes will be two '.' characters
    // and the terminating '\0', leaving "Test TrimIPLen payload.".
    p1->TrimIpLen(3);
    CPPUNIT_ASSERT(p1->GetIpLen(ip_len) == true);
    CPPUNIT_ASSERT(ip_len == (sizeof(ip_hdr_) + sizeof(udp_hdr_) +
                              test_string_len - 3));

    char      payload_string[64];
    uint8_t*  payload = p1->GetBuffer(sizeof(ip_hdr_) + sizeof(udp_hdr_));

    memset(payload_string, '\0', sizeof(payload_string));
    memcpy(payload_string, payload, p1->GetLengthInBytes() - sizeof(ip_hdr_)
           - sizeof(udp_hdr_));

    string  string_from_packet_p1 = payload_string;
    CPPUNIT_ASSERT(string_from_packet_p1 == "Test TrimIPLen payload.");

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestUpdateChecksums()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    // The UpdateChecksums() method exercies both UpdateIPChecksum and
    // UpdateTransportChecksum so we won't test those individually.
    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    CPPUNIT_ASSERT(p1->UpdateChecksums() == true);

    // Remember the IP Checksum before making any modifications.
    uint16_t       orig_ip_checksum;
    struct iphdr*  ip_hdr = reinterpret_cast<struct iphdr*>(p1->GetBuffer());

    orig_ip_checksum = ip_hdr->check;

    // Change the source address in the IP header.
    ip_hdr->saddr = 6;

    CPPUNIT_ASSERT(p1->UpdateChecksums() == true);

    uint16_t  new_ip_checksum = ip_hdr->check;

    CPPUNIT_ASSERT(orig_ip_checksum != new_ip_checksum);

    // Remember the UDP Checksum before making any modifications.
    uint16_t        orig_udp_checksum;
    struct udphdr*  udp_hdr =
      reinterpret_cast<struct udphdr*>(p1->GetBuffer(sizeof(ip_hdr_)));

    orig_udp_checksum = udp_hdr->check;

    // Change the source port in the UDP header.
    uint16_t  new_src_port = 1234;

    CPPUNIT_ASSERT(p1->SetSrcPort(new_src_port) == true);

    CPPUNIT_ASSERT(p1->UpdateChecksums() == true);

    uint16_t  new_udp_checksum = udp_hdr->check;

    CPPUNIT_ASSERT(orig_udp_checksum != new_udp_checksum);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestZeroChecksums()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    CPPUNIT_ASSERT(p1->UpdateChecksums() == true);

    CPPUNIT_ASSERT(p1->UpdateChecksums() == true);
    // Get original ip checksum for comparison
    struct iphdr*  ip_hdr = reinterpret_cast<struct iphdr*>(p1->GetBuffer());
    uint16_t orig_ip_checksum = ip_hdr->check;

    // Get origin udp checksum for comparison
    uint16_t        orig_udp_checksum;
    struct udphdr*  udp_hdr =
      reinterpret_cast<struct udphdr*>(p1->GetBuffer(sizeof(ip_hdr_)));

    orig_udp_checksum = udp_hdr->check;

    CPPUNIT_ASSERT(p1->ZeroChecksums() == true);

    // Get the updated values of both checksums
    uint16_t  new_ip_checksum = ip_hdr->check;
    uint16_t  new_udp_checksum = udp_hdr->check;

    CPPUNIT_ASSERT(new_ip_checksum != orig_ip_checksum);
    CPPUNIT_ASSERT(new_ip_checksum == 0);

    CPPUNIT_ASSERT(new_udp_checksum != orig_udp_checksum);
    CPPUNIT_ASSERT(new_udp_checksum == 0);

    pkt_pool.Recycle(p1);
   }

  //==========================================================================
  void TestGetFiveTuple()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    uint32_t  src_addr_nbo = 0;
    uint32_t  dst_addr_nbo = 0;
    uint32_t  protocol     = 0;
    uint16_t  src_port_nbo = 0;
    uint16_t  dst_port_nbo = 0;

    CPPUNIT_ASSERT(p1->GetFiveTuple(src_addr_nbo, dst_addr_nbo, src_port_nbo,
                                    dst_port_nbo, protocol) == true);

    CPPUNIT_ASSERT(src_addr_nbo == ntohl(1));
    CPPUNIT_ASSERT(dst_addr_nbo == ntohl(2));
    CPPUNIT_ASSERT(protocol == IPPROTO_UDP);
    CPPUNIT_ASSERT(src_port_nbo == ntohs(4444));
    CPPUNIT_ASSERT(dst_port_nbo == ntohs(9999));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestRecvTimeAccessors()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get(iron::PACKET_NOW_TIMESTAMP);

    // Check that there is some initial recv time
    CPPUNIT_ASSERT(p1->recv_time().GetTimeInUsec() != 0);

    usleep(100);
    Time now = Time::Now();
    // Check that it is different from the time now;
    CPPUNIT_ASSERT(p1->recv_time().GetTimeInUsec() != now.GetTimeInUsec());

    p1->set_recv_time(now);
    // Check that it is now set to the new time;
    CPPUNIT_ASSERT(p1->recv_time().GetTimeInUsec() == now.GetTimeInUsec());

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestTtgMethods()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get(iron::PACKET_NOW_TIMESTAMP);
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    // Add FEC controller for time to go.
    p1->SetLengthInBytes(sizeof(ip_hdr_) + sizeof(FECControlTrailer));

    p1->SetTimeToGo(Time(-2));
    CPPUNIT_ASSERT(p1->HasExpired());
    CPPUNIT_ASSERT(!p1->CanBeDeliveredInTime(Time(11)));

    p1->SetTimeToGo(Time(10));
    CPPUNIT_ASSERT(!p1->CanBeDeliveredInTime(Time(11)));
    CPPUNIT_ASSERT(p1->CanBeDeliveredInTime(Time(9)));

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestMgenGets()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Append the UDP header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udp_hdr_),
                                       sizeof(udp_hdr_)) == true);

    // Append the MGEN header to the Packet.
    CPPUNIT_ASSERT(p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&mgen_hdr_),
                                       sizeof(mgen_hdr_)) == true);

    CPPUNIT_ASSERT(p1->GetMgenSeqNum() == 10);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestToString()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    Packet*  p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1->ToString().find("Packet length: (phy: 0B, virt: 0B) "
                   "maximum length: 2048B") != string::npos);
    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestConstructors()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    // Test the default constructor.
    Packet*  p1 = pkt_pool.Get();
    Time     now = Time::Now();
    Packet*  p2 = pkt_pool.Get(iron::PACKET_NOW_TIMESTAMP);

    CPPUNIT_ASSERT(p1);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == 0);
    CPPUNIT_ASSERT(p1->MaxPacketSizeInBytes() == 2048);
    CPPUNIT_ASSERT(p1->recv_time().GetTimeInUsec() == 0);

    // Check that the timestamp in the packet was set when we got the
    // packet (not 0, or a stale timestamp).
    CPPUNIT_ASSERT(p2->recv_time().GetTimeInUsec() -
                               now.GetTimeInUsec() < 1000);

    pkt_pool.Recycle(p1);
    pkt_pool.Recycle(p2);
  }

  //==========================================================================
  void TestReset()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    // Create a Packet that contains the IP header.
    Packet* p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));

    // Recycle the Packet.
    pkt_pool.Recycle(p1);

    // Get a Packet from the pool and ensure that its fields have been reset.
    p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1->GetType() == UNKNOWN_PACKET);
    CPPUNIT_ASSERT(p1->GetLengthInBytes() == 0);

    pkt_pool.Recycle(p1);
  }

  //==========================================================================
  void TestBroadcastPacket()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(8) == true);

    // Create a control packet of type LSA (for the sake of a type to use).
    // This won't look like an LSA - that's just an arbitrary type to use for
    // testing control packet creation/parsing.

    iron::PacketType test_type      = LSA_PACKET;
    BinId            test_src_bin   = 6;
    uint16_t         test_seq_num   = 4932;
    uint64_t         test_data_1    = 9872236235574234;
    uint16_t         test_data_2    = 1235;
    uint32_t         test_data_3    = 8;
    size_t           test_data_len  = 0;

    Packet* p1 = pkt_pool.Get();
    CPPUNIT_ASSERT(p1);
    p1->PopulateBroadcastPacket(test_type, test_src_bin, test_seq_num);
    p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&test_data_1),
                         sizeof(test_data_1));
    test_data_len += sizeof(test_data_1);
    p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&test_data_2),
                         sizeof(test_data_2));
    test_data_len += sizeof(test_data_2);
    p1->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&test_data_3),
                         sizeof(test_data_3));
    test_data_len += sizeof(test_data_3);

    BinId        read_src_bin   = 0;
    uint16_t     read_seq_num   = 0;
    size_t       read_data_len  = 0;
    const uint8_t* read_data    = NULL;
    CPPUNIT_ASSERT(p1->ParseBroadcastPacket(read_src_bin,
                                            read_seq_num,
                                            &read_data,
                                            read_data_len));
    // Recycle the Packet.
    pkt_pool.Recycle(p1);

    CPPUNIT_ASSERT(read_src_bin == test_src_bin);
    LogD("Test", __func__, "read_seq_num = %" PRIu16
         ", test_seq_num = %" PRIu16 "\n", read_seq_num, test_seq_num);
    CPPUNIT_ASSERT(read_seq_num == test_seq_num);
    CPPUNIT_ASSERT(read_data_len == test_data_len);
    CPPUNIT_ASSERT(read_data);

    uint64_t     read_data_1    = 0;
    uint16_t     read_data_2    = 0;
    uint32_t     read_data_3    = 0;

    size_t       read_ptr       = 0;

    memcpy(&read_data_1, &(read_data[read_ptr]), sizeof(read_data_1));
    read_ptr += sizeof(read_data_1);
    memcpy(&read_data_2, &(read_data[read_ptr]), sizeof(read_data_2));
    read_ptr += sizeof(read_data_2);
    memcpy(&read_data_3, &(read_data[read_ptr]), sizeof(read_data_3));
    read_ptr += sizeof(read_data_3);
    CPPUNIT_ASSERT(test_data_1 == read_data_1);
    CPPUNIT_ASSERT(test_data_2 == read_data_2);
    CPPUNIT_ASSERT(test_data_3 == read_data_3);
  }

  //==========================================================================
  void TestHistory()
  {
    PacketPoolHeap pkt_pool;
    CPPUNIT_ASSERT(pkt_pool.Create(1) == true);

    Packet*  p1 = pkt_pool.Get();
    memcpy(p1->GetBuffer(), reinterpret_cast<void*>(&ip_hdr_),
           sizeof(ip_hdr_));
    p1->SetLengthInBytes(sizeof(ip_hdr_));

    // Check that the history vector is not sent by default.
    CPPUNIT_ASSERT(!p1->send_packet_history());
    CPPUNIT_ASSERT(*(p1->history()) == iron::kHistoryEntryUnused);

    uint8_t history_data[11];
    memset(history_data, 0, sizeof(history_data));
    history_data[0] = 2;
    history_data[1] = 4;
    history_data[2] = 5;
    if (iron::kHistoryFieldSizeBytes > 3)
    {
      history_data[3] = 2;
    }
    p1->set_history(history_data);

    p1->set_send_packet_history(true);
    CPPUNIT_ASSERT(p1->send_packet_history());

    CPPUNIT_ASSERT(*(p1->history()) == 2);
    CPPUNIT_ASSERT(*(p1->history() + 1) == 4);
    CPPUNIT_ASSERT(*(p1->history() + 2) == 5);
    if (iron::kHistoryFieldSizeBytes > 3)
    {
      CPPUNIT_ASSERT(*(p1->history() + 3) == 2);
    }
    p1->InsertNodeInHistory(4);
    CPPUNIT_ASSERT(*(p1->history()) == 4);
    CPPUNIT_ASSERT(*(p1->history() + 1) == 2);
    pkt_pool.Recycle(p1);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(PacketTest);
