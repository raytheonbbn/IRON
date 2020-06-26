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

#include "log.h"
#include "fifo.h"
#include "packet.h"
#include "packet_fifo.h"
#include "packet_pool_heap.h"
#include "rng.h"

#include <inttypes.h>
#include <sys/select.h>


using ::iron::Log;
using ::iron::Fifo;
using ::iron::Packet;
using ::iron::PacketFifo;
using ::iron::PACKET_OWNER_NONE;
using ::iron::PacketPoolHeap;
using ::iron::PktMemIndex;
using ::iron::RNG;


//============================================================================
class PacketFifoTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(PacketFifoTest);

  CPPUNIT_TEST(TestPacketFifo);

  CPPUNIT_TEST_SUITE_END();

 private:

  static const size_t  kNameSize = 64;

  Fifo*      src_fifo_;
  Fifo*      dst_fifo_;
  PacketFifo*      src_;
  PacketFifo*      dst_;
  PacketPoolHeap*  pkt_pool_;

 public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FEW");

    pkt_pool_ = new PacketPoolHeap();

    CPPUNIT_ASSERT(pkt_pool_->Create(16) == true);

    // Set the FIFO path name.
    RNG rng;
    int32_t num = rng.GetInt(10000);

    char   path_name[kNameSize];
    snprintf(path_name, kNameSize, "/tmp/packetfifounittest%" PRId32, num);
    src_fifo_ = new Fifo(path_name);
    dst_fifo_ = new Fifo(path_name);
    src_ = new PacketFifo(*pkt_pool_, src_fifo_, PACKET_OWNER_NONE, 0);
    dst_ = new PacketFifo(*pkt_pool_, dst_fifo_, PACKET_OWNER_NONE, 10);

    CPPUNIT_ASSERT(src_ != NULL);
    CPPUNIT_ASSERT(dst_ != NULL);
  }

  //==========================================================================
  void tearDown()
  {
    delete src_fifo_;
    delete dst_fifo_;
    delete src_;
    delete dst_;
    delete pkt_pool_;

    src_fifo_ = NULL;
    dst_fifo_ = NULL;
    src_ = NULL;
    dst_ = NULL;
    pkt_pool_ = NULL;

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestPacketFifo()
  {

    // Make sure nothing is open.
    CPPUNIT_ASSERT(src_->IsOpen() == false);
    CPPUNIT_ASSERT(dst_->IsOpen() == false);

    // Set up a packet fifo.
    CPPUNIT_ASSERT(src_->OpenSender() == false);
    CPPUNIT_ASSERT(src_->IsOpen() == false);

    CPPUNIT_ASSERT(dst_->OpenReceiver() == true);
    CPPUNIT_ASSERT(dst_->IsOpen() == true);

    CPPUNIT_ASSERT(src_->OpenSender() == true);
    CPPUNIT_ASSERT(src_->IsOpen() == true);

    // Pass fewer packets than the receive buffer can take
    PktMemIndex packets[16];
    for (int num = 0; num < 5; num++)
    {
      Packet *pkt = pkt_pool_->Get();
      packets[num] = pkt->mem_index();
      CPPUNIT_ASSERT(src_->Send(pkt));
    }

    // Receive the packets.
    CPPUNIT_ASSERT(dst_->Recv());

    Packet* received = NULL;
    int i = 0;
    while (dst_->GetNextRcvdPacket(&received))
    {
      CPPUNIT_ASSERT(received->mem_index() == packets[i]);
      i++;
      pkt_pool_->Recycle(received);
    }
    CPPUNIT_ASSERT(i == 5);
    
    // Pass more packets than the receive buffer can take
    for (int num = 0; num < 15; num++)
    {
      Packet *pkt = pkt_pool_->Get();
      packets[num] = pkt->mem_index();
      CPPUNIT_ASSERT(src_->Send(pkt) > 0);
    }

    // get as many as the receiver can take at a time.
    CPPUNIT_ASSERT(dst_->Recv());
    i = 0;
    while (dst_->GetNextRcvdPacket(&received))
    {
      CPPUNIT_ASSERT(received->mem_index() == packets[i]);
      i++;
      pkt_pool_->Recycle(received);
    }
    CPPUNIT_ASSERT(i == 10);

    // get the rest
    CPPUNIT_ASSERT(dst_->Recv());
    int count = 0;
    while (dst_->GetNextRcvdPacket(&received))
    {
      CPPUNIT_ASSERT(received->mem_index() == packets[i]);
      i++;
      count++;
      pkt_pool_->Recycle(received);
    }
    CPPUNIT_ASSERT(count == 5);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(PacketFifoTest);
