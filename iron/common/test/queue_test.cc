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

/*
 * File:   XQTest.cc
 * Author: sdabideen
 *
 * Created on Aug 3, 2015, 11:32:19 AM
 */

#include <cppunit/extensions/HelperMacros.h>

#include "packet_queue.h"

#include "itime.h"
#include "log.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "rng.h"
#include "runnable_if.h"
#include "thread.h"

using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPoolHeap;
using ::iron::PacketQueue;
using ::iron::RunnableIf;
using ::iron::Thread;
using ::iron::Time;

//============================================================================
// Main test class.
class QTest : public CPPUNIT_NS::TestFixture
{
  CPPUNIT_TEST_SUITE(QTest);

  CPPUNIT_TEST(TestDequeue);
  CPPUNIT_TEST(TestDropPacketHEAD);
  CPPUNIT_TEST(TestEnqueue);
  CPPUNIT_TEST(TestWalk);
  CPPUNIT_TEST(TestOrderedWalk);
  CPPUNIT_TEST(TestPurge);
  CPPUNIT_TEST(TestGetCount);
  CPPUNIT_TEST(TestGetSize);
  CPPUNIT_TEST(TestGetDropPolicy);
  CPPUNIT_TEST(TestSetDropPolicy);

  CPPUNIT_TEST_SUITE_END();

private:

  PacketQueue*     xq_;
  PacketQueue*     oq_;
  PacketPoolHeap*  pkt_pool_;
  iron::RNG        rng_;

public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FEWIAD");

    pkt_pool_ = new PacketPoolHeap();
    CPPUNIT_ASSERT(pkt_pool_->Create(20) == true);

    // Create a(n unordered) packet queue.
    xq_ = new PacketQueue(*pkt_pool_, 100, iron::HEAD);
    CPPUNIT_ASSERT(xq_);

    // Create an ordered) packet queue.
    oq_ = new PacketQueue(*pkt_pool_, 100, iron::HEAD, true);
    CPPUNIT_ASSERT(oq_);

    // Add two packets:  one 100 bytes long, and one 50 bytes long.
    Packet* pkt1 = pkt_pool_->Get();
    CPPUNIT_ASSERT(pkt1);
    pkt1->SetLengthInBytes(100);
    xq_->Enqueue(pkt1);

    Packet* pkt2 = pkt_pool_->Get();
    CPPUNIT_ASSERT(pkt2);
    pkt2->SetLengthInBytes(50);
    xq_->Enqueue(pkt2);

    // Add two packets:  one 100 bytes long, and one 50 bytes long.
    Packet* pkt10 = pkt_pool_->Get();
    CPPUNIT_ASSERT(pkt10);
    pkt10->InitIpPacket();
    pkt10->SetIpDscp(46);
    pkt10->SetLengthInBytes(100);
    oq_->Enqueue(pkt10);

    Packet* pkt20 = pkt_pool_->Get();
    CPPUNIT_ASSERT(pkt20);
    pkt20->InitIpPacket();
    pkt20->SetIpDscp(46);
    pkt20->SetLengthInBytes(50);
    oq_->Enqueue(pkt20);
  }

  //==========================================================================
  void tearDown()
  {
    // Delete the packet queues.
    delete xq_;
    xq_ = NULL;

    delete oq_;
    oq_ = NULL;

    delete pkt_pool_;
    pkt_pool_ = NULL;

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestDequeue()
  {
    Packet*  result = xq_->Peek();
    CPPUNIT_ASSERT(result != NULL);
    CPPUNIT_ASSERT(result->GetLengthInBytes() == 100);
    
    result = xq_->Dequeue();

    CPPUNIT_ASSERT(result != NULL);
    CPPUNIT_ASSERT(result->GetLengthInBytes() == 100);

    pkt_pool_->Recycle(result);
    result = xq_->Dequeue();

    CPPUNIT_ASSERT(result != NULL);
    CPPUNIT_ASSERT(result->GetLengthInBytes() == 50);

    pkt_pool_->Recycle(result);

    result = oq_->Peek();
    CPPUNIT_ASSERT(result != NULL);
    CPPUNIT_ASSERT(result->GetLengthInBytes() == 100);
    
    result = oq_->Dequeue();

    CPPUNIT_ASSERT(result != NULL);
    CPPUNIT_ASSERT(result->GetLengthInBytes() == 100);

    pkt_pool_->Recycle(result);
    result = oq_->Dequeue();

    CPPUNIT_ASSERT(result != NULL);
    CPPUNIT_ASSERT(result->GetLengthInBytes() == 50);

    pkt_pool_->Recycle(result);
  }

  //==========================================================================
  void TestDropPacketHEAD()
  {
    xq_->DropPacket();

    Packet*  result2 = xq_->Dequeue();
    CPPUNIT_ASSERT(result2);

    CPPUNIT_ASSERT(result2->GetLengthInBytes() == 50);

    pkt_pool_->Recycle(result2);

    oq_->DropPacket();

    result2 = oq_->Dequeue();
    CPPUNIT_ASSERT(result2);

    CPPUNIT_ASSERT(result2->GetLengthInBytes() == 50);

    pkt_pool_->Recycle(result2);
  }

  //==========================================================================
  void TestEnqueue()
  {
    CPPUNIT_ASSERT(xq_->GetCount() == 2);
    CPPUNIT_ASSERT(xq_->GetSize() == 150);

    Packet* pkt3 = pkt_pool_->Get();
    CPPUNIT_ASSERT(pkt3);
    pkt3->SetLengthInBytes(200);
    xq_->Enqueue(pkt3);

    CPPUNIT_ASSERT(xq_->GetCount() == 3);
    CPPUNIT_ASSERT(xq_->GetSize() == 350);

    CPPUNIT_ASSERT(oq_->GetCount() == 2);
    CPPUNIT_ASSERT(oq_->GetSize() == 150);

    Packet* pkt30 = pkt_pool_->Get();
    CPPUNIT_ASSERT(pkt30);
    pkt30->InitIpPacket();
    pkt30->SetIpDscp(46);
    pkt30->SetLengthInBytes(200);
    oq_->Enqueue(pkt30);

    CPPUNIT_ASSERT(oq_->GetCount() == 3);
    CPPUNIT_ASSERT(oq_->GetSize() == 350);
  }

  //==========================================================================
  void TestWalk()
  {
    Packet* pkt = xq_->Dequeue();
    CPPUNIT_ASSERT(pkt);
    pkt_pool_->Recycle(pkt);

    pkt = xq_->Dequeue();
    CPPUNIT_ASSERT(pkt);
    pkt_pool_->Recycle(pkt);

    for (uint8_t i = 0; i < 10; ++i)
    {
      pkt = pkt_pool_->Get();
      CPPUNIT_ASSERT(pkt);
      pkt->SetLengthInBytes(50);

      uint8_t* p  = pkt->GetBuffer(0);
      *p          = i;
      CPPUNIT_ASSERT(xq_->Enqueue(pkt));
    }

    xq_->PrepareQueueIterator();
    uint8_t                           i = 0;
    iron::PacketQueue::QueueWalkState dummy_ws;
    while (NULL != (pkt = xq_->PeekNextPacket(dummy_ws)))
    {
      uint8_t* p  = pkt->GetBuffer(0);
      CPPUNIT_ASSERT(*p == i);

      if (i == 5)
      {
        pkt = xq_->DequeueAtIterator();
        pkt_pool_->Recycle(pkt);
      }
      ++i;
    }

    xq_->PrepareQueueIterator();
    while (NULL != (pkt = xq_->Dequeue()))
    {
      pkt_pool_->Recycle(pkt);
    }
  }

  //==========================================================================
  void TestOrderedWalk()
  {
    Packet* pkt = oq_->Dequeue();
    CPPUNIT_ASSERT(pkt);
    pkt_pool_->Recycle(pkt);

    pkt = oq_->Dequeue();
    CPPUNIT_ASSERT(pkt);
    pkt_pool_->Recycle(pkt);

    for (uint8_t i = 0; i < 10; ++i)
    {
      pkt = pkt_pool_->Get();
      CPPUNIT_ASSERT(pkt);
      pkt->InitIpPacket();
      pkt->SetIpDscp(46);
      pkt->SetLengthInBytes(50);
      pkt->SetTimeToGo(Time(rng_.GetFloat(100.)));
      pkt->SetOrderTime(pkt->GetTimeToGo());

      uint8_t* p  = pkt->GetBuffer(0);
      *p          = i;
      CPPUNIT_ASSERT(oq_->Enqueue(pkt));
    }

    oq_->PrepareQueueIterator();
    uint8_t                           i = 0;
    iron::PacketQueue::QueueWalkState dummy_ws(true);
    Time                              prev_time = Time(0);
    while (NULL != (pkt = oq_->PeekNextPacket(dummy_ws)))
    {
      CPPUNIT_ASSERT(prev_time <= pkt->GetTimeToGo());
      prev_time   = pkt->GetTimeToGo();

      uint8_t* p  = pkt->GetBuffer(0);

      if (*p == 5)
      {
        pkt = oq_->DequeueAtIterator();
        pkt_pool_->Recycle(pkt);
      }
      ++i;
    }

    oq_->PrepareQueueIterator();
    while (NULL != (pkt = oq_->Dequeue()))
    {
      pkt_pool_->Recycle(pkt);
    }
  }

  //==========================================================================
  void TestPurge()
  {
    xq_->Purge();

    CPPUNIT_ASSERT(xq_->GetCount() == 0);

    oq_->Purge();

    CPPUNIT_ASSERT(oq_->GetCount() == 0);
  }

  //==========================================================================
  void TestGetCount()
  {
    CPPUNIT_ASSERT(xq_->GetCount() == 2);
    CPPUNIT_ASSERT(oq_->GetCount() == 2);
  }

  //==========================================================================
  void TestGetDropPolicy()
  {
    CPPUNIT_ASSERT(xq_->drop_policy() == iron::HEAD);
  }

  //==========================================================================
  void TestGetSize()
  {
    CPPUNIT_ASSERT(xq_->GetSize() == 150);
  }

  //==========================================================================
  void TestSetDropPolicy()
  {
    iron::DropPolicy  pol = iron::TAIL;
    xq_->set_drop_policy(pol);

    CPPUNIT_ASSERT(xq_->drop_policy() == iron::TAIL);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(QTest);
