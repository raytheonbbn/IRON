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

#include "four_tuple.h"
#include "hash_table.h"

#include <cstdio>
#include <arpa/inet.h>

using ::iron::FourTuple;
using ::iron::HashTable;

namespace
{
  const size_t  NUM_FLOWS   = 16;
  const size_t  NUM_BUCKETS = 8;
}


//============================================================================
class HashTableTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(HashTableTest);

  CPPUNIT_TEST(TestHashTable);
  CPPUNIT_TEST(TestDuplicateKey);

  CPPUNIT_TEST_SUITE_END();

private:

  FourTuple*                     flows_;
  HashTable<FourTuple, size_t>*  htable_;

public:

  //==========================================================================
  uint32_t ip_nbo(uint32_t dot1, uint32_t dot2, uint32_t dot3, uint32_t dot4)
  {
    return htonl((dot1 << 24) | (dot2 << 16) | (dot3 << 8) | dot4);
  }

  //==========================================================================
  void setUp()
  {
    // Create the flows.
    flows_ = new FourTuple[NUM_FLOWS];

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      flows_[i].Set(ip_nbo(192, 168, 0, i), htons(1000 + i),
                    ip_nbo( 10,  10, i, i), htons(32000 + i));
    }

    // Create the hash table.
    htable_ = new HashTable<FourTuple, size_t>();
  }

  //==========================================================================
  void tearDown()
  {
    delete [] flows_;
    delete htable_;

    flows_  = NULL;
    htable_ = NULL;
  }

  //==========================================================================
  void TestHashTable()
  {
    size_t  value = 0;

    // Initialize the hash table.
    CPPUNIT_ASSERT(htable_ != NULL);
    CPPUNIT_ASSERT(htable_->Initialize(NUM_BUCKETS) == true);

    // Check the empty state.
    CPPUNIT_ASSERT(htable_->Find(flows_[0], value) == false);
    CPPUNIT_ASSERT(htable_->FindAndRemove(flows_[1], value) == false);
    CPPUNIT_ASSERT(htable_->Count(flows_[2]) == 0);
    CPPUNIT_ASSERT(htable_->Erase(flows_[3]) == 0);
    CPPUNIT_ASSERT(htable_->IsEmpty() == true);
    CPPUNIT_ASSERT(htable_->Size() == 0);
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    // Add the key/value pairs to the table once.
    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Insert(flows_[i], i) == true);
    }

    // Check the state.
    CPPUNIT_ASSERT(htable_->IsEmpty() == false);
    CPPUNIT_ASSERT(htable_->Size() == NUM_FLOWS);
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value == i);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 1);
    }

    // FindAndRemove the first 4 flows.
    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(htable_->FindAndRemove(flows_[i], value) == true);
      CPPUNIT_ASSERT(value == i);
      CPPUNIT_ASSERT(htable_->FindAndRemove(flows_[i], value) == false);
    }

    // Check the state.
    CPPUNIT_ASSERT(htable_->IsEmpty() == false);
    CPPUNIT_ASSERT(htable_->Size() == (NUM_FLOWS - 4));
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 0);
    }

    for (size_t i = 4; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value == i);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 1);
    }

    // Erase the next 4 flows.
    for (size_t i = 4; i < 8; ++i)
    {
      CPPUNIT_ASSERT(htable_->Erase(flows_[i]) == 1);
      CPPUNIT_ASSERT(htable_->Erase(flows_[i]) == 0);
    }

    // Check the state.
    CPPUNIT_ASSERT(htable_->IsEmpty() == false);
    CPPUNIT_ASSERT(htable_->Size() == (NUM_FLOWS - 8));
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < 8; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 0);
    }

    for (size_t i = 8; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value == i);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 1);
    }

    // Duplicate the first 4 flows.
    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(htable_->Insert(flows_[i], i) == true);
      CPPUNIT_ASSERT(htable_->Insert(flows_[i], (i + 100)) == true);
    }

    // Check the state.
    CPPUNIT_ASSERT(htable_->IsEmpty() == false);
    CPPUNIT_ASSERT(htable_->Size() == NUM_FLOWS);
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT((value == i) || (value == (i + 100)));
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 2);
    }

    for (size_t i = 4; i < 8; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 0);
    }

    for (size_t i = 8; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value == i);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 1);
    }

    // Walk the table, erasing the duplicated first flow.
    HashTable<FourTuple, size_t>::WalkState  ws;
    FourTuple                                flow;
    size_t                                   cnt = 0;

    while (htable_->GetNextPair(ws, flow, value))
    {
      if (value == 100)
      {
        htable_->EraseCurrentPair(ws);
        ++cnt;
      }
    }

    CPPUNIT_ASSERT(cnt == 1);

    // Check the state.
    CPPUNIT_ASSERT(htable_->IsEmpty() == false);
    CPPUNIT_ASSERT(htable_->Size() == (NUM_FLOWS - 1));
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    CPPUNIT_ASSERT(htable_->Find(flows_[0], value) == true);
    CPPUNIT_ASSERT(value == 0);
    CPPUNIT_ASSERT(htable_->Count(flows_[0]) == 1);

    for (size_t i = 1; i < 4; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT((value == i) || (value == (i + 100)));
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 2);
    }

    for (size_t i = 4; i < 8; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 0);
    }

    for (size_t i = 8; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value == i);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 1);
    }

    // Clear the table.
    htable_->Clear();

    // Check the state.
    CPPUNIT_ASSERT(htable_->IsEmpty() == true);
    CPPUNIT_ASSERT(htable_->Size() == 0);
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->FindAndRemove(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 0);
      CPPUNIT_ASSERT(htable_->Erase(flows_[i]) == 0);
    }

    // Reload the table, then walk the table, erasing each flow.
    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Insert(flows_[i], i) == true);
    }

    ws.PrepareForWalk();
    cnt = 0;

    while (htable_->EraseNextPair(ws, flow, value))
    {
      ++cnt;
    }

    CPPUNIT_ASSERT(cnt == NUM_FLOWS);

    // Check the state.
    CPPUNIT_ASSERT(htable_->IsEmpty() == true);
    CPPUNIT_ASSERT(htable_->Size() == 0);
    CPPUNIT_ASSERT(htable_->NumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(htable_->Find(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->FindAndRemove(flows_[i], value) == false);
      CPPUNIT_ASSERT(htable_->Count(flows_[i]) == 0);
      CPPUNIT_ASSERT(htable_->Erase(flows_[i]) == 0);
    }
  }

  //==========================================================================
  void TestDuplicateKey()
  {
    HashTable<FourTuple, size_t>*  htable2;

    // Create the hash table.
    htable2 = new HashTable<FourTuple, size_t>();

    // Initialize the hash table.
    CPPUNIT_ASSERT(htable2 != NULL);
    CPPUNIT_ASSERT(htable2->Initialize(NUM_BUCKETS) == true);

    // Add two entries with the same key.
    FourTuple  key;

    key.Set(ip_nbo(192, 168, 0, 1), 100,
            ip_nbo( 10,  10, 0, 1), 200);

    CPPUNIT_ASSERT(htable2->Insert(key, 1) == true);
    CPPUNIT_ASSERT(htable2->Insert(key, 2) == true);

    // Check the state.
    CPPUNIT_ASSERT(htable2->IsEmpty() == false);
    CPPUNIT_ASSERT(htable2->Size() == 2);
    CPPUNIT_ASSERT(htable2->NumBuckets() == NUM_BUCKETS);

    // Erase the entries.
    CPPUNIT_ASSERT(htable2->Erase(key) == 2);
    CPPUNIT_ASSERT(htable2->Erase(key) == 0);

    // Check the state.
    CPPUNIT_ASSERT(htable2->IsEmpty() == true);
    CPPUNIT_ASSERT(htable2->Size() == 0);
    CPPUNIT_ASSERT(htable2->NumBuckets() == NUM_BUCKETS);

    // Clean up.
    delete htable2;

    htable2 = NULL;
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(HashTableTest);
