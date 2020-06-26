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
#include "mash_table.h"

#include <cstdio>
#include <arpa/inet.h>

using ::iron::FourTuple;
using ::iron::MashTable;

namespace
{
  const size_t  NUM_FLOWS   = 16;
  const size_t  NUM_BUCKETS = 8;
}

class HashValue
{
public:
  HashValue(size_t v)
    : val_(v)
  {}

  virtual ~HashValue() 
  {}

  inline int Order() { return(val_);}

  size_t val_;
};
   

//============================================================================
class MashTableTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(MashTableTest);

  CPPUNIT_TEST(TestMashTable);

  CPPUNIT_TEST_SUITE_END();

private:

  FourTuple*                         flows_;
  MashTable<FourTuple, HashValue*>*  mash_table_;

public:
  //==========================================================================
  uint32_t ip_nbo(uint32_t dot1, uint32_t dot2, uint32_t dot3, uint32_t dot4)
  {
    return htonl((dot1 << 24) | (dot2 << 16) | (dot3 << 8) | dot4);
  }

  //==========================================================================
  void setUp()
  {
    // Create the mash table.
    mash_table_ = new (std::nothrow) MashTable<FourTuple, HashValue*>();

    // Create the flows.
    flows_  = new FourTuple[NUM_FLOWS];

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      flows_[i].Set(ip_nbo(192, 168, 0, i), htons(1000 + i),
                    ip_nbo( 10,  10, i, i), htons(32000 + i));
    }
  }

  //==========================================================================
  void tearDown()
  {
    MashTable<FourTuple, HashValue*>::WalkState  ws;
    HashValue*  value = NULL;
    while (mash_table_->GetNextItem(ws, value))
    {
      delete value;
    }

    delete [] flows_;

   // Delete the mash table.
    delete mash_table_;
    mash_table_ = NULL;
  }

  //==========================================================================
  void TestMashTable()
  {
    HashValue* value = NULL;
    HashValue* hash_vals[NUM_FLOWS] = {};
    CPPUNIT_ASSERT(mash_table_ != NULL);
    CPPUNIT_ASSERT(mash_table_->Initialize(NUM_BUCKETS) == true);

    // Check the empty state.
    CPPUNIT_ASSERT(mash_table_->Find(flows_[0], value) == false);
    CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[1], value) == false);
    CPPUNIT_ASSERT(mash_table_->Count(flows_[2]) == 0);
    CPPUNIT_ASSERT(mash_table_->Empty() == true);
    CPPUNIT_ASSERT(mash_table_->size() == 0);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    // Add the key/value pairs to the table once.
    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      hash_vals[i] = new (std::nothrow) HashValue(i);
      CPPUNIT_ASSERT(mash_table_->Insert(flows_[i], hash_vals[i]) == true);
    }

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == false);
    CPPUNIT_ASSERT(mash_table_->size() == NUM_FLOWS);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value->val_ == i);
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 1);
    }

    // FindAndRemove the first 4 flows.
    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[i], value) == true);
      CPPUNIT_ASSERT(value->val_ == i);
      CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[i], value) == false);
      delete value;
    }

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == false);
    CPPUNIT_ASSERT(mash_table_->size() == (NUM_FLOWS - 4));
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == false);
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 0);
    }

    for (size_t i = 4; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value->val_ == i);
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 1);
    }

    // Duplicate the first 4 flows.
    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Insert(flows_[i], 
        new (std::nothrow) HashValue(i)) == true);
      CPPUNIT_ASSERT(mash_table_->Insert(flows_[i], 
        new (std::nothrow) HashValue(i + 100)) == true);
    }

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == false);
    CPPUNIT_ASSERT(mash_table_->size() == NUM_FLOWS + 4);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT((value->val_ == i) || (value->val_ == (i + 100)));
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 2);
    }

    for (size_t i = 4; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value->val_ == i);
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 1);
    }

    // Test the iterator.
    MashTable<FourTuple, HashValue*>::WalkState  ws;
    ws.PrepareForWalk();

    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value);
    CPPUNIT_ASSERT(value->val_ == 4);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 5);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 6);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 7);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 8);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 9);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 10);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 11);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 12);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 13);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 14);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 15);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 0);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 100);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 1);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 101);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 2);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 102);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 3);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 103);

    // FindAndRemove 1 copy of the first 4 flows.
    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[i], value) == true);
      CPPUNIT_ASSERT((value->val_ == i) || (value->val_ == (i + 100)));
      delete value;
    }

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == false);
    CPPUNIT_ASSERT(mash_table_->size() == NUM_FLOWS);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT((value->val_ == i) || (value->val_ == (i + 100)));
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 1);
    }

    // Empty the mash table.
    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[i], value) == true);
      CPPUNIT_ASSERT((value->val_ == i) || (value->val_ == (i + 100)));
      CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[i], value) == false);
      delete value;
    }

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == true);
    CPPUNIT_ASSERT(mash_table_->size() == 0);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    // Add the key/value pairs to the table once.
    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      hash_vals[i] = new (std::nothrow) HashValue(i);
      CPPUNIT_ASSERT(mash_table_->Insert(flows_[i], hash_vals[i]) == true);
    }

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == false);
    CPPUNIT_ASSERT(mash_table_->size() == NUM_FLOWS);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);


    // Remove an element from the middle.
    CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[3], value) == true);
    delete value;
    CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[3], value) == false);
    ws.PrepareForWalk();
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 0);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 1);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 2);
    CPPUNIT_ASSERT(mash_table_->GetNextItem(ws, value));
    CPPUNIT_ASSERT(value->val_ == 4);

    // Test Clear(). 
    HashValue* v1 = NULL;
    HashValue* v2 = NULL;
    HashValue* v4 = NULL;
    CPPUNIT_ASSERT(mash_table_->Find(flows_[1], v1) == true);
    CPPUNIT_ASSERT(mash_table_->Find(flows_[2], v2) == true);
    CPPUNIT_ASSERT(mash_table_->Find(flows_[3], v4) == false);
    CPPUNIT_ASSERT(mash_table_->Find(flows_[4], v4) == true);
    mash_table_->Clear();
    delete v1;
    delete v2;
    delete v4;

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == true);
    CPPUNIT_ASSERT(mash_table_->size() == 0);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    delete hash_vals[0];
    for (uint8_t i = 5; i < NUM_FLOWS; ++i)
    {
      delete hash_vals[i];
    }
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(MashTableTest);
