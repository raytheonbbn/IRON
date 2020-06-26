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
#include "ordered_mash_table.h"
#include "rng.h"

#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

using ::iron::FourTuple;
using ::iron::OrderedMashTable;

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
  { }

  virtual ~HashValue()
  { }

  size_t  val()
  { return val_; }

  size_t  val_;
};


//============================================================================
class OrderedMashTableTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(OrderedMashTableTest);

  CPPUNIT_TEST(TestOrderedMashTable);

  CPPUNIT_TEST_SUITE_END();

private:

  FourTuple*                                        flows_;
  OrderedMashTable<FourTuple, HashValue*, uint8_t>* mash_table_;
  iron::RNG                                         rng_;

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
    mash_table_ = new (std::nothrow)
      OrderedMashTable<FourTuple, HashValue*, uint8_t>(
        iron::LIST_DECREASING);
    CPPUNIT_ASSERT(mash_table_);

    // Create the flows.
    flows_  = new FourTuple[NUM_FLOWS];

    CPPUNIT_ASSERT(flows_);

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      flows_[i].Set(ip_nbo(192, 168, 0, i), htons(1000 + i),
                    ip_nbo( 10,  10, i, i), htons(32000 + i));
    }
  }

  //==========================================================================
  void tearDown()
  {
    OrderedMashTable<FourTuple, HashValue*, uint8_t>::WalkState ws;
    HashValue*  value = NULL;
    while (mash_table_->GetNextItem(ws, value))
    {
      CPPUNIT_ASSERT(value);
      delete value;
    }

    delete [] flows_;

   // Delete the mash table.
    delete mash_table_;
    mash_table_ = NULL;
  }

  //==========================================================================
  void TestOrderedMashTable()
  {
    HashValue*  value                           = NULL;
    HashValue*  hash_vals[NUM_FLOWS]            = {};
    uint8_t     value_order[NUM_FLOWS * 2]      = {};
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
      CPPUNIT_ASSERT(hash_vals[i]);

      value_order[i]  = rng_.GetInt(NUM_FLOWS - 1);
      CPPUNIT_ASSERT(mash_table_->OrderedInsert(flows_[i], hash_vals[i],
        value_order[i]) == true);
    }

    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == false);
    CPPUNIT_ASSERT(mash_table_->size() == NUM_FLOWS);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT(value->val_ == i);
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 1);
    }

    OrderedMashTable<FourTuple, HashValue*, uint8_t>::WalkState ws;
    uint8_t                                               order     = NUM_FLOWS;
    while (mash_table_->GetNextItem(ws, value))
    {
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT(order >= value_order[value->val()]);
      order = value_order[value->val()];
    }

    // FindAndRemove the first 4 flows.
    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[i], value) == true);
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT(value->val_ == i);
      delete value;
      value = NULL;
      CPPUNIT_ASSERT(mash_table_->FindAndRemove(flows_[i], value) == false);
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
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT(value->val_ == i);
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 1);
    }

    // Duplicate the first 4 flows.
    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->OrderedInsert(flows_[i], 
        new (std::nothrow) HashValue(i), value_order[i]) == true);
      CPPUNIT_ASSERT(mash_table_->OrderedInsert(flows_[i],
        new (std::nothrow) HashValue(i + 20), value_order[i] + 20) == true);
      value_order[i + 20]  = value_order[i] + 20;
    }
    
    // Check the state.
    CPPUNIT_ASSERT(mash_table_->Empty() == false);
    CPPUNIT_ASSERT(mash_table_->size() == NUM_FLOWS + 4);
    CPPUNIT_ASSERT(mash_table_->GetNumBuckets() == NUM_BUCKETS);

    for (size_t i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT((value->val_ == i) || (value->val_ == (i + 20)));
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 2);
    }

    for (size_t i = 4; i < NUM_FLOWS; ++i)
    {
      CPPUNIT_ASSERT(mash_table_->Find(flows_[i], value) == true);
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT(value->val_ == i);
      CPPUNIT_ASSERT(mash_table_->Count(flows_[i]) == 1);
    }

    // Test the iterator. 
    ws.PrepareForWalk();
    order = NUM_FLOWS + 20;

    while (mash_table_->GetNextItem(ws, value))
    {
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT(order >= value_order[value->val()]);
      order = value_order[value->val()];
    }

    // Test Reposition.
    mash_table_->Reposition(flows_[5], 100);
    value_order[5]  = 100;

    // Test the iterator. 
    ws.PrepareForWalk();
    order = NUM_FLOWS + 120;

    while (mash_table_->GetNextItem(ws, value))
    {
      CPPUNIT_ASSERT(value != NULL);
      CPPUNIT_ASSERT(order >= value_order[value->val()]);
      order = value_order[value->val()];
    }
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(OrderedMashTableTest);
