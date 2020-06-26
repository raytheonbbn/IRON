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
#include "ordered_list.h"
#include "rng.h"

using ::iron::OrderedList;
using ::iron::Log;

namespace
{
}


//============================================================================
class OrderedListTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(OrderedListTest);

  CPPUNIT_TEST(TestOrderedList);
  CPPUNIT_TEST(TestOrderedPtrList);
  CPPUNIT_TEST(TestPtrLoadedList);
  CPPUNIT_TEST(TestIterator);

  CPPUNIT_TEST_SUITE_END();

  private:
  struct TestObject
  {
    TestObject() {}

    TestObject(std::string name, float value)
    {
      name_   = name;
      value_  = value;
    }

    bool operator==(const TestObject& other)
    {
      return (name_ == other.name_) && (value_ == other.value_);
    }

    void operator=(const TestObject& other)
    {
      name_   = other.name_;
      value_  = other.value_;
    }

    std::string name_;
    float       value_;
  };

  public:
  //==========================================================================
  void setUp()
  {
  }

  //==========================================================================
  void tearDown()
  {
  }

  //==========================================================================
  void TestOrderedList()
  {
    OrderedList<TestObject, float>
      list_(iron::LIST_DECREASING);

    TestObject o0("first", 3.45);
    list_.Push(o0, o0.value_);

    CPPUNIT_ASSERT(list_.size() == 1);

    TestObject  obj;
    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)3.45));

    TestObject o1("second", 1.23);
    list_.Push(o1, o1.value_);

    CPPUNIT_ASSERT(list_.size() == 2);

    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)3.45));

    TestObject o2("third", 0.12);
    list_.Push(o2, o2.value_);

    CPPUNIT_ASSERT(list_.size() == 3);

    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)3.45));

    TestObject o3("fourth", 7.89);
    list_.Push(o3, o3.value_);

    CPPUNIT_ASSERT(list_.size() == 4);

    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "fourth") && (obj.value_ == (float)7.89));

    // Walk the list.
    OrderedList<TestObject, float>::WalkState ws;
    ws.PrepareForWalk();

    TestObject  next_elem;
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fourth");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "first");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "second");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");

    CPPUNIT_ASSERT(!list_.GetNextItem(ws, next_elem));

    ws.PrepareForWalk();
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));

    // Save iterator to the second object.
    CPPUNIT_ASSERT(next_elem.name_ == "first");
    OrderedList<TestObject, float>::WalkState saved_ws  = ws;

    // Restart iterator.
    ws.PrepareForWalk();

    // Remove the second object.
    CPPUNIT_ASSERT(list_.RemoveInPlace(saved_ws));

    // Walk the list.
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fourth");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "second");
    saved_ws                  = ws;
    TestObject  saved_object(next_elem.name_, next_elem.value_);
    saved_object.value_       = 8.90;

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");

    // Move an object.
    list_.Reposition(saved_ws, saved_object.value_);

    ws.PrepareForWalk();

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "second");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fourth");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");

    saved_object.name_  = "fourth";
    saved_object.value_ = 7.89;
    CPPUNIT_ASSERT(list_.Remove(saved_object));

    ws.PrepareForWalk();

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "second");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");

    list_.Clear();
    CPPUNIT_ASSERT(list_.size() == 0);
  }

  //==========================================================================
  void TestOrderedPtrList()
  {
    OrderedList<TestObject*, float>
      list_(iron::LIST_INCREASING);

    TestObject* o0  = new TestObject("first", 3.45);
    CPPUNIT_ASSERT(o0);
    list_.Push(o0, o0->value_);

    TestObject* next_elem = NULL;

    CPPUNIT_ASSERT(list_.size() == 1);
    CPPUNIT_ASSERT(list_.Peek(next_elem));
    CPPUNIT_ASSERT(next_elem);
    CPPUNIT_ASSERT((next_elem->name_ == "first") &&
      (next_elem->value_ == (float)3.45));

    TestObject* o1  = new TestObject("second", 1.23);
    CPPUNIT_ASSERT(o1);
    list_.Push(o1, o1->value_);

    CPPUNIT_ASSERT(list_.size() == 2);
    CPPUNIT_ASSERT(list_.Peek(next_elem));
    CPPUNIT_ASSERT((next_elem->name_ == "second") &&
      (next_elem->value_ == (float)1.23));

    TestObject* o2  = new TestObject("third", 0.12);
    CPPUNIT_ASSERT(o2);
    list_.Push(o2, o2->value_);

    CPPUNIT_ASSERT(list_.size() == 3);
    CPPUNIT_ASSERT(list_.Peek(next_elem));
    CPPUNIT_ASSERT((next_elem->name_ == "third") &&
      (next_elem->value_ == (float)0.12));

    TestObject* o3  = new TestObject("fourth", 7.89);
    CPPUNIT_ASSERT(o3);
    list_.Push(o3, o3->value_);

    CPPUNIT_ASSERT(list_.size() == 4);

    // Check ordering.
    OrderedList<TestObject*, float>::WalkState  ws;
    ws.PrepareForWalk();

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "third");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "second");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "first");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "fourth");

    // Check moving an element.
    ws.PrepareForWalk();

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "third");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "second");
  
    OrderedList<TestObject*, float>::WalkState  saved_ws  = ws;
    next_elem->value_ = 4.56;

    // Reposition second.
    ws.PrepareForWalk();

    list_.Reposition(saved_ws, next_elem->value_);

    // Make sure it worked.
    ws.PrepareForWalk();
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "third");
    delete next_elem;

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "first");
    delete next_elem;

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "second");
    delete next_elem;

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "fourth");
    delete next_elem;
  }

  //==========================================================================
  void TestPtrLoadedList()
  {
    iron::RNG rng;

#define STR_NAME(i) ("string##_#i")
    OrderedList<TestObject*, float>
      list_(iron::LIST_INCREASING);

#define TEST_NUM_ELEMS 10000
    TestObject* obj = NULL;
    for (uint64_t i = 0; i < TEST_NUM_ELEMS; ++i)
    {
      TestObject* o = new TestObject(STR_NAME(i),
        rng.GetFloat(TEST_NUM_ELEMS));
      CPPUNIT_ASSERT(o);
      list_.Push(o, o->value_);

      CPPUNIT_ASSERT(list_.size() == (i + 1));
    }

    CPPUNIT_ASSERT(list_.size() == TEST_NUM_ELEMS);

    OrderedList<TestObject*, float>::WalkState  ws;
    OrderedList<TestObject*, float>::WalkState  saved_ws;
    ws.PrepareForWalk();

    float         prev    = -1;
    uint64_t      i       = 0;

    while (list_.GetNextItem(ws, obj))
    {
      CPPUNIT_ASSERT(obj);
      CPPUNIT_ASSERT(prev <= obj->value_);
      prev  = obj->value_;

      if (i == (TEST_NUM_ELEMS / 2))
      {
        saved_ws  = ws;
      }

      ++i;
    }

    CPPUNIT_ASSERT(list_.PopAt(saved_ws, obj));
    CPPUNIT_ASSERT(obj);
    delete  obj;

    ws.PrepareForWalk();
    i = 0;

    while (list_.Peek(obj))
    {
      list_.Pop(obj);
      CPPUNIT_ASSERT(obj);
      delete obj;
    }
  }

  //==========================================================================
  void TestIterator()
  {
    OrderedList<TestObject, float> list_;

    OrderedList<TestObject, float>::WalkState  ws;
    OrderedList<TestObject, float>::WalkState  comp_ws;
    ws.PrepareForWalk();
    comp_ws.PrepareForWalk();

    CPPUNIT_ASSERT(ws.IsNULL());

    TestObject  o0("first", 0.12);
    TestObject  o1("first", 0.12);

    list_.Push(o0, 0.12);
    list_.Push(o1, 0.12);

    TestObject  obj;
    list_.GetNextItem(ws, obj);
    list_.GetNextItem(comp_ws, obj);
    CPPUNIT_ASSERT(ws == comp_ws);

    list_.GetNextItem(ws, obj);
    CPPUNIT_ASSERT(!(ws == comp_ws));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(OrderedListTest);
