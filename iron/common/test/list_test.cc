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

#include "list.h"
#include "log.h"

using ::iron::List;
using ::iron::Log;

namespace
{
}


//============================================================================
class ListTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(ListTest);

  CPPUNIT_TEST(TestList);
  CPPUNIT_TEST(TestPtrList);
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
  void TestList()
  {
    List<TestObject> list_;

    TestObject o0("first", 0.12);
    list_.Push(o0);

    CPPUNIT_ASSERT(list_.size() == 1);

    TestObject obj;
    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)0.12));

    TestObject o1("second", 1.23);
    list_.Push(o1);

    CPPUNIT_ASSERT(list_.size() == 2);

    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)0.12));

    TestObject o2("third", 5.67);
    list_.Push(o2);

    CPPUNIT_ASSERT(list_.size() == 3);

    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)0.12));

    TestObject o3("fourth", 7.89);
    list_.Push(o3);

    CPPUNIT_ASSERT(list_.size() == 4);

    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)0.12));

    TestObject o4("fifth", 2.34);
    list_.Push(o4);

    CPPUNIT_ASSERT(list_.size() == 5);

    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj.name_ == "first") && (obj.value_ == (float)0.12));

    // Walk the list.
    List<TestObject>::WalkState ws;
    ws.PrepareForWalk();

    TestObject  next_elem;
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "first");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "second");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fourth");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fifth");

    CPPUNIT_ASSERT(!list_.GetNextItem(ws, next_elem));

    // Test RemoveInPlace.
    ws.PrepareForWalk();
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));

    // Save iterator to the second object.
    CPPUNIT_ASSERT(next_elem.name_ == "second");
    List<TestObject>::WalkState saved_ws  = ws;

    // Restart iterator.
    ws.PrepareForWalk();

    // Remove the second object, ws should point to previous element.
    CPPUNIT_ASSERT(list_.RemoveInPlace(saved_ws));

    // Walk the list.
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "first");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fourth");

    TestObject  saved_object;
    saved_object.name_  = "fourth";
    saved_object.value_ = 7.89;

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fifth");

    // Test Remove.
    CPPUNIT_ASSERT(list_.Remove(saved_object));

    ws.PrepareForWalk();

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "first");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");

    saved_ws  = ws;

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "fifth");

    // Test Pop.
    CPPUNIT_ASSERT(list_.Pop(next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "first");

    // Test PopAt.
    CPPUNIT_ASSERT(list_.PopAt(saved_ws, next_elem));
    CPPUNIT_ASSERT(next_elem.name_ == "third");
    CPPUNIT_ASSERT(list_.size() == 1);

    CPPUNIT_ASSERT(!list_.PeekAt(saved_ws, next_elem));

    // Clear rest.
    list_.Clear();
    CPPUNIT_ASSERT(list_.size() == 0);
  }
  //==========================================================================
  void TestPtrList()
  {
    List<TestObject*> list_;

    TestObject* o0  = new TestObject("first", 0.12);
    CPPUNIT_ASSERT(o0);
    list_.Push(o0);

    TestObject* obj = NULL;

    CPPUNIT_ASSERT(list_.size() == 1);
    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj->name_ == "first") && (obj->value_ == (float)0.12));

    TestObject* o1  = new TestObject("second", 1.23);
    CPPUNIT_ASSERT(o1);
    list_.Push(o1);

    CPPUNIT_ASSERT(list_.size() == 2);
    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj->name_ == "first") && (obj->value_ == (float)0.12));

    TestObject* o2  = new TestObject("third", 5.67);
    CPPUNIT_ASSERT(o2);
    list_.Push(o2);

    CPPUNIT_ASSERT(list_.size() == 3);
    CPPUNIT_ASSERT(list_.Peek(obj));
    CPPUNIT_ASSERT((obj->name_ == "first") && (obj->value_ == (float)0.12));

    TestObject* o3  = new TestObject("fourth", 7.89);
    CPPUNIT_ASSERT(o3);
    list_.Push(o3);

    CPPUNIT_ASSERT(list_.size() == 4);

    TestObject* o4  = new TestObject("fifth", 2.34);
    CPPUNIT_ASSERT(o4);
    list_.Push(o4);

    CPPUNIT_ASSERT(list_.size() == 5);

    // Walk the list.
    List<TestObject*>::WalkState ws;
    ws.PrepareForWalk();

    TestObject* next_elem = NULL;
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem != NULL);
    CPPUNIT_ASSERT(next_elem->name_ == "first");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem != NULL);
    CPPUNIT_ASSERT(next_elem->name_ == "second");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem != NULL);
    CPPUNIT_ASSERT(next_elem->name_ == "third");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem != NULL);
    CPPUNIT_ASSERT(next_elem->name_ == "fourth");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem != NULL);
    CPPUNIT_ASSERT(next_elem->name_ == "fifth");

    CPPUNIT_ASSERT(!list_.GetNextItem(ws, next_elem));

    ws.PrepareForWalk();
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem != NULL);
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem != NULL);

    // Save iterator to the second object.
    CPPUNIT_ASSERT(next_elem->name_ == "second");
    TestObject*                   second_obj  = next_elem;
    List<TestObject*>::WalkState  saved_ws    = ws;

    // Restart iterator.
    ws.PrepareForWalk();

    // Remove the second object, ws should point to previous element.
    CPPUNIT_ASSERT(list_.RemoveInPlace(saved_ws));
    delete second_obj;

    // Walk the list.
    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "first");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "third");

    saved_ws  = ws;

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "fourth");

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "fifth");

    // Test Remove.
    TestObject* saved_object  = next_elem;
    CPPUNIT_ASSERT(list_.Remove(saved_object));
    delete next_elem;
    next_elem = NULL;
    saved_object = NULL;

    CPPUNIT_ASSERT(list_.PopBack(saved_object));
    CPPUNIT_ASSERT(saved_object && (saved_object->name_ == "fourth"));
    delete saved_object;
    saved_object = NULL;

    CPPUNIT_ASSERT(list_.PopAt(saved_ws, saved_object));
    CPPUNIT_ASSERT(saved_object && (saved_object->name_ == "third"));
    delete saved_object;
    saved_object = NULL;

    ws.PrepareForWalk();

    CPPUNIT_ASSERT(list_.GetNextItem(ws, next_elem));
    CPPUNIT_ASSERT(next_elem->name_ == "first");

    list_.Clear();
    CPPUNIT_ASSERT(list_.size() == 0);

    // The first element was on the list when it was cleared; delete it
    // after clearing the list to avoid a temporary dangling pointer.
    delete next_elem;
    next_elem = NULL;

    CPPUNIT_ASSERT(list_.Empty());
  }

  //==========================================================================
  void TestPtrLoadedList()
  {
#define STR_NAME(i) ("string##_#i")
    List<TestObject*> list_;

#define TEST_NUM_ELEMS 10000
    TestObject* obj = NULL;
    for (uint64_t i = 0; i < TEST_NUM_ELEMS; ++i)
    {
      TestObject* o = new TestObject(STR_NAME(i), (float)i);
      CPPUNIT_ASSERT(o);
      list_.Push(o);

      CPPUNIT_ASSERT(list_.size() == (i + 1));
      CPPUNIT_ASSERT(list_.PeekBack(obj));
      CPPUNIT_ASSERT((obj->name_ == STR_NAME(i)) && (obj->value_ == (float)i));
    }

    CPPUNIT_ASSERT(list_.size() == TEST_NUM_ELEMS);

    List<TestObject*>::WalkState  ws;
    List<TestObject*>::WalkState  saved_ws;
    ws.PrepareForWalk();

    uint64_t    i   = 0;
    while (list_.GetNextItem(ws, obj))
    {
      CPPUNIT_ASSERT(obj);
      CPPUNIT_ASSERT(obj->name_ == STR_NAME(i));
      if (i == (TEST_NUM_ELEMS / 2))
      {
        saved_ws  = ws;
      }
      ++i;
    }

    CPPUNIT_ASSERT(list_.PopAt(saved_ws, obj));
    delete obj;

    ws.PrepareForWalk();
    i = 0;
    while (list_.Peek(obj))
    {
      CPPUNIT_ASSERT(list_.Pop(obj));
      if (i == (TEST_NUM_ELEMS / 2))
      {
        ++i;
      }

      CPPUNIT_ASSERT(obj->name_ == STR_NAME(i));
      delete obj;
      ++i;
    }
  }

  //==========================================================================
  void TestIterator()
  {
    List<TestObject>  list_;

    List<TestObject>::WalkState ws;
    List<TestObject>::WalkState comp_ws;
    ws.PrepareForWalk();
    comp_ws.PrepareForWalk();

    CPPUNIT_ASSERT(ws.IsNULL());

    TestObject  o0("first", 0.12);
    TestObject  o1("first", 0.12);

    TestObject  obj;

    list_.Push(o0);
    list_.Push(o1);

    list_.GetNextItem(ws, obj);
    list_.GetNextItem(comp_ws, obj);
    CPPUNIT_ASSERT(ws == comp_ws);

    list_.GetNextItem(ws, obj);
    CPPUNIT_ASSERT(!(ws == comp_ws));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(ListTest);
