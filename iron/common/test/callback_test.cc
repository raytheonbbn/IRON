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

#include "callback.h"

#include <string>

#include <stdint.h>


using ::iron::CallbackInterface;
using ::iron::CallbackNoArg;
using ::iron::CallbackOneArg;
using ::iron::CallbackTwoArg;
using ::iron::CallbackThreeArg;
using ::std::string;


//============================================================================
// A copyable class for testing callback arguments.
class CopyableClass
{
public:
  CopyableClass(int first, string second) : first_(first), second_(second)
  { }
  CopyableClass(const CopyableClass& cc)
      : first_(cc.first_), second_(cc.second_)
  { }
  const CopyableClass& operator=(const CopyableClass& cc)
  {
    first_  = cc.first_;
    second_ = cc.second_;
    return *this;
  }
  virtual ~CopyableClass()
  { }
  int GetFirst()
  {
    return first_;
  }
  string GetSecond()
  {
    return second_;
  }
private:
  CopyableClass();
  int     first_;   // A copyable item.
  string  second_;  // A copyable item.
};


//============================================================================
// A non-copyable class for testing callback arguments.
class NonCopyableClass
{
public:
  NonCopyableClass(int size) : size_(size), buf_(NULL)
  {
    if (size > 0)
    {
      buf_ = new uint8_t[size];
    }
  }
  virtual ~NonCopyableClass()
  {
    if (buf_ != NULL)
    {
      delete[] buf_;
    }
  }
  int GetSize()
  {
    return size_;
  }
  uint8_t* GetBuffer()
  {
    return buf_;
  }
private:
  NonCopyableClass();
  NonCopyableClass(NonCopyableClass&);
  const NonCopyableClass& operator=(const NonCopyableClass&);
  int        size_;  // A copyable item.
  uint8_t*   buf_;   // A non-copyable item.
};


//============================================================================
// The class that will receive the callbacks.
class CBTarget
{
public:
  CBTarget() : no_arg_cnt_(0), int_arg_(0), cc_arg_(0, ""), ncc_arg_(NULL)
  { }
  virtual ~CBTarget()
  { }
  void MethodNoArg()
  {
    no_arg_cnt_++;
  }
  void MethodI(int arg)
  {
    int_arg_ = arg;
  }
  virtual void MethodC(CopyableClass arg)
  {
    cc_arg_ = arg;
  }
  virtual void MethodN(NonCopyableClass* arg)
  {
    ncc_arg_ = arg;
  }
  void MethodIC(int arg1, CopyableClass arg2)
  {
    int_arg_ = arg1;
    cc_arg_  = arg2;
  }
  virtual void MethodIN(int arg1, NonCopyableClass* arg2)
  {
    int_arg_ = arg1;
    ncc_arg_ = arg2;
  }
  void MethodCN(CopyableClass arg1, NonCopyableClass* arg2)
  {
    cc_arg_  = arg1;
    ncc_arg_ = arg2;
  }
  virtual void MethodNIC(NonCopyableClass* arg1, int arg2,
                         CopyableClass arg3)
  {
    int_arg_ = arg2;
    cc_arg_  = arg3;
    ncc_arg_ = arg1;
  }
  void MethodCNI(CopyableClass arg1, NonCopyableClass* arg2, int arg3)
  {
    int_arg_ = arg3;
    cc_arg_  = arg1;
    ncc_arg_ = arg2;
  }
  int GetNoArgCount()
  {
    return no_arg_cnt_;
  }
  int GetIntArg()
  {
    return int_arg_;
  }
  CopyableClass GetCopyableArg()
  {
    return cc_arg_;
  }
  NonCopyableClass* GetNonCopyableArg()
  {
    return ncc_arg_;
  }
private:
  int                no_arg_cnt_;
  int                int_arg_;
  CopyableClass      cc_arg_;
  NonCopyableClass*  ncc_arg_;
};


//============================================================================
// A service that will fire the callbacks.  It has no knowledge of CBTarget.
class Service
{
public:
  Service(int max_cb) : max_cb_(max_cb), cb_cnt_(0), cb_(NULL)
  {
    cb_ = new CallbackInterface*[max_cb_];
    for (int i = 0; i < max_cb_; ++i)
    {
      cb_[i] = NULL;
    }
  }
  virtual ~Service()
  {
    for (int i = 0; i < cb_cnt_; ++i)
    {
      cb_[i]->ReleaseClone();
      cb_[i] = NULL;
    }
    delete [] cb_;
    cb_ = NULL;
  }
  bool RegisterCallback(CallbackInterface* cb)
  {
    if ((cb_cnt_ >= max_cb_) || (cb == NULL))
    {
      return false;
    }
    cb_[cb_cnt_] = cb->Clone();
    cb_cnt_++;
    return true;
  }
  void ClearCallbacks()
  {
    for (int i = 0; i < cb_cnt_; ++i)
    {
      cb_[i]->ReleaseClone();
      cb_[i] = NULL;
    }
    cb_cnt_ = 0;
  }
  void DoCallbacks()
  {
    for (int i = 0; i < cb_cnt_; ++i)
    {
      cb_[i]->PerformCallback();
    }
  }
private:
  int                  max_cb_;
  int                  cb_cnt_;
  CallbackInterface**  cb_;
};


//============================================================================
class CallbackTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(CallbackTest);

  CPPUNIT_TEST(TestNoArg);
  CPPUNIT_TEST(TestOneArg);
  CPPUNIT_TEST(TestTwoArg);
  CPPUNIT_TEST(TestThreeArg);

  CPPUNIT_TEST_SUITE_END();

private:

  CBTarget*          target_;
  Service*           service_;
  NonCopyableClass*  ncc1_;
  NonCopyableClass*  ncc2_;

public:

  //==========================================================================
  void setUp()
  {
    target_  = new CBTarget();
    service_ = new Service(4);
    // The non-copyable arguments must be managed outside of the callback
    // objects.
    ncc1_    = new NonCopyableClass(32);
    ncc2_    = new NonCopyableClass(64);
  }

  //==========================================================================
  void tearDown()
  {
    // Delete the objects first.  This might release cloned object.
    delete ncc2_;
    delete ncc1_;
    delete service_;
    delete target_;
    ncc2_    = NULL;
    ncc1_    = NULL;
    service_ = NULL;
    target_  = NULL;

    // Empty the callback pools.  This will delete all of the cloned objects.
    CallbackNoArg<CBTarget>::EmptyPool();
    CallbackOneArg<CBTarget, int>::EmptyPool();
    CallbackOneArg<CBTarget, CopyableClass>::EmptyPool();
    CallbackOneArg<CBTarget, NonCopyableClass*>::EmptyPool();
    CallbackTwoArg<CBTarget, int, CopyableClass>::EmptyPool();
    CallbackTwoArg<CBTarget, int, NonCopyableClass*>::EmptyPool();
    CallbackTwoArg<CBTarget, CopyableClass, NonCopyableClass*>::EmptyPool();
    CallbackThreeArg<CBTarget, NonCopyableClass*, int,
                     CopyableClass>::EmptyPool();
    CallbackThreeArg<CBTarget, CopyableClass, NonCopyableClass*,
                     int>::EmptyPool();
  }

  //==========================================================================
  void TestNoArg()
  {
    // Keep the callback object in scope for the actual callback.
    CallbackNoArg<CBTarget>  cb1(target_, &CBTarget::MethodNoArg);
    service_->RegisterCallback(&cb1);

    // One callback registered -> total of one callback as a result.
    service_->DoCallbacks();
    CPPUNIT_ASSERT(target_->GetNoArgCount() == 1);

    // Force the callback object out of scope for the actual callback.
    {
      CallbackNoArg<CBTarget>  cb2(target_, &CBTarget::MethodNoArg);
      service_->RegisterCallback(&cb2);
    }

    // Two callbacks registered -> total of three callbacks as a result (one
    // above, two right now).
    service_->DoCallbacks();
    CPPUNIT_ASSERT(target_->GetNoArgCount() == 3);
  }

  //==========================================================================
  void TestOneArg()
  {
    const int    val1 = 42;
    const int    val2 = 71;
    const char*  str2 = "Test string";

    // Keep the callback object in scope for the actual callback.
    CallbackOneArg<CBTarget, int>  cb1(target_, &CBTarget::MethodI, val1);
    service_->RegisterCallback(&cb1);

    service_->DoCallbacks();
    CPPUNIT_ASSERT(target_->GetIntArg() == val1);

    // Force the callback object out of scope for the actual callback.
    {
      CopyableClass  cc1(val2, str2);
      CallbackOneArg<CBTarget, CopyableClass>  cb2(
        target_, &CBTarget::MethodC, cc1);
      service_->ClearCallbacks();
      service_->RegisterCallback(&cb2);
    }

    service_->DoCallbacks();
    CopyableClass  rv1 = target_->GetCopyableArg();
    CPPUNIT_ASSERT(rv1.GetFirst()  == val2);
    CPPUNIT_ASSERT(rv1.GetSecond() == str2);

    // Force the callback object out of scope for the actual callback.
    {
      CallbackOneArg<CBTarget, NonCopyableClass*>  cb3(
        target_, &CBTarget::MethodN, ncc1_);
      service_->ClearCallbacks();
      service_->RegisterCallback(&cb3);
    }

    service_->DoCallbacks();
    NonCopyableClass*  rv2 = target_->GetNonCopyableArg();
    CPPUNIT_ASSERT(rv2->GetSize()   == ncc1_->GetSize());
    CPPUNIT_ASSERT(rv2->GetBuffer() == ncc1_->GetBuffer());

    // Force the callback object out of scope for the actual callback.
    {
      CallbackOneArg<CBTarget, NonCopyableClass*>  cb4(
        target_, &CBTarget::MethodN, ncc2_);
      service_->ClearCallbacks();
      service_->RegisterCallback(&cb4);
    }

    service_->DoCallbacks();
    NonCopyableClass*  rv3 = target_->GetNonCopyableArg();
    CPPUNIT_ASSERT(rv3->GetSize()   == ncc2_->GetSize());
    CPPUNIT_ASSERT(rv3->GetBuffer() == ncc2_->GetBuffer());
  }

  //==========================================================================
  void TestTwoArg()
  {
    const int    val1 = 111;
    const char*  str1 = "One two three";
    const int    val2 = 555;
    const int    val3 = 49;
    const int    val4 = 202;
    const char*  str4 = "A string";

    // Keep the callback object in scope for the actual callback.
    CopyableClass  cc1(val1, str1);
    CallbackTwoArg<CBTarget, int, CopyableClass>  cb1(
      target_, &CBTarget::MethodIC, val2, cc1);
    service_->RegisterCallback(&cb1);

    service_->DoCallbacks();
    CopyableClass  rv1 = target_->GetCopyableArg();
    CPPUNIT_ASSERT(target_->GetIntArg() == val2);
    CPPUNIT_ASSERT(rv1.GetFirst()       == val1);
    CPPUNIT_ASSERT(rv1.GetSecond()      == str1);

    // Force the callback object out of scope for the actual callback.
    {
      CallbackTwoArg<CBTarget, int, NonCopyableClass*>  cb2(
        target_, &CBTarget::MethodIN, val3, ncc1_);
      service_->ClearCallbacks();
      service_->RegisterCallback(&cb2);
    }

    service_->DoCallbacks();
    NonCopyableClass*  rv2 = target_->GetNonCopyableArg();
    CPPUNIT_ASSERT(target_->GetIntArg() == val3);
    CPPUNIT_ASSERT(rv2->GetSize()       == ncc1_->GetSize());
    CPPUNIT_ASSERT(rv2->GetBuffer()     == ncc1_->GetBuffer());

    // Force the callback object out of scope for the actual callback.
    {
      CopyableClass  cc2(val4, str4);
      CallbackTwoArg<CBTarget, CopyableClass, NonCopyableClass*>  cb3(
        target_, &CBTarget::MethodCN, cc2, ncc2_);
      service_->ClearCallbacks();
      service_->RegisterCallback(&cb3);
    }

    service_->DoCallbacks();
    CopyableClass      rv3 = target_->GetCopyableArg();
    NonCopyableClass*  rv4 = target_->GetNonCopyableArg();
    CPPUNIT_ASSERT(rv3.GetFirst()   == val4);
    CPPUNIT_ASSERT(rv3.GetSecond()  == str4);
    CPPUNIT_ASSERT(rv4->GetSize()   == ncc2_->GetSize());
    CPPUNIT_ASSERT(rv4->GetBuffer() == ncc2_->GetBuffer());
  }

  //==========================================================================
  void TestThreeArg()
  {
    const int    val1 = 4567;
    const char*  str1 = "Another string";
    const int    val2 = 5;
    const int    val3 = 1234;
    const char*  str3 = "Yet another string";
    const int    val4 = 99;

    // Force the callback object out of scope for the actual callback.
    {
      CopyableClass  cc1(val1, str1);
      CallbackThreeArg<CBTarget, NonCopyableClass*, int, CopyableClass>  cb1(
        target_, &CBTarget::MethodNIC, ncc1_, val2, cc1);
      service_->RegisterCallback(&cb1);
    }

    service_->DoCallbacks();
    CopyableClass      rv1 = target_->GetCopyableArg();
    NonCopyableClass*  rv2 = target_->GetNonCopyableArg();
    CPPUNIT_ASSERT(target_->GetIntArg() == val2);
    CPPUNIT_ASSERT(rv1.GetFirst()       == val1);
    CPPUNIT_ASSERT(rv1.GetSecond()      == str1);
    CPPUNIT_ASSERT(rv2->GetSize()       == ncc1_->GetSize());
    CPPUNIT_ASSERT(rv2->GetBuffer()     == ncc1_->GetBuffer());

    // Force the callback object out of scope for the actual callback.
    {
      CopyableClass  cc2(val3, str3);
      CallbackThreeArg<CBTarget, CopyableClass, NonCopyableClass*, int>  cb2(
        target_, &CBTarget::MethodCNI, cc2, ncc2_, val4);
      service_->ClearCallbacks();
      service_->RegisterCallback(&cb2);
    }

    service_->DoCallbacks();
    CopyableClass      rv3 = target_->GetCopyableArg();
    NonCopyableClass*  rv4 = target_->GetNonCopyableArg();
    CPPUNIT_ASSERT(target_->GetIntArg() == val4);
    CPPUNIT_ASSERT(rv3.GetFirst()       == val3);
    CPPUNIT_ASSERT(rv3.GetSecond()      == str3);
    CPPUNIT_ASSERT(rv4->GetSize()       == ncc2_->GetSize());
    CPPUNIT_ASSERT(rv4->GetBuffer()     == ncc2_->GetBuffer());
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(CallbackTest);
