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

#include "timer.h"

#include <cstdio>
#include <unistd.h>

using ::iron::CallbackOneArg;
using ::iron::Timer;
using ::iron::Time;


#define NUM_TIMERS 32


/// Class for receiving the callbacks.
class TimerTarget
{

 public:

  TimerTarget(Timer& t)
      : timer(t), handle(), cb_cnt(0), cb_order()
  { }

  virtual ~TimerTarget()
  { }

  void CallbackMethod(int arg1)
  {
    // Attempt to cancel the timer that just expired within the callback.
    CPPUNIT_ASSERT(timer.CancelTimer(handle[arg1]) == false);

    cb_order[cb_cnt] = arg1;
    ++cb_cnt;
  }

  void CallbackMethod2(int arg1)
  {
    // Attempt to cancel the timer that just expired within the callback.
    CPPUNIT_ASSERT(timer.CancelTimer(handle[arg1]) == false);

    cb_order[cb_cnt] = arg1;
    ++cb_cnt;

    if (arg1 < 4)
    {
      // Attempt to create other timers within the callback.
      int                               index = (arg1 + 4);
      Time                              delta = Time::FromMsec(100);
      CallbackOneArg<TimerTarget, int>  cb(this,
                                           &TimerTarget::CallbackMethod2,
                                           index);

      CPPUNIT_ASSERT(timer.StartTimer(delta, &cb, handle[index]) == true);
    }
  }

  Timer&         timer;
  Timer::Handle  handle[NUM_TIMERS];
  int            cb_cnt;
  int            cb_order[NUM_TIMERS];
};

//============================================================================
class TimerTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(TimerTest);

  CPPUNIT_TEST(TestStartAndCancelTimers);
  CPPUNIT_TEST(TestStartTimersInCallback);
  CPPUNIT_TEST(TestModifyTimers);
  CPPUNIT_TEST(TestCancelAllTimers);

  CPPUNIT_TEST_SUITE_END();

  Timer*        timer;
  TimerTarget*  target;

 public:

  //==========================================================================
  void setUp()
  {
    timer  = new (std::nothrow) Timer();
    target = new (std::nothrow) TimerTarget(*timer);
  }

  //==========================================================================
  void tearDown()
  {
    CallbackOneArg<TimerTarget, int>::EmptyPool();
    delete target;
    delete timer;
    target = NULL;
    timer  = NULL;
  }

  //==========================================================================
  void TestStartAndCancelTimers()
  {
    Time  delta;

    {
      // Create 8 timers to expire in the following order:  5 1 3 0 7 4 2 6
      CallbackOneArg<TimerTarget, int>  cb0(target,
                                            &TimerTarget::CallbackMethod, 0);
      CallbackOneArg<TimerTarget, int>  cb1(target,
                                            &TimerTarget::CallbackMethod, 1);
      CallbackOneArg<TimerTarget, int>  cb2(target,
                                            &TimerTarget::CallbackMethod, 2);
      CallbackOneArg<TimerTarget, int>  cb3(target,
                                            &TimerTarget::CallbackMethod, 3);
      CallbackOneArg<TimerTarget, int>  cb4(target,
                                            &TimerTarget::CallbackMethod, 4);
      CallbackOneArg<TimerTarget, int>  cb5(target,
                                            &TimerTarget::CallbackMethod, 5);
      CallbackOneArg<TimerTarget, int>  cb6(target,
                                            &TimerTarget::CallbackMethod, 6);
      CallbackOneArg<TimerTarget, int>  cb7(target,
                                            &TimerTarget::CallbackMethod, 7);

      delta = Time::FromMsec(200);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb0,
                                       target->handle[0]) == true);
      delta = Time::FromMsec(100);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb1,
                                       target->handle[1]) == true);
      delta = Time::FromMsec(350);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb2,
                                       target->handle[2]) == true);
      delta = Time::FromMsec(150);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb3,
                                       target->handle[3]) == true);
      delta = Time::FromMsec(300);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb4,
                                       target->handle[4]) == true);
      delta = Time::FromMsec(50);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb5,
                                       target->handle[5]) == true);
      delta = Time::FromMsec(400);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb6,
                                       target->handle[6]) == true);
      delta = Time::FromMsec(250);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb7,
                                       target->handle[7]) == true);

      // Have the callback objects go out of scope.
    }

    // Cancel timers 5, 0, and 6.
    CPPUNIT_ASSERT(timer->CancelTimer(target->handle[5]) == true);
    CPPUNIT_ASSERT(timer->CancelTimer(target->handle[0]) == true);
    CPPUNIT_ASSERT(timer->CancelTimer(target->handle[6]) == true);

    {
      // Recreate timers 5, 0, and 6.
      CallbackOneArg<TimerTarget, int>  cb0(target,
                                            &TimerTarget::CallbackMethod, 0);
      CallbackOneArg<TimerTarget, int>  cb5(target,
                                            &TimerTarget::CallbackMethod, 5);
      CallbackOneArg<TimerTarget, int>  cb6(target,
                                            &TimerTarget::CallbackMethod, 6);

      delta = Time::FromMsec(200);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb0,
                                       target->handle[0]) == true);
      delta = Time::FromMsec(50);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb5,
                                       target->handle[5]) == true);
      delta = Time::FromMsec(400);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb6,
                                       target->handle[6]) == true);

      // Have the callback objects go out of scope.
    }

    // Check that all of the timers are set.
    for (int i = 0; i < 8; ++i)
    {
      CPPUNIT_ASSERT(timer->IsTimerSet(target->handle[i]) == true);
    }

    // The next expiration time should be < 50 milliseconds from now.
    Time  wait_time  = timer->GetNextExpirationTime();
    Time  limit_time = Time::FromMsec(50);
    CPPUNIT_ASSERT(wait_time <= limit_time);

    // Allow the timers to go off, recording the callback order in the target.
    for (int i = 0; i < 100; ++i)
    {
      usleep(5000);
      timer->DoCallbacks();
      if (target->cb_cnt >= 8)
      {
        break;
      }
    }

    // Verify the callback count and order.
    CPPUNIT_ASSERT(target->cb_cnt == 8);
    CPPUNIT_ASSERT(target->cb_order[0] == 5);
    CPPUNIT_ASSERT(target->cb_order[1] == 1);
    CPPUNIT_ASSERT(target->cb_order[2] == 3);
    CPPUNIT_ASSERT(target->cb_order[3] == 0);
    CPPUNIT_ASSERT(target->cb_order[4] == 7);
    CPPUNIT_ASSERT(target->cb_order[5] == 4);
    CPPUNIT_ASSERT(target->cb_order[6] == 2);
    CPPUNIT_ASSERT(target->cb_order[7] == 6);
  }

  //==========================================================================
  void TestStartTimersInCallback()
  {
    Time  delta;

    {
      // Create 4 timers to expire in the following order:  1 3 0 2
      CallbackOneArg<TimerTarget, int>  cb0(target,
                                            &TimerTarget::CallbackMethod2, 0);
      CallbackOneArg<TimerTarget, int>  cb1(target,
                                            &TimerTarget::CallbackMethod2, 1);
      CallbackOneArg<TimerTarget, int>  cb2(target,
                                            &TimerTarget::CallbackMethod2, 2);
      CallbackOneArg<TimerTarget, int>  cb3(target,
                                            &TimerTarget::CallbackMethod2, 3);

      delta = Time::FromMsec(60);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb0,
                                       target->handle[0]) == true);
      delta = Time::FromMsec(20);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb1,
                                       target->handle[1]) == true);
      delta = Time::FromMsec(80);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb2,
                                       target->handle[2]) == true);
      delta = Time::FromMsec(40);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb3,
                                       target->handle[3]) == true);

      // Have the callback objects go out of scope.
    }

    // Check that all of the timers are set.
    for (int i = 0; i < 4; ++i)
    {
      CPPUNIT_ASSERT(timer->IsTimerSet(target->handle[i]) == true);
    }

    // The next expiration time should be < 20 milliseconds from now.
    Time  wait_time  = timer->GetNextExpirationTime();
    Time  limit_time = Time::FromMsec(20);
    CPPUNIT_ASSERT(wait_time <= limit_time);

    // Allow the timers to go off, recording the callback order in the target.
    for (int i = 0; i < 100; ++i)
    {
      usleep(5000);
      timer->DoCallbacks();
      if (target->cb_cnt >= 8)
      {
        break;
      }
    }

    // Verify the callback count and order.
    CPPUNIT_ASSERT(target->cb_cnt == 8);
    CPPUNIT_ASSERT(target->cb_order[0] == 1);
    CPPUNIT_ASSERT(target->cb_order[1] == 3);
    CPPUNIT_ASSERT(target->cb_order[2] == 0);
    CPPUNIT_ASSERT(target->cb_order[3] == 2);
    CPPUNIT_ASSERT(target->cb_order[4] == 5);
    CPPUNIT_ASSERT(target->cb_order[5] == 7);
    CPPUNIT_ASSERT(target->cb_order[6] == 4);
    CPPUNIT_ASSERT(target->cb_order[7] == 6);
  }

  //==========================================================================
  void TestModifyTimers()
  {
    Time  delta;

    {
      // Create 8 timers to expire in the following order:  5 1 3 0 7 4 2 6
      CallbackOneArg<TimerTarget, int>  cb0(target,
                                            &TimerTarget::CallbackMethod, 0);
      CallbackOneArg<TimerTarget, int>  cb1(target,
                                            &TimerTarget::CallbackMethod, 1);
      CallbackOneArg<TimerTarget, int>  cb2(target,
                                            &TimerTarget::CallbackMethod, 2);
      CallbackOneArg<TimerTarget, int>  cb3(target,
                                            &TimerTarget::CallbackMethod, 3);
      CallbackOneArg<TimerTarget, int>  cb4(target,
                                            &TimerTarget::CallbackMethod, 4);
      CallbackOneArg<TimerTarget, int>  cb5(target,
                                            &TimerTarget::CallbackMethod, 5);
      CallbackOneArg<TimerTarget, int>  cb6(target,
                                            &TimerTarget::CallbackMethod, 6);
      CallbackOneArg<TimerTarget, int>  cb7(target,
                                            &TimerTarget::CallbackMethod, 7);

      delta = Time::FromMsec(200);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb0,
                                       target->handle[0]) == true);
      delta = Time::FromMsec(100);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb1,
                                       target->handle[1]) == true);
      delta = Time::FromMsec(400);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb2,
                                       target->handle[2]) == true);
      delta = Time::FromMsec(150);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb3,
                                       target->handle[3]) == true);
      delta = Time::FromMsec(300);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb4,
                                       target->handle[4]) == true);
      delta = Time::FromMsec(50);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb5,
                                       target->handle[5]) == true);
      delta = Time::FromMsec(450);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb6,
                                       target->handle[6]) == true);
      delta = Time::FromMsec(250);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb7,
                                       target->handle[7]) == true);

      // Have the callback objects go out of scope.
    }

    // Modify timers 5, 0, and 6.  The new order will be:  6 1 3 7 4 0 2 5
    delta = Time::FromMsec(450);
    CPPUNIT_ASSERT(timer->ModifyTimer(delta, target->handle[5]) == true);
    delta = Time::FromMsec(350);
    CPPUNIT_ASSERT(timer->ModifyTimer(delta, target->handle[0]) == true);
    delta = Time::FromMsec(50);
    CPPUNIT_ASSERT(timer->ModifyTimer(delta, target->handle[6]) == true);

    // Check that all of the timers are set.
    for (int i = 0; i < 8; ++i)
    {
      CPPUNIT_ASSERT(timer->IsTimerSet(target->handle[i]) == true);
    }

    // The next expiration time should be < 50 milliseconds from now.
    Time  wait_time  = timer->GetNextExpirationTime();
    Time  limit_time = Time::FromMsec(50);
    CPPUNIT_ASSERT(wait_time <= limit_time);

    // Allow the timers to go off, recording the callback order in the target.
    for (int i = 0; i < 100; ++i)
    {
      usleep(5000);
      timer->DoCallbacks();
      if (target->cb_cnt >= 8)
      {
        break;
      }
    }

    // Verify the callback count and order.
    CPPUNIT_ASSERT(target->cb_cnt == 8);
    CPPUNIT_ASSERT(target->cb_order[0] == 6);
    CPPUNIT_ASSERT(target->cb_order[1] == 1);
    CPPUNIT_ASSERT(target->cb_order[2] == 3);
    CPPUNIT_ASSERT(target->cb_order[3] == 7);
    CPPUNIT_ASSERT(target->cb_order[4] == 4);
    CPPUNIT_ASSERT(target->cb_order[5] == 0);
    CPPUNIT_ASSERT(target->cb_order[6] == 2);
    CPPUNIT_ASSERT(target->cb_order[7] == 5);
  }

  //==========================================================================
  void TestCancelAllTimers()
  {
    Time  delta;

    {
      // Create 8 timers.
      CallbackOneArg<TimerTarget, int>  cb0(target,
                                            &TimerTarget::CallbackMethod, 0);
      CallbackOneArg<TimerTarget, int>  cb1(target,
                                            &TimerTarget::CallbackMethod, 1);
      CallbackOneArg<TimerTarget, int>  cb2(target,
                                            &TimerTarget::CallbackMethod, 2);
      CallbackOneArg<TimerTarget, int>  cb3(target,
                                            &TimerTarget::CallbackMethod, 3);
      CallbackOneArg<TimerTarget, int>  cb4(target,
                                            &TimerTarget::CallbackMethod, 4);
      CallbackOneArg<TimerTarget, int>  cb5(target,
                                            &TimerTarget::CallbackMethod, 5);
      CallbackOneArg<TimerTarget, int>  cb6(target,
                                            &TimerTarget::CallbackMethod, 6);
      CallbackOneArg<TimerTarget, int>  cb7(target,
                                            &TimerTarget::CallbackMethod, 7);

      delta = Time::FromMsec(50);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb0,
                                       target->handle[0]) == true);
      delta = Time::FromMsec(100);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb1,
                                       target->handle[1]) == true);
      delta = Time::FromMsec(150);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb2,
                                       target->handle[2]) == true);
      delta = Time::FromMsec(200);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb3,
                                       target->handle[3]) == true);
      delta = Time::FromMsec(250);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb4,
                                       target->handle[4]) == true);
      delta = Time::FromMsec(300);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb5,
                                       target->handle[5]) == true);
      delta = Time::FromMsec(350);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb6,
                                       target->handle[6]) == true);
      delta = Time::FromMsec(400);
      CPPUNIT_ASSERT(timer->StartTimer(delta, &cb7,
                                       target->handle[7]) == true);

      // Have the callback objects go out of scope.
    }

    // The next expiration time should be < 50 milliseconds from now.
    Time  wait_time  = timer->GetNextExpirationTime();
    Time  limit_time = Time::FromMsec(50);
    CPPUNIT_ASSERT(wait_time <= limit_time);

    // Check that all of the timers are set.
    for (int i = 0; i < 8; ++i)
    {
      CPPUNIT_ASSERT(timer->IsTimerSet(target->handle[i]) == true);
    }

    // Cancel all of the timers.
    timer->CancelAllTimers();

    // Check that all of the timers are canceled.
    for (int i = 0; i < 8; ++i)
    {
      CPPUNIT_ASSERT(timer->IsTimerSet(target->handle[i]) == false);
    }

    // The next expiration time should be equal to the time limit specified.
    limit_time = Time::FromMsec(2500);
    wait_time  = timer->GetNextExpirationTime(limit_time);
    CPPUNIT_ASSERT(wait_time == limit_time);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(TimerTest);
