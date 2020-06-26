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

// \brief The IRON Timer source file.
//
// Provides the IRON software with a Timer capability.

#include "timer.h"

#include "log.h"
#include "itime.h"
#include "unused.h"

#include <iostream>

#include <inttypes.h>

using ::iron::Log;
using ::iron::Time;
using ::iron::Timer;


namespace
{
  /// Class name for logging.
  const char*   UNUSED(kClassName) = "Timer";

  /// The initial number of timer elements to add to the pool.
  const size_t  kInitPoolSize      = 64;
}

//============================================================================
Timer::Timer()
    : next_handle_(1), events_head_(NULL), events_tail_(NULL),
      next_event_(NULL), pool_(NULL)
{
  Time  exp_time;

  // Add an initial number of timer elements to the pool.
  for (size_t i = 0; i < kInitPoolSize; ++i)
  {
    TimerElem*  te = new (std::nothrow) TimerElem(0, exp_time);

    if (te != NULL)
    {
      te->next = pool_;
      pool_    = te;
    }
  }
}

//============================================================================
Timer::~Timer()
{
  // Move all of the timer elements back to the pool.
  CancelAllTimers();

  // Delete all of the timer elements in the pool.
  while (pool_ != NULL)
  {
    TimerElem*  te = pool_;
    pool_          = te->next;
    delete te;
  }
}

//============================================================================
bool Timer::StartTimer(const Time& delta_time, CallbackInterface* cb,
                       Handle& handle)
{
  // Compute the absolute expiration time.
  Time  timeout;

  if (!timeout.GetNow())
  {
    LogF(kClassName, __func__, "Error getting current time.\n");
    return false;
  }

  timeout += delta_time;

  // Fetch a new element for the timer event.
  TimerElem*  new_te = NULL;

  if (pool_ == NULL)
  {
    new_te = new (std::nothrow) TimerElem(next_handle_, timeout);

    if (new_te == NULL)
    {
      LogF(kClassName, __func__, "Cannot allocate timer element.\n");
      return false;
    }
  }
  else
  {
    new_te = pool_;
    pool_  = new_te->next;

    new_te->handle_id  = next_handle_;
    new_te->event_time = timeout;
  }

  new_te->cb = cb->Clone();

  // Return the assigned handle for the timer.
  handle.id_   = next_handle_;
  handle.elem_ = new_te;

  // Increment the next handle to assign, avoiding zero.
  ++next_handle_;

  if (next_handle_ == 0)
  {
    next_handle_ = 1;
  }

  // Add the new timer element to the tail of the event list.
  if (events_tail_ == NULL)
  {
    new_te->next = NULL;
    new_te->prev = NULL;
    events_head_ = new_te;
    events_tail_ = new_te;
    next_event_  = new_te;
  }
  else
  {
    events_tail_->next = new_te;
    new_te->next       = NULL;
    new_te->prev       = events_tail_;
    events_tail_       = new_te;

    // If this timer event has an earlier expiration time than the current
    // next timer event, then update the next timer event to this timer event.
    if ((next_event_ != NULL) && (timeout < next_event_->event_time))
    {
      next_event_ = new_te;
    }
  }

  return true;
}

//============================================================================
bool Timer::ModifyTimer(const Time& delta_time, Handle& handle)
{
  bool  rv = false;

  // Check if the timer event is still set.
  if ((handle.id_ != 0) && (handle.elem_ != NULL) &&
      (handle.id_ == handle.elem_->handle_id))
  {
    // Compute the new absolute expiration time.
    Time  timeout;

    if (!timeout.GetNow())
    {
      LogF(kClassName, __func__, "Error getting current time.\n");
      return false;
    }

    timeout += delta_time;

    // If this timer element is the current next timer event, and the
    // expiration time is being pushed out, then invalidate the next timer
    // event.
    if ((handle.elem_ == next_event_) && (timeout > handle.elem_->event_time))
    {
      next_event_ = NULL;
    }

    // Update the expiration time.
    handle.elem_->event_time = timeout;

    rv = true;
  }

  return rv;
}

//============================================================================
bool Timer::CancelTimer(Handle& handle)
{
  bool  rv = false;

  // Check if the timer event is still set.
  if ((handle.id_ != 0) && (handle.elem_ != NULL) &&
      (handle.id_ == handle.elem_->handle_id))
  {
    TimerElem*  te = handle.elem_;

    // If this timer element is the current next timer event, then invalidate
    // the next timer event.
    if (te == next_event_)
    {
      next_event_ = NULL;
    }

    // Remove it from the list and add it to the pool.
    if (te->next != NULL)
    {
      te->next->prev = te->prev;
    }
    if (te->prev != NULL)
    {
      te->prev->next = te->next;
    }
    if (te == events_head_)
    {
      events_head_ = te->next;
    }
    if (te == events_tail_)
    {
      events_tail_ = te->prev;
    }

    te->handle_id = 0;
    if (te->cb != NULL)
    {
      te->cb->ReleaseClone();
      te->cb = NULL;
    }
    te->next = pool_;
    te->prev = NULL;
    pool_    = te;

    rv = true;
  }

  // Invalidate the handle.
  handle.id_   = 0;
  handle.elem_ = NULL;

  return rv;
}

//============================================================================
void Timer::CancelAllTimers()
{
  // Navigate the list of events, removing each element and adding it to the
  // pool.
  while (events_head_ != NULL)
  {
    TimerElem*  te = events_head_;
    events_head_   = te->next;

    te->handle_id = 0;
    if (te->cb != NULL)
    {
      te->cb->ReleaseClone();
      te->cb = NULL;
    }
    te->next = pool_;
    te->prev = NULL;
    pool_    = te;
  }

  events_tail_ = NULL;
  next_event_  = NULL;
}

//============================================================================
Time Timer::GetNextExpirationTime(const Time& max_wait)
{
  // If the event list is empty, then return the maximum wait.
  if (events_head_ == NULL)
  {
    return max_wait;
  }

  // Get the current time.
  Time  now;

  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Error getting current time.\n");
    return max_wait;
  }

  // Get the next timer event wait time.
  Time  wait_time;

  if (next_event_ == NULL)
  {
    if (!FindNextEvent())
    {
      return max_wait;
    }
  }

  if (next_event_->event_time > now)
  {
    // The next expiration time has not been reached yet, so return the time
    // difference from now until the event, limited to max_wait.
    wait_time = Time::Min((next_event_->event_time - now), max_wait);
  }
  else
  {
    // The next expiration time has passed, so return a zero time difference.
    Time  time_difference = (now - events_head_->event_time);
    Time  limit(0, 1000);

    if (time_difference > limit)
    {
      LogW(kClassName, __func__,
           "Timer handle %" PRIu32 " late by more than 1 ms! (diff %s)\n",
           events_head_->handle_id, time_difference.ToString().c_str());
    }
  }

  return wait_time;
}

//============================================================================
void Timer::DoCallbacks()
{
  while (events_head_ != NULL)
  {
    // Get the current time.
    Time  now;

    if (!now.GetNow())
    {
      LogF(kClassName, __func__, "Error getting current time.\n");
      break;
    }

    // Get the next timer event.
    if (next_event_ == NULL)
    {
      if (!FindNextEvent())
      {
        break;
      }
    }

    // Check if the next timer event has expired.
    if (next_event_->event_time <= now)
    {
      // It has expired, so remove it from the event list.
      TimerElem*  te = next_event_;

      if (te->next != NULL)
      {
        te->next->prev = te->prev;
      }
      if (te->prev != NULL)
      {
        te->prev->next = te->next;
      }
      if (te == events_head_)
      {
        events_head_ = te->next;
      }
      if (te == events_tail_)
      {
        events_tail_ = te->prev;
      }
      next_event_ = NULL;

      // Invalidate any handles to this timer.
      te->handle_id = 0;

      // Do the callback.
      if (te->cb != NULL)
      {
        te->cb->PerformCallback();
        te->cb->ReleaseClone();
        te->cb = NULL;
      }
      else
      {
        LogF(kClassName, __func__, "Callback pointer is NULL.\n");
      }

      // Add it to the pool, then allow another loop.
      te->next = pool_;
      te->prev = NULL;
      pool_    = te;
    }
    else
    {
      // If the next timer event hasn't expired yet, then the other events are
      // guaranteed to not be expired either.
      break;
    }
  }
}

//============================================================================
bool Timer::FindNextEvent()
{
  // Search for the timer event that will expire next.
  TimerElem*  ne = events_head_;

  if (events_head_ != NULL)
  {
    for (TimerElem* te = events_head_->next; te != NULL; te = te->next)
    {
      if (te->event_time < ne->event_time)
      {
        ne = te;
      }
    }
  }

  next_event_ = ne;

  return (ne != NULL);
}
