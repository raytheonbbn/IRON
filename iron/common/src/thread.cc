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

#include "thread.h"
#include "log.h"

#include <cerrno>
#include <csignal>
#include <cstring>


using ::iron::Thread;
using ::iron::RunnableIf;


//
// Class name used for logging.
//
static const char  kCn[] = "Thread";


//============================================================================
Thread::Thread() : thread_(0), isRunning_(false)
{
}

//============================================================================
Thread::~Thread()
{
  if (isRunning_)
  {
    StopThread();
  }
}

//============================================================================
bool Thread::StartThread(runner_t* fn, void* arg)
{
  pthread_attr_t  attr;
  
  if (fn == NULL)
  {
    LogE(kCn, __func__, "Null function pointer provided.\n");
    return false;
  }
  
  if (isRunning_)
  {
    LogW(kCn, __func__, "Thread is already running.\n");
    return true;
  }
  
  LogA(kCn, "StartThread", "Starting thread.\n");
  
  //
  // Create a detached thread.
  //
  
  if (pthread_attr_init(&attr) != 0)
  {
    LogE(kCn, __func__, "pthread_attr_init error.\n");
    return false;
  }
  
  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
  {
    LogE(kCn, __func__, "pthread_attr_setdetachedstate error.\n");
    pthread_attr_destroy(&attr);
    return false;
  }
  
  if (pthread_create(&thread_, &attr, fn, arg) != 0)
  {
    LogE(kCn, __func__, "pthread_create error.\n");
    pthread_attr_destroy(&attr);
    return false;
  }
  
  LogA(kCn, __func__, "Thread created.\n");
  
  if (pthread_attr_destroy(&attr) != 0)
  {
    LogE(kCn, __func__, "pthread_attr_destroy error.\n");
  }
  
  isRunning_ = true;
  
  return true;
}

//============================================================================
bool Thread::StartThread(iron::RunnableIf* object)
{
  StartThread(Thread::Run, object);

  return true;
}

//============================================================================
bool Thread::StopThread()
{
  int              rv = 0;
  struct timespec  sleepTime;
  struct timespec  remTime;
  
  if (isRunning_)
  {
    LogI(kCn, __func__, "Stopping thread.\n");
    
    isRunning_ = false;
    
    rv = pthread_cancel(thread_);
    
    //
    // Sleep for a small amount of time to let the thread terminate.
    //
    
    sleepTime.tv_sec  = 1;
    sleepTime.tv_nsec = 0;
    
    while ((sleepTime.tv_sec != 0) || (sleepTime.tv_nsec != 0))
    {
      if ((nanosleep(&sleepTime, &remTime) < 0) && (errno == EINTR))
      {
        memcpy(&sleepTime, &remTime, sizeof(remTime));
      }
      else
      {
        break;
      }
    }

    LogI(kCn, __func__, "Thread stopped.\n");
  }
  else
  {
    LogW(kCn, __func__, "Thread is not running.\n");
  }
  
  return ((rv == 0) ? true : false);
}

//============================================================================
void* Thread::Run(void* arg) 
{
  RunnableIf*  runnable = static_cast<RunnableIf*>(arg);

  //
  // Block the SIGINT signal in this thread.
  //

  sigset_t  blockedSignals;

  sigemptyset(&blockedSignals);
  sigaddset(&blockedSignals, SIGINT);
  pthread_sigmask(SIG_BLOCK, &blockedSignals, NULL);
  
  //
  // Fire the runnable's run method.
  //

  runnable->Run();

  return NULL;
}
