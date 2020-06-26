/* IRON: iron_headers */
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
#include <stdio.h>
#include <string.h>
#ifndef _WINDOWS
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#endif

#include "Thread.h"
#include "ZLog.h"


static const char  cn[] = "Thread";


//============================================================================
Thread::Thread() : isRunning(false)
{
  return;
}

//============================================================================
Thread::~Thread()
{
  if (isRunning)
  {
    stopThread();
  }
}

//============================================================================
bool Thread::startThread(runner_t* fn, void* arg)
{
  static const char  mn[] = "startThread";
  
  pthread_attr_t  attr;
  
  if (fn == NULL)
  {
    zlogE(cn, mn, ("Null function pointer specified.\n"));
    return(false);
  }
  
  if (isRunning)
  {
    zlogW(cn, mn, ("Thread is already running.\n"));
    return(true);
  }
  
#ifdef LOUD
  zlogD(cn, mn, ("Starting thread.\n"));
#endif
  
  /*
   * Create a detached thread.
   */
  
  // Fixup to keep valgrind happy

  memset(&attr,0,sizeof(attr));

  if (pthread_attr_init(&attr) != 0)
  {
    zlogE(cn, mn, ("pthread_attr_init error.\n"));
    return(false);
  }
  
  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
  {
    perror("pthread_attr_setdetachedstate");
    zlogE(cn, mn, ("pthread_attr_setdetachedstate error.\n"));
    pthread_attr_destroy(&attr);
    return(false);
  }
  
  // Fixup to keep valgrind happy

  memset(&thread,0,sizeof(thread));

  if (pthread_create(&thread, &attr, fn, arg) != 0)
  {
    perror("pthread_create");
    zlogE(cn, mn, ("pthread_create error.\n"));
    pthread_attr_destroy(&attr);
    return(false);
  }
  
#ifdef LOUD
  zlogD(cn, mn, ("Thread created.\n"));
#endif
  
  if (pthread_attr_destroy(&attr) != 0)
  {
    perror("pthread_attr_destroy");
    zlogE(cn, mn, ("pthread_attr_destroy error.\n"));
  }
  
  isRunning = true;
  
  return(true);
}

//============================================================================
bool Thread::stopThread()
{
#ifdef LOUD
  static const char  mn[] = "stopThread";
#endif
  
  int              rv = 0;
  struct timespec  sleepTime;
  struct timespec  remTime;
  
  if (isRunning)
  {
#ifdef LOUD
    zlogD(cn, mn, ("Stopping thread.\n"));
#endif
    
    isRunning = false;
    
    rv = pthread_cancel(thread);
    
    /*
     * Sleep for a small amount of time to let the thread terminate.
     */
    
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
    
#ifdef LOUD
    zlogD(cn, mn, ("Thread stopped.\n"));
#endif
  }
  
  return(((rv == 0) ? true : false));
}

//============================================================================
void* Thread::threadRunBinding(void* arg) 
{
  Runnable* object = (Runnable*)arg;

  //
  // Block the SIGINT signal in this thread.
  //
  sigset_t blockedSignals;
  sigemptyset(&blockedSignals);
  sigaddset(&blockedSignals, SIGINT);
  pthread_sigmask(SIG_BLOCK, &blockedSignals, NULL);
  
  //
  // Fire the runnable's run method.
  //
  object->run();

  return NULL;
}

//============================================================================
bool Thread::startThread(Runnable* object)
{
  startThread(Thread::threadRunBinding,object);
  return true;
};
