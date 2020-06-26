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
#ifndef Thread_h
#define Thread_h


#include <pthread.h>

class Runnable; // Forward declaration.

/**
 * Definition of function type for execution within a thread.
 */
typedef void* runner_t(void*);


/**
 * \class Thread
 *
 * A simple class to streamline the threading of an object.
 *
 * A helper class that needs to operate in a thread should not inherit from
 * this class.  Instead, the higher level entity should create the helper
 * class object, then create a Thread object and call startThread() on it
 * specifying a static runner_t method in the helper class and the helper
 * class object as arguments.  In the static runner_t method, the helper class
 * object appears as an argument which can be cast to a helper class object
 * and used as needed.
 *
 * If a helper class needs more than one thread, then it is free to implement
 * more than one static runner_t method.  In this case, the higher level
 * entity must create multiple Thread objects, one for each thread it must
 * start.
 *
 * This class is not thread-safe.  Each instance of this class is intended to
 * be used by a single thread.
 *
 */
class Thread
{
public:
  
  Thread();
  virtual ~Thread();
  
  /**
   * Start a thread.  This will launch the thread executing against the
   * provided static runner_t method with the provided argument.
   *
   * @param fn  The static runner_t method that will be called inside the new
   *            thread.
   * @param arg The argument passed to the static runner_t method.  In most
   *            cases, this is an object pointer that may be cast back to the
   *            proper type in the static runner_t method and used.
   *
   * @return Returns true on success, or false on error.
   */
  bool startThread(runner_t* fn, void* arg);
  
  /**
   * Start a thread.  This will lauch a thread executing against the
   * Runnable object's run method.
   *
   * @param object The runnable object to execute.
   */
  bool startThread(Runnable* object);
  
  /**
   * Stop the thread.
   *
   * @return Returns true on success, or false on error.
   */
  bool stopThread();
  
private:
  /**
   * The static routine that binds the thread to the
   * abstract run method on a Runnable object.
   */
  static void* threadRunBinding(void* arg);

protected:
  
  /**
   * A flag for recording if the thread is currently running.
   */
  bool       isRunning;

  /**
   * The thread.  Not valid when isRunning is false.
   */
  pthread_t  thread;
  
}; // end class Thread


/**
 * \class Runnable
 *
 * A simple class to enable objects to overload a run method and then
 * simply start an instance of the class within the thead by calling
 * thread->startThread(object).
 *
 * It remains the responsbility of the author to judiciously place
 * thread_testcancel calls within the run at the appropriate
 * locations.
 *
 * @author Brian DeCleene
 */
class Runnable
{
public:
  virtual void run() = 0;
};

#endif
