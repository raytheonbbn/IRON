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

///
/// Provides the IRON software with a simple class to streamline the threading
/// of an object.
///

#ifndef IRON_COMMON_THREAD_H
#define IRON_COMMON_THREAD_H


#include "runnable_if.h"

#include <pthread.h>


//
// Definition of function type for execution within a thread.
//
typedef void* runner_t(void*);


namespace iron
{
  ///
  /// A simple class to streamline the threading of an object.
  ///
  /// Threads can be started in one of the following two ways:
  ///
  /// - Implement a static function that conforms to the runner_t signature
  ///   and pass this into the StartThread() method. The following illustrates
  ///   how this can be achieved:
  ///
  /// \code
  ///   //
  ///   // Example of a class that is not a RunnableIf that is to be run in a
  ///   // Thread. 
  ///   //
  ///   class ThreadedClass
  ///   {
  ///     public:
  ///     
  ///     ThreadedClass() { }
  ///
  ///     ~ThreadedClass() { }
  ///
  ///     static void* Run(void* arg)
  ///     {
  ///       for (int i_ = 0; i_ < 10; ++i_)
  ///       {
  ///         LogW("Runnable1", __func__, "Hello World\n");
  ///         sleep(1);
  ///       }
  ///     }
  ///   };
  ///
  ///   int main(int argc, char** argv)
  ///   {
  ///     Thread  thread;
  ///
  ///     // This will start a thread of control.
  ///     thread.StartThread(ThreadedClass::Run);
  ///
  ///     ...
  ///     ...
  ///     ...
  ///   }
  ///
  /// \endcode
  ///   
  /// - Implement a class that is to be threaded that inherits from the
  ///   RunnableIf abstract base class and provide a pointer to the class to
  ///   the StartThread() method.
  ///
  /// \code
  ///   //
  ///   // Example of a RunnableIf class that is to be run in a Thread.
  ///   //
  ///   class RunnableExample : public RunnableIf
  ///   {
  ///     public:
  ///     
  ///     RunnableExample()
  ///     {
  ///       thread.StartThread(this);
  ///     }
  ///
  ///     ~RunnableExample() { }
  ///
  ///     void Run()
  ///     {
  ///       for (int i_ = 0; i_ < 10; ++i_)
  ///       {
  ///         LogW("Runnable1", __func__, "Hello World\n");
  ///         sleep(1);
  ///       }
  ///     }
  ///
  ///   private:
  ///     Thread  thread;
  ///   };
  ///
  ///   int main(int argc, char** argv)
  ///   {
  ///     // This will start a thread of control.
  ///     RunnableExample re;
  ///
  ///     ...
  ///     ...
  ///     ...
  ///   }
  ///
  /// \endcode
  ///
  class Thread
  {
    public:
  
    ///
    /// Default no-arg constructor.
    ///
    Thread();

    ///
    /// Destructor. 
    ///
    virtual ~Thread();
  
    ///
    /// Start a thread. This will launch the thread executing against the
    /// provided static runner_t method with the provided argument.
    ///
    /// \param  fn   The static runner_t method that will be called inside the new
    ///              thread.
    /// \param  arg  The argument passed to the static runner_t method. In most
    ///              cases, this is an object pointer that may be cast back to
    ///              the proper type in the static runner_t method and used.
    ///
    /// \return true if successful, false if an error occurs.
    ///
    bool StartThread(runner_t* fn, void* arg);
  
    ///
    /// Start a thread. This will lauch a thread executing against the
    /// iron::RunnableIf object's run method.
    ///
    /// \param  object  The runnable object to execute.
    ///
    /// \return true if successful, false if an error occurs.
    ///
    bool StartThread(iron::RunnableIf* object);
  
    ///
    /// Stop the thread.
    ///
    /// \return true if successful, false if an error occurs.
    ///
    bool StopThread();
  
    private:

    /// Copy Constructor.
    Thread(const Thread& other);

    /// Copy operator.
    Thread& operator=(const Thread& other);

    ///
    /// The static routine that binds the thread to the abstract run method on
    /// a iron::RunnableIf object.
    ///
    static void* Run(void* arg);

    ///
    /// The thread. Not valid when isRunning is false.
    ///
    pthread_t  thread_;
  
    ///
    /// A flag for recording if the thread is currently running.
    ///
    bool       isRunning_;

  }; // end class Thread

} // namespace iron

#endif // IRON_COMMON_THREAD_H
