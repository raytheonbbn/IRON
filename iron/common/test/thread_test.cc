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
#include "runnable_if.h"
#include "thread.h"

#include <cstdio>
#include <cstring>
#include <unistd.h>


using ::iron::Log;
using ::iron::RunnableIf;
using ::iron::Thread;


//
// Example of a RunnableIf class that is to be run in a Thread.
//
class Runnable1 : public RunnableIf
{
public:
  Runnable1() { }

  ~Runnable1() { }

  void Run()
  {
    for (int i = 0; i < 10; ++i)
    {
      LogW("Runnable1", __func__, "Hello World\n");
      usleep(10000);
    }
  }
};

//
// Example of a class that is not a RunnableIf that is to be run in a Thread.
//
class ThreadedClass
{
public:
  ThreadedClass() { }

  ~ThreadedClass() { }

  static void* Run(void* arg)
  {
    for (int i = 0; i < 5; ++i)
    {
      LogW("ThreadedClass", __func__, "Goodbye World\n");
      usleep(20000);
    }

    return NULL;
  }
};

//============================================================================
class ThreadTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(ThreadTest);

  CPPUNIT_TEST(TestStartThreadWithRunnable);
  CPPUNIT_TEST(TestStopThread);
  CPPUNIT_TEST(TestMultipleThreads);  

  CPPUNIT_TEST_SUITE_END();

public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FEW");
  }

  //==========================================================================
  void tearDown()
  {
    Log::Destroy();

    //
    // Delete the log files this program generated.
    // 

    remove("tmp_thread_output_1.txt");
    remove("tmp_thread_output_2.txt");
    remove("tmp_thread_output_3.txt");

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  int ProcessLogFile(const char* fn, const char* search_string)
  {
    int    result = 0;
    FILE*  fd     = fopen(fn, "r");
    
    char   line[128];

    //
    // Examine a log file to see how many times the provided search string
    // appears. 
    //

    if (fd != NULL)
    {
      while (fgets(line, sizeof(line), fd) != NULL)
      {
        if (strstr(line, search_string) != NULL)
        {
          ++result;
        }
      }
      
      fclose(fd);
    }

    return result;
  }

  //==========================================================================
  void TestStartThreadWithRunnable()
  {
    Thread     thread1;
    Runnable1  runnable1;

    Log::SetOutputFile("tmp_thread_output_1.txt", false);

    thread1.StartThread(&runnable1);

    //
    // Try to start the thread again.
    //

    thread1.StartThread(&runnable1);

    //
    // This is where joining a thread might be useful. After spending a bit of
    // time trying to get it to work, ran into some issues (a return code of 2
    // which is "No such file or directory"). This return code isn't in the
    // pthread_join man page. Due to time constraints and the thought that we
    // won't need to join a thread in general, don't implement join. Instead,
    // just sleep to ensure that the thread for this test has time to run
    // before it goes out of scope and is stopped.
    //

    usleep(110000);

    Log::Flush();

    CPPUNIT_ASSERT(ProcessLogFile("tmp_thread_output_1.txt",
                                  "Hello World") == 10);

    CPPUNIT_ASSERT(ProcessLogFile("tmp_thread_output_1.txt",
                                  "Thread is already running") == 1);
  }

  //==========================================================================
  void TestStopThread()
  {
    Thread     thread1;
    Runnable1  runnable1;
    
    Log::SetOutputFile("tmp_thread_output_2.txt", false);

    thread1.StartThread(&runnable1);

    //
    // This is where joining a thread might be useful. After spending a bit of
    // time trying to get it to work, ran into some issues (a return code of 2
    // which is "No such file or directory"). This return code isn't in the
    // pthread_join man page. Due to time constraints and the thought that we
    // won't need to join a thread in general, don't implement join. Instead,
    // just sleep to ensure that the thread for this test has time to run
    // before it goes out of scope and is stopped.
    //

    usleep(30000);

    thread1.StopThread();

    usleep(20000);

    //
    // Try to stop the thread again.
    //

    thread1.StopThread();

    Log::Flush();

    CPPUNIT_ASSERT(ProcessLogFile("tmp_thread_output_2.txt",
                                  "Hello World") < 10);

    CPPUNIT_ASSERT(ProcessLogFile("tmp_thread_output_2.txt",
                                  "Thread is not running") == 1);
  }

  //==========================================================================
  void TestMultipleThreads()
  {
    Thread     thread1;
    Thread     thread2;
    Runnable1  runnable1;

    Log::SetOutputFile("tmp_thread_output_3.txt", false);

    //
    // Start one thread as a RunnableIf and the other using the runner_t
    // method.
    //

    thread1.StartThread(&runnable1);
    thread2.StartThread(ThreadedClass::Run, NULL);

    //
    // This is where joining a thread might be useful. After spending a bit of
    // time trying to get it to work, ran into some issues (a return code of 2
    // which is "No such file or directory"). This return code isn't in the
    // pthread_join man page. Due to time constraints and the thought that we
    // won't need to join a thread in general, don't implement join. Instead,
    // just sleep to ensure that the threads for this test have time to run
    // before they go out of scope and are stopped.
    //

    usleep(100000);

    Log::Flush();

    CPPUNIT_ASSERT(ProcessLogFile("tmp_thread_output_3.txt",
                                  "Hello World") == 10);

    CPPUNIT_ASSERT(ProcessLogFile("tmp_thread_output_3.txt",
                                  "Goodbye World") == 5);
  }
}; // end class ThreadTest

CPPUNIT_TEST_SUITE_REGISTRATION(ThreadTest);
