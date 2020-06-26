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

#include "scoped_lock.h"

#include "log.h"
#include <cstring>


using ::iron::ScopedLock;
using ::iron::Log;


//============================================================================
class ScopedLockTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(ScopedLockTest);

#if 0
  CPPUNIT_TEST(TestUninitializedMutex);
#endif
  CPPUNIT_TEST(TestGrabUnlockedMutex);
  CPPUNIT_TEST(TestGrabLockedMutex);

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
    
    remove("tmp_scoped_lock_output.txt");

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  int ProcessLogFile(const char* fn)
  {
    int    result = 0;
    FILE*  fd     = fopen(fn, "r");

    char   line[128];

    //
    // Examine a log file and count number of Errors.
    //
    
    if (fd != NULL)
    {
      while (fgets(line, sizeof(line), fd) != NULL)
      {
        if (strstr(line, " Error ") != NULL)
        {
          result++;
        }
      }

      fclose(fd);
    }

    return result;
  }

  //==========================================================================
  void TestUninitializedMutex()
  {
    Log::SetOutputFile("tmp_scoped_lock_output.txt", false);

    ::memset(&mutex_, -1, sizeof(mutex_));
    
    {
      ScopedLock sl_(&mutex_);
    }

    Log::Flush();
    
    CPPUNIT_ASSERT(ProcessLogFile("tmp_scoped_lock_output.txt") == 2);
  }

  //==========================================================================
  void TestGrabUnlockedMutex()
  {
    int  ret;
    
    //
    // Attempt to grab the mutex when we know it is unlocked.
    //

    pthread_mutex_init(&mutex_, NULL);

    ret = pthread_mutex_trylock(&mutex_);
    CPPUNIT_ASSERT(ret == 0);

    if (ret == 0)
    {
      pthread_mutex_unlock(&mutex_);
    }
  }

  //==========================================================================
  void TestGrabLockedMutex()
  {
    ScopedLock sl_(&mutex_);

    //
    // Attempt to grab the mutex when we know it is locked by the ScopedLock
    // object.
    //

    pthread_mutex_init(&mutex_, NULL);
    
    CPPUNIT_ASSERT(pthread_mutex_trylock(&mutex_) == 0);
  }

  // The mutex that will be used for the unit tests.
  pthread_mutex_t  mutex_;
};

CPPUNIT_TEST_SUITE_REGISTRATION(ScopedLockTest);
