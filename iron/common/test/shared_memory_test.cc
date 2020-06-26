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

#include "shared_memory.h"
#include "random_shared_memory.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>


using ::iron::SharedMemory;


//============================================================================
class SharedMemoryTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(SharedMemoryTest);

  CPPUNIT_TEST(TestShm);

  CPPUNIT_TEST_SUITE_END();

 private:

  static const size_t  kBufSize  = 32;

  SharedMemory*  src_;
  SharedMemory*  dst_;
  uint8_t*       send_buf_;
  uint8_t*       recv_buf_;
  key_t          shm_key_;
  char           shm_name_[kRandomShmNameSize];

 public:

  //==========================================================================
  void setUp()
  {
    src_      = new SharedMemory();
    dst_      = new SharedMemory();
    send_buf_ = new uint8_t[kBufSize];
    recv_buf_ = new uint8_t[kBufSize];

    CPPUNIT_ASSERT(src_ != NULL);
    CPPUNIT_ASSERT(dst_ != NULL);
    CPPUNIT_ASSERT(send_buf_ != NULL);
    CPPUNIT_ASSERT(recv_buf_ != NULL);

    // Set the shared memory key and name.
    iron::RandomShmNameAndKey("shmunittest", shm_name_,
                              kRandomShmNameSize, shm_key_);
  }

  //==========================================================================
  void tearDown()
  {
    delete src_;
    delete dst_;
    delete [] send_buf_;
    delete [] recv_buf_;

    src_      = NULL;
    dst_      = NULL;
    send_buf_ = NULL;
    recv_buf_ = NULL;
  }

  //==========================================================================
  void SetRandomSourceData()
  {
    // Set random data in the send buffer.
    for (size_t i = 0; i < kBufSize; ++i)
    {
      send_buf_[i] = static_cast<uint8_t>(rand() % (UINT8_MAX + 1));
    }
  }

  //==========================================================================
  void ValidateDestinationData(size_t offset)
  {
    // Validate the destination data matches the source data.
    for (size_t i = offset; i < kBufSize; ++i)
    {
      CPPUNIT_ASSERT(recv_buf_[i] == send_buf_[i]);
    }
  }

  //==========================================================================
  void TestShm()
  {
    // Set up a shared memory segment.
    CPPUNIT_ASSERT(src_->Create(shm_key_, shm_name_, kBufSize) == true);
    CPPUNIT_ASSERT(dst_->Attach(shm_key_, shm_name_, kBufSize) == true);

    // Make sure that the shared memory segment gets mapped into two different
    // areas in local memory.
    CPPUNIT_ASSERT(src_->GetShmPtr() != dst_->GetShmPtr());

    // Pass source data through shared memory and validate using the default
    // offset.
    SetRandomSourceData();
    CPPUNIT_ASSERT(src_->CopyToShm(send_buf_, kBufSize)   == true);
    CPPUNIT_ASSERT(dst_->CopyFromShm(recv_buf_, kBufSize) == true);
    ValidateDestinationData(0);

    // Pass source data through shared memory and validate using different
    // offsets.
    for (size_t offset = 0; offset < kBufSize; ++offset)
    {
      size_t  len = (kBufSize - offset);

      SetRandomSourceData();
      CPPUNIT_ASSERT(src_->CopyToShm(&(send_buf_[offset]), len,
                                     offset)   == true);
      CPPUNIT_ASSERT(dst_->CopyFromShm(&(recv_buf_[offset]), len,
                                       offset) == true);
      ValidateDestinationData(offset);
    }

    // Pass source data through shared memory and validate using manual APIs.
    SetRandomSourceData();
    CPPUNIT_ASSERT(src_->Lock() == true);
    memcpy(src_->GetShmPtr(), send_buf_, kBufSize);
    CPPUNIT_ASSERT(src_->Unlock() == true);
    CPPUNIT_ASSERT(dst_->Lock() == true);
    memcpy(recv_buf_, dst_->GetShmPtr(), kBufSize);
    CPPUNIT_ASSERT(dst_->Unlock() == true);
    ValidateDestinationData(0);

    // Clean up.
    src_->Destroy();
    dst_->Detach();
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(SharedMemoryTest);
