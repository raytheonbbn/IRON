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

#include "fifo.h"
#include "log.h"

#include "rng.h"

#include <cstdlib>
#include <inttypes.h>
#include <sys/select.h>


using ::iron::Fifo;
using ::iron::Log;
using ::iron::RNG;

class FifoTester : public Fifo
{
 public:
  FifoTester(const char* path_name) :
    Fifo(path_name) { }

  int GetFd() { return fifo_fd_; }
};

//============================================================================
class FifoTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(FifoTest);

  CPPUNIT_TEST(TestFifo);

  CPPUNIT_TEST_SUITE_END();

 private:

  static const size_t  kNameSize = 64;

  FifoTester*  src_;
  FifoTester*  dst_;

 public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("FEW");

    // Set the FIFO path name.
    RNG rng;
    int32_t num = rng.GetInt(10000);

    char   path_name[kNameSize];
    snprintf(path_name, kNameSize, "/tmp/fifounittest%" PRId32, num);
    src_ = new FifoTester(path_name);
    dst_ = new FifoTester(path_name);

    CPPUNIT_ASSERT(src_ != NULL);
    CPPUNIT_ASSERT(dst_ != NULL);

  }

  //==========================================================================
  void tearDown()
  {
    delete src_;
    delete dst_;

    src_ = NULL;
    dst_ = NULL;

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestFifo()
  {
    uint8_t  tmp_buf = 0;

    // Make sure nothing is open.
    CPPUNIT_ASSERT(src_->IsOpen() == false);
    CPPUNIT_ASSERT(dst_->IsOpen() == false);

    // Set up a fifo.
    CPPUNIT_ASSERT(src_->OpenSender() == false);
    CPPUNIT_ASSERT(src_->IsOpen() == false);

    CPPUNIT_ASSERT(dst_->OpenReceiver() == true);
    CPPUNIT_ASSERT(dst_->IsOpen() == true);

    CPPUNIT_ASSERT(src_->OpenSender() == true);
    // The following receive is needed for UNIX sockets to connect if they are
    // being used inside of the Fifo class.
    CPPUNIT_ASSERT(dst_->Recv(&tmp_buf, sizeof(tmp_buf)) == 0);
    CPPUNIT_ASSERT(src_->IsOpen() == true);

    // Pass messages over the FIFO, validating each transfer.
    for (int msg = 0; msg <= UINT8_MAX; ++msg)
    {
      // Send the one-byte message.
      uint8_t  msg_buf = static_cast<uint8_t>(msg);

      CPPUNIT_ASSERT(src_->Send(&msg_buf, sizeof(msg_buf)) == true);

      // Prepare for the select() call.
      int     max_fd = 0;
      fd_set  read_fds;

      FD_ZERO(&read_fds);

      if ((msg % 2) == 0)
      {
        int  fifo_fd = dst_->GetFd();
        CPPUNIT_ASSERT(fifo_fd >= 0);
        FD_SET(fifo_fd, &read_fds);
        max_fd = fifo_fd;
      }
      else
      {
        dst_->AddFileDescriptors(max_fd, read_fds);
      }

      struct timeval  tv;

      tv.tv_sec  = 1;
      tv.tv_usec = 0;

      // Wait until a message is ready to be received.
      int  rv = select((max_fd + 1), &read_fds, NULL, NULL, &tv);

      // Verify that a message is ready to be received.
      CPPUNIT_ASSERT(rv > 0);
      CPPUNIT_ASSERT(FD_ISSET(dst_->GetFd(), &read_fds) > 0);

      // Receive the one-byte message and validate it.
      uint8_t  buf = 0;

      CPPUNIT_ASSERT(dst_->Recv(&buf, sizeof(buf)) == 1);
      CPPUNIT_ASSERT(buf == static_cast<uint8_t>(msg));
    }

    // Pass multiple messages over the FIFO and receive them all at once.
    int  num_msg = 8;

    for (int msg = 0; msg < num_msg; ++msg)
    {
      uint8_t  msg_buf = static_cast<uint8_t>(msg);

      CPPUNIT_ASSERT(src_->Send(&msg_buf, sizeof(msg_buf)) == true);
    }

    uint8_t  rcv_buf[16];
    size_t   rv = dst_->Recv(rcv_buf, sizeof(rcv_buf));

    CPPUNIT_ASSERT(rv == static_cast<size_t>(num_msg));

    for (int msg = 0; msg < num_msg; ++msg)
    {
      CPPUNIT_ASSERT(rcv_buf[msg] == static_cast<uint8_t>(msg));
    }
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(FifoTest);
