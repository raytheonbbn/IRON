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

#include "inter_process_comm.h"

#include <string>

using ::iron::InterProcessComm;
using ::std::string;


#define MAX_BUF_LEN  2048


//============================================================================
class InterProcessCommTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(InterProcessCommTest);

  CPPUNIT_TEST(TestBlocking);
  CPPUNIT_TEST(TestNonBlocking);

  CPPUNIT_TEST_SUITE_END();

private:

  InterProcessComm*  endpoint1_;
  InterProcessComm*  endpoint2_;
  uint8_t*           send_buf_;
  uint8_t*           recv_buf_;
  string             path1_;
  string             path2_;

public:

  //==========================================================================
  void setUp()
  {
    endpoint1_ = new InterProcessComm();
    endpoint2_ = new InterProcessComm();
    send_buf_  = new uint8_t[MAX_BUF_LEN];
    recv_buf_  = new uint8_t[MAX_BUF_LEN];

    // Set the pathnames.
    path1_ = "./IRON_IPC_TEST_1";
    path2_ = "./IRON_IPC_TEST_2";
  }

  //==========================================================================
  void tearDown()
  {
    endpoint1_->Close();
    endpoint2_->Close();
    delete endpoint1_;
    delete endpoint2_;
    delete [] send_buf_;
    delete [] recv_buf_;
    endpoint1_ = NULL;
    endpoint2_ = NULL;
    send_buf_  = NULL;
    recv_buf_  = NULL;
  }

  //==========================================================================
  void SetupEndpoints()
  {
    CPPUNIT_ASSERT(endpoint1_->IsOpen()              == false);
    CPPUNIT_ASSERT(endpoint2_->IsOpen()              == false);
    CPPUNIT_ASSERT(endpoint1_->IsConnected()         == false);
    CPPUNIT_ASSERT(endpoint2_->IsConnected()         == false);
    CPPUNIT_ASSERT(endpoint1_->GetLocalPath()        == "");
    CPPUNIT_ASSERT(endpoint2_->GetLocalPath()        == "");
    CPPUNIT_ASSERT(endpoint1_->GetRemotePath()       == "");
    CPPUNIT_ASSERT(endpoint2_->GetRemotePath()       == "");
    CPPUNIT_ASSERT(endpoint1_->GetSocketDescriptor() == -1);
    CPPUNIT_ASSERT(endpoint2_->GetSocketDescriptor() == -1);

    CPPUNIT_ASSERT(endpoint1_->Open(path1_) == true);
    CPPUNIT_ASSERT(endpoint2_->Open(path2_) == true);

    CPPUNIT_ASSERT(endpoint1_->IsOpen()              == true);
    CPPUNIT_ASSERT(endpoint2_->IsOpen()              == true);
    CPPUNIT_ASSERT(endpoint1_->IsConnected()         == false);
    CPPUNIT_ASSERT(endpoint2_->IsConnected()         == false);
    CPPUNIT_ASSERT(endpoint1_->GetLocalPath()        == path1_);
    CPPUNIT_ASSERT(endpoint2_->GetLocalPath()        == path2_);
    CPPUNIT_ASSERT(endpoint1_->GetRemotePath()       == "");
    CPPUNIT_ASSERT(endpoint2_->GetRemotePath()       == "");
    CPPUNIT_ASSERT(endpoint1_->GetSocketDescriptor() >= 0);
    CPPUNIT_ASSERT(endpoint2_->GetSocketDescriptor() >= 0);

    CPPUNIT_ASSERT(endpoint1_->Connect(path2_) == true);
    CPPUNIT_ASSERT(endpoint2_->Connect(path1_) == true);

    CPPUNIT_ASSERT(endpoint1_->IsOpen()              == true);
    CPPUNIT_ASSERT(endpoint2_->IsOpen()              == true);
    CPPUNIT_ASSERT(endpoint1_->IsConnected()         == true);
    CPPUNIT_ASSERT(endpoint2_->IsConnected()         == true);
    CPPUNIT_ASSERT(endpoint1_->GetLocalPath()        == path1_);
    CPPUNIT_ASSERT(endpoint2_->GetLocalPath()        == path2_);
    CPPUNIT_ASSERT(endpoint1_->GetRemotePath()       == path2_);
    CPPUNIT_ASSERT(endpoint2_->GetRemotePath()       == path1_);
    CPPUNIT_ASSERT(endpoint1_->GetSocketDescriptor() >= 0);
    CPPUNIT_ASSERT(endpoint2_->GetSocketDescriptor() >= 0);
  }

  //==========================================================================
  void RandomizeSendBuffer(size_t len)
  {
    // Fill the send buffer with random bytes.
    for (size_t i = 0; i < len; ++i)
    {
      send_buf_[i] = static_cast<uint8_t>(random() % 256);
    }
  }

  //==========================================================================
  void SendMessage(InterProcessComm* ep, size_t len)
  {
    CPPUNIT_ASSERT(ep->SendMessage(send_buf_, len, true) == true);
  }

  //==========================================================================
  void RecvMessage(InterProcessComm* ep, size_t len, bool blocking)
  {
    size_t rv = ep->ReceiveMessage(recv_buf_, MAX_BUF_LEN, blocking);

    CPPUNIT_ASSERT(rv == len);

    for (size_t i = 0; i < len; ++i)
    {
      CPPUNIT_ASSERT(recv_buf_[i] == send_buf_[i]);
    }
  }

  //==========================================================================
  void Poll(InterProcessComm* ep)
  {
    size_t rv = ep->ReceiveMessage(recv_buf_, MAX_BUF_LEN, false);

    CPPUNIT_ASSERT(rv == 0);
  }

  //==========================================================================
  void RunTest(bool blocking)
  {
    SetupEndpoints();

    for (size_t len = 1; len <= MAX_BUF_LEN; len += 3)
    {
      RandomizeSendBuffer(len);
      SendMessage(endpoint1_, len);
      RecvMessage(endpoint2_, len, blocking);

      RandomizeSendBuffer(len);
      SendMessage(endpoint2_, len);
      RecvMessage(endpoint1_, len, blocking);

      if (!blocking)
      {
        Poll(endpoint1_);
        Poll(endpoint2_);
      }
    }
  }

  //==========================================================================
  void TestBlocking()
  {
    RunTest(true);
  }

  //==========================================================================
  void TestNonBlocking()
  {
    RunTest(false);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(InterProcessCommTest);
