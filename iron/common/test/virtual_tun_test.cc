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

#include "config_info.h"
#include "log.h"
#include "rng.h"
#include "string_utils.h"
#include "virtual_tun.h"
#include "virtual_tun_config.h"

#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

using ::iron::ConfigInfo;
using ::iron::RNG;
using ::iron::StringUtils;
using ::iron::TCP;
using ::iron::VirtualTun;
using ::iron::VirtualTunConfig;
using std::string;

// Test cases for VirtualTun
//
// Send() and Recv() are not tested because they are thin wrappers for system
// calls and it would be overly complicated to make tunnel loop packets back
// to the tunnel.

namespace
{
  const char* kClassName = "VirtualTunTest";
  const string kSomeTunNameFmt = "test_tun_%d";
  const string kSomeLocalIpFmt = "10.98.98.%d";
  const string kSomeNetmask = "255.255.255.0";
  const int kSomeAltTable = 25;
  const int kSomeFwMark = 26;
  const int kMaxIpOctet = 255;
  const int kMaxIpLen = 15;
  const string kIfacePrefixes[] = { "em", "eno", "eth" };
  const int kIfacePrefixeCount =
    sizeof(kIfacePrefixes)/sizeof(kIfacePrefixes[0]);
}

// Iterate over all the interfaces on the machine to find one whose name
// starts with one of the expected prefixes. Use the first interface whose
// name matches.
static string SelectInboundInterface()
{
  struct ifaddrs *ifaddr;
  if (getifaddrs(&ifaddr) != 0)
  {
    LogF(kClassName, __func__, "getifaddrs() failed: %s\n", strerror(errno));
  }

  struct ifaddrs *ifa;
  string result;
  bool done = false;
  for (ifa = ifaddr; ifa != NULL && !done; ifa = ifa->ifa_next)
  {
    struct sockaddr *addr = ifa->ifa_addr;
    if (addr == NULL)
    {
      continue;
    }

    if (addr->sa_family == AF_INET)
    {
      for (int i = 0; i < kIfacePrefixeCount; i++)
      {
        const char *prefix = kIfacePrefixes[i].c_str();
        if (strncmp(prefix, ifa->ifa_name, strlen(prefix)) == 0)
        {
          result = ifa->ifa_name;
          done = true;
          break;
        }
      }
    }
  }
  freeifaddrs(ifaddr);

  CPPUNIT_ASSERT_MESSAGE("No matching interface found", done == true);
  return result;
}

class SimpleVirtualTunConfig : public VirtualTunConfig
{
 public:
  SimpleVirtualTunConfig(string default_name, string default_addr,
                         string default_broadcast) :
    VirtualTunConfig(TCP, false, false, default_name, default_addr,
                     kSomeNetmask, default_broadcast,
                     SelectInboundInterface(),
                     kSomeAltTable, kSomeFwMark) { }
};

class VirtualTunTester : public VirtualTun
{
 public:
  VirtualTunTester(VirtualTunConfig& config) :
    VirtualTun(config) { }

  int GetFd() { return fd_; }
};

//============================================================================
class VirtualTunTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(VirtualTunTest);

  bool haveRoot = (geteuid() == 0);
  bool doRootTests = true;

  // If we are not root, skip the tests.
  if (!haveRoot)
  {
    doRootTests = false;
    LogW(kClassName, __func__, "Virtual tunnel test cases will be skipped.\n");
  }

  CPPUNIT_TEST(IsOpen_NewInstance_NotOpen);
  if (doRootTests)
  {
    CPPUNIT_TEST(Open_ConfiguredInstance_OpenSuccess);
    CPPUNIT_TEST(IsOpen_OpenTun_Open);
  }
  CPPUNIT_TEST(Close_ClosingNonOpen_NotOpen);
  if (doRootTests)
  {
    CPPUNIT_TEST(Close_ClosingOpen_NotOpen);
    CPPUNIT_TEST(Close_ClosingOpenTwice_NotOpen);
  }
  CPPUNIT_TEST(InSet_NonOpenEmptySet_NotInSet);
  CPPUNIT_TEST(InSet_NonOpenNonEmptySet_NotInSet);
  if (doRootTests)
  {
    CPPUNIT_TEST(InSet_OpenEmptySet_NotInSet);
    CPPUNIT_TEST(InSet_OpenNonEmptySet_NotInSet);
    CPPUNIT_TEST(InSet_OpenFdInSet_InSet);
    CPPUNIT_TEST(InSet_OpenFdInSetWithOthers_InSet);
  }

  CPPUNIT_TEST_SUITE_END();

 private:

  VirtualTunTester*  tun_;
  VirtualTunConfig*  config_;

 public:

  //==========================================================================
  void setUp()
  {
    iron::Log::SetDefaultLevel("FEW");
    tun_ = NULL;

    RNG rng;
    string name = StringUtils::FormatString(NAME_MAX - 1,
                                            kSomeTunNameFmt.c_str(),
                                            rng.GetInt(8000));
    string addr = StringUtils::FormatString(kMaxIpLen, kSomeLocalIpFmt.c_str(),
                                            rng.GetInt(kMaxIpOctet - 1));
    string bcast = StringUtils::FormatString(kMaxIpLen, kSomeLocalIpFmt.c_str(),
                                             rng.GetInt(kMaxIpOctet - 1));

    config_ = new SimpleVirtualTunConfig(name, addr, bcast);
  }

  //==========================================================================
  void tearDown()
  {
    if (tun_ != NULL) 
    {
      delete tun_;
      tun_ = NULL;
    }

    if (config_ != NULL) 
    {
      delete config_;
      config_ = NULL;
    }

    iron::Log::SetDefaultLevel("FE");
  }

  //==========================================================================
  void Open_ConfiguredInstance_OpenSuccess()
  {
    ConfigInfo ci;
    config_->Initialize(ci);
    tun_ = new VirtualTunTester(*config_);

    CPPUNIT_ASSERT(tun_->Open() == true);
  }

  //==========================================================================
  void IsOpen_NewInstance_NotOpen()
  {
    tun_ = new VirtualTunTester(*config_);

    CPPUNIT_ASSERT(tun_->IsOpen() == false);
  }

  //==========================================================================
  void IsOpen_OpenTun_Open()
  {
    tun_ = MakeOpenTun();

    CPPUNIT_ASSERT(tun_->IsOpen() == true);
  }

  //==========================================================================
  void Close_ClosingOpen_NotOpen()
  {
    tun_ = MakeOpenTun();

    tun_->Close();

    CPPUNIT_ASSERT(tun_->IsOpen() == false);
  }

  //==========================================================================
  void Close_ClosingOpenTwice_NotOpen()
  {
    tun_ = MakeOpenTun();

    tun_->Close();
    tun_->Close();

    CPPUNIT_ASSERT(tun_->IsOpen() == false);
  }

  //==========================================================================
  void Close_ClosingNonOpen_NotOpen()
  {
    tun_ = new VirtualTunTester(*config_);

    tun_->Close();

    CPPUNIT_ASSERT(tun_->IsOpen() == false);
  }

  //==========================================================================
  void InSet_NonOpenEmptySet_NotInSet()
  {
    tun_ = new VirtualTunTester(*config_);

    fd_set set;
    FD_ZERO(&set);

    CPPUNIT_ASSERT(tun_->InSet(&set) == false);
  }

  //==========================================================================
  void InSet_NonOpenNonEmptySet_NotInSet()
  {
    tun_ = new VirtualTunTester(*config_);

    fd_set set;
    FD_ZERO(&set);

    CPPUNIT_ASSERT(tun_->InSet(&set) == false);
  }

  //==========================================================================
  void InSet_OpenEmptySet_NotInSet()
  {
    tun_ = MakeOpenTun();

    fd_set set;
    FD_ZERO(&set);

    CPPUNIT_ASSERT(tun_->InSet(&set) == false);
  }

  //==========================================================================
  void InSet_OpenNonEmptySet_NotInSet()
  {
    tun_ = MakeOpenTun();

    fd_set set;
    FD_ZERO(&set);
    AddSomeFds(&set);

    CPPUNIT_ASSERT(tun_->InSet(&set) == false);
  }

  //==========================================================================
  void InSet_OpenFdInSet_InSet()
  {
    tun_ = MakeOpenTun();

    fd_set set;
    FD_ZERO(&set);
    FD_SET(tun_->GetFd(), &set);

    CPPUNIT_ASSERT(tun_->InSet(&set) == true);
  }

  //==========================================================================
  void InSet_OpenFdInSetWithOthers_InSet()
  {
    tun_ = MakeOpenTun();

    fd_set set;
    FD_ZERO(&set);
    FD_SET(tun_->GetFd(), &set);
    AddSomeFds(&set);

    CPPUNIT_ASSERT(tun_->InSet(&set) == true);
  }

  //==========================================================================
  VirtualTunTester* MakeOpenTun()
  {
    ConfigInfo ci;
    config_->Initialize(ci);

    VirtualTunTester* tun = new VirtualTunTester(*config_);
    tun->Open();

    return tun;
  }

  //==========================================================================
  void AddSomeFds(fd_set* set)
  {
    // Some high numbers that are unlikely to be used for actual fd
    // but less than FD_SETSIZE
    FD_SET(1001, set);
    FD_SET(1002, set);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(VirtualTunTest);
