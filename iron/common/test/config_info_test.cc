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

#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>


using ::iron::ConfigInfo;
using ::iron::Log;


//============================================================================
class ConfigInfoTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(ConfigInfoTest);

  CPPUNIT_TEST(TestAddAndGet);
  CPPUNIT_TEST(TestLoadFromFile);
#if 0
  // \todo LoadFromFile calls LogF. Decide if it should return an error
  // instead, and keep the test, convert the test to expect an abort,
  // or drop the test.
  CPPUNIT_TEST(TestLoadFromFileFailure);
#endif
  CPPUNIT_TEST(TestWriteToFile);
  CPPUNIT_TEST(TestToString);
  CPPUNIT_TEST(TestGetBool);
  CPPUNIT_TEST(TestGetInt);
  CPPUNIT_TEST(TestGetUint);
  CPPUNIT_TEST(TestGetUint64);
  CPPUNIT_TEST(TestGetFloat);
  CPPUNIT_TEST(TestGetIpAddr);

  CPPUNIT_TEST_SUITE_END();

public:

  //==========================================================================
  void setUp() 
  {
    //
    // Turn down logging levels for the unit testing.
    //

    Log::SetDefaultLevel("");
  }

  //==========================================================================
  void tearDown()
  {

    //
    // Delete the log files this program generated.
    //

    remove("main_config.txt");
    remove("foo_config.txt");
    remove("config_info_test_xyzzy/bar_config.txt");
    remove("/tmp/config_info_test_xyzzy/fubar_config.txt");
    ::rmdir("../config_info_test_xyzzy");
    ::rmdir("/tmp/config_info_test_xyzzy");
    remove("tmp_config_info_output_1.txt");
    remove("tmp_config_info_output_1.txt.bak");

    //
    // Restore default logging levels so we don't break other unit tests.
    //

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  std::string ProcessConfigFile(const char* fn)
  {
    FILE*        fd = ::fopen(fn, "r");
    char         line[128];
    std::string  result;

    if (fd != NULL)
    {
      while (::fgets(line, sizeof(line), fd) != NULL)
      {
        result.append(line);
      }

      ::fclose(fd);
    }

    return result;
  }

  //==========================================================================
  void GenerateConfigFiles()
  {

    //
    // Generate some configuration files that will be utilized to test out the
    // 'include' directive. Following are the files and their contents for the
    // tests:
    //
    // main_config.txt:
    //
    // #
    // # Test comment.
    // #
    //
    // include foo_config.txt
    //
    // key1 1
    // key2 2
    //
    // 
    // foo_config.txt:
    //
    // include ../config_info_test_xyzzy/bar_config.txt
    // include /tmp/config_info_test_xyzzy/fubar_config.txt
    //
    // foo1 10
    // foo2 20
    //
    // 
    // bar_config.txt
    //
    // bar1 100
    // bar2 200
    //
    // 
    // fubar_config.txt
    //
    // fubar1 1000
    // fubar2 2000
    //

    FILE*  fd = ::fopen("main_config.txt", "w");

    if (fd != NULL)
    {
      ::fprintf(fd, "%s\n", "");
      ::fprintf(fd, "%s\n", "include foo_config.txt");
      ::fprintf(fd, "%s\n", "");
      ::fprintf(fd, "%s %s\n", "key1", "1");
      ::fprintf(fd, "%s %s\n", "key2", "2");
      ::fclose(fd);
    }

    fd = ::fopen("foo_config.txt", "w");
    
    if (fd != NULL)
    {
      ::fprintf(fd, "%s\n", "");
      ::fprintf(fd, "%s\n", "include ../config_info_test_xyzzy/bar_config.txt");
      ::fprintf(fd, "%s\n", "include /tmp/config_info_test_xyzzy/fubar_config.txt");
      ::fprintf(fd, "%s\n", "");
      ::fprintf(fd, "%s %s\n", "foo1", "10");
      ::fprintf(fd, "%s %s\n", "foo2", "20");
      ::fclose(fd);
    }

    struct stat  st;
    
    if (::stat("../config_info_test_xyzzy", &st) == -1)
    {
      
      CPPUNIT_ASSERT(::mkdir("../config_info_test_xyzzy", 0700) == 0);
    }
    
    fd = ::fopen("../config_info_test_xyzzy/bar_config.txt", "w");
    
    if (fd != NULL)
    {
      ::fprintf(fd, "%s\n", "");
      ::fprintf(fd, "%s %s\n", "bar1", "100");
      ::fprintf(fd, "%s %s\n", "bar2", "200");
      ::fclose(fd);
    }

    if (::stat("/tmp/config_info_test_xyzzy", &st) == -1)
    {
      CPPUNIT_ASSERT(::mkdir("/tmp/config_info_test_xyzzy", 0700) == 0);
    }

    fd = ::fopen("/tmp/config_info_test_xyzzy/fubar_config.txt", "w");
    
    if (fd != NULL)
    {
      ::fprintf(fd, "%s\n", "");
      ::fprintf(fd, "%s %s\n", "fubar1", "1000");
      ::fprintf(fd, "%s %s\n", "fubar2", "2000");
      ::fclose(fd);
    }
  }

  //==========================================================================
  void TestAddAndGet()
  {
    ConfigInfo  ci;

    ci.Add("TestAddKey1", "TestAddValue1");

    CPPUNIT_ASSERT(ci.Get("TestAddKey1", "") == "TestAddValue1");
    CPPUNIT_ASSERT(ci.Get("TestAddKey2", "") == "");
  }

  //==========================================================================
  void TestLoadFromFile()
  {

    //
    // Generate some configuration files, create a new ConfigInfo object and
    // load the main configuration file (which contains nested 'include'
    // directives), and test out the accessors from the loaded configuration
    // information.
    //

    GenerateConfigFiles();

    ConfigInfo  ci;
    CPPUNIT_ASSERT(ci.LoadFromFile("main_config.txt") == true);

    //
    // Test getting values that should be part of the configuration.
    //

    CPPUNIT_ASSERT(ci.GetInt("key1", 0) == 1);
    CPPUNIT_ASSERT(ci.GetInt("key2", 0) == 2);
    CPPUNIT_ASSERT(ci.GetInt("foo1", 0) == 10);
    CPPUNIT_ASSERT(ci.GetInt("foo2", 0) == 20);
    CPPUNIT_ASSERT(ci.GetInt("bar1", 0) == 100);
    CPPUNIT_ASSERT(ci.GetInt("bar2", 0) == 200);
    CPPUNIT_ASSERT(ci.GetInt("fubar1", 0) == 1000);
    CPPUNIT_ASSERT(ci.GetInt("fubar2", 0) == 2000);

    //
    // Test values that are not part of the configuration.
    //

    CPPUNIT_ASSERT(ci.GetInt("key3", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("foo3", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("bar3", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("fubar3", 0) == 0);
  }

  //==========================================================================
  void TestLoadFromFileFailure()
  {

    //
    // Generate some configuration files, remove one of the 'included'
    // configuration files, create a new ConfigInfo object and load the main
    // configuration file (which contains nested 'include' directives). The
    // load should fail.
    //

    GenerateConfigFiles();
    CPPUNIT_ASSERT(remove("../config_info_test_xyzzy/bar_config.txt") == 0);

    ConfigInfo  ci;
    CPPUNIT_ASSERT(ci.LoadFromFile("/tmp/main_config.txt") == false);

    //
    // Since the load fails, all lookups should contain default values.
    //

    CPPUNIT_ASSERT(ci.GetInt("key1", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("key2", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("foo1", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("foo2", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("bar1", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("bar2", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("fubar1", 0) == 0);
    CPPUNIT_ASSERT(ci.GetInt("fubar2", 0) == 0);
  }
  
  //==========================================================================
  void TestWriteToFile()
  {
    
    //
    // Add configuration items, write to an output file, and compare the
    // output file to the expected contents of the file.
    //

    ci_.Add("Foo", "Bar");
    ci_.Add("foo.bar", "fubar");
    ci_.WriteToFile("tmp_config_info_output_1.txt");
    CPPUNIT_ASSERT(ProcessConfigFile("tmp_config_info_output_1.txt") ==
                   "Foo Bar\nfoo.bar fubar\n");

    //
    // Write to the file again to test that we don't damage the existing
    // file.
    //

    CPPUNIT_ASSERT(ci_.WriteToFile("tmp_config_info_output_1.txt") == true);
    CPPUNIT_ASSERT(::access("tmp_config_info_output_1.txt.bak", F_OK) == 0);

    //
    // Try one more time. This should fail.
    //
    
    CPPUNIT_ASSERT(ci_.WriteToFile("tmp_config_info_output_1.txt") == false);
  }

  //==========================================================================
  void TestToString()
  {
    ci_.Add("key1", "value1");
    ci_.Add("key2", "value2");
    ci_.Add("key3", "value3");

    CPPUNIT_ASSERT(ci_.ToString() ==
                   "\nkey1 value1\nkey2 value2\nkey3 value3\n");
  }

  //==========================================================================
  void TestGetBool()
  {
    ci_.Add("boolean.1", "true");
    CPPUNIT_ASSERT(ci_.GetBool("boolean.1", true) == true);

    ci_.Add("boolean.2", "TrUe");
    CPPUNIT_ASSERT(ci_.GetBool("boolean.2", true) == true);

    ci_.Add("boolean.3", "1");
    CPPUNIT_ASSERT(ci_.GetBool("boolean.3", true) == true);
    
    ci_.Add("boolean.4", "false");
    CPPUNIT_ASSERT(ci_.GetBool("boolean.4", true) == false);
    
    ci_.Add("boolean.5", "fAlSE");
    CPPUNIT_ASSERT(ci_.GetBool("boolean.5", true) == false);

    ci_.Add("boolean.6", "0");
    CPPUNIT_ASSERT(ci_.GetBool("boolean.6", true) == false);

    CPPUNIT_ASSERT(ci_.GetBool("boolean.7", true) == true);
  }

  //==========================================================================
  void TestGetInt()
  {
    ci_.Add("int1", "1234");
    CPPUNIT_ASSERT(ci_.GetInt("int1", 9999) == 1234);
    
    ci_.Add("int2", "-98765");
    CPPUNIT_ASSERT(ci_.GetInt("int2", 9999) == -98765);

    ci_.Add("int3", "foobar");
    CPPUNIT_ASSERT(ci_.GetInt("int3", 9999) == 9999);

    CPPUNIT_ASSERT(ci_.GetInt("int4", 9999) == 9999);
  }

  //==========================================================================
  void TestGetUint()
  {
    ci_.Add("uint1", "1234");
    CPPUNIT_ASSERT(ci_.GetUint("uint1", 9999) == 1234);

    ci_.Add("uint2", "-1234");
    CPPUNIT_ASSERT(ci_.GetUint("uint2", 9999) ==
                   static_cast<unsigned int>(-1234));
    
    ci_.Add("uint3", "foobar");
    CPPUNIT_ASSERT(ci_.GetUint("uint3", 9999) == 9999);

    CPPUNIT_ASSERT(ci_.GetUint("uint4", 9999) == 9999);
  }

  //==========================================================================
  void TestGetUint64()
  {
    ci_.Add("uint64_1", "10000000000");
    CPPUNIT_ASSERT(ci_.GetUint64("uint64_1", 9999) == 10000000000);

    ci_.Add("uint64_2", "-1234");
    CPPUNIT_ASSERT(ci_.GetUint64("uint64_2", 9999) ==
                   static_cast<uint64_t>(-1234));
    
    ci_.Add("uint64_3", "foobar");
    CPPUNIT_ASSERT(ci_.GetUint64("uint64_3", 9999) == 9999);

    CPPUNIT_ASSERT(ci_.GetUint64("uint64_4", 100000000000) == 100000000000);
  }

  //==========================================================================
  void TestGetFloat()
  {
    ci_.Add("float1", "7.890");
    CPPUNIT_ASSERT(ci_.GetFloat("float1", 0.0) == 7.890f);

    ci_.Add("float2", "0.99845");
    CPPUNIT_ASSERT(ci_.GetFloat("float2", 0.0) == 0.99845f);

    ci_.Add("float3", "-9.8765");
    CPPUNIT_ASSERT(ci_.GetFloat("float3", 0.0) == -9.8765f);

    CPPUNIT_ASSERT(ci_.GetFloat("float4", 0.0) == 0.0f);
  }

  //==========================================================================
  void TestGetIpAddr()
  {
    ci_.Add("ipaddr", "192.168.0.1");
    CPPUNIT_ASSERT(ci_.GetIpAddr("ipaddr", "0.0.0.0").address() ==
                   inet_addr("192.168.0.1"));
  }

private:

  /// The ConfigInfo object utilized for the unit tests.
  ConfigInfo  ci_;
};

CPPUNIT_TEST_SUITE_REGISTRATION(ConfigInfoTest);
