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

#include <cstdio>
#include <cstring>

using ::iron::Log;


//============================================================================
class LogTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(LogTest);

  CPPUNIT_TEST(TestDefaultLevels);
  CPPUNIT_TEST(TestLogging);
  CPPUNIT_TEST(TestClassLogging);
  CPPUNIT_TEST(TestLogToFile_ConfigActiveDefaultLevelAll_ConfigLogInFile);
  CPPUNIT_TEST(TestLogToFile_ConfigActiveDefaultLevelNone_ConfigLogInFile);
  CPPUNIT_TEST(TestLogToFile_ConfigDeactiveDefaultLevelAll_ConfigLogNotInFile);
  CPPUNIT_TEST(TestLogToFile_ConfigDeactiveDefaultLevelNone_ConfigLogNotInFile);

  CPPUNIT_TEST(TestWouldLog_ConfigActiveDefaultLevelAll_AllLog);
  CPPUNIT_TEST(TestWouldLog_ConfigActiveDefaultLevelNone_OnlyConfig);
  CPPUNIT_TEST(TestWouldLog_ConfigDeactiveDefaultLevelAll_AllButConfigLog);
  CPPUNIT_TEST(TestWouldLog_ConfigDeactiveDefaultLevelNone_NoneLog);

  CPPUNIT_TEST_SUITE_END();

public:

  //==========================================================================
  void setUp()
  {
  }

  //==========================================================================
  void tearDown()
  {
    Log::SetDefaultLevel("FEW");

    Log::Destroy();

    // Delete the log files this program generated.
    remove("tmp_log_output_01.txt");
    remove("tmp_log_output_02.txt");
    remove("tmp_log_output_03.txt");
    remove("tmp_log_output_04.txt");
    remove("tmp_log_output_05.txt");
    remove("tmp_log_output_06.txt");
    remove("tmp_log_output_07.txt");
    remove("tmp_log_output_08.txt");
    remove("tmp_log_output_09.txt");
    remove("tmp_log_output_10.txt");
    remove("tmp_log_output_11.txt");
    remove("tmp_log_output_12.txt");

    Log::SetDefaultLevel("FEWI");
    Log::SetConfigLoggingActive(false);
  }

  //==========================================================================
#define COMMON_CLASS_NAME "Class"
  void LogToFile(const char* fn)
  {
    LogToFile(fn, COMMON_CLASS_NAME);
  }

  void LogToFile(const char* fn, const char* cn)
  {
    // Log to each of the log levels in a new file, and flush when done.
    Log::SetOutputFile(fn, false);

    LogE(cn, "Method", "Error %d %s\n", 1234, "foobar");
    LogW(cn, "Method", "Warning %d %s\n", 1234, "foobar");
    LogI(cn, "Method", "Info %d %s\n", 1234, "foobar");
    LogA(cn, "Method", "Analysis %d %s\n", 1234, "foobar");
    LogD(cn, "Method", "Debug %d %s\n", 1234, "foobar");
    LogC(cn, "Method", "Config %d %s\n", 1234, "foobar");

    Log::Flush();
  }

  //==========================================================================
  std::string ProcessLogFile(const char* fn)
  {
    // Examine a log file to see what levels it contains.
    char          line[128];
    std::string   result;
    FILE         *fd = fopen(fn, "r");

    if (fd != NULL)
    {
      while (fgets(line, sizeof(line), fd) != NULL)
      {
        if (strstr(line, " Fatal ") != NULL)
        {
          result.append("F");
        }

        if (strstr(line, " Error ") != NULL)
        {
          result.append("E");
        }

        if (strstr(line, " Warning ") != NULL)
        {
          result.append("W");
        }

        if (strstr(line, " Info ") != NULL)
        {
          result.append("I");
        }

        if (strstr(line, " Analysis ") != NULL)
        {
          result.append("A");
        }

        if (strstr(line, " Debug ") != NULL)
        {
          result.append("D");
        }

        if (strstr(line, " Config ") != NULL)
        {
          result.append("C");
        }
      }

      fclose(fd);
    }

    return result;
  }

  //==========================================================================
  void TestDefaultLevels()
  {
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "FEWI");

    Log::SetDefaultLevel("");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "");

    Log::SetDefaultLevel("ALL");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "FEWIAD");

    Log::SetDefaultLevel("all");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "FEWIAD");

    Log::SetDefaultLevel("F");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "F");

    Log::SetDefaultLevel("E");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "E");

    Log::SetDefaultLevel("W");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "W");

    Log::SetDefaultLevel("I");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "I");

    Log::SetDefaultLevel("A");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "A");

    Log::SetDefaultLevel("D");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "D");

    Log::SetDefaultLevel("f");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "F");

    Log::SetDefaultLevel("e");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "E");

    Log::SetDefaultLevel("w");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "W");

    Log::SetDefaultLevel("i");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "I");

    Log::SetDefaultLevel("a");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "A");

    Log::SetDefaultLevel("d");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "D");

    Log::SetDefaultLevel("fwE");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "FEW");

    Log::SetDefaultLevel("aID");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "IAD");

    Log::SetDefaultLevel("fWAd");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "FWAD");

    Log::SetDefaultLevel("daiwef");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "FEWIAD");

    Log::SetDefaultLevel("DAIWEF");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "FEWIAD");

    Log::SetDefaultLevel("BchzqpSM");
    CPPUNIT_ASSERT(Log::GetDefaultLevel() == "");
  }

  //==========================================================================
  void TestLogging()
  {
    // Some tests are only possible when compiling with DEBUG set.
#ifdef DEBUG
    Log::SetDefaultLevel("ALL");
    LogToFile("tmp_log_output_01.txt");
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_01.txt") == "EWIAD");
#endif

    Log::SetDefaultLevel("FEW");
    LogToFile("tmp_log_output_02.txt");
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_02.txt") == "EW");

#ifdef DEBUG
    Log::SetDefaultLevel("DIA");
    LogToFile("tmp_log_output_03.txt");
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_03.txt") == "IAD");

    Log::SetDefaultLevel("df");
    LogToFile("tmp_log_output_04.txt");
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_04.txt") == "D");
#endif
  }

  //==========================================================================
#define UNIQUE_CN "UniqueClassName"
#define NOT_USED_CN "Missing"
  void TestClassLogging()
  {
    // Some tests are only possible when compiling with DEBUG set.
#ifdef DEBUG
    Log::SetDefaultLevel("ALL");
    Log::SetClassLevel(NOT_USED_CN, "FEW");
    LogToFile("tmp_log_output_05.txt");
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_05.txt") == "EWIAD");

    Log::SetClassLevel(UNIQUE_CN, "FEW");
    LogToFile("tmp_log_output_06.txt", UNIQUE_CN);
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_06.txt") == "EW");

    Log::SetClassLevel(UNIQUE_CN, "DIA");
    LogToFile("tmp_log_output_07.txt", UNIQUE_CN);
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_07.txt") == "IAD");

    Log::SetClassLevel(UNIQUE_CN, "df");
    LogToFile("tmp_log_output_08.txt", UNIQUE_CN);
    CPPUNIT_ASSERT(ProcessLogFile("tmp_log_output_08.txt") == "D");
#endif
  }

  //==========================================================================
  void TestLogToFile_ConfigActiveDefaultLevelAll_ConfigLogInFile()
  {
    Log::SetConfigLoggingActive(true);
    Log::SetDefaultLevel("ALL");

    LogToFile("tmp_log_output_09.txt");

    std::string result = ProcessLogFile("tmp_log_output_09.txt");
#ifdef DEBUG
    CPPUNIT_ASSERT_MESSAGE(result, result == "EWIADC");
#else
    CPPUNIT_ASSERT_MESSAGE(result, result == "EWIAC");
#endif
  }

  //==========================================================================
  void TestLogToFile_ConfigActiveDefaultLevelNone_ConfigLogInFile()
  {
    Log::SetConfigLoggingActive(true);
    Log::SetDefaultLevel("None");

    LogToFile("tmp_log_output_10.txt");

    std::string result = ProcessLogFile("tmp_log_output_10.txt");
    CPPUNIT_ASSERT_MESSAGE(result, result == "C");
  }

  //==========================================================================
  void TestLogToFile_ConfigDeactiveDefaultLevelAll_ConfigLogNotInFile()
  {
    Log::SetConfigLoggingActive(false);
    Log::SetDefaultLevel("ALL");

    LogToFile("tmp_log_output_11.txt");

    std::string result = ProcessLogFile("tmp_log_output_11.txt");
#ifdef DEBUG
    CPPUNIT_ASSERT_MESSAGE(result, result == "EWIAD");
#else
    CPPUNIT_ASSERT_MESSAGE(result, result == "EWIA");
#endif
  }

  //==========================================================================
  void TestLogToFile_ConfigDeactiveDefaultLevelNone_ConfigLogNotInFile()
  {
    Log::SetConfigLoggingActive(false);
    Log::SetDefaultLevel("None");

    LogToFile("tmp_log_output_12.txt");

    std::string result = ProcessLogFile("tmp_log_output_12.txt");
    CPPUNIT_ASSERT_MESSAGE(result, result == "");
  }

  //==========================================================================
  void TestWouldLog_ConfigActiveDefaultLevelAll_AllLog()
  {
    Log::SetConfigLoggingActive(true);
    Log::SetDefaultLevel("ALL");

    CPPUNIT_ASSERT(WouldLogF(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogE(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogW(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogI(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogA(COMMON_CLASS_NAME));

    // debug depends on build type
#ifdef DEBUG
    CPPUNIT_ASSERT(WouldLogD(COMMON_CLASS_NAME));
#else
    CPPUNIT_ASSERT(!WouldLogD(COMMON_CLASS_NAME));
#endif

    CPPUNIT_ASSERT(WouldLogC(COMMON_CLASS_NAME));
  }

  //==========================================================================
  void TestWouldLog_ConfigActiveDefaultLevelNone_OnlyConfig()
  {
    Log::SetConfigLoggingActive(true);
    Log::SetDefaultLevel("NONE");

    CPPUNIT_ASSERT(!WouldLogF(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogE(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogW(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogI(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogA(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogD(COMMON_CLASS_NAME));

    CPPUNIT_ASSERT(WouldLogC(COMMON_CLASS_NAME));
  }

  //==========================================================================
  void TestWouldLog_ConfigDeactiveDefaultLevelAll_AllButConfigLog()
  {
    Log::SetConfigLoggingActive(false);
    Log::SetDefaultLevel("ALL");

    CPPUNIT_ASSERT(WouldLogF(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogE(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogW(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogI(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(WouldLogA(COMMON_CLASS_NAME));

    // debug depends on build type
#ifdef DEBUG
    CPPUNIT_ASSERT(WouldLogD(COMMON_CLASS_NAME));
#else
    CPPUNIT_ASSERT(!WouldLogD(COMMON_CLASS_NAME));
#endif

    CPPUNIT_ASSERT(!WouldLogC(COMMON_CLASS_NAME));
  }

  //==========================================================================
  void TestWouldLog_ConfigDeactiveDefaultLevelNone_NoneLog()
  {
    Log::SetConfigLoggingActive(false);
    Log::SetDefaultLevel("NONE");

    CPPUNIT_ASSERT(!WouldLogF(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogE(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogW(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogI(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogA(COMMON_CLASS_NAME));
    CPPUNIT_ASSERT(!WouldLogD(COMMON_CLASS_NAME));

    CPPUNIT_ASSERT(!WouldLogC(COMMON_CLASS_NAME));
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(LogTest);
