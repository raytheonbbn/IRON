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
#include "string_utils.h"

#include <list>
#include <string>

using ::iron::Log;
using ::iron::StringUtils;
using ::iron::List;
using std::string;


//============================================================================
class StringUtilsTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(StringUtilsTest);

  CPPUNIT_TEST(TestTokenize);
  CPPUNIT_TEST(TestTokenize_NoTokenFound);
  CPPUNIT_TEST(TestTokenize_TrailingToken);
  CPPUNIT_TEST(TestTokenize_EmptyString);
  CPPUNIT_TEST(TestGetBool);
  CPPUNIT_TEST(TestGetInt);
  CPPUNIT_TEST(TestGetInt64);
  CPPUNIT_TEST(TestGetUint);
  CPPUNIT_TEST(TestGetUint64);
  CPPUNIT_TEST(TestGetFloat);
  CPPUNIT_TEST(TestGetDouble);
  CPPUNIT_TEST(TestGetIpAddr);
  CPPUNIT_TEST(TestIntToString);
  CPPUNIT_TEST(TestDoubleToString);

  CPPUNIT_TEST_SUITE_END();

public:

  //==========================================================================
  void setUp() 
  {

    //
    // Turn down logging levels for the unit testing.
    //

    Log::SetDefaultLevel("F");
  }

  //==========================================================================
  void tearDown()
  {

    //
    // Restore default logging levels so we don't break other unit tests.
    //

    Log::SetDefaultLevel("FEWI");
  }

  //==========================================================================
  void TestTokenize()
  {
    string        str_to_tokenize;
    string        cur_token;
    List<string>  tokens;

    str_to_tokenize = "a=1;b=2;c=3;d=4;e=5";

    StringUtils::Tokenize(str_to_tokenize, ";", tokens);

    CPPUNIT_ASSERT(tokens.size() == 5);

    CPPUNIT_ASSERT(tokens.Peek(cur_token));
    CPPUNIT_ASSERT(cur_token == "a=1");
    CPPUNIT_ASSERT(tokens.Pop(cur_token));
    CPPUNIT_ASSERT(cur_token == "a=1");
    
    CPPUNIT_ASSERT(tokens.Pop(cur_token));
    CPPUNIT_ASSERT(cur_token == "b=2");
    
    CPPUNIT_ASSERT(tokens.Pop(cur_token));
    CPPUNIT_ASSERT(cur_token == "c=3");
    
    CPPUNIT_ASSERT(tokens.Pop(cur_token));
    CPPUNIT_ASSERT(cur_token == "d=4");
    
    CPPUNIT_ASSERT(tokens.Pop(cur_token));
    CPPUNIT_ASSERT(cur_token == "e=5");
  }

  //==========================================================================
  void TestTokenize_NoTokenFound()
  {
    string        str_to_tokenize;
    string        cur_token;
    List<string>  tokens;

    str_to_tokenize = "a=1";

    StringUtils::Tokenize(str_to_tokenize, ";", tokens);

    CPPUNIT_ASSERT(tokens.size() == 1);

    CPPUNIT_ASSERT(tokens.Peek(cur_token));
    CPPUNIT_ASSERT(cur_token == "a=1");
    CPPUNIT_ASSERT(tokens.Pop(cur_token));
    CPPUNIT_ASSERT(cur_token == "a=1");
  }

  //==========================================================================
  void TestTokenize_TrailingToken()
  {
    string        str_to_tokenize;
    string        cur_token;
    List<string>  tokens;

    str_to_tokenize = "a=1;";

    StringUtils::Tokenize(str_to_tokenize, ";", tokens);

    CPPUNIT_ASSERT(tokens.size() == 1);

    CPPUNIT_ASSERT(tokens.Peek(cur_token));
    CPPUNIT_ASSERT(cur_token == "a=1");
    CPPUNIT_ASSERT(tokens.Pop(cur_token));
    CPPUNIT_ASSERT(cur_token == "a=1");
  }

  //==========================================================================
  void TestTokenize_EmptyString()
  {
    string        str_to_tokenize;
    string        cur_token;
    List<string>  tokens;

    str_to_tokenize = "";

    StringUtils::Tokenize(str_to_tokenize, ";", tokens);

    CPPUNIT_ASSERT(tokens.size() == 0);
  }

  //==========================================================================
  void TestGetBool()
  {
    CPPUNIT_ASSERT(StringUtils::GetBool("true") == true);
    CPPUNIT_ASSERT(StringUtils::GetBool("tRUe") == true);
    CPPUNIT_ASSERT(StringUtils::GetBool("1") == true);
    CPPUNIT_ASSERT(StringUtils::GetBool("false") == false);
    CPPUNIT_ASSERT(StringUtils::GetBool("FALse") == false);
    CPPUNIT_ASSERT(StringUtils::GetBool("0") == false);
    CPPUNIT_ASSERT(StringUtils::GetBool("bubba", false) == false);
  }

  //==========================================================================
  void TestGetInt()
  {
    CPPUNIT_ASSERT(StringUtils::GetInt("1234") == 1234);
    CPPUNIT_ASSERT(StringUtils::GetInt("-98765") == -98765);
    CPPUNIT_ASSERT(StringUtils::GetInt("foobar") == INT_MAX);
    CPPUNIT_ASSERT(StringUtils::GetInt("foobar", 7777) == 7777);
  }

  //==========================================================================
  void TestGetInt64()
  {
    CPPUNIT_ASSERT(StringUtils::GetInt64("12345678901") == 12345678901);
    CPPUNIT_ASSERT(StringUtils::GetInt64("-12345678901") ==
                   static_cast<int64_t>(-12345678901));
    CPPUNIT_ASSERT(StringUtils::GetInt64("foobar") == INT64_MAX);
    CPPUNIT_ASSERT(StringUtils::GetInt64("foobar", 77777777777) ==
                   77777777777);
  }

  //==========================================================================
  void TestGetUint()
  {
    CPPUNIT_ASSERT(StringUtils::GetUint("1234") == 1234);
    CPPUNIT_ASSERT(StringUtils::GetUint("-1234") ==
                   static_cast<unsigned int>(-1234));
    CPPUNIT_ASSERT(StringUtils::GetUint("foobar") == UINT_MAX);
    CPPUNIT_ASSERT(StringUtils::GetUint("foobar", 7777) == 7777);
  }

  //==========================================================================
  void TestGetUint64()
  {
    CPPUNIT_ASSERT(StringUtils::GetUint64("12345678901") == 12345678901);
    CPPUNIT_ASSERT(StringUtils::GetUint64("-12345678901") ==
                   static_cast<uint64_t>(-12345678901));
    CPPUNIT_ASSERT(StringUtils::GetUint64("foobar") == UINT64_MAX);
    CPPUNIT_ASSERT(StringUtils::GetUint64("foobar", 77777777777) ==
                   77777777777);
  }

  //==========================================================================
  void TestGetFloat()
  {
    CPPUNIT_ASSERT(StringUtils::GetFloat("7.890") == 7.890f);
    CPPUNIT_ASSERT(StringUtils::GetFloat("0.99845") == 0.99845f);
    CPPUNIT_ASSERT(StringUtils::GetFloat("-9.8765") == -9.8765f);
    CPPUNIT_ASSERT(StringUtils::GetFloat("foobar") == FLT_MAX);
    CPPUNIT_ASSERT(StringUtils::GetFloat("foobar", 77.77) == 77.77f);
  }

  //==========================================================================
  void TestGetDouble()
  {
    CPPUNIT_ASSERT(StringUtils::GetDouble("7.890") == 7.890);
    CPPUNIT_ASSERT(StringUtils::GetDouble("0.99845") == 0.99845);
    CPPUNIT_ASSERT(StringUtils::GetDouble("-9.8765") == -9.8765);
    CPPUNIT_ASSERT(StringUtils::GetDouble("foobar") == DBL_MAX);
    CPPUNIT_ASSERT(StringUtils::GetDouble("foobar", 77.77) == 77.77);
  }

  //==========================================================================
  void TestGetIpAddr()
  {
    CPPUNIT_ASSERT(StringUtils::GetIpAddr("192.168.0.1").address() ==
                   inet_addr("192.168.0.1"));
    CPPUNIT_ASSERT(StringUtils::GetIpAddr("bubba").address() ==
                   inet_addr("0.0.0.0"));
    CPPUNIT_ASSERT(StringUtils::GetIpAddr("bubba", "10.1.1.1").address() ==
                   inet_addr("10.1.1.1"));
  }

  //==========================================================================
  void TestIntToString()
  {
    int  v = 0;

    // Test zero.
    v = 0;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "0");

    // Test positive value.
    v = 123;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "123");

    // Test negative value.
    v = -123;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "-123");

    // Test maximum int value.
    v = 2147483647;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "2147483647");

    // Test minimum int value.
    v = -2147483648;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "-2147483648");
  }

  //==========================================================================
  void TestDoubleToString()
  {
    double  v = 0.;

    // Test zero.
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "0.000000");

    // Test positive value.
    v = 123.456;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "123.456000");

    // Test negative value.
    v = -123.456;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "-123.456000");

  }
  //==========================================================================
  void TestUint64ToString()
  {
    uint64_t v =0;
   
    // Test 0.
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "0");

    // Test a value greater than a uint32.
    v = 9000000000; 
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "9000000000");

    // Test a value smaller than a uint32.
    v = 2147483647;
    CPPUNIT_ASSERT(StringUtils::ToString(v) == "2147483647");
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(StringUtilsTest);
