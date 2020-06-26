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

#include <getopt.h>

#include <cstring>
#include <ostream>
#include <fstream>
#include <string>

#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/XmlOutputter.h>

#include "log.h"

using std::ofstream;
using std::string;

namespace
{
  const char* kClassName = "tcp_proxy_cppunit_main";
}

//============================================================================
int main(int argc, char** argv)
{
  string                         xmlfile;
  CppUnit::TextUi::TestRunner    runner;
  CppUnit::TestFactoryRegistry&  registry =
    CppUnit::TestFactoryRegistry::getRegistry();

  while (1)
  {
    int  c;
    int  option_index = 0;
    static struct option long_options[] = {
      {"xmlfile", required_argument, 0,  0 },
      {0,         0,                 0,  0 }
    };

    c = getopt_long(argc, argv, "x:", long_options, &option_index);

    if (c == -1)
    {
      break;
    }

    switch (c)
    {
    case 0:
      if (strncmp("xmlfile", long_options[option_index].name,
                  strlen(long_options[option_index].name)) == 0)
      {
        xmlfile = string(optarg);
        LogI(kClassName, __func__, "Will output results to %s \n",
             xmlfile.c_str());
      }
      else
      {
        LogW(kClassName, __func__, "Unrecognized long option: %s \n",
             long_options[option_index].name);
      }
      break;

    case 'x':
      xmlfile = string(optarg);
      break;

    default:
      LogW(kClassName, __func__, "Unrecognized short option: %d \n", c);
    }
  }

  // Disable config logging for tests.
  iron::Log::SetConfigLoggingActive(false);

  runner.addTest(registry.makeTest());

  ofstream  outfile;
  if (!xmlfile.empty())
  {
    outfile.open(xmlfile.c_str());
    runner.setOutputter(new CppUnit::XmlOutputter(&runner.result(), outfile));
  }

  bool was_successful = runner.run("", false);

  if (!xmlfile.empty())
  {
    outfile.close();
  }

  if (was_successful)
  {
    return 0;
  }
  else
  {
    return 1;
  }
}
