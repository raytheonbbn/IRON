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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "oracle.h"
#include "config_info.h"
#include "list.h"
#include "log.h"
#include "string_utils.h"
#include "unused.h"
#include "rapidjson/filereadstream.h"
#include <cstdio>
#include <csignal>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>           //getopt

#include <cstdlib>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <limits>
#include <algorithm>

#include <stdint.h>
#include <sys/select.h>
#include <sys/select.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"

using ::rapidjson::Document;
using ::rapidjson::Value;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;
using ::iron::Oracle;
using ::iron::ConfigInfo;
using ::iron::List;
using ::iron::Log;
using ::iron::StringUtils;
using ::std::string;


//============================================================================
// A child class of Oracle for testing that algorithm.
// This class lets a test call protected methods ParseTopology and
// ParsePetition

class OracleTest : public Oracle
{
public:

  /// \brief  The constructor.
  OracleTest();
    
  /// \brief The destructor.
  virtual ~OracleTest();

  /// \brief  Configure Oracle
  /// \param   ci A config info object for the IRON node for this ORACLE.
  /// \return  True if successful.
  bool Configure(const ConfigInfo& ci);

  /// \brief Parse topology contained in BPF update
  void ParseTopology(char *buffer);

  /// \brief parse petition
  Document ParsePetition(char *buffer);
};

OracleTest::OracleTest(){}

OracleTest::~OracleTest(){}

bool OracleTest::Configure(const ConfigInfo& ci)
{
  return Oracle::Configure(ci);
}

void OracleTest::ParseTopology(char *buffer)
{
  Oracle::ParseTopology(buffer);
}

Document OracleTest::ParsePetition(char *buffer)
{
  return Oracle::ParsePetition(buffer);
}

namespace
{
  const char* UNUSED(kClassName) = "OracleTest";
  OracleTest*     oracle              = NULL;
}


///
/// Print out the usage syntax.
///
/// \param  prog_name  The name of the program.
///
void Usage(const std::string& prog_name)
{
  fprintf(stderr,"\n");
  fprintf(stderr,"Usage:\n");
  fprintf(stderr,"  %s [options]\n", prog_name.c_str());
  fprintf(stderr,"\n");
  fprintf(stderr,"Options:\n");
  fprintf(stderr," -c <name>  The fully qualified name of the system\n");
  fprintf(stderr,"             configuration file with control port information..\n");
  fprintf(stderr," -t <name>  The fully qualified name of the topology json file\n");
  fprintf(stderr," -p <name>  The fully qualified name of the petition json file\n");
  fprintf(stderr," -l <name>  The fully qualified name of the log file\n");
  fprintf(stderr," -h         Print out usage information.\n");
  fprintf(stderr,"\n");

  exit(2);
}

int main(int argc, char** argv)
{ 
  extern char*  optarg;
  int           c;
  ConfigInfo    config_info;
  string        config_file = "";
  string        topo_file = "";
  string        petition_file = "";
  string        log_file = "";
  bool          debug = false;

  while ((c = getopt(argc, argv, "c:t:p:l:dh")) != -1)
    {
      switch (c)
	{
	case 'c':
	  config_file = optarg;

	case 't':
	  topo_file = optarg;
	  break;

	case 'p':
	  petition_file = optarg;
	  break;

	case 'l':
	  log_file = optarg;
	  break;

	case 'd':
	  debug = true;
	  break;

	case 'h':
	default:
	  Usage(argv[0]);
	}
    }

  bool status;
  if (strcmp(config_file.c_str(), "") == 0)
    {
      status = config_info.LoadFromFile("oracle.cfg");
    }
  else
    {
      status = config_info.LoadFromFile(config_file);
    }
  if (!status)
    {
      LogE(kClassName, __func__, "Error loading configuration file.\n");

      Usage(argv[0]);
      exit(1);
    }

  if (strcmp(topo_file.c_str(), "") == 0)
    {
      LogE(kClassName, __func__, "Must specify topology file\n");
      Usage(argv[0]);
      exit(1);
    }

  if (strcmp(log_file.c_str(), "") == 0)
    {
      log_file = "output.json";
    }

  //
  // Set logging options based on properties.
  //
  if (debug)
  {
    Log::SetDefaultLevel("FEWIAD");
  }
  else
  {
    Log::SetDefaultLevel(config_info.Get("Log.DefaultLevel", "All", false));
  }

  // Set class level logging.
  std::string class_levels = config_info.Get("Log.ClassLevels", "", false);
  List<string>  tokens;
  StringUtils::Tokenize(class_levels, ";", tokens);
  List<string>::WalkState token_ws;
  token_ws.PrepareForWalk();

  string  token;
  while (tokens.GetNextItem(token_ws, token))
  {
    if (token.find("=") == string::npos)
    {
      continue;
    }

    List<string> token_values;
    StringUtils::Tokenize(token, "=", token_values);

    string  token_name;
    string  token_value;

    token_values.Pop(token_name);
    token_values.Peek(token_value);

    LogI(kClassName, __func__,
         "Setting class %s logging to %s.\n",
         token_name.c_str(), token_value.c_str());
    Log::SetClassLevel(token_name, token_value);
  }

  oracle = new (std::nothrow) OracleTest();
  oracle->Configure(config_info);

  FILE* fp = fopen(topo_file.c_str(), "r");
  unsigned long lSize;
  char * buffer;
  size_t result;

  if (fp==NULL) {
    LogF(kClassName, __func__, "File error opening topology file\n");
  }

  // obtain file size:
  fseek (fp , 0 , SEEK_END);
  lSize = ftell (fp);
  rewind (fp);

  // allocate memory to contain the whole file:
  buffer = (char*) malloc (sizeof(char)*lSize);
  if (buffer == NULL) {
    LogF(kClassName, __func__, "Memory error allocating buffer for topo file\n");
  }

  // copy the file into the buffer:
  result = fread (buffer,1,lSize,fp);
  if (result != lSize) {
    LogF(kClassName, __func__, "Read error on topology file");
  }

  /* the whole file is now loaded in the memory buffer. */

  // terminate
  fclose (fp); 
  buffer[sizeof(char)*lSize] = '\0';
 
  oracle->ParseTopology(buffer);
 
  fp = fopen(petition_file.c_str(), "r");

  if (fp==NULL) {
    LogF(kClassName, __func__, "File error opening petition file");
  }

  // obtain file size:
  fseek (fp , 0 , SEEK_END);
  lSize = ftell (fp);
  rewind (fp);

  // allocate memory to contain the whole file:
  buffer = (char*) malloc (sizeof(char)*lSize+1);
  if (buffer == NULL) {
    LogF(kClassName, __func__, "Memory error for petition file\n");
  }

  // copy the file into the buffer:
  result = fread (buffer,1,lSize,fp);
  if (result != lSize) {
    LogF(kClassName, __func__,"Read error on petition file\n");
  }
  buffer[sizeof(char)*lSize] = '\0';
  /* the whole file is now loaded in the memory buffer. */

  // terminate
  fclose (fp); 
  printf("%s\n", buffer);
  Document response = oracle->ParsePetition(buffer);


  StringBuffer out_buf;
  PrettyWriter<StringBuffer> writer(out_buf);
  response.Accept(writer);
  
  int buf_len = static_cast<int>(out_buf.GetSize());

  FILE *fd;
  fd = fopen(log_file.c_str(), "w");
  fwrite(out_buf.GetString(), 1, buf_len, fd);
  fclose(fd);
  
}



