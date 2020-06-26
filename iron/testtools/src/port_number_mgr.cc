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

#include "port_number_mgr.h"

#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <list>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using ::iron::PortNumberMgr;

using std::fstream;
using std::ifstream;
using std::ios;
using std::list;
using std::ofstream;
using std::string;
using std::vector;

namespace
{
  const char* UNUSED(kClassName)    = "PortNumberMgr";
}

#define BAD_CHUNK -1

const string PortNumberMgr::USED_FILE = "/tmp/iron_test_used_ports.txt";


//============================================================================
PortNumberMgr& PortNumberMgr::GetInstance()
{
  static PortNumberMgr instance;
  return instance;
}

//============================================================================
bool file_exists(string fname)
{
  struct stat stat_data;
  return stat(fname.c_str(), &stat_data) == 0;
}

//============================================================================
PortNumberMgr::PortNumberMgr()
{
  int chunk_to_use;
  if (file_exists(USED_FILE))
  {
    chunk_to_use = get_free_chunk();
  
    if (chunk_to_use == BAD_CHUNK)
    {
      LogF(kClassName, __func__, "Failure reading used port range file\n");
      return; // expects LogF to abort
    }
  }
  else
  {
    chunk_to_use = 0;
    set_file_permissions();
  }

  write_used_chunk(chunk_to_use);
  
  chunk_ = chunk_to_use;
  min_ = MIN_PORT + chunk_to_use * PORTS_PER_CHUNK;
  next_ = min_;
  max_ = min_ + PORTS_PER_CHUNK;
}

//============================================================================
PortNumberMgr::~PortNumberMgr()
{
  remove_used_chunk(chunk_);
}

//============================================================================
void PortNumberMgr::set_file_permissions()
{
  int fd = open(USED_FILE.c_str(), O_RDWR|O_CREAT, 0666); // rw for all
  if (fd == -1)
  {
    LogF(kClassName, __func__,
	 "Unable to set file permissions for %s. Error %d\n",
         USED_FILE.c_str(), errno);
    return;
  }
  else
  {
    fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    close(fd);
  }
}

//============================================================================
int PortNumberMgr::get_free_chunk()
{
  list<int> used_chunks;
  ifstream used_file(USED_FILE.c_str());

  if (!used_file.is_open())
  {
    LogF(kClassName, __func__, "Unable to open port range use file %s\n",
         USED_FILE.c_str());
    return BAD_CHUNK;
  }

  string line;
  while(std::getline(used_file, line))
  {
    int chunk = StringUtils::GetInt(line, BAD_CHUNK);
    if (chunk == BAD_CHUNK)
    {
      LogE(kClassName, __func__,
           "Value in port range use file (%s) is not an integer\n",
	   line.c_str());
    }
    else
    {
      used_chunks.push_back(chunk);
    }
  }

  if (used_file.bad())
  {
    LogF(kClassName, __func__, "Failure reading port range use file\n");
    return BAD_CHUNK;
  }

  int free_chunk = 0;
  used_chunks.sort();
  for (list<int>::const_iterator it = used_chunks.begin();
       it != used_chunks.end(); it++)
  {
    int curr = *it;
    if (free_chunk < curr)
    {
      break;
    }
    free_chunk = curr + 1;
  }
  
  return free_chunk;
}

//============================================================================
void PortNumberMgr::write_used_chunk(int chunk_used)
{
  ofstream used_file(USED_FILE.c_str(), ofstream::out | ofstream::app);

  if (!used_file.is_open())
  {
    LogE(kClassName, __func__,
         "Unable to open port range use file %s, chunk being used is %d\n",
         USED_FILE.c_str(), chunk_used);
    return;
  }

  used_file << StringUtils::ToString(chunk_used) << "\n";
}

//============================================================================
void PortNumberMgr::remove_used_chunk(int chunk_used)
{
  fstream used_file(USED_FILE.c_str(), ios::in);
  set_file_permissions();

  if (!used_file.is_open())
  {
    LogE(kClassName, __func__, "Unable to open port range use file %s "
         "for reading, chunk being removed is %d\n", USED_FILE.c_str(),
         chunk_used);
    return;
  }

  vector<string> chunks;
  string chunk = StringUtils::ToString(chunk_used);
  string line;
  while(std::getline(used_file, line))
  {
    if (chunk != line)
    {
      chunks.push_back(line);
    }
  }
  used_file.close();
  used_file.open(USED_FILE.c_str(), ios::out | ios::trunc);

  if (!used_file.is_open())
  {
    LogE(kClassName, __func__, "Unable to open port range use file %s "
         "for writing, chunk being removed is %d\n", USED_FILE.c_str(),
         chunk_used);
    return;
  }

  for (vector<string>::const_iterator it = chunks.begin(); it != chunks.end();
       it++)
  {
    string curr = *it;
    used_file << curr << "\n";
  }
  used_file.close();
}

//============================================================================
int PortNumberMgr::NextAvailable()
{
  int result = next_;
  if (result >= max_)
  {
    LogE(kClassName, __func__,
         "Reach max port number in chunk %d, restarting at %d\n",
         max_, min_);
    result = min_;
    next_ = min_ + 1;
  }
  else
  {
    next_++;
  }
  return result;
}

//============================================================================
string PortNumberMgr::NextAvailableStr()
{
  return StringUtils::ToString(NextAvailable());
}
