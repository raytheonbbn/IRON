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

#include "ipv4_address.h"
#include "iron_constants.h"
#include "remote_control.h"
#include "string_utils.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "list.h"
#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <iostream>
#include <string>
#include <unistd.h>

using ::iron::List;
using ::iron::Log;
using ::rapidjson::Value;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;
using ::std::string;

namespace
{
  /// The default remote control BPF port number.
  const uint16_t  kDefaultAmpCtlPort              = 3140;

  const char* UNUSED(kClassName)                  = "GNATCTL";

}

void Usage(const std::string& prog_name)
{
  fprintf(stderr,"\n");
  fprintf(stderr,"Usage:\n");
  fprintf(stderr,"  %s [options]\n", prog_name.c_str());
  fprintf(stderr,"\n");
  fprintf(stderr,"Options:\n");
  fprintf(stderr," -S <IP:port> The source IP address and port of the flow.\n");
  fprintf(stderr," -D <IP:port> The dest IP address and port of the flow.\n");
  fprintf(stderr," -A <IP> The IP address of the ingress IRON node.\n");
  fprintf(stderr," -P <udp/tcp> The type of flow (udp or tcp).\n");
  fprintf(stderr," -V Service definition to be added.\n");
  fprintf(stderr," -R remove flow with the specified tuple.\n");
  fprintf(stderr," -f Flag to indicate if the flow is a file transfer with deadline.\n");
  fprintf(stderr," -s The size of the file, if it is a file transfer, in bytes.\n");
  fprintf(stderr," -d The deadline of the filetransfer, if it is a file transfer.\n");
  fprintf(stderr," -p The priority of the flow. \n");
  fprintf(stderr," -u The utility function to be assigned to the flow.\n");

  exit(2);
}

//=============================================================================
int main(int argc, char** argv)
{
  string source_info             = "";
  string dest_info               = "";
  string amp_addr_str            = "";
  bool   is_file_transfer        = false;
  bool   is_file_transfer_update = false;
  string file_size_bytes         = "0";
  string transfer_deadline_sec   = "0";
  string priority                = "0";
  string utility_type            = "";
  string protocol                = "";
  string service_defn            = "";
  bool   delete_flow             = false;

  int c=0;
  while ((c = getopt(argc, argv, "S:D:A:P:V:RUfs:d:p:u:h")) != -1)
  {
    switch (c)
    {
      case 'S':
        source_info             = optarg;
        break;
      case 'D':
        dest_info               = optarg;
        break;
      case 'A':
        amp_addr_str            = optarg;
        break;
      case 'P':
        protocol                = optarg;
        break;
      case 'R':
        delete_flow             = true;
        break;
      case 'V':
        service_defn            = optarg;
        break;
      case 'U':
        is_file_transfer_update = true;
        break;
      case 'f':
        is_file_transfer        = true;
        break;
      case 's':
        file_size_bytes         = optarg;
        break;
      case 'd':
        transfer_deadline_sec   = optarg;
        break;
      case 'p':
        priority                = optarg;
        break;
      case 'u':
        utility_type            = optarg;
        break;
      default:
        Usage(argv[0]);
    }
  }

  string message = "";

  if (amp_addr_str == "")
  {
    LogE(kClassName, __func__, "AMP IP address is required.\n");
    Usage(argv[0]);
  }

  if (service_defn != "")
  {
    string search = ";";
    string replace= ".";
    iron::StringUtils::Replace(service_defn, search, replace);
    search = ":";
    replace= "..";
    iron::StringUtils::Replace(service_defn, search, replace);
    message = "parameter;svc_defn;svc_defn;" + service_defn;
  }
  else if (source_info == "")
  {
    LogE(kClassName, __func__, "Source info is required.\n");
    Usage(argv[0]);
  }
  else if (dest_info == "")
  {
    LogE(kClassName, __func__, "Destination info is required.\n");
    Usage(argv[0]);
  }
  else if (delete_flow)
  {
    message = "parameter;del_flow;flow_tuple;" + source_info +
              " -> " + dest_info;
  }
  else if (is_file_transfer)
  {
    if (file_size_bytes == "0")
    {
      LogE(kClassName, __func__, "File transfers must have a size.\n");
      return 1;
    }
    if (transfer_deadline_sec == "0")
    {
      LogE(kClassName, __func__, "File transfers must have a deadline.\n");
      return 1;
    }
    if (priority == "0")
    {
      LogE(kClassName, __func__, "File transfers must have a priority.\n");
      return 1;
    }
    message = "parameter;ft_params;flow_tuple;" + source_info +
                         " -> " + dest_info + ";deadline;" +
                         transfer_deadline_sec + ";size;" + file_size_bytes +
                         ";priority;" + priority;
  }
  else if (is_file_transfer_update)
  {
    message = "parameter;ft_params;flow_tuple;" + source_info +
                         " -> " + dest_info + ";deadline;" +
                         transfer_deadline_sec + ";size;" + file_size_bytes +
                         ";priority;" + priority;
  }
  else if (utility_type != "")
  {
    if (protocol == "")
    {
      LogE(kClassName, __func__,
        "Utility function configuration requires the protocol type.\n");
      exit(2);
    }
    message = "parameter;utility_fn;flow_tuple;" + source_info +
                         " -> " + dest_info + ";utility;" + utility_type;
    if (priority != "0")
    {
      message = message + ";priority;" + priority;
    }
  }
  else if (priority != "0")
  {
    if (protocol == "")
    {
      LogE(kClassName, __func__,
        "Utility function configuration requires the protocol type.\n");
      exit(2);
    }
    message =     message = "parameter;priority;flow_tuple;" + source_info +
                         " -> " + dest_info + ";priority;" + priority + ";protocol;" + protocol;
  }
  else
  {
    LogE(kClassName, __func__, "Unsupported configuration request.\n");
    Usage(argv[0]);
  }

  // Connect to the AMP.
  iron::RemoteControlClient rc_client_;
  struct sockaddr_in  amp_addr;
  ::memset(&amp_addr, 0, sizeof(amp_addr));
  amp_addr.sin_family       = AF_INET;
  amp_addr.sin_addr.s_addr  = inet_addr(amp_addr_str.c_str());
  amp_addr.sin_port         = htons(kDefaultAmpCtlPort);
  uint32_t amp_ep           = 0;

  string target = "amp";
  if (protocol == "udp")
  {
    target = "udp_proxy";
  }
  else if (protocol == "tcp")
  {
    target = "tcp_proxy";
  }

  while (amp_ep ==0)
  {
    LogD(kClassName, __func__, "Connecting to AMP\n");
    amp_ep = rc_client_.Connect(amp_addr);
    if (amp_ep != 0)
    {
      LogD(kClassName, __func__, "Connected to AMP\n");
      break;
    }
    sleep(2);
  }

  rc_client_.SendSetMessage(amp_ep, target, message);

  exit(0);
}
