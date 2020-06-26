//============================================================================
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
//============================================================================

#include "error_model.h"
#include "jitter_model.h"

#include <cstring>
#include <errno.h>
#include <netdb.h>
#include <popt.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <sstream>

using ::std::cerr;
using ::std::cout;
using ::std::endl;
using ::std::string;
using ::std::stringstream;

namespace
{
  /// The maximum size of message received from the LinkEmClient.
  int  kMaxMsgSize = 2048;

  /// The port number to connect to.
  int  kPortNum = 3456;
}

//============================================================================
/// \brief Establish a connection to a host.
///
/// \param  host  The host to connect to.
///
/// \return The created socket file descriptor or -1 if an error occurs.
int CreateClientSocket(const string& host)
{
  int  sock = -1;

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("socket()");
    return -1;
  }

  struct sockaddr_in  addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(kPortNum);

  struct hostent*  host_lookup = gethostbyname(host.c_str());
  if (host_lookup == NULL)
  {
    perror("gethostbyname()");
    close(sock);
    return -1;
  }
  bcopy(host_lookup->h_addr, &addr.sin_addr, host_lookup->h_length);

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
  {
    perror("connect()");
    close(sock);
    return -1;
  }

  return sock;
}

//============================================================================
/// \brief Send a message to a host.
///
/// \param  host     The host to send the message to.
/// \param  message  The message to send.
///
/// \return True if the message is successfully sent to the host, false
///         otherwise.
bool SendMessage(const string& host, const string& message)
{
  // Create the connection to the host.
  int  sock = CreateClientSocket(host);
  if (sock == -1)
  {
    return false;
  }

  // Send the message.
  if (send(sock, (void*)message.c_str(), message.size(), 0) < 0)
  {
    close(sock);
    return false;
  }

  // Close the connection to the host.
  close(sock);

  return true;
}

//============================================================================
/// \brief Send a message to a host and receive a response back from the
/// host.
///
/// \param  host      The host to send the message to.
/// \param  message   The message to send.
/// \param  response  The response received back from the host.
///
/// \return True if the message is successfully sent to the host and a
///         response is successfully received, false otherwise.
bool SendMessage(string host, string message, string& response)
{
  // Create the connection to the host.
  int  sock = CreateClientSocket(host);
  if (sock == -1)
  {
    return false;
  }

  // Send the message.
  if (send(sock, (void*)message.c_str(), message.size(), 0) < 0)
  {
    close(sock);
    return false;
  }

  // Receive the response.
  size_t  len = kMaxMsgSize;
  char    rcv_buf[kMaxMsgSize];
  memset(rcv_buf, 0, sizeof(rcv_buf));

  if (recv(sock, (void*)rcv_buf, len, 0) < 0)
  {
    close(sock);
    return false;
  }

  response = rcv_buf;

  // Close the connection to the host.
  close(sock);

  return true;
}

//============================================================================
int main(int argc, const char** argv)
{
  int     path                 = 0;
  int     interface            = 0;
  string  subnet               = "";
  char*   subnet_c             = (char*)"\0";
  string  host                 = "";
  char*   host_c               = (char*)"\0";
  int     delay                = -1;
  float   throttle             = -1.0;
  string  model_name           = "";
  char*   model_name_c         = (char*)"\0";
  string  model_param          = "";
  char*   model_param_c        = (char*)"\0";
  string  jitter_model_name    = "";
  char*   jitter_model_name_c  = (char*)"\0";
  string  jitter_model_param   = "";
  char*   jitter_model_param_c = (char*)"\0";
  string  buffer_accounting    = "";
  char*   buffer_accounting_c  = (char*)"\0";
  int     query                = -1;
  int     max_buffer           = -1;
  int     bypass_val           = -1;
  int     op_status            = -1;
  int     stats_rep_int        = -1;
  int     access_link          = -1;

  static struct poptOption options[] = {
    {NULL, 'h', POPT_ARG_STRING, &host_c, 0, "LinkEm host.", "<host>"},
    {NULL, 'p', POPT_ARG_INT, &kPortNum, 0, "LinkEm management listen port.",
     "<port, default=3456>"},
    {NULL, 'w', POPT_ARG_INT, &bypass_val, 0, "TOS bypass value. 0 "
     "disables bypass.", ""},
    {NULL, 'q', POPT_ARG_NONE, &query, 0, "Query the LinkEm state.", ""},
    {NULL, 'S', POPT_ARG_NONE, &op_status, 0, "Query the operation status of "
     "the LinkEm.", ""},
    {NULL, 'R', POPT_ARG_INT, &stats_rep_int, 0, "Periodic statistics "
     "logging interval, in milliseconds. 0 disables periodic logginging.",
     "<interval, in milliseconds>"},
    {NULL, 'A', POPT_ARG_NONE, &access_link, 0, "Access Link modification.",
     ""},
    {NULL, 'P', POPT_ARG_INT, &path, 0, "Identifier of the Path to which the "
     "command applies. This must be between 1 and 15. This is required to "
     "modify the behavior of one of the LinkEm Paths.", "<path>"},
    {NULL, 'I', POPT_ARG_INT, &interface, 0, "Identifier of the interface to "
     "which the command applies. A value of 0 indicates the command applies "
     "to both interfaces for the specified Path Identifier.", "<interface, "
      "default=0>"},
    {NULL, 's', POPT_ARG_STRING, &subnet_c, 0, "Path subnet specifications. "
     "Up to 8 subnets specifications can be provided for each Path. If more "
     "than 1 subnet specification is provided, they must be separated by "
     "commas.", "<ipaddress/prefix length,...>"},
    {NULL, 'd', POPT_ARG_INT, &delay, 0, "Propagation delay, in ms.",
     "<delay>"},
    {NULL, 't', POPT_ARG_FLOAT, &throttle, 0, "Throttle value, in Kbps.",
     "<throttle>"},
    {NULL, 'E', POPT_ARG_STRING, &model_name_c, 0, "The error model name. "
     "One of " ERR_MODEL_PACKET ", " ERR_MODEL_BIT ", or " ERR_MODEL_NONE ".",
     "<error model name>"},
    {NULL, 'e', POPT_ARG_STRING, &model_param_c, 0, "An error model specific "
     "parameter.", "<key>=<val>|<type>"},
    {NULL, 'J', POPT_ARG_STRING, &jitter_model_name_c, 0, "The jitter model "
     "name. One of " JITTER_MODEL_GMM ", " JITTER_MODEL_DMM ", or "
     ERR_MODEL_NONE ".", "<jitter model name>"},
    {NULL, 'j', POPT_ARG_STRING, &jitter_model_param_c, 0, "A jitter model "
     "specific parameter.", "<key>=<val>"},
    {NULL, 'b', POPT_ARG_INT, &max_buffer, 0, "Buffer size, in bytes.",
     ""},
    {NULL, 'B', POPT_ARG_STRING, &buffer_accounting_c, 0, "Buffer accounting "
     "type, either BYTE or PKT.", "<BYTE|PKT>"},
    POPT_AUTOHELP POPT_TABLEEND
  };

  poptContext optCon;

  optCon = poptGetContext(NULL, argc, argv, options, 0);
  poptGetNextOpt(optCon);
  host               = host_c;
  model_name         = model_name_c;
  model_param        = model_param_c;
  jitter_model_name  = jitter_model_name_c;
  jitter_model_param = jitter_model_param_c;
  buffer_accounting  = buffer_accounting_c;
  subnet             = subnet_c;

  if (host == "")
  {
    host = "localhost";
  }

  // Validate the command line options.
  if (((access_link == -1) &&
       ((query < 0) && (bypass_val < 0) && (op_status == -1) &&
        (stats_rep_int == -1) && (delay < 0) && (throttle < 0.0) &&
        (subnet == "") && (model_param == "") && (model_name == "") &&
        (jitter_model_param == "") && (jitter_model_name == "") &&
        (max_buffer < 0) && (buffer_accounting == "")))
      ||
      ((access_link != -1) && (throttle < 0.0)))
  {
    poptPrintUsage(optCon, stderr, 0);
    return 1;
  }
  poptFreeContext(optCon);

  if (op_status == 1)
  {
    string  response;

    if (!SendMessage(host, "StatusCheck", response))
    {
      cerr << "Failed to communicate with LinkEm.\n";
      return -1;
    }

    cout << response << endl;
  }
  else if (query == 1)
  {
    string response;

    if (!SendMessage(host, "Query", response))
    {
      cerr << "Failed to communicate with LinkEm.\n";
      return -1;
    }

    cout << response << endl;
  }
  else if (bypass_val >= 0)
  {
    cout << "Setting bypass TOS value to 0x" <<
      std::hex << (int)(bypass_val & 0xff) << std::dec << endl;
    stringstream  bypass_val_ss;
    bypass_val_ss << "Bypass=" << bypass_val;

    if (!SendMessage(host, bypass_val_ss.str()))
    {
      cerr << "Failed to communicate with LinkEm.\n";
      return -1;
    }
  }
  else if (stats_rep_int >= 0)
  {
    cout << "Setting statistics reporting interval to " << stats_rep_int << endl;

    stringstream  stats_report_int_ss;
    stats_report_int_ss << "StatsReportInt=" << stats_rep_int;

    if (!SendMessage(host, stats_report_int_ss.str()))
    {
      cerr << "Failed to communicate with LinkEm.\n";
      return -1;
    }
  }
  else if (subnet != "")
  {
    if (path == 0)
    {
      cout << "Unable to change the subnet specification for Path 0." << endl;
      return -1;
    }

    // We are changing the subnet specification of a Path.
    stringstream  message;
    message << "Path" << path << "." << interface << ":s=" << subnet << ";";

    cout << "Sending msg: " << message.str() << endl;

    if (!SendMessage(host, message.str()))
    {
      cerr << "Failed to communicate with LinkEm." << endl;
      return -1;
    }
  }
  else if (access_link == 1)
  {
    stringstream  message;
    message << "AccessLink." << interface << ":t=" << throttle << ";";

    cout << "Sending msg: " << message.str() << endl;

    if (!SendMessage(host, message.str()))
    {
      cerr << "Failed to communicate with LinkEm." << endl;
      return -1;
    }
  }
  else
  {
    // We are changing the state of a Path if we get here.
    if (model_name != "" && model_name != ERR_MODEL_PACKET &&
        model_name != ERR_MODEL_BIT && model_name != ERR_MODEL_SBURST &&
        model_name != ERR_MODEL_NONE)
    {
      cerr << "Invalid error model:" << model_name << endl;
      return -1;
    }

    if (buffer_accounting != "" && buffer_accounting != "BYTE" &&
        buffer_accounting != "PKT")
    {
      cerr << "Invalid buffer accounting type: " << buffer_accounting << endl;
      return -1;
    }

    stringstream  message;
    message << "Path" << path << "." << interface << ":";

    if (delay >= 0)
    {
      cout << "Setting delay to " << delay << endl;
      stringstream  delay_ss;
      delay_ss << "d=" << delay << ";";
      message << delay_ss.str();
    }

    if (throttle >= 0.0)
    {
      cout << "Setting throttle to " << throttle << endl;
      stringstream  throttle_ss;
      throttle_ss << "t=" << throttle << ";";
      message << throttle_ss.str();
    }

    if (model_name != "")
    {
      cout << "setting model type: " << model_name << endl;
      stringstream  model_ss;
      model_ss << "E=" << model_name << ";";
      message << model_ss.str();
    }

    if (model_param != "")
    {
      cout << "setting model parameter: " << model_param << endl;
      stringstream  model_param_ss;
      model_param_ss << "e=" << model_param << ";";
      message << model_param_ss.str();
    }

    if (jitter_model_name != "")
    {
      cout << "setting jitter model type: " << jitter_model_name << endl;
      stringstream  jitter_model_ss;
      jitter_model_ss << "J=" << jitter_model_name << ";";
      message << jitter_model_ss.str();
    }

    if (jitter_model_param != "")
    {
      cout << "setting jitter model parameter: " << jitter_model_param <<
        endl;
      stringstream  jitter_model_param_ss;
      jitter_model_param_ss << "j=" << jitter_model_param << ";";
      message << jitter_model_param_ss.str();
    }

    if (max_buffer >= 0)
    {
      cout << "Setting buffer size to " << max_buffer << " bytes" << endl;
      stringstream  max_buffer_ss;
      max_buffer_ss << "b=" << max_buffer << ";";
      message << max_buffer_ss.str();
    }

    if (buffer_accounting != "")
    {
      cout << "Setting buffer accounting to " << buffer_accounting << endl;
      stringstream  buffer_accounting_ss;
      buffer_accounting_ss << "B=" << buffer_accounting << ";";
      message << buffer_accounting_ss.str();
    }

    struct timeval  cur_time;
    gettimeofday(&cur_time, 0);

    cout << "LinkEmClient command " << cur_time.tv_sec << "." <<
      cur_time.tv_usec << ": " << message.str() << endl;

    if (!SendMessage(host, message.str()))
    {
      cerr << "Failed to communicate with LinkEm." << endl;
      return -1;
    }

    gettimeofday(&cur_time, 0);

    cout << "LinkEmClient done " << cur_time.tv_sec << "." <<
      cur_time.tv_usec << endl;
  }
}
