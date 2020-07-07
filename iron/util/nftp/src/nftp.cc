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

// This is a modified version of the NORM examples normFileRecv.cpp and
// normFileSend.cpp distributed with the NORM source version 1.5.8.

#include "nftp.h"
#include "nftp_defaults.h"
#include "nftp_config_info.h"
#include "stream_info.h"

#include "protoDefs.h"
#include "protoDebug.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>


#define MSG_LEN_MAX  1024

const char  DIR_DELIMITER = '/';

using ::std::map;
using ::std::string;

//============================================================================
Nftp::Nftp(NftpNetIf* net_if)
    : net_if_(net_if),
      mcast_if_name_(DEFAULT_MCAST_IF_NAME),
      mcast_addr_str_(DEFAULT_MCAST_ADDR_STR),
      mcast_dst_port_(DEFAULT_MCAST_DST_PORT),
      src_port_(),
      sndr_(DEFAULT_SNDR),
      src_addr_(0),
      file_path_(),
      enable_cc_(DEFAULT_ENABLE_CC),
      enable_fc_(DEFAULT_ENABLE_FC),
      rcvr_(DEFAULT_RCVR),
      output_dir_(),
      output_file_name_(),
      fq_output_file_name_(),
      src_addr_str_(),
      use_temp_files_(false)
{
}

//============================================================================
Nftp::~Nftp()
{
  // Nothing to destroy.
}

//============================================================================
bool Nftp::Initialize(ConfigInfo& config_info)
{
  mcast_if_name_    = config_info.Get("McastIfName", DEFAULT_MCAST_IF_NAME);
  mcast_addr_str_   = config_info.Get("McastAddrStr", DEFAULT_MCAST_ADDR_STR);
  mcast_dst_port_   = config_info.GetInt("McastDstPort",
                                         DEFAULT_MCAST_DST_PORT);
  src_port_         = config_info.GetInt("SrcPort", 0);
  sndr_             = config_info.GetBool("Sndr", DEFAULT_SNDR);
  file_path_        = config_info.Get("FilePath", "");
  enable_cc_        = config_info.GetBool("EnableCc", DEFAULT_ENABLE_CC);
  enable_fc_        = config_info.GetBool("EnableFc", DEFAULT_ENABLE_FC);
  rcvr_             = config_info.GetBool("Rcvr", DEFAULT_RCVR);
  output_dir_       = config_info.Get("OutputDir", "./");
  output_file_name_ = config_info.Get("OutputFileName", "");
  src_addr_str_     = config_info.Get("SrcAddrStr", "");
  use_temp_files_   = config_info.GetBool("UseTempFiles", false);

  // Get the destination information. Each specified destination includes the
  // destination host name and the destination path for the file transfer.
  size_t  num_dsts  = config_info.GetInt("NumDsts", 0);
  bool    first_dst = true;
  string  dst_list  = "";
  for (size_t i = 0; i < num_dsts; ++i)
  {
    char  key[64];
    snprintf(key, 64, "Dst%zd", i);
    string  dst_str = config_info.Get(key, "");
    if (dst_str.length() != 0)
    {
      // The format of a destination is as follow:
      //
      //   dst_name:[dst_path]
      size_t  colon_pos;
      if ((colon_pos = dst_str.find_first_of(':')) == string::npos)
      {
        fprintf(stderr, "[Nftp::Initialize] Error in destination: %s\n",
                dst_str.c_str());
        return false;
      }

      DstInfo  dst_info;
      dst_info.name = dst_str.substr(0, colon_pos);
      dst_info.path = dst_str.substr(colon_pos + 1,
                                     dst_str.length() - colon_pos);

      fprintf(stdout, "[Nftp::Initialize] dst: %s, dst path: %s\n",
              dst_info.name.c_str(), dst_info.path.c_str());

      // Get the destination IP Address, in network byte order.
      struct hostent*  host_ent = gethostbyname(dst_info.name.c_str());
      if (host_ent == NULL)
      {
        fprintf(stderr, "[Nftp::Initialize] Error getting IP Address for host "
                "%s\n", dst_info.name.c_str());
        return false;
      }
      dst_info.ip_addr_nbo = (*(struct in_addr*)host_ent->h_addr).s_addr;

      dsts_.push_back(dst_info);

      if (!first_dst)
      {
        dst_list += ",";
      }

      dst_list += dst_info.name;
      first_dst = false;
    }
  }

  if (sndr_ && rcvr_)
  {
    fprintf(stderr, "[Nftp::Initialize] Cannot be both sender and "
            "receiver.\n");
    return false;
  }

  if (!sndr_ && !rcvr_)
  {
    fprintf(stderr, "[Nftp::Initialize] Must be a sender or a receiver.\n");
    return false;
  }

  if (rcvr_ && (src_port_ == 0))
  {
    fprintf(stderr, "[Nftp::Initialize] A source port for the file transfer "
            "MUST be provided.\n");
    return false;
  }

  if (sndr_ && (num_dsts == 0))
  {
    fprintf(stderr, "[Nftp::Initialize] Must provide at least one "
            "destination as a sender.\n");
    return false;
  }

  // Get the source address. This is the IP Address of the multicast
  // interface.
  int           fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq  ifr;

  // Type of address to retrieve, IPv4 IP address.
  ifr.ifr_addr.sa_family = AF_INET;

  // Copy the interface name in the ifreq structure
  strncpy(ifr.ifr_name, mcast_if_name_.c_str(), IFNAMSIZ-1);

  ioctl(fd, SIOCGIFADDR, &ifr);
  src_addr_ = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

  string  saddr = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);

  close(fd);

  // We will add general information about the file transfer to the
  // configuration information and then we'll configure the network
  // interface. This general information includes the following:
  //
  // - FileXfer.SrcAddr
  // - FileXfer.SrcPort
  // - FileXfer.DstAddr
  // - FileXfer.DstPort
  // - FileXfer.DstList
  config_info.Add("FileXfer.Saddr", saddr);
  char  src_port_str[64];
  snprintf(src_port_str, 64, "%d", src_port_);
  config_info.Add("FileXfer.Sport", src_port_str);
  config_info.Add("FileXfer.Daddr", mcast_addr_str_);
  char  dst_port_str[64];
  snprintf(dst_port_str, 64, "%d", mcast_dst_port_);
  config_info.Add("FileXfer.Dport", dst_port_str);

  // If there is a user-provided destination list use it. Otherwise, use the
  // locally generated destination list.
  string  cfg_dst_list = config_info.Get("FileXfer.DstList", "");
  if (cfg_dst_list.length() == 0)
  {
    if (!dst_list.empty())
    {
      config_info.Add("FileXfer.DstList", dst_list.c_str());
    }
  }

  // Initialize the network interface.
  if (!net_if_->Initialize(config_info))
  {
    fprintf(stderr, "[Nftp::Initialize] Error initializing nftp network "
            "interface. Aborting...\n");
    return false;
  }

  return true;
}

//============================================================================
void Nftp::Start()
{
  if (sndr_)
  {
    SendFile();
  }
  else
  {
    RecvFile();
  }
}

//============================================================================
void Nftp::SendFile()
{
  // Coordinate with the network.
  if (!net_if_->CoordinateWithNetwork())
  {
    fprintf(stderr, "[Nftp::SendFile] Error coordinating with "
            "network. Aborting...\n");
    return;
  }

  // Create a socket that will not be used for sending or receiving
  // packets. This socket will perform a bind() call so that it is assigned an
  // ephemeral source port. We will then query the socket for the assigned
  // source port and will use this port in the File Transfer Advertisement and
  // for the NORM Session that will do the file transfer.
  int  s = -1;
  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket()");
    return;
  }

  // Set SO_REUSEADDR for the socket so we can reuse the assigned ephemeral
  // source port.
  int optval = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  // Bind to get assigned an ephemeral source port.
  struct sockaddr_in  addr;
  memset(&addr, 0, sizeof(addr));

  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(0);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("bind()");
    close(s);
    return;
  }

  // Query the created socket for the ephemeral source port.
  struct sockaddr sock_addr;
  socklen_t       sock_len = sizeof(addr);
  if (getsockname(s, (struct sockaddr*)&sock_addr, &sock_len) < 0)
  {
    perror("getsockname()");
    close(s);
    return;
  }

  src_port_ = ntohs(((struct sockaddr_in*)&sock_addr)->sin_port);

  fprintf(stderr, "[Nftp::SendFile] Source port: %hu\n", src_port_);

  if (!AdvFileXfer())
  {
    fprintf(stderr, "[Nftp::SendFile] File transfer advertisement signaling "
            "error. Aborting...\n");
    close(s);
    return;
  }

  // Grab the file name from the provided fully qualified file path, to be
  // used later on.
  const char*  file_name = strrchr(file_path_.c_str(), DIR_DELIMITER);

  if (file_name)
  {
    file_name++;
  }
  else
  {
    file_name = file_path_.c_str();
  }

  // Create a NORM API NormInstance.
  NormInstanceHandle  instance = NormCreateInstance();

  // Create a NormSession using default "automatic" local node id.
  NormSessionHandle  session = NormCreateSession(instance,
                                                 mcast_addr_str_.c_str(),
                                                 mcast_dst_port_, 1);

  NormSetRxPortReuse(session, true);

  // Uncomment to enable multicast loopback.
  // NormSetMulticastLoopback(session, true);

  // Set the multicast interface to the data plane interface.
  NormSetMulticastInterface(session, mcast_if_name_.c_str());

  // NOTE: These are some debugging routines available and are not necessary
  // for normal app use. If desired, need to include protoDebug.h.
  // SetDebugLevel(2);

  // Uncomment to turn on debug NORM message tracing
  // NormSetMessageTrace(session, true);

  struct timeval current_time;
  ProtoSystemTime(current_time);

  // Seed random number generator.
  srand(current_time.tv_usec);

  // Set transmission rate, in bps.
  // XXX Make this configurable...
  NormSetTxRate(session, 25000.0e+03);

  // Uncomment to use a specific transmit port number. This can be the same as
  // session port (rx port), but this is not recommended when unicast feedback
  // may be possible. This must be called before NormStartSender().
  if (src_port_ != 0)
  {
    NormSetTxPort(session, src_port_, true);

    // Filter on source port in received packets.
    NormSetSsmSrcPort(session, src_port_);
  }

  if (enable_cc_)
  {
    // Enable TCP-friendly congestion control.
    NormSetCongestionControl(session, true);
  }

  if (enable_fc_)
  {
    // Enable window-based flow control.
    // fprintf(stderr, "Instructing NORM to do window flow control.\n");
    NormSetWindowFlowControl(session, true);

    // Since we are doing flow control, we will set the transmission rate to
    // 100 Mbps.
    NormSetTxRate(session, 100000.0e+03);
  }

  // Start the sender using a random sessionId.
  NormSessionId  sessionId = (NormSessionId)rand();
  NormStartSender(session, sessionId, 1024*1024, 1200, 64, 16);

  // Uncomment to set large tx socket buffer size. This might be needed for
  // high rate sessions.
  // NormSetTxSocketBuffer(session, 512000);

  // Enqueue the file for transmission, using the file name for NORM_INFO.
  NormFileEnqueue(session, file_path_.c_str(), file_name, strlen(file_name));

  // Enter NORM event loop.
  bool running = true;
  while (running)
  {
    NormEvent  event;
    if (!NormGetNextEvent(instance, &event))
    {
      continue;
    }

    switch (event.type)
    {
      case NORM_TX_QUEUE_VACANCY:
	fprintf(stderr, "[Nftp::SendFile] NORM_TX_QUEUE_VACANCY event...\n");
	break;

      case NORM_TX_QUEUE_EMPTY:
	fprintf(stderr, "[Nftp::SendFile] NORM_TX_QUEUE_EMPTY event...\n");
	break;

      case NORM_TX_OBJECT_PURGED:
	fprintf(stderr, "[Nftp::SendFile] NORM_TX_OBJECT_PURGED event ...\n");
	break;

      case NORM_TX_FLUSH_COMPLETED:
	fprintf(stderr, "[Nftp::SendFile] NORM_TX_FLUSH_COMPLETED event "
                "...\n");
	running = false;
	break;

      default:
	TRACE("[Nftp::SendFile] Unhandled event type: %d\n", event.type);
    }
  }

  // Stop the sender and destroy the session and instance.
  NormStopSender(session);
  NormDestroySession(session);
  NormDestroyInstance(instance);

  // Close the temporary socket, created at the beginning of the method.
  close(s);

  fprintf(stderr, "[Nftp::SendFile] Done.\n");
}

//============================================================================
bool Nftp::AdvFileXfer() const
{
  // Create a NORM API NormInstance.
  NormInstanceHandle  instance = NormCreateInstance();

  // Create a NormSession.
  NormSessionHandle  session = NormCreateSession(instance,
                                                 mcast_addr_str_.c_str(),
                                                 mcast_dst_port_,
                                                 NORM_NODE_ANY);//1);

  // NOTE: These are some debugging routines available and are not necessary
  // for normal app use. If desired, need to include protoDebug.h.
  // NormSetDebugLevel(3);

  // Uncomment to turn on debug NORM message tracing.
  // NormSetMessageTrace(session, true);

  // Set the multicast interface to the data plane interface.
  NormSetMulticastInterface(session, mcast_if_name_.c_str());

  struct timeval current_time;
  gettimeofday(&current_time, NULL);

  // Seed the random number generator.
  srand(current_time.tv_usec);

  // Set transmission rate, in bps.
  // XXX Make this configurable...
  NormSetTxRate(session, 1.0e+07);

  NormSetRxPortReuse(session, true);

  // NormSetFlowControl(session, 0.0);

  // Init GRTT to low value (3 msec)
  // NormSetGrttEstimate(session, 1.0e-03);

  // Disable receiver backoffs (for lower latency, high speed performance).
  // For large group sizes, the default backoff factor is RECOMMENDED.
  // NormSetBackoffFactor(session, 2.0);

  // Uncomment to use a specific transmit port number. This can be the same as
  // session port (rx port), but this is not recommended when unicast feedback
  // may be possible. This must be called before NormStartSender().
  NormSetTxPort(session, 6003, true);

  // Uncomment to enable TCP-friendly congestion control
  if (enable_cc_)
  {
    NormSetCongestionControl(session, true);
  }

  // Uncomment to enable rx port reuse. This plus unique NormNodeId's enables
  // same-machine send/recv.
  // NormSetRxPortReuse(session, true);

  // Start the sender using a random sessionId.
  NormSessionId  session_id = (NormSessionId)rand();
  NormStartSender(session, session_id, 1024*1024, 1200, 64, 16);

  // Start the receiver.
  NormStartReceiver(session, 8 * 1024 * 1024);
  NormSetSilentReceiver(session, true);
  if (!NormSetRxSocketBuffer(session, 8*1024*1024))
  {
    perror("[Nftp AdvFileXfer] Error: unable to set requested socket buffer "
           "size");
  }

  // Uncomment to set large tx socket buffer size (may be needed to achieve
  // very high packet output rates).
  // NormSetTxSocketBuffer(session, 512000);

  // 4 MB stream buffer size.
  UINT32  stream_buffer_size = 4 * 1024 * 1024;

  // Enqueue the NORM_OBJECT_STREAM object. Provide some "info" about this
  // stream. Note that the info is OPTIONAL.
  char  data_info[256];
  sprintf(data_info, "nftp control message stream...");

  NormObjectHandle  tx_stream = NormStreamOpen(session, stream_buffer_size,
                                               data_info,
                                               strlen(data_info) + 1);
  if (NORM_OBJECT_INVALID == tx_stream)
  {
    fprintf(stderr, "[Nftp::AdvFileXfer] NormStreamOpen() error.\n");
    return false;
  }

  // Generate the file transfer control message.
  char    ctrl_msg[MAX_MSG_LEN];
  UINT16  ctrl_msg_len = 0;
  if (!GenerateCtrlMsg(ctrl_msg, ctrl_msg_len))
  {
    return false;
  }

  fprintf(stderr, "[Nftp::AdvFileXfer] File transfer advertisement msg len: %u"
          " bytes.\n", ctrl_msg_len);

  // Next, we will send the control message and wait for acknowledgements from
  // the destinations.

  // Write the message, as much as stream buffer will accept.
  unsigned int  bytes_written = NormStreamWrite(tx_stream, ctrl_msg,
                                                ctrl_msg_len);

  // Map of receive streams.
  map<NormObjectHandle, StreamInfo>  stream_map;

  // We use a "select()" call to wait for NORM events.
  int     norm_fd = NormGetDescriptor(instance);
  fd_set  fd_set;

  // Enter NORM event loop.
  bool    cont         = true;
  bool    flushed      = false;
  size_t  num_acks     = 0;
  size_t  num_req_acks = dsts_.size();

  while (cont)
  {
    FD_SET(norm_fd, &fd_set);

    int  result = select(norm_fd + 1, &fd_set, NULL, NULL, NULL);

    if (result > 0)
    {
      // Get and handle NORM API event.
      NormEvent  event;
      if (!NormGetNextEvent(instance, &event))
      {
        continue;
      }

      switch (event.type)
      {
        case NORM_TX_QUEUE_EMPTY:
        case NORM_TX_QUEUE_VACANCY:
        {
          // if (NORM_TX_QUEUE_VACANCY == event.type)
          // {
          //   fprintf(stderr, "[Nftp::AdvFileXfer] NORM_TX_QUEUE_VACANCY event "
          //           "...\n");
          // }
          // else
          // {
          //   fprintf(stderr, "[Nftp::AdvFileXfer] NORM_TX_QUEUE_EMPTY event "
          //           "...\n");
          // }

          // XXX Reintroduce keepSending logic??
          // if (keepSending && (bytes_written < msg_len))
          if (bytes_written < ctrl_msg_len)
          {
            // Finish writing remaining pending message content, as much as
            // can be written.
            bytes_written +=
              NormStreamWrite(tx_stream, ctrl_msg + bytes_written,
                              ctrl_msg_len - bytes_written);

            if (bytes_written == ctrl_msg_len)
            {
              // Complete message was written.
              NormStreamMarkEom(tx_stream);
              NormStreamFlush(tx_stream);
              flushed = true;
              fprintf(stderr, "[Nftp::AdvFileXfer] NORM stream flushed #1, "
                      "%u bytes written.\n", bytes_written);
            }
          }
          else
          {
            if (!flushed)
            {
              NormStreamMarkEom(tx_stream);
              NormStreamFlush(tx_stream, false, NORM_FLUSH_ACTIVE);
              flushed = true;
              fprintf(stderr, "[Nftp::AdvFileXfer] NORM stream flushed #2, "
                      "%u bytes written.\n", bytes_written);
            }
          }
          break;
        }

        case NORM_TX_OBJECT_PURGED:
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_TX_OBJECT_PURGED "
                  "event...\n");
          break;

        case NORM_TX_FLUSH_COMPLETED:
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_TX_FLUSH_COMPLETED "
                  "event...\n");
          break;

        case NORM_GRTT_UPDATED:
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_GRTT_UPDATED event...\n");
          break;

        case NORM_RX_OBJECT_NEW:
        {
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_RX_OBJECT_NEW "
                  "event...\n");

          // Add the stream information to to the stream map if it is not
          // already there.
          map<NormObjectHandle, StreamInfo>::iterator  it;
          it = stream_map.find(event.object);
          if (it == stream_map.end())
          {
            StreamInfo  si;
            stream_map[event.object] = si;
          }

          break;
        }

        case NORM_RX_OBJECT_INFO:
        {
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_RX_OBJECT_INFO "
                  "event...\n");

          // Get the stream information from the stream map.
          map<NormObjectHandle, StreamInfo>::iterator  it =
            stream_map.find(event.object);
          if (it == stream_map.end())
          {
            fprintf(stderr, "[Nftp::AdvFileXfer] Error: received "
                    "NORM_RX_OBJECT_INFO for unhandled object.\n");
            break;
          }

          char          stream_info[8192];
          unsigned int  info_len = NormObjectGetInfo(event.object,
                                                     stream_info, 8191);
          stream_info[info_len]  = '\0';
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_RX_OBJECT_INFO event, "
                  "info = \"%s\"\n", stream_info);

          break;
        }

        case NORM_RX_OBJECT_UPDATED:
        {
          // Get the stream information from the stream map.
          map<NormObjectHandle, StreamInfo>::iterator  it =
            stream_map.find(event.object);
          if (it == stream_map.end())
          {
            fprintf(stderr, "[Nftp::AdvFileXfer] Error: received "
                    "NORM_RX_OBJECT_UPDATED for unhandled object.\n");
            break;
          }

          StreamInfo  si = it->second;
          while (1)
          {
            // If we're not "in sync", seek message start.
            if (!si.msg_sync)
            {
              si.msg_sync = NormStreamSeekMsgStart(event.object);
              if (!si.msg_sync)
              {
                // Wait for next NORM_RX_OBJECT_UPDATED to re-sync.
                break;
              }
            }

            if (si.msg_index < 2)
            {
              // We still need to read the 2-byte message header for the next
              // message.
              unsigned int  num_bytes = 2 - si.msg_index;

              if (!NormStreamRead(event.object, si.msg_buffer + si.msg_index,
                                  &num_bytes))
              {
                fprintf(stderr, "[Nftp::AdvFileXfer] Error: broken stream "
                        "detected, re-syncing...\n");
                si.Reset();

                // Try to re-sync and read again.
                continue;
              }

              si.msg_index += num_bytes;
              if (si.msg_index < 2)
              {
                // Wait for next NORM_RX_OBJECT_UPDATED to read more.
                break;
              }

              memcpy(&si.msg_len, si.msg_buffer, 2);
              si.msg_len = ntohs(si.msg_len);

              if ((si.msg_len < 2) || (si.msg_len > MSG_LEN_MAX))
              {
                fprintf(stderr, "[Nftp::AdvFileXfer] Error: message received "
                        "with invalid length.\n");
                si.Reset();

                // Try to re-sync and read again.
                continue;
              }
            }

            // Read content portion of message (note msg_index accounts for
            // length header).
            unsigned int  num_bytes = si.msg_len - si.msg_index;
            if (!NormStreamRead(event.object, si.msg_buffer + si.msg_index,
                                &num_bytes))
            {
              fprintf(stderr, "[Nftp::AdvFileXfer] Error: broken stream "
                      "detected, re-syncing...\n");
              si.Reset();

              // Try to re-sync and read again.
              continue;
            }

            si.msg_index += num_bytes;
            if (si.msg_index == si.msg_len)
            {
              // Message read is complete. Process the received message.
              if (ProcessNftpAck(si.msg_buffer))
              {
                num_acks++;
              }

              // Reset state variables for next message.
              si.msg_len   = 0;
              si.msg_index = 0;

              fprintf(stderr, "[Nftp::AdvFileXfer] num_acks: %zd, "
                      "num_req_acks: %zd\n", num_acks, num_req_acks);
              if (num_acks >= num_req_acks)
              {
                cont = false;
              }
            }
            else
            {
              // Wait for next NORM_RXOBJECT_UPDATED to read more.
              break;
            }
          }
          break;
        }

        case NORM_RX_OBJECT_COMPLETED:
        {
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_RX_OBJECT_COMPLETED "
                  "event...\n");
          stream_map.erase(event.object);
          break;
        }

        case NORM_RX_OBJECT_ABORTED:
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_RX_OBJECT_ABORTED "
                  "event...\n");
          stream_map.erase(event.object);
          break;

        case NORM_REMOTE_SENDER_NEW:
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_REMOTE_SENDER_NEW "
                  "event...\n");
          break;

        case NORM_REMOTE_SENDER_ACTIVE:
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_REMOTE_SENDER_ACTIVE "
                  "event...\n");
          break;

        case NORM_REMOTE_SENDER_INACTIVE:
          fprintf(stderr, "[Nftp::AdvFileXfer] NORM_REMOTE_SENDER_INACTIVE "
                  "event...\n");
          break;

        default:
          fprintf(stderr, "[Nftp::AdvFileXfer] Got event type: %d\n",
                  event.type);
      }
    }
    else if (result < 0)
    {
      // select() error.
      perror("[Nftp::AdvFileXfer] select() error");
      break;
    }
  }

  NormStopSender(session);
  NormDestroySession(session);
  NormDestroyInstance(instance);

  fprintf(stderr, "[Nftp::AdvFileXfer] Done.\n");

  return true;
}

//============================================================================
bool Nftp::GenerateCtrlMsg(char* ctrl_msg, UINT16& ctrl_msg_len) const
{
  // Construct the stream message for the pending file transfer. This message
  // includes the following information pertaining to the file transfer:
  //
  //   - source address
  //   - source port
  //   - list of destination information
  //
  // A 4 byte header indicating the length of the message, in network byte
  // order, and the message type precedes the message.
  //
  // The message format is depicted below:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |          msg len              |  msg type = 1 |   reserved    |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                      source IP Address                        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |          src port             |  num dsts     |   reserved    |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                       dst 1 IP Address                        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |dst 1 path len |              dst 1 output path                |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                       dst 2 IP Address                        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |dst 2 path len |              dst 2 output path                |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //                                ...
  //                                ...
  //                                ...
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                       dst N IP Address                        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |dst N path len |              dst N output path                |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  ctrl_msg_len = 0;

  // Add the common message header message type field. To do so, we will start
  // with an offset of 2. At the end of the method, we will add the message
  // length field to the message. We wait because we will compute it as we
  // go.
  UINT16  offset   = 2;
  ctrl_msg[offset] = NFTP_CTRL_MSG;
  offset += sizeof(UINT8);
  offset += sizeof(UINT8);
  ctrl_msg_len += sizeof(UINT8);
  ctrl_msg_len += sizeof(UINT8);

  // Add the source address to the control message.
  memcpy(ctrl_msg + offset, &src_addr_, sizeof(src_addr_));
  offset       += sizeof(UINT32);
  ctrl_msg_len += sizeof(UINT32);

  // Add the source port to the control message.
  UINT16  src_port_nbo = htons(src_port_);
  memcpy(ctrl_msg + offset, &src_port_nbo, sizeof(src_port_nbo));
  offset       += sizeof(src_port_nbo);
  ctrl_msg_len += sizeof(src_port_nbo);

  // Add the number of destinations to the control message and skip the
  // reserved byte.
  ctrl_msg[offset]  = dsts_.size();
  offset           += sizeof(UINT8);
  ctrl_msg_len     += sizeof(UINT8);
  offset           += sizeof(UINT8);
  ctrl_msg_len     += sizeof(UINT8);

  // Add the destination information to the control message.
  for (size_t i = 0; i < dsts_.size(); i++)
  {
    DstInfo  dst = dsts_[i];

    // Add the destination IP Address.
    memcpy(ctrl_msg + offset, &dst.ip_addr_nbo, sizeof(UINT32));
    offset       += sizeof(UINT32);
    ctrl_msg_len += sizeof(UINT32);

    // Add the destination path length and output path.
    size_t  path_len = dst.path.length();
    ctrl_msg[offset] = path_len;
    offset       += sizeof(UINT8);
    ctrl_msg_len += sizeof(UINT8);
    if (path_len != 0)
    {
      memcpy(ctrl_msg + offset, dst.path.c_str(), path_len);
      offset       += path_len;
      ctrl_msg_len += path_len;
    }
  }

  // Finally, add the message length to the control message.
  offset = 0;
  ctrl_msg_len += sizeof(UINT16);
  UINT16  msg_len_nbo = htons(ctrl_msg_len);
  memcpy(ctrl_msg, &msg_len_nbo, sizeof(msg_len_nbo));

  return true;
}

//============================================================================
bool Nftp::ProcessNftpAck(const char* ack_msg) const
{
  // An "acknowledgement" for the sent control message has been received. The
  // format of the received message is as follows:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |            msg len            |  msg type = 2 |   reserved    |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                      source IP Address                        +
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |           src port            |            reserved           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                   destination IP Address                      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  // TODO: Maybe do some additional verification here that we have received
  // enough bytes before proceeding with the "parsing".

  // We don't care about the message length, so start at an offset of 2.
  UINT16  offset = 2;

  // Get the message type.
  UINT8   msg_type;
  memcpy(&msg_type, ack_msg + offset, sizeof(msg_type));
  offset += sizeof(msg_type);
  offset += sizeof(msg_type);

  if (msg_type != NFTP_CTRL_MSG_ACK)
  {
    fprintf(stderr, "[Nftp::ProcessNftpAck] Wrong msg type (%d).\n",
            msg_type);
    return false;
  }

  // Get the source address. Verify that it matches the source address sent in
  // the control message.
  UINT32  msg_src_addr;
  memcpy(&msg_src_addr, ack_msg + offset, sizeof(msg_src_addr));
  offset += sizeof(msg_src_addr);

  if (msg_src_addr != src_addr_)
  {
    return false;
  }

  // Get the source port. Verify that it matches the source port send in the
  // control message.
  UINT16  msg_src_port   = 0;
  memcpy(&msg_src_port, ack_msg + offset, sizeof(msg_src_port));
  offset += sizeof(msg_src_port);

  if (ntohs(msg_src_port) != src_port_)
  {
    return false;
  }

  // Skip the reserved bytes.
  offset += 2;

  // Get the destination.
  //
  // TODO: Seems like we should do some kind of verification here...
  UINT32  dst_addr;
  memcpy(&dst_addr, ack_msg + offset, sizeof(UINT32));

  return true;
}

//============================================================================
void Nftp::RecvFile()
{
  // Create a NORM API NormInstance.
  NormInstanceHandle  instance = NormCreateInstance();

  // Create a NormSession using default "automatic" local node id.
  NormSessionHandle  session = NormCreateSession(instance,
                                                 mcast_addr_str_.c_str(),
                                                 mcast_dst_port_,
                                                 NORM_NODE_ANY);

  NormSetRxPortReuse(session, true);

  // Uncomment if multicast loopback is desired.
  // NormSetMulticastLoopback(session, true);

  // Set the multicast interface to the data plane interface.
  NormSetMulticastInterface(session, mcast_if_name_.c_str());

  // NOTE: These are some debugging routines available and are not necessary
  // for normal app use. If desired, need to include protoDebug.h.
  // SetDebugLevel(2);

  // Uncomment to turn on debug NORM message tracing.
  // NormSetMessageTrace(session, true);

  struct timeval current_time;
  ProtoSystemTime(current_time);

  // Seed random number generator.
  // Do we need to do this?
  // srand(current_time.tv_usec);

  // Set receiver file cache path. This is where received files are stored.
  string  cache_dir = output_dir_;
  if (use_temp_files_)
  {
    if (cache_dir[0] == '/')
    {
      cache_dir = "/tmp" + cache_dir;
    }
    else
    {
      cache_dir = "/tmp/" + cache_dir;
    }

    struct stat  sb;
    if (stat(cache_dir.c_str(), &sb) != 0)
    {
      if (errno == ENOENT)
      {
        // Something along the path does not exist.
        mkdir(cache_dir.c_str(), S_IRWXU);
        fprintf(stderr, "[Nftp::RecvFile] Created cache directory: %s.\n",
                cache_dir.c_str());
      }
    }
  }

  if (!NormSetCacheDirectory(instance, cache_dir.c_str()))
  {
    fprintf(stderr, "[Nftp::RecvFile] Error setting cache directory.\n");
    return;
  }

  if (src_addr_str_.size() != 0)
  {
    // Filter on source address in received packets.
    NormSetSSM(session, src_addr_str_.c_str());
  }

  if (src_port_ != 0)
  {
    // Filter on source port in received packets.
    NormSetSsmSrcPort(session, src_port_);

    // Use the sender's source port for the Tx port for any repair messages.
    NormSetTxPort(session, src_port_, true);
  }

  // Start the receiver with 1 Mbyte buffer per sender.
  NormStartReceiver(session, 1024*1024);

  // Enter NORM event loop
  char  file_name[PATH_MAX];
  bool  running = true;
  while (running)
  {
    NormEvent  event;
    if (!NormGetNextEvent(instance, &event))
    {
      fprintf(stderr, "[Nftp::RecvFile] Getting next NORM event failed.\n");
      continue;
    }

    switch (event.type)
    {
      case NORM_RX_OBJECT_NEW:
        fprintf(stderr, "[Nftp::RecvFile] NORM_RX_OBJECT_NEW event ...\n");
        break;

      case NORM_RX_OBJECT_INFO:
        // Assume info contains '/' delimited <path/fileName> string
        fprintf(stderr, "[Nftp::RecvFile] NORM_RX_OBJECT_INFO event...\n");

        if (NORM_OBJECT_FILE == NormObjectGetType(event.object))
        {
          if (output_file_name_.length() == 0)
          {
            strcpy(file_name, output_dir_.c_str());

            int  path_len = strlen(file_name);
            if (DIR_DELIMITER != file_name[path_len-1])
            {
              file_name[path_len++] = DIR_DELIMITER;
              file_name[path_len]   = '\0';
            }
            unsigned short  name_len = PATH_MAX - path_len;
            name_len = NormObjectGetInfo(event.object, file_name + path_len,
                                         name_len);
            file_name[name_len + path_len] = '\0';
            char*  ptr = file_name + 5;
            while ('\0' != *ptr)
            {
              if ('/' == *ptr)
              {
                *ptr = DIR_DELIMITER;
              }

              ptr++;
            }
          }
          else
          {
            string  fq_output_file = output_dir_;
            fq_output_file += output_file_name_;
            strcpy(file_name, fq_output_file.c_str());
          }

          // At this point, we have the desired destination file name. Save it
          // and modify the file name if we have been instructed to use
          // temporary files during the transfer.
          fq_output_file_name_ = file_name;
          if (use_temp_files_)
          {
            snprintf(file_name, PATH_MAX, "/tmp/%s",
                     fq_output_file_name_.c_str());
          }

          fprintf(stderr, "[Nftp::RecvFile] Renaming file to: %s\n",
                  file_name);
          if (!NormFileRename(event.object, file_name))
          {
            fprintf(stderr, "[Nftp::RecvFile] NormSetFileName (%s) error.\n",
                    file_name);
          }
        }
        break;

      case NORM_RX_OBJECT_UPDATED:
      {
        // fprintf(stderr, "[Nftp::RecvFile] NORM_RX_OBJECT_UPDATE event...\n");

        // Monitors file receive progress. At high packet rates, you may want
        // to be careful here and only calculate/post updates occasionally
        // rather than for each and every RX_OBJECT_UPDATE event.
        NormSize  object_size = NormObjectGetSize(event.object);
        fprintf(stderr, "[Nftp::RecvFile] sizeof(NormSize) = %d\n",
                (int)sizeof(NormSize));

        NormSize  completed = object_size -
          NormObjectGetBytesPending(event.object);
        double  percent_complete = 100.0 *
          ((double)completed/(double)object_size);

        fprintf(stderr, "[Nftp::RecvFile] completion status %lu/%lu "
                "(%3.0lf%%)\n", (unsigned long)completed,
                (unsigned long)object_size, percent_complete);
        break;
      }

      case NORM_RX_OBJECT_COMPLETED:
        fprintf(stderr, "[Nftp::RecvFile] NORM_RX_OBJECT_COMPLETED "
                "event...\n");
        running = false;
        break;

      case NORM_RX_OBJECT_ABORTED:
        fprintf(stderr, "[Nftp::RecvFile] NORM_RX_OBJECT_ABORTED event...\n");
        break;

      case NORM_REMOTE_SENDER_NEW:
        fprintf(stderr, "[Nftp::RecvFile] NORM_REMOTE_SENDER_NEW event...\n");
        break;

      case NORM_REMOTE_SENDER_ACTIVE:
        fprintf(stderr, "[Nftp::RecvFile] NORM_REMOTE_SENDER_ACTIVE "
                "event...\n");
        break;

      case NORM_REMOTE_SENDER_INACTIVE:
        fprintf(stderr, "[Nftp::RecvFile] NORM_REMOTE_SENDER_INACTIVE "
                "event...\n");
        break;

      default:
        fprintf(stderr, "[Nftp::RecvFile] Unhandled event type: %d\n",
                event.type);
    }
  }

  // Stop the receiver and destroy the session and instance.
  NormStopReceiver(session);
  NormDestroySession(session);
  NormDestroyInstance(instance);

  if (use_temp_files_)
  {
    char  cmd[128];
    sprintf(cmd, "mv %s %s", file_name, fq_output_file_name_.c_str());
    if (system(cmd) == -1)
    {
      fprintf(stderr, "[Nftp::RecvFile] Error executing command: %s\n", cmd);
    }

    sprintf(cmd, "touch %s", fq_output_file_name_.c_str());

    if (system(cmd) == -1)
    {
      fprintf(stderr, "[Nftp::RecvFile] Error executing command: %s\n", cmd);
    }
  }

  fprintf(stderr, "[Nftp::RecvFile] Done.\n");
}
