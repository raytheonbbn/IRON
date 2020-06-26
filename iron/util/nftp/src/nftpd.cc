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

// A NORM-based FTP daemon. This receives nftp control messages and starts an
// nftp receiver if the receiving node is in the destination list for the
// upcoming NORM-based file transfer.
//
// This is a modified version of the NORM example, normStreamRecv.cpp,
// distributed with the NORM source version 1.5.8.
//

#include "nftpd.h"
#include "stream_info.h"
#include "nftp_defaults.h"

#include "protoDebug.h"

#include <map>
#include <string>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <net/if.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


using ::std::map;
using ::std::string;

//============================================================================
Nftpd::Nftpd()
    : if_addrs_(),
      mcast_if_name_(DEFAULT_MCAST_IF_NAME),
      mcast_addr_str_(DEFAULT_MCAST_ADDR_STR),
      mcast_dst_port_(DEFAULT_MCAST_DST_PORT),
      running_(false),
      nftp_bin_dir_(),
      temp_files_opt_("")
{
}

//============================================================================
Nftpd::~Nftpd()
{
  // Nothing to destroy.
}

//============================================================================
bool Nftpd::Initialize(ConfigInfo& config_info)
{
  mcast_if_name_  = config_info.Get("McastIfName", DEFAULT_MCAST_IF_NAME);
  mcast_addr_str_ = config_info.Get("McastAddrStr", DEFAULT_MCAST_ADDR_STR);
  mcast_dst_port_ = config_info.GetInt("McastDstPort", DEFAULT_MCAST_DST_PORT);
  nftp_bin_dir_   = config_info.Get("NftpBinDir", DEFAULT_NFTP_BIN_DIR);
  temp_files_opt_ = config_info.Get("TempFilesOpt", "");

  if (nftp_bin_dir_[nftp_bin_dir_.length() - 1] != '/')
  {
    nftp_bin_dir_ += "/";
  }

  // If a virtual address has been provided, add it to the collection of
  // interface addresses.
  string  virt_addr_str = config_info.Get("VirtualAddrStr", "");
  if (virt_addr_str.length() != 0)
  {
    struct in_addr  addr;
    if (inet_aton(virt_addr_str.c_str(), &addr) != 0)
    {
      fprintf(stderr, "[Nftpd::Initialize] Virtual IP Address: 0x%x\n",
              addr.s_addr);
      if_addrs_.push_back(addr.s_addr);
    }
  }

  // Get the IP Addresses, in network byte order, of the local interfaces.
  int  s;
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    fprintf(stderr, "[Nftpd::Initialize] Socket error.\n");
    return false;
  }

  char           buf[2048];
  struct ifreq*  ifr;
  struct ifconf  ifc;

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;

  if (ioctl(s, SIOCGIFCONF, (char*)&ifc) < 0)
  {
    fprintf(stderr, "[Nftpd::Initialize] Ioctl error.\n");
    return false;
  }

  ifr       = ifc.ifc_req;
  int numif = (ifc.ifc_len / sizeof(struct ifreq));

  for (int i = 0; i < numif; i++, ifr++)
  {
    if (ifr->ifr_addr.sa_family != AF_INET)
    {
      continue;
    }

    struct sockaddr_in* inaddr = (struct sockaddr_in *)&(ifr->ifr_addr);

    UINT32  if_addr = inaddr->sin_addr.s_addr;
    fprintf(stderr, "[Nftpd::Initialize] Interface IP Address: 0x%x\n",
            if_addr);
    if_addrs_.push_back(if_addr);
  }

  close(s);

  return true;
}

//============================================================================
void Nftpd::Start()
{
  running_ = true;

  // Create a NORM API NormInstance.
  NormInstanceHandle  instance = NormCreateInstance();

  // Create a NormSession using default automatic local node id.
  NormSessionHandle  session = NormCreateSession(instance,
                                                 mcast_addr_str_.c_str(),
                                                 mcast_dst_port_,
                                                 NORM_NODE_ANY);

  fprintf(stderr, "[Nftpd::Start] Starting nftpd...\n");

  fflush(stderr);

  // NOTE: These are debugging routines available and are not necessary for
  // normal app use. If desired, need to include protoDebug.h.
  //
  // NOTE: We tried to use this and it didn't work. For now, we won't track
  // down why. If the following lines are uncommented, the desired behavior
  // will not be observed.
  // NormSetDebugLevel(3);

  // Uncomment to turn on debug NORM message tracing
  // NormSetMessageTrace(session, true);

  // Uncomment to write debug output to file norm_log.txt.
  // NormOpenDebugLog(instance, "norm_log.txt");

  // Set the multicast interface.
  NormSetMulticastInterface(session, mcast_if_name_.c_str());

  struct timeval currentTime;
  gettimeofday(&currentTime, NULL);

  // Seed random number generator.
  srand(currentTime.tv_sec);

  // Uncomment to enable rx port reuse. This plus unique NormNodeId's enables
  // same-machine send/recv.
  NormSetRxPortReuse(session, true);

  // Only receive packets from source port 6003.
  NormSetSsmSrcPort(session, 6003);

  // Start the sender using a random sessionId.
  NormSessionId  session_id = (NormSessionId)rand();
  NormStartSender(session, session_id, 1024*1024, 1200, 64, 16);

  // Start the receiver with 1 Mbyte buffer per sender.
  NormStartReceiver(session, 8 * 1024 * 1024);

  NormSetSilentReceiver(session, true);

  if (!NormSetRxSocketBuffer(session, 8*1024*1024))
  {
    perror("[Nftpd::Start] Error: unable to set requested socket buffer size");
  }

  // 4 MB stream buffer size.
  UINT32  stream_buffer_size = 4 * 1024 * 1024;

  // Enqueue the NORM_OBJECT_STREAM object. Provide some "info" about this
  // stream. Note that the info is OPTIONAL.
  char  data_info[256];
  sprintf(data_info, "nftpd control message stream...");

  NormObjectHandle  stream = NormStreamOpen(session, stream_buffer_size,
                                            data_info, strlen(data_info) + 1);
  if (NORM_OBJECT_INVALID == stream)
  {
    fprintf(stderr, "[Nftp Start] NormStreamOpen() error. Aborting...\n");
    exit(1);
  }

  // Map of receive streams.
  map<NormObjectHandle, StreamInfo>  stream_map;

  // Enter NORM event loop.
  while (running_)
  {
    NormEvent event;
    if (!NormGetNextEvent(instance, &event))
    {
      continue;
    }

    fprintf(stderr, "[Nftpd::Start] Rcvd. NORM event object: %p\n",
            event.object);

    switch (event.type)
    {
      case NORM_RX_OBJECT_NEW:
      {
        fprintf(stderr, "[Nftpd::Start] NORM_RX_OBJECT_NEW event...\n");

        // Add the stream information to the stream map if it is not already
        // there.
        map<NormObjectHandle, StreamInfo>::iterator  it;
        it = stream_map.find(event.object);
        if (it == stream_map.end())
        {
          // This is a new stream, so add it to the map.
          StreamInfo  si;
          stream_map[event.object] = si;
        }

        break;
      }

      case NORM_RX_OBJECT_INFO:
      {
        fprintf(stderr, "[Nftpd::Start] NORM_RX_OBJECT_INFO event...\n");

        // Get the stream information from the stream map.
        map<NormObjectHandle, StreamInfo>::iterator  it =
          stream_map.find(event.object);
        if (it == stream_map.end())
        {
          fprintf(stderr, "[Nftpd::Start] Error: received NORM_RX_OBJECT_INFO "
                  "for unhandled object.\n");
          break;
        }

        char         stream_info[8192];
        unsigned int stream_info_len = NormObjectGetInfo(event.object,
                                                         stream_info, 8191);
        stream_info[stream_info_len]  = '\0';
        fprintf(stderr, "[Nftpd::Start] NORM_RX_OBJECT_INFO event, info = "
                "\"%s\"\n", stream_info);

        break;
      }

      case NORM_RX_OBJECT_UPDATED:
      {
        fprintf(stderr, "[Nftpd::Start] NORM_RX_OBJECT_UPDATED event...\n");

        // Get the stream information from the stream map.
        map<NormObjectHandle, StreamInfo>::iterator  it =
          stream_map.find(event.object);
        if (it == stream_map.end())
        {
          fprintf(stderr, "[Nftpd::Start] Error: received "
                  "NORM_RX_OBJECT_UPDATED for unhandled object.\n");
          break;
        }

        StreamInfo  si = it->second;
        while (1)
        {
          // If we're not "in sync", seek message start
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
              fprintf(stderr, "[Nftpd::Start] Error: broken stream detected, "
                      "re-syncing...\n");
              si.Reset();

              // Try to re-sync and read again.
              continue;
            }

            fprintf(stderr, "[Nftpd::Start] Read %u bytes\n", num_bytes);

            si.msg_index += num_bytes;
            if (si.msg_index < 2)
            {
              // Wait for next NORM_RX_OBJECT_UPDATED to read more.
              break;
            }

            memcpy(&si.msg_len, si.msg_buffer, 2);
            si.msg_len = ntohs(si.msg_len);
            if ((si.msg_len < 2) || (si.msg_len > MAX_MSG_LEN))
            {
              fprintf(stderr, "[Nftpd::Start] Error: message received with "
                      "invalid length.\n");
              si.Reset();

              // Try to re-sync and read again.
              fprintf(stderr, "[Nftpd::Start] continue #2...\n");
              continue;
            }
          }

          // Read content portion of message (note msg_index accounts for
          // length header).
          unsigned int  num_bytes = si.msg_len - si.msg_index;
          if (!NormStreamRead(event.object, si.msg_buffer + si.msg_index,
                              &num_bytes))
          {
            fprintf(stderr, "[Nftpd::Start] Error: broken stream detected, "
                    "re-syncing...\n");
            si.Reset();

            // Try to re-sync and read again.
            continue;
          }

          fprintf(stderr, "[Nftpd::Start] Read %u bytes\n", num_bytes);

          si.msg_index += num_bytes;
          if (si.msg_index == si.msg_len)
          {
            // Complete message read, process received message. The following
            // variables will capture information from the received message
            // that will be used when constructing an acknowledgement, if
            // necessary.
            char    msg_output_path[128];
            UINT32  dst;
            UINT16  src_port;
            UINT32  src_addr;
            string  output_dir;
            string  output_file_name = "";

            if (ProcessMsg(si.msg_buffer, src_addr, src_port, dst,
                           msg_output_path))
            {
              fprintf(stderr, "[Nftpd::Start] Processing rcvd msg...\n");

              struct in_addr  inaddr;
              inaddr.s_addr = src_addr;
              string  src_addr_str = inet_ntoa(inaddr);
              fprintf(stderr, "[Nftpd::Start] File transfer src address: %s, "
                      "src port: " "%hu\n", src_addr_str.c_str(),
                      ntohs(src_port));

              if (ProcessOutputPath(msg_output_path, output_dir,
                                    output_file_name))
              {
                // Start the nftp receiver for the upcoming file transfer.
                char  cmd[128];
                if (output_file_name.length() == 0)
                {
                  sprintf(cmd, "%snftp -R %s -a %s -s %hu -i %s %s&",
                          nftp_bin_dir_.c_str(), output_dir.c_str(),
                          src_addr_str.c_str(), ntohs(src_port),
                          mcast_if_name_.c_str(), temp_files_opt_.c_str());
                }
                else
                {
                  sprintf(cmd, "%snftp -R %s -o %s -a %s -s %hu -i %s %s&",
                          nftp_bin_dir_.c_str(), output_dir.c_str(),
                          output_file_name.c_str(), src_addr_str.c_str(),
                          ntohs(src_port), mcast_if_name_.c_str(),
                          temp_files_opt_.c_str());
                }

                fprintf(stderr, "[Nftpd::Start] Executing command: %s\n", cmd);
                if (system(cmd) == -1)
                {
                  fprintf(stderr, "[Nftpd::Start] Error executing command: %s\n",
                          cmd);
                  break;
                }
                fprintf(stderr, "[Nftpd::Start] Done executing command: %s\n",
                        cmd);
              }

              fprintf(stderr, "[Nftpd::Start] Waiting for receiver...\n");
              WaitForRcvr(ntohs(src_port));

              // The local node is in the destination list for the received
              // nftp control message "announcing" an upcoming file
              // transfer. Generate an acknowledgement and send it.

              char    ack_msg[MAX_MSG_LEN];
              UINT16  ack_msg_len;
              GenerateNftpAck(src_addr, src_port, dst, ack_msg, ack_msg_len);

              // Write the message (as much as stream buffer will accept)
              NormStreamWrite(stream, ack_msg, ack_msg_len);

              NormStreamMarkEom(stream);
              NormStreamFlush(stream, false, NORM_FLUSH_ACTIVE);
            }

            // Reset state variables for next message.
            si.msg_len   = 0;
            si.msg_index = 0;

            break;
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
        fprintf(stderr, "[Nftpd::Start] NORM_RX_OBJECT_COMPLETED event...\n");
        stream_map.erase(event.object);
        break;
      }

      case NORM_RX_OBJECT_ABORTED:
        fprintf(stderr, "[Nftpd::Start] NORM_RX_OBJECT_ABORTED event...\n");
        stream_map.erase(event.object);
        break;

      case NORM_REMOTE_SENDER_NEW:
        fprintf(stderr, "[Nftpd::Start] NORM_REMOTE_SENDER_NEW event...\n");
        break;

      case NORM_REMOTE_SENDER_ACTIVE:
        fprintf(stderr, "[Nftpd::Start] NORM_REMOTE_SENDER_ACTIVE event...\n");
        break;

      case NORM_REMOTE_SENDER_INACTIVE:
        fprintf(stderr, "[Nftpd::Start] NORM_REMOTE_SENDER_INACTIVE "
                "event...\n");
        break;

      case NORM_GRTT_UPDATED:
        fprintf(stderr, "[Nftpd::Start] NORM_GRTT_UPDATED event...\n");
        break;

      default:
        fprintf(stderr, "[Nftpd::Start] Unhandled event type: %d\n",
                event.type);
    }

    fflush(stderr);
  }

  // We are done with the session and instance, so destroy them.
  NormStopReceiver(session);
  NormDestroySession(session);
  NormDestroyInstance(instance);

  fprintf(stderr, "[Nftpd::Start] Done...\n");
}

//============================================================================
bool Nftpd::ProcessMsg(const char* msg, UINT32& src_addr, UINT16& src_port,
                       UINT32& dst, char* output_path) const
{
  // Determine if the received message should be processed. We ONLY process
  // nftp control messages. All other messages received on the control group
  // (including nftp control message acknowledgements from other nfpt daemons)
  // are ignored. To figure out if the message should be processed, we only
  // need look at the common message header. The format of this header is as
  // follows:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |          msg len              |  msg type = 1 |   reserved    |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  // The message length portion of the common header has already been stripped
  // from the received message.

  UINT8  offset = 2;
  UINT8  msg_type = msg[offset];

  if (msg_type == NFTP_CTRL_MSG)
  {
    offset += 2 * sizeof(msg_type);

    return ParseNftpCtrlMsg(msg + offset, src_addr, src_port, dst,
                            output_path);
  }
  else
  {
    fprintf(stderr, "Not processing received message...\n");
  }

  return false;
}

//============================================================================
bool Nftpd::ParseNftpCtrlMsg(const char* msg, UINT32& src_addr,
                             UINT16& src_port, UINT32& dst, char* output_path)
  const
{
  // An nftp control message contains the information pertaining to an
  // upcoming file transfer, including the source address, source port, and a
  // list of the destinations. The format of the received nftp control message
  // is as follows:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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

  // TODO: Maybe do some additional verification here that we have received
  // enough bytes before proceeding with the "parsing".


  // Note: The common message header, including message length and type, is
  // not included in the remaining message buffer, so we can begin with an
  // offset of 0 here.
  UINT16  offset = 0;

  // Get the source address.
  memcpy(&src_addr, msg + offset, sizeof(src_addr));
  offset += sizeof(src_addr);

  // Get the source port.
  memcpy(&src_port, msg + offset, sizeof(src_port));
  offset += sizeof(src_port);

  struct in_addr  addr;
  addr.s_addr = src_addr;
  fprintf(stderr, "[Nftpd::ParseNftpCtrlMsg] nftp src addr: %s, src port: "
          "%hu\n", inet_ntoa(addr), ntohs(src_port));

  // Get the number of destinations and skip the reserved byte.
  uint8_t num_dsts = msg[offset];
  offset += sizeof(num_dsts);
  offset += sizeof(UINT8);

  for (UINT8 i = 0; i < num_dsts; i++)
  {
    // Get the destination information.
    UINT32  dst_addr;
    memcpy(&dst_addr, msg + offset, sizeof(UINT32));
    offset += sizeof(UINT32);

    size_t  dst_path_str_len = msg[offset];
    offset += sizeof(UINT8);
    if (dst_path_str_len != 0)
    {
      memcpy(output_path, msg + offset, dst_path_str_len);
      offset += dst_path_str_len;
    }
    output_path[dst_path_str_len] = '\0';

    for (size_t i = 0; i < if_addrs_.size(); ++i)
    {
      if (if_addrs_[i] == dst_addr)
      {
        dst = dst_addr;
        fprintf(stderr, "[Nfptd::ParseNftpCtrlMsg] IN destination list.\n");
        return true;
      }
    }
  }

  fprintf(stderr, "[Nfptd::ParseNftpCtrlMsg] NOT IN destination list.\n");
  return false;
}

//============================================================================
void Nftpd::WaitForRcvr(UINT16 src_port) const
{
  char    buffer[128];
  char    cmd[1024];
  string  result = "";

  // sprintf(cmd, "lsof -i -P -n | grep nftp | grep %d", src_port);
  sprintf(cmd, "ps -ef | grep nftp | grep %d | grep -v grep", src_port);

  while (result.length() == 0)
  {
    fprintf(stderr, "[Nftpd::WaitForRcvr] Executing command: %s\n", cmd);
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
    {
      fprintf(stderr, "[Nftpd::WaitForRcvr] popen(%s) failed...\n", cmd);
      return;
    }

    // Read till end of process.
    while (!feof(pipe))
    {
      if (fgets(buffer, 128, pipe) != NULL)
      {
        result += buffer;
      }
    }

    pclose(pipe);

    usleep(500000);
  }

  fprintf(stderr, "[Nftpd::WaitForRcvr] Rcvr. ready...\n");
}

//============================================================================
void Nftpd::GenerateNftpAck(UINT32 src_addr, UINT16 src_port, UINT32 dst,
                            char* ack_msg, UINT16& ack_msg_len) const
{
  // Build an "acknowledgement" for a received nftp control message. As part
  // of the acknowledgement message, we echo back the source address, source
  // port, and destination received in the control message. The format for the
  // message is as follows:
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

  UINT8 offset = 0;

  // Add the message length to the message.
  ack_msg_len = sizeof(UINT16) + sizeof(UINT8) + sizeof(UINT8) +
    sizeof(src_addr) + sizeof(src_port) + sizeof(UINT16) + sizeof(dst);
  UINT16  ack_msg_len_nbo = htons(ack_msg_len);
  memcpy(ack_msg, &ack_msg_len_nbo, sizeof(ack_msg_len_nbo));
  offset += sizeof(UINT16);

  // Add the message type to the message and skip the reserved byte.
  ack_msg[offset] = NFTP_CTRL_MSG_ACK;
  offset += sizeof(UINT8);
  offset += sizeof(UINT8);

  // Add the source address to the message.
  memcpy(ack_msg + offset, &src_addr, sizeof(src_addr));
  offset += sizeof(src_addr);

  // Add the source port to the message.
  memcpy(ack_msg + offset, &src_port, sizeof(src_port));
  offset += sizeof(src_port);

  // Skip the reserved bytes.
  offset += 2;

  // Add the destination address to the message.
  memcpy(ack_msg + offset, &dst, sizeof(dst));
  offset += sizeof(dst);
}

//============================================================================
bool Nftpd::ProcessOutputPath(const char* msg_output_path, string& output_dir,
                              string& output_file_name) const
{
  // Process the output path from the received nftp control message. This is
  // either:
  //
  //   1. An output directory specification (in which output_dir will be
  //      filled in)
  //
  //   or
  //
  //   2. An output directory and output file specification (in which
  //      output_dir and output_file_name will be filled in)
  //
  // To figure this out, the existence of the provided message output path as
  // a directory is checked. If this directory does not exist, the message
  // output path is split, into an output directory and an output file
  // name. The split occurs at the last occurrence of the '/' character in the
  // message output path.
  //
  // For success in either of the above cases, the resultant output directory
  // must exist and we must have write permission to the directory.
  //
  // Additionally, if the message output directory does not start with a '/'
  // character it is interpreted as being relative to the user's home
  // directory, e.g., /home/USER/ is prepended to the message output path
  // prior to the verification checks.

  fprintf(stderr, "[Nftpd::ProcessOutputPath] Received output path: %s\n",
          msg_output_path);

  output_dir       = msg_output_path;
  output_file_name = "";

  if (output_dir.length() == 0)
  {
    // This is the case where no path was specified in nftp for the
    // destination. The resulting output directory will simply be the user's
    // home directory.
    string  home_dir = GetHomeDir();
    output_dir  = home_dir;
    if (output_dir[output_dir.length() - 1] != '/')
    {
      output_dir += "/";
    }
  }
  else if (output_dir[0] == '/')
  {
    // We need to check if the message output path exists as a directory AND
    // that we have write permission in that directory.
    if (DirExists(output_dir.c_str()))
    {
      if (access(output_dir.c_str(), W_OK) == 0)
      {
        // The message output path exists and we have write permission.
        // output_dir  = msg_output_path;
        if (output_dir[output_dir.length() - 1] != '/')
        {
          output_dir += "/";
        }
      }
      else
      {
        // The message output path is a directory but we don't have write
        // permission in the directory.
        fprintf(stderr, "[Nftpd::ProcessOutputPath] Permission denied: %s\n",
                msg_output_path);
        return false;
      }
    }
    else
    {
      // Split the message output path into an output directory and an output
      // file name. The split occurs on the last occurrence of the '/'
      // character. Once the split happens, check the resulting directory for
      // existence and write permission.

      string  output_path_str = msg_output_path;
      size_t  last_slash_pos  = output_path_str.find_last_of('/');

      output_dir       = output_path_str.substr(0, last_slash_pos + 1);
      output_file_name = output_path_str.substr(last_slash_pos + 1);

      if (DirExists(output_dir.c_str()))
      {
        if (access(output_dir.c_str(), W_OK) != 0)
        {
          fprintf(stderr, "[Nftpd::ProcessOutputPath] Permission denied: "
                  "%s\n", output_dir.c_str());
          return false;
        }
      }
    }
  }
  else
  {
    // This is the case were the output path will be relative to the user's
    // home directory.

    output_dir = GetHomeDir();
    if (output_dir[output_dir.length() - 1] != '/')
    {
      output_dir += "/";
    }
    output_dir += msg_output_path;

    if (!DirExists(output_dir.c_str()))
    {
      size_t  last_slash_pos = output_dir.find_last_of('/');

      output_file_name = output_dir.substr(last_slash_pos + 1);
      output_dir       = output_dir.substr(0, last_slash_pos + 1);

      if (!DirExists(output_dir.c_str()))
      {
        fprintf(stderr, "[Nftpd::ProcessOutputPath] No such file or "
                "directory: %s\n", output_dir.c_str());
        return false;
      }
    }
  }

  fprintf(stderr, "[Nftpd::ProcessOutputPath] Output directory: %s, output "
          "file name: %s.\n\n", output_dir.c_str(), output_file_name.c_str());

  return true;
}

//============================================================================
string Nftpd::GetHomeDir() const
{
  const char*  home_dir;
  if ((home_dir = getenv("HOME")) == NULL)
  {
    home_dir = getpwuid(getuid())->pw_dir;
  }

  return home_dir;
}

//============================================================================
bool Nftpd::DirExists(const char* dir) const
{
  // Check if the provided directory exists.
  struct stat  sb;
  if ((stat(dir, &sb) == 0) &&
      (S_ISDIR(sb.st_mode)))
  {
    return true;
  }

  return false;
}
