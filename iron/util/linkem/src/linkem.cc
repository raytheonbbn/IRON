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

#include "linkem.h"
#include "frame_pool.h"
#include "log.h"
#include "string_utils.h"

#include <arpa/inet.h>
#include <cassert>
#include <cmath>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <unistd.h>

using ::iron::List;
using ::iron::StringUtils;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "LinkEm";

  /// The default managment listen port.
  int  kDefaultMgmtPort = 3456;

  /// The default bypass TOS value.
  int  kDefaultBypassTosValue = 0x3;

  /// The maximum size of message received from the LinkEmClient.
  int  kMaxMsgSize = 2048;

  /// The array index identifying WAN-facing paths.
  uint8_t  kWanIf = 0;

  /// The array index identifying LAN-facing paths.
  uint8_t  kLanIf = 1;
}

//============================================================================
LinkEm::LinkEm()
    : done_(false),
      hrc_(),
      if1_raw_socket_(-1),
      if2_raw_socket_(-1),
      frame_pool_(),
      mgmt_port_(kDefaultMgmtPort),
      bypass_tos_value_(kDefaultBypassTosValue),
      not_in_group_cnt_(0),
      stats_report_time_ns_(0),
      stats_report_int_ms_(0),
      log_stats_(false)
{
  LogD(kClassName, __func__, "Creating LinkEm...\n ");
}

//============================================================================
LinkEm::~LinkEm()
{
  // Return any frames that are in the various queues to the frame pool.
  for (uint8_t i = 0; i < NUM_PATHS; i++)
  {
    for (uint8_t j = 0; j < NUM_IFS; j++)
    {
      if (paths_[j][i].in_use)
      {
        Frame*  frame;
        while (paths_[j][i].pd_queue.Pop(frame))
        {
          frame_pool_.Recycle(frame);
        }

        for (uint8_t k = 0; k < 2; k++)
        {
          while (paths_[j][i].sd_info[k].queue.Pop(frame))
          {
            frame_pool_.Recycle(frame);
          }
        }
      }
    }
  }

  // Clean up the error and jitter models.
  for (int if_num = 0; if_num < NUM_IFS; if_num++)
  {
    for (int path_num = 0; path_num < NUM_PATHS; path_num++)
    {
      if (paths_[if_num][path_num].error_model != NULL)
      {
        delete paths_[if_num][path_num].error_model;
        paths_[if_num][path_num].error_model = NULL;
      }

      if (paths_[if_num][path_num].jitter_model != NULL)
      {
        delete paths_[if_num][path_num].jitter_model;
        paths_[if_num][path_num].jitter_model = NULL;
      }
    }
  }
}

//============================================================================
bool LinkEm::Initialize(const char* if1, const char* if2)
{
  hrc_.Initialize();

  // Open a raw socket for each interface and set the sockets to be
  // non-blocking.
  if1_raw_socket_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (if1_raw_socket_ == -1)
  {
    LogE(kClassName, __func__, "Error creating if1 socket: %s.\n",
         strerror(errno));
    return false;
  }

  if (fcntl(if1_raw_socket_, F_SETFL,
            fcntl(if1_raw_socket_, F_GETFL, 0) | O_NONBLOCK) == -1)
  {
    LogE(kClassName, __func__, "Error setting if1 socket to non-blocking: "
         "%s.\n", strerror(errno));
    return false;
  }

  if2_raw_socket_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (if2_raw_socket_ == -1)
  {
    LogE(kClassName, __func__, "Error creating if2 socket: %s.\n",
         strerror(errno));
    return false;
  }

  if (fcntl(if2_raw_socket_, F_SETFL,
            fcntl(if2_raw_socket_, F_GETFL, 0) | O_NONBLOCK) == -1)
  {
    LogE(kClassName, __func__, "Error setting if2 socket to non-blocking: "
         "%s.\n", strerror(errno));
    return false;
  }

  // Get names, macs, indexes of interfaces for later lookup.
  InitializeInterfaceLookup(0, if1);
  InitializeInterfaceLookup(1, if2);

  // Bind the raw sockets to their respective interfaces.
  struct sockaddr_ll  sl;
  bzero(&sl , sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_ifindex = paths_[0][0].index;
  sl.sll_protocol = htons(ETH_P_ALL);
  if (bind(if1_raw_socket_, (struct sockaddr*)&sl , sizeof(sl)) == -1)
  {
    LogE(kClassName, __func__, "Error binding if1 socket: %s.\n",
         strerror(errno));
    return false;
  }
  paths_[0][0].sock = if1_raw_socket_;

  bzero(&sl , sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_ifindex = paths_[1][0].index;
  sl.sll_protocol = htons(ETH_P_ALL);
  if (bind(if2_raw_socket_, (struct sockaddr*)&sl , sizeof(sl)) == -1)
  {
    LogE(kClassName, __func__, "Error binding if2 socket: %s.\n",
         strerror(errno));
    return false;
  }
  paths_[1][0].sock = if2_raw_socket_;

  // Set promiscuous mode on the created sockets.
  return (SetPromiscuous(if1_raw_socket_, if1, true) &&
          SetPromiscuous(if2_raw_socket_, if2, true));
}

//============================================================================
bool LinkEm::Configure(const char* file_name)
{
  ConfigureDefaultPath();

  if (file_name == NULL)
  {
      return true;
  }

  FILE*  input_file = fopen(file_name, "r");

  if (input_file == NULL)
  {
    LogE(kClassName, __func__, "Unable to open configuration file %s.\n",
         file_name);
    return false;
  }

  char  line[1024];
  while (fgets(line, sizeof(line), input_file) != NULL)
  {
    int line_len = strlen(line);

    if (line_len <= 1)
    {
      // Skip blank lines.
      continue;
    }

    if (line[0] == '#')
    {
      // Skip comment lines.
      continue;
    }

    ProcessCmd(line);
  }

  fclose(input_file);

  LogC(kClassName, __func__, "%s\n", ToString().c_str());

  return true;
}

//============================================================================
void LinkEm::Start()
{
  struct sockaddr_ll  sl;
  socklen_t           sllen = 0;
  memset(&sl, 0, sizeof(sl));

  LogI(kClassName, __func__, "Starting main loop...\n");

  int  server_socket = -1;
  if ((server_socket = CreateServerSocket()) == -1)
  {
    LogE(kClassName, __func__, "Can't open management socket.\n");
    abort();
  }

  int  max_fd = server_socket;
  if (if1_raw_socket_ > max_fd)
  {
    max_fd = if1_raw_socket_;
  }
  if (if2_raw_socket_ > max_fd)
  {
    max_fd = if2_raw_socket_;
  }

  fd_set          read_fds;
  struct timeval  timeout;

  unsigned long long start_time = hrc_.GetTimeInNsec();
  DumpStats(start_time);

  while (!done_)
  {
    FD_ZERO(&read_fds);
    FD_SET(if1_raw_socket_, &read_fds);
    FD_SET(if2_raw_socket_, &read_fds);
    FD_SET(server_socket, &read_fds);

    //  Wait for a new frame to arrive or for the backstop time.
    timeout.tv_sec  = 0;
    timeout.tv_usec = 0;

    if (select(max_fd + 1, &read_fds, NULL, NULL, &timeout) == -1)
    {
      if (errno == EINTR)
      {
        LogW(kClassName, __func__, "select interrupted\n");
        break;
      }

      LogE(kClassName, __func__, "select failed: %s\n", strerror(errno));
      break;
    }

    // Process delay queue for both interfaces.
    for (int if_num = 0; if_num < NUM_IFS; if_num++)
    {
      Frame*  frame = NULL;
      for (unsigned short path_num = 0; path_num < NUM_PATHS;
           path_num++)
      {
        if (!paths_[if_num][path_num].in_use)
        {
          continue;
        }

        // Service delay queues for if_num interface.
        if (!paths_[if_num][path_num].pd_queue.Empty())
        {
          unsigned long long  current_time_ns = hrc_.GetTimeInNsec();

          if (!paths_[if_num][path_num].pd_queue.Peek(frame))
          {
            // The delay_queue isn't empty and Peek() failed. Something is
            // terribly wrong.
            LogF(kClassName, __func__, "Error peeking at non-empty delay "
                 "queue.\n");
          }

          LogD(kClassName, __func__, "Checking expiration time for "
               "interface %d\n", if_num);

          while (frame->IsTimeToTransmit(current_time_ns))
          {
            // Send frame to other side.
            BridgeFrame(frame);

            if (!paths_[if_num][path_num].pd_queue.Pop(frame))
            {
              // The delay_queue isn't empty and Pop() failed. Something is
              // terribly wrong.
              LogF(kClassName, __func__, "Error popping a non-empty delay "
                     "queue.\n");
            }
            frame_pool_.Recycle(frame);

            if (paths_[if_num][path_num].pd_queue.Empty())
            {
              break;
            }
            else
            {
              if (!paths_[if_num][path_num].pd_queue.Peek(frame))
              {
                // The delay_queue isn't empty and Peek() failed. Something is
                // terribly wrong.
                LogF(kClassName, __func__, "Error peeking at non-empty delay "
                     "queue.\n");
              }
            }
          }
        }
      }
    }

    // Process frames in the path queues.
    TransmitFramesToLanIf();
    TransmitFramesToWanIf();

    // Handle the control interface only if there are no arriving packets on
    // the bridge interfaces.
    if (!FD_ISSET(if1_raw_socket_, &read_fds) &&
        !FD_ISSET(if2_raw_socket_, &read_fds))
    {
      if (FD_ISSET(server_socket, &read_fds))
      {
        if (ProcessCliMsg(server_socket) < 0)
        {
          continue;
        }
      }
    }
    // Grab any newly arriving frames and process them.
    ssize_t  len = 0;
    if (FD_ISSET(if1_raw_socket_, &read_fds))
    {
      Frame*  frame = frame_pool_.Get();
      len = recvfrom(if1_raw_socket_, frame->buffer(),
                     frame->GetMaxSizeBytes(), 0,
                     (struct sockaddr*)&sl, &sllen);

      if (len > 0)
      {
        // Set the src, dst, and length in the frame.
        frame->set_len(len);
        frame->set_src(sl.sll_ifindex);
        frame->set_dst(OtherIF(sl.sll_ifindex));

        ProcessRcvdFrame(frame);
      }
      else if (len <= 0)
      {
        if (errno != EINTR)
        {
          LogE(kClassName, __func__, "recvfrom error: %s\n", strerror(errno));
        }

        frame_pool_.Recycle(frame);
      }
    }

    if (FD_ISSET(if2_raw_socket_, &read_fds))
    {
      Frame*  frame = frame_pool_.Get();
      len = recvfrom(if2_raw_socket_, frame->buffer(),
                     frame->GetMaxSizeBytes(), 0,
                     (struct sockaddr*)&sl, &sllen);

      if (len > 0)
      {
        // Set the src, dst, and length in the frame.
        frame->set_len(len);
        frame->set_src(sl.sll_ifindex);
        frame->set_dst(OtherIF(sl.sll_ifindex));

        ProcessRcvdFrame(frame);
      }
      else if (len <= 0)
      {
        if (errno != EINTR)
        {
          LogE(kClassName, __func__, "recvfrom error: %s\n", strerror(errno));
        }

        frame_pool_.Recycle(frame);
      }
    }

    unsigned long long cur_time = hrc_.GetTimeInNsec();
    if (log_stats_ && (stats_report_time_ns_ < cur_time))
    {
      DumpStats(cur_time);
      stats_report_time_ns_ = cur_time + (stats_report_int_ms_ * 1000000);
    }
  }

  LogI(kClassName, __func__, "Exiting main loop...\n");
  LogI(kClassName, __func__, "Number of packets received not in LinkEm "
       "group: %u\n", not_in_group_cnt_);

  unsigned long long end_time = hrc_.GetTimeInNsec();
  DumpStats(end_time);

  if (server_socket != -1)
  {
    close(server_socket);
    server_socket = -1;
  }
}

//============================================================================
void LinkEm::set_bypass_tos_value(int bypass_tos_value)
{
  LogC(kClassName, __func__, "Setting bypass TOS value to 0x%x.\n",
       bypass_tos_value);

  bypass_tos_value_ = bypass_tos_value;
}

//============================================================================
bool LinkEm::CleanupBridge()
{
  // The interfaces are the same for all the paths, so look at Path 0, which
  // we know will be there.
  return (SetPromiscuous(if1_raw_socket_, paths_[0][0].name, false)
          && SetPromiscuous(if2_raw_socket_, paths_[1][0].name, false));
}

//============================================================================
void LinkEm::ConfigureDefaultPath()
{
  SetInUse(0, 1);
  SetInUse(0, 2);

  SetErrorModel(ERR_MODEL_PACKET, 0, 0);
  SetErrorModel(ERR_MODEL_PACKET, 0, 1);

  paths_[0][0].num_subnets = 1;
  paths_[1][0].num_subnets = 1;
}

//============================================================================
int LinkEm::CreateServerSocket()
{
  int                 server_socket;
  struct sockaddr_in  addr;

  if ((server_socket = socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
    LogE(kClassName, __func__, "Error creating socket: %s\n",
         strerror(errno));
    return -1;
  }

  int  on = 1;
  if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on,
                 sizeof(on)) == -1)
  {
    LogE(kClassName, __func__, "Error setting sockopt SO_REUSADDR: %s\n",
         strerror(errno));
    close(server_socket);
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port        = htons(mgmt_port_);

  if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    LogE(kClassName, __func__, "Error binding socket: %s\n", strerror(errno));
    close(server_socket);
    return -1;
  }

  if (listen(server_socket, 3) < 0)
  {
    LogE(kClassName, __func__, "Listen error: %s\n", strerror(errno));
    close(server_socket);
    return -1;
  }

  return server_socket;
}

//============================================================================
bool LinkEm::InitializeInterfaceLookup(int p, const char* interface)
{
  int           s;
  struct ifreq  ifr;

  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
  {
    LogE(kClassName, __func__, "Error getting special socket: %s\n",
         strerror(errno));
    return false;
  }

  for (int path_num = 0; path_num < NUM_PATHS; path_num++)
  {
    strncpy(paths_[p][path_num].name, interface, IFNAMSIZ);
  }
  memset(&ifr, 0, sizeof(ifr));

  strcpy(ifr.ifr_name, interface);
  ioctl(s, SIOCGIFINDEX, &ifr);

  for (int path_num = 0; path_num < NUM_PATHS; path_num++)
  {
    paths_[p][path_num].index = ifr.ifr_ifindex;
  }

  ioctl(s, SIOCGIFHWADDR, &ifr);
  for (int path_num = 0; path_num < NUM_PATHS; path_num++)
  {
    memcpy(paths_[p][path_num].hardware, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
  }

  LogI(kClassName, __func__, "%d: %s  %s  [%d]\n", p + 1,
       paths_[p][0].name,
       MacFormat((unsigned char*)paths_[p][0].hardware).c_str(),
       paths_[p][0].index);

  ioctl(s, SIOCGIFMTU, &ifr);

  unsigned long long  now = hrc_.GetTimeInNsec();
  for (int path_num = 0; path_num < NUM_PATHS; path_num++)
  {
    paths_[p][path_num].mtu                = ifr.ifr_mtu;
    paths_[p][path_num].max_sd_queue_depth = 128 * 100;

    for (uint8_t bypass_num = 0; bypass_num < 2; bypass_num++)
    {
      paths_[p][path_num].sd_info[bypass_num].credit           = 0;
      paths_[p][path_num].sd_info[bypass_num].queue_size_bytes = 0;
      paths_[p][path_num].sd_info[bypass_num].last_time        = now;
    }
  }

  for (uint8_t bypass_num = 0; bypass_num < 2; bypass_num++)
  {
    access_links_[p][bypass_num].last_time         = now;
    access_links_[p][bypass_num].next_release_time = now;
  }

  return true;
}

//============================================================================
void LinkEm::ProcessRcvdFrame(Frame* frame)
{
  // Ignore frames from interfaces not in LinkEm's group.
  if (!IsLinkEmGroup(frame->src()))
  {
    LogD(kClassName, __func__, "Rcvd. pkt frame in group...\n");
    not_in_group_cnt_++;
    return;
  }

  // Get interface that received this packet.
  int  if_num = IndexIF(frame->src());

  ssize_t  len    = frame->len();
  int     maxMtu = paths_[IndexIF(OtherIF(frame->src()))][0].mtu;
  if (len > maxMtu + (int) sizeof(struct ether_header))
  {
    // XXX Disable generation of PMTU msg and LogF here?
    LogE(kClassName, __func__, "Setting up message too large reply for "
         "packet of length %ld with max MTU of %d\n", len, maxMtu);

    int retLen = SetupPmtuMsg(frame->buffer(), frame->len(), maxMtu);
    if (retLen > 0)
    {
      frame->set_len(retLen);
      BridgeFrame(frame);
      frame_pool_.Recycle(frame);
    }
    return;
  }

  // Get the path index for the packet.
  short  path_num = GetPathNumber(frame, if_num);
  paths_[if_num][path_num].stats.packets_rcvd += 1;
  paths_[if_num][path_num].stats.bytes_rcvd += len;

  int bypass_num;
  HasBypassBitsSet(frame) ? bypass_num = 1 : bypass_num = 0;

  // The serialization delay queue accounting is either in terms of bytes or
  // packets. The PathInfo member variable, sd_queue_size_is_in_bytes,
  // identifies the type of queue accounting that has been configured for the
  // Path.
  if ((paths_[if_num][path_num].sd_queue_size_is_in_bytes &&
      (paths_[if_num][path_num].sd_info[bypass_num].queue_size_bytes <=
       paths_[if_num][path_num].max_sd_queue_depth - len))
       ||
      (!paths_[if_num][path_num].sd_queue_size_is_in_bytes &&
       (int)paths_[if_num][path_num].sd_info[bypass_num].queue.size() <=
       paths_[if_num][path_num].max_sd_queue_depth))
  {
    // The received packet will fit in the queue. First, compute the
    // serialization delay, in nanoseconds. This includes the access link
    // serialization delay and the path serialization delay.
    unsigned long long  total_ser_delay_ns = 0;

    total_ser_delay_ns += GetAccessLinkSerDelay(frame, if_num, bypass_num);
    total_ser_delay_ns += GetPathSerDelay(frame, if_num, path_num,
                                          bypass_num);

    size_t  frame_len = frame->len();

    if (total_ser_delay_ns > 0)
    {
      // Put it in the path buffer.
      frame->set_xmit_timestamp_nsec(hrc_.GetTimeInNsec() +
                                     total_ser_delay_ns);

      if (!paths_[if_num][path_num].sd_info[bypass_num].queue.Push(frame))
      {
        // This should never happen. If it does we are out of memory, so no
        // need to continue.
        LogF(kClassName, __func__, "Error pushing frame to serialization "
             "delay queue.\n");
      }

      paths_[if_num][path_num].sd_info[bypass_num].queue_size_bytes +=
        frame_len;
    }
    else
    {
      ModelErrorAndDelay(frame, path_num);
    }
  }
  else
  {
    // There is no room in the queue, so drop the received packet.
    paths_[if_num][path_num].stats.dropped_q_pkt_cnt++;
    paths_[if_num][path_num].stats.dropped_q_byte_cnt += len;
    frame_pool_.Recycle(frame);
  }
}

//============================================================================
unsigned long long LinkEm::GetAccessLinkSerDelay(Frame* frame, int if_num,
                                                 int bypass_num)
{
  unsigned long long  access_delay = 0;
  unsigned long long  now          = hrc_.GetTimeInNsec();

  if (access_links_[if_num][bypass_num].do_throttle)
  {
    // We have received a packet, so increment the access link credits.

    // Add credits to leaky buckets.
    unsigned int elapsed_time = now -
      access_links_[if_num][bypass_num].last_time;

    // Process the queue for the primary stream
    double credits = (elapsed_time *
                      access_links_[if_num][bypass_num].throttle2)
      + access_links_[if_num][bypass_num].remainder;

    unsigned long long  credit_ull   = (unsigned long long)credits;
    access_links_[if_num][bypass_num].remainder  = credits -
      (double)credit_ull;
    access_links_[if_num][bypass_num].credit    += credit_ull;

    if (access_links_[if_num][bypass_num].credit > 0)
    {
      access_links_[if_num][bypass_num].credit = 0;
    }

    access_delay = (-access_links_[if_num][bypass_num].credit
                    + frame->len()) /
      access_links_[if_num][bypass_num].throttle2;

    // Erode the credits.
    access_links_[if_num][bypass_num].credit -= frame->len();

    // Update the access link check time.
    access_links_[if_num][bypass_num].last_time = now;
  }

  return access_delay;
}

//============================================================================
unsigned long long LinkEm::GetPathSerDelay(Frame* frame, int if_num,
                                           int path_num, int bypass_num)
{
  unsigned long long  path_delay = 0;
  unsigned long long  now        = hrc_.GetTimeInNsec();

  if (paths_[if_num][path_num].do_throttle)
  {
    // We have received a packet, so increment the path credits.

    // Add credits to leaky buckets.
    unsigned int elapsed_time = now -
      paths_[if_num][path_num].sd_info[bypass_num].last_time;

    // Process the queue for the primary stream
    if (!paths_[if_num][path_num].sd_info[bypass_num].queue.Empty())
    {
      double credits = (elapsed_time * paths_[if_num][path_num].throttle2) +
        paths_[if_num][path_num].sd_info[bypass_num].remainder;

      unsigned long long  credit_ull = (unsigned long long)credits;
      paths_[if_num][path_num].sd_info[bypass_num].remainder  = credits -
        (double)credit_ull;
      paths_[if_num][path_num].sd_info[bypass_num].credit   += credit_ull;

      if (paths_[if_num][path_num].sd_info[bypass_num].credit > 0)
      {
        paths_[if_num][path_num].sd_info[bypass_num].credit = 0;
      }
    }
    else
    {
      // If the queue is empty clear the credits to prevent burst of traffic
      // to go through at a rate higher than permitted by the throttle
      // variable.
      paths_[if_num][path_num].sd_info[bypass_num].credit    = 0;
      paths_[if_num][path_num].sd_info[bypass_num].remainder = 0.0;
    }

    path_delay = (-paths_[if_num][path_num].sd_info[bypass_num].credit +
                  frame->len()) /
      paths_[if_num][path_num].throttle2;

    // Erode the credits.
    paths_[if_num][path_num].sd_info[bypass_num].credit -= frame->len();

    // Update the path check time.
    paths_[if_num][path_num].sd_info[bypass_num].last_time = now;
  }

  return path_delay;
}

//============================================================================
void LinkEm::TransmitFramesToWanIf()
{
  Frame*  frame = NULL;

  for (unsigned short path_num = 0; path_num < NUM_PATHS;
       path_num++)
  {
    if (!paths_[kLanIf][path_num].in_use)
    {
      continue;
    }

    for (int bypass_num = 0; bypass_num < 2; bypass_num++)
    {
      // Process the serialization delay queue.
      if (!paths_[kLanIf][path_num].sd_info[bypass_num].queue.Empty())
      {
        unsigned long long  current_time_ns = hrc_.GetTimeInNsec();

        if (!paths_[kLanIf][path_num].sd_info[bypass_num].queue.Peek(frame))
        {
          // The delay_queue isn't empty and Peek() failed. Something is
          // terribly wrong.
          LogF(kClassName, __func__, "Error peeking at non-empty serialization "
               "delay queue.\n");
        }

        while (frame->IsTimeToTransmit(current_time_ns))
        {
          if (!paths_[kLanIf][path_num].sd_info[bypass_num].queue.Pop(frame))
          {
            // The delay_queue isn't empty and Pop() failed. Something is
            // terribly wrong.
            LogF(kClassName, __func__, "Error popping a non-empty "
                 "serialization delay queue.\n");
          }

          paths_[kLanIf][path_num].sd_info[bypass_num].queue_size_bytes -=
            frame->len();
          ModelErrorAndDelay(frame, path_num);

          if (paths_[kLanIf][path_num].sd_info[bypass_num].queue.Empty())
          {
            break;
          }
          else
          {
            if (!paths_[kLanIf][path_num].sd_info[bypass_num].queue.Peek(
                  frame))
            {
              // The delay_queue isn't empty and Peek() failed. Something is
              // terribly wrong.
              LogF(kClassName, __func__, "Error peeking at non-empty "
                   "serialization delay queue.\n");
            }
          }
        }
      }
    }
  }
}

//============================================================================
void LinkEm::TransmitFramesToLanIf()
{
  Frame*  frame = NULL;
  for (uint8_t bypass_num = 0; bypass_num < 2; bypass_num++)
  {
    if (access_links_[kWanIf][bypass_num].do_throttle)
    {
      int                 path_to_svc          = -1;
      bool                found_frame          = true;
      unsigned long long  oldest_frame_time_ns = ULLONG_MAX;
      unsigned long long  current_time_ns      = hrc_.GetTimeInNsec();

      // Process the serialization delay queue.
      if (access_links_[kWanIf][bypass_num].next_release_time <=
          current_time_ns)
      {
        while (found_frame)
        {
          found_frame          = false;
          oldest_frame_time_ns = ULLONG_MAX;
          path_to_svc          = -1;

          for (unsigned short path_num = 0; path_num < NUM_PATHS;
               path_num++)
          {
            if (!paths_[kWanIf][path_num].in_use)
            {
              continue;
            }

            // Service delay queue for if_num interface.
            if (!paths_[kWanIf][path_num].sd_info[bypass_num].queue.Empty())
            {
              if (!paths_[kWanIf][path_num].sd_info[bypass_num].queue.Peek(
                    frame))
              {
                // The delay_queue isn't empty and Peek() failed. Something is
                // terribly wrong.
                LogF(kClassName, __func__, "Error peeking at non-empty delay "
                     "queue.\n");
              }

              unsigned long long  frame_xmit_time_ns =
                frame->xmit_timestamp_nsec();

              if ((frame_xmit_time_ns < current_time_ns)
                  &&
                  (frame_xmit_time_ns < oldest_frame_time_ns))
              {
                path_to_svc          = path_num;
                oldest_frame_time_ns = frame_xmit_time_ns;
                found_frame          = true;
              }
            }
          }

          if (found_frame)
          {
            if (!paths_[kWanIf][path_to_svc].sd_info[bypass_num].queue.Pop(
                  frame))
            {
              // The delay_queue isn't empty and Pop() failed. Something is
              // terribly wrong.
              LogF(kClassName, __func__, "Error popping a non-empty delay "
                   "queue.\n");
            }

            // Send frame to other side.
            BridgeFrame(frame);

            paths_[kWanIf][path_to_svc].sd_info[bypass_num].queue_size_bytes
              -= frame->len();
            frame_pool_.Recycle(frame);

            access_links_[kWanIf][bypass_num].next_release_time =
              MAX(access_links_[kWanIf][bypass_num].next_release_time,
                  current_time_ns - 1000);
            access_links_[kWanIf][bypass_num].next_release_time +=
              frame->len() / access_links_[kWanIf][bypass_num].throttle2;
          }
        }
      }
    }
    else
    {
      // No access link throttling.
      for (unsigned short path_num = 0; path_num < NUM_PATHS;
           path_num++)
      {
        if (!paths_[kWanIf][path_num].in_use)
        {
          continue;
        }

        // Process the serialization delay queue.
        if (!paths_[kWanIf][path_num].sd_info[bypass_num].queue.Empty())
        {
          unsigned long long current_time_ns = hrc_.GetTimeInNsec();

          if (!paths_[kWanIf][path_num].sd_info[bypass_num].queue.Peek(frame))
          {
            // The delay_queue isn't empty and Peek() failed. Something is
            // terribly wrong.
            LogF(kClassName, __func__, "Error peeking at non-empty delay "
                 "queue.\n");
          }

          while (frame->IsTimeToTransmit(current_time_ns))
          {
            if (!paths_[kWanIf][path_num].sd_info[bypass_num].queue.Pop(
                  frame))
            {
              // The delay_queue isn't empty and Pop() failed. Something is
              // terribly wrong.
              LogF(kClassName, __func__, "Error popping a non-empty delay "
                   "queue.\n");
            }

            paths_[kWanIf][path_num].sd_info[bypass_num].queue_size_bytes -=
              frame->len();
            ModelErrorAndDelay(frame, path_num);

            if (paths_[kWanIf][path_num].sd_info[bypass_num].queue.Empty())
            {
              break;
            }
            else
            {
              if (!paths_[kWanIf][path_num].sd_info[bypass_num].queue.Peek(
                    frame))
              {
                // The delay_queue isn't empty and Peek() failed. Something is
                // terribly wrong.
                LogF(kClassName, __func__, "Error peeking at non-empty delay "
                     "queue.\n");
              }
            }
          }
        }
      }
    }
  }
}

//============================================================================
void LinkEm::ModelErrorAndDelay(Frame* frame, short path_num)
{
  int          if_index    = frame->src();
  int          if_num      = IndexIF(if_index);
  ErrorModel*  error_model = paths_[if_num][path_num].error_model;

  if (error_model)
  {
    // There is a loss model, so check for errors.
    if (error_model->CheckForErrors((char*)frame->buffer(), frame->len()))
    {
      paths_[if_num][path_num].stats.dropped_err_pkt_cnt +=1;
      paths_[if_num][path_num].stats.dropped_err_byte_cnt +=frame->len();
      // Do not forward, do not process. Simply drop the data on the floor.
      LogD(kClassName, __func__, "Dropping packet.\n");

      frame_pool_.Recycle(frame);

      return;
    }
  }

  unsigned long long  jitter_nsec = 0;
  if (paths_[if_num][path_num].jitter_model != NULL)
  {
    jitter_nsec =
      paths_[if_num][path_num].jitter_model->GetJitterInNsec();
  }

  unsigned long long  total_delay_nsec =
    paths_[if_num][path_num].delay_ns + jitter_nsec;

  if (total_delay_nsec > 0)
  {
    // Put it in the wait buffer.
    frame->set_xmit_timestamp_nsec(hrc_.GetTimeInNsec() + total_delay_nsec);

    if (!paths_[if_num][path_num].pd_queue.Push(frame))
    {
      // This should never happen. If it does we are out of memory, so no
      // need to continue.
      LogF(kClassName, __func__, "Error pushing frame to delay_queue.\n");
    }
  }
  else
  {
    BridgeFrame(frame);

    frame_pool_.Recycle(frame);
  }
}

//============================================================================
int LinkEm::BridgeFrame(Frame* frame)
{
  // See http://lists.shmoo.com/pipermail/hostap/2015-February/032054.html for
  // explanation for the changes, namely initializing sockaddr_ll structure by
  // using a sockaddr_storage structure.
  //
  // This eliminates a Valgrind error reporting:
  //
  // "Syscall param socketcall.sendto(to.sa_data) points to uninitialised
  // byte(s)"

  struct sockaddr_storage  storage;
  struct sockaddr_ll*      sl;
  memset(&storage, 0, sizeof(storage));

  unsigned char*  buf = frame->buffer();
  sl = (struct sockaddr_ll*)&storage;
  sl->sll_family   = AF_PACKET;
  sl->sll_ifindex  = frame->dst();
  sl->sll_protocol = ntohs(*(unsigned short int *)(buf + 12));
  sl->sll_halen    = 6;
  memcpy(sl->sll_addr, buf, 6);

  ssize_t  length = frame->len();
  ssize_t  result = sendto(paths_[IndexIF(frame->dst())][0].sock, buf,
                           length, 0, (struct sockaddr*)sl, sizeof(*sl));

  int  if_num = IndexIF(frame->src());
  short  path_num = GetPathNumber(frame, if_num);

  paths_[if_num][path_num].stats.packets_sent += 1;
  paths_[if_num][path_num].stats.bytes_sent += length;

  if (result != length)
  {
    LogE(kClassName, __func__, "Error: %s\n", strerror(errno));

    LogE(kClassName, __func__, "sendto failed sending packet of size: %zd "
         "result is %d.\n", length, result);
  }

  return result;
}

//============================================================================
string LinkEm::ProcessCmd(const string& command)
{
  // Following are the commands that may be received:
  //
  //   - Pathx.y:<path parameters>
  //   - AccessLink.x:<access link parameters>
  //   - Bypass=<TOS value>
  //   - Query
  //
  // First, tokenize the command string, utilizing the ':' character as a
  // delimiter.
  List<string>  cmd_tokens;
  StringUtils::Tokenize(command, ":", cmd_tokens);

  string  cmd;
  if (!cmd_tokens.Pop(cmd))
  {
    LogW(kClassName, __func__, "Invalid command string rcvd: %s\n",
         command.c_str());
    return "";
  }

  size_t  pos;

  if ((pos = cmd.find("Path")) != string::npos)
  {
    // We have received the Pathx.y command. Extract the path number and the
    // interface number and then process the received path command.
    size_t  dot_pos  = cmd.find_first_of(".");
    string  path_str = cmd.substr(pos + 4, dot_pos - (pos + 4));
    string  if_str   = cmd.substr(dot_pos + 1);

    uint8_t  path_num = StringUtils::GetInt(path_str);
    uint8_t  if_num   = StringUtils::GetInt(if_str);

    string  path_cmd;
    if (!cmd_tokens.Pop(path_cmd))
    {
      LogW(kClassName, __func__, "Invalid command string rcvd: %s\n",
           command.c_str());
      return "";
    }
    ProcessPathCmd(path_cmd, path_num, if_num);
  }
  else if ((pos = cmd.find("AccessLink")) != string::npos)
  {
    // We have received the AccessLink.x command. Extract the interface number
    // and then process the received access link command.
    size_t  dot_pos  = cmd.find_first_of(".");
    string  if_str   = cmd.substr(dot_pos + 1);

    uint8_t  if_num   = StringUtils::GetInt(if_str);

    string  access_link_cmd;
    if (!cmd_tokens.Pop(access_link_cmd))
    {
      LogW(kClassName, __func__, "Invalid command string rcvd: %s\n",
           command.c_str());
      return "";
    }
    ProcessAccessLinkCmd(access_link_cmd, if_num);
  }
  else if ((pos = cmd.find("Bypass")) != string::npos)
  {
    // We have received the Bypass command. Simply set the bypass value in the
    // LinkEm.
    size_t  equals_pos     = cmd.find("=");
    string  bypass_val_str = cmd.substr(equals_pos + 1);

    set_bypass_tos_value(StringUtils::GetInt(bypass_val_str) & 0xff);
  }
  else if (cmd.compare("Query") == 0)
  {
    // We have received the Query command. Create a string representation of
    // the LinkEm state and send it back to the requester.
    return ToString();
  }
  else if (cmd.compare("StatusCheck") == 0)
  {
    return "LinkEm Operational";
  }
  else if ((pos = cmd.find("StatsReportInt")) != string::npos)
  {
    // We have received the StatsReportInt command. If non-zero, remember that
    // we are logging statistics and set the next statistics report time. If
    // zero, remember that we are no longer logging statistics.
    size_t  equals_pos    = cmd.find("=");
    string  stats_int_str = cmd.substr(equals_pos + 1);

    stats_report_int_ms_  = StringUtils::GetUint64(stats_int_str);

    if (stats_report_int_ms_ == 0)
    {
      log_stats_ = false;
    }
    else
    {
      log_stats_ = true;
      stats_report_time_ns_ = hrc_.GetTimeInNsec() +
        (stats_report_int_ms_ * 1000000);
    }
  }
  else
  {
    LogE(kClassName, __func__, "Unrecognized command: %s\n", command.c_str());
  }

  return "";
}

//============================================================================
void LinkEm::ProcessAccessLinkCmd(const string& access_link_cmd,
                                  uint8_t if_num)
{
  // The access link command includes a single parameter, illustrated below:
  //
  //   t=throttle;
  //
  // First, validate the interface number, which must be 0, 1, or 2.
  if (if_num > 2)
  {
    LogE(kClassName, __func__, "Interface number %" PRIu8 " is out of "
         "range. Must be 0, 1, or 2.\n", if_num);
    return;
  }

  uint8_t  if_index = if_num - 1;

  // Tokenize the path command string, utilizing the ';' character as a
  // delimiter.
  List<string>  access_link_cmd_tokens;
  StringUtils::Tokenize(access_link_cmd, ";", access_link_cmd_tokens);

  string                   token_iter;
  List<string>::WalkState  ws;
  ws.PrepareForWalk();

  while (access_link_cmd_tokens.GetNextItem(ws, token_iter))
  {
    size_t  equals_pos = token_iter.find("=");
    string  name       = token_iter.substr(0, equals_pos);
    string  value      = token_iter.substr(equals_pos + 1);

    if (name == "t")
    {
      // The throttle parameter of the AccessLink command.

      double  access_link_throttle = StringUtils::GetDouble(value, 0.0);

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetAccessLinkThrottle(access_link_throttle, i);
        }
      }
      else
      {
        SetAccessLinkThrottle(access_link_throttle, if_index);
      }
    }
    else
    {
      LogW(kClassName, __func__, "Unrecognized Access Link parameter: %s\n",
           token_iter.c_str());
      return;
    }
  }
}

//============================================================================
void LinkEm::ProcessPathCmd(const string& path_cmd, uint8_t path_num,
                            uint8_t if_num)
{
  // The path command can include a series of path parameters. If more than 1
  // is provided, they are separated by the ';' character as illustrated:
  //
  //   s=address/prefix;E=error_model;
  //     e=<error_model_feature_name=error_model_feature_value>;
  //     J=jitter_model;
  //     j=<jitter_model_feature_name=jitter_model_feature_value>
  //     t=throttle;d=delay;b=buffer;
  //
  // First, validate the path and interface numbers.
  //
  // The path number must be between 0 and NUM_PATHS.
  if (path_num > NUM_PATHS)
  {
    LogE(kClassName, __func__, "Path number %" PRIu8 " is out of range. Must "
         "be between 0 and %d.\n", path_num, NUM_PATHS);
    return;
  }

  // The interface number must be 0, 1, or 2.
  if (if_num > 2)
  {
    LogE(kClassName, __func__, "Interface number %" PRIu8 " is out of "
         "range. Must be 0, 1, or 2.\n", if_num);
    return;
  }

  uint8_t  if_index = if_num - 1;

  // Tokenize the path command string, utilizing the ';' character as a
  // delimiter.
  List<string>  path_cmd_tokens;
  StringUtils::Tokenize(path_cmd, ";", path_cmd_tokens);

  string                   token_iter;
  List<string>::WalkState  ws;
  ws.PrepareForWalk();

  while (path_cmd_tokens.GetNextItem(ws, token_iter))
  {
    size_t  equals_pos = token_iter.find("=");
    string  name       = token_iter.substr(0, equals_pos);
    string  value      = token_iter.substr(equals_pos + 1);

    if (name == "s")
    {
      // The subnet parameter of the Path command.
      if (if_num != 0)
      {
        // It does not make sense to specify the subnet for interface 1 or
        // 2. The subnet specification is the same for each interface.
        LogE(kClassName, __func__, "Unable to specify the subnet for "
             "interface 1 or 2.\n");
        return;
      }

      if (path_num == 0)
      {
        // We don't permit setting the subnet on Path 0. This is a "catch all"
        // Path that will be used if no other subnet matches are found.
        LogE(kClassName, __func__, "Unable to specify the subnet for Path "
             "0.\n");
        return;
      }

      SetSubnets(value, path_num);
    }
    else if (name == "E")
    {
      // The error model parameter of the Path command.

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetErrorModel(value, path_num, i);
        }
      }
      else
      {
        SetErrorModel(value, path_num, if_index);
      }
    }
    else if (name == "e")
    {
      // The error model feature parameter of the Path command. The format of
      // error model features is:
      //
      //  error_model_feature_name=error_model_feature_value

      size_t  feature_equals_pos   = value.find("=");
      string  error_feature_name  = value.substr(0, feature_equals_pos);
      string  error_feature_value = value.substr(feature_equals_pos + 1);

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetErrorModelFeature(error_feature_name, error_feature_value,
                               path_num, i);
        }
      }
      else
      {
        SetErrorModelFeature(error_feature_name, error_feature_value,
                             path_num, if_index);
      }
    }
    else if (name == "J")
    {
      // The jitter model parameter of the Path command.

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetJitterModel(value, path_num, i);
        }
      }
      else
      {
        SetJitterModel(value, path_num, if_index);
      }
    }
    else if (name == "j")
    {
      // The jitter model feature parameter of the Path command. The format of
      // jitter model features is:
      //
      //  jitter_model_feature_name=jitter_model_feature_value

      size_t  feature_equals_pos   = value.find("=");
      string  jitter_feature_name  = value.substr(0, feature_equals_pos);
      string  jitter_feature_value = value.substr(feature_equals_pos + 1);

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetJitterModelFeature(jitter_feature_name, jitter_feature_value,
                                path_num, i);
        }
      }
      else
      {
        SetJitterModelFeature(jitter_feature_name, jitter_feature_value,
                              path_num, if_index);
      }
    }
    else if (name == "t")
    {
      // The throttle parameter of the Path command.

      double  throttle = StringUtils::GetDouble(value, 0.0);

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetThrottle(throttle, path_num, i);
        }
      }
      else
      {
        SetThrottle(throttle, path_num, if_index);
      }
    }
    else if (name == "d")
    {
      // The delay parameter of the Path command.

      int  delay = StringUtils::GetInt(value);

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetDelay(delay, path_num, i);
        }
      }
      else
      {
        SetDelay(delay, path_num, if_index);
      }
    }
    else if (name == "b")
    {
      // The buffer size parameter of the Path command.

      int  buffer_size = StringUtils::GetInt(value);

      if (if_num == 0)
      {
        for (uint8_t  i = 0; i < NUM_IFS; ++i)
        {
          SetMaxSdBufferDepth(buffer_size, path_num, i);
        }
      }
      else
      {
        SetMaxSdBufferDepth(buffer_size, path_num, if_index);
      }
    }
    else if (name == "B")
    {
      if (if_num == 0)
      {
        for (uint8_t i = 0; i < NUM_IFS; ++i)
        {
          SetSdBufferAccountingType(value, path_num, i);
        }
      }
      else
      {
        SetSdBufferAccountingType(value, path_num, if_index);
      }
    }
  }

  // Record that the Interface Record is in use.
  SetInUse(path_num, if_num);
}

//============================================================================
void LinkEm::SetSubnets(const string& subnets_str, uint8_t path_num)
{
  // NOTE: This function will completely replace any exisitng subnet
  // specifications for the Path.
  uint8_t       subnet_num = 0;
  List<string>  subnet_str_tokens;
  StringUtils::Tokenize(subnets_str, ",", subnet_str_tokens);

  string                   token_iter;
  List<string>::WalkState  ws;
  ws.PrepareForWalk();

  while (subnet_str_tokens.GetNextItem(ws, token_iter))
  {
    size_t  slash_pos = token_iter.find("/");
    string  subnet_address_str = token_iter.substr(0, slash_pos);
    string  subnet_prefix_str  = token_iter.substr(slash_pos + 1);

    if (inet_pton(AF_INET, subnet_address_str.c_str(),
                  &(paths_[0][path_num].subnets[subnet_num].address))
        != 1)
    {
      LogE(kClassName, __func__, "Invalid IPv4 address: %s\n",
           subnet_address_str.c_str());
      paths_[0][path_num].subnets[subnet_num].address = 0;
    }
    paths_[1][path_num].subnets[subnet_num].address =
      paths_[0][path_num].subnets[subnet_num].address;

    uint8_t  num_mask_bits = atoi(subnet_prefix_str.c_str());
    paths_[0][path_num].subnets[subnet_num].prefix = num_mask_bits;
    paths_[1][path_num].subnets[subnet_num].prefix = num_mask_bits;

    if (num_mask_bits > 32)
    {
      LogE(kClassName, __func__, "Prefix length, %" PRIu8 " out of range. "
           "Must be between 0 and 32.\n", num_mask_bits);
      paths_[0][path_num].subnets[subnet_num].mask = 0;
    }

    if (num_mask_bits == 0)
    {
      paths_[0][path_num].subnets[subnet_num].mask = 0;
    }
    else
    {
      paths_[0][path_num].subnets[subnet_num].mask =
        htonl((0xffffffff << (32 - num_mask_bits)));
    }
    paths_[1][path_num].subnets[subnet_num].mask =
      paths_[0][path_num].subnets[subnet_num].mask;

    paths_[0][path_num].subnets[subnet_num].subnet =
      paths_[0][path_num].subnets[subnet_num].address &
      paths_[0][path_num].subnets[subnet_num].mask;
    paths_[1][path_num].subnets[subnet_num].subnet =
      paths_[0][path_num].subnets[subnet_num].subnet;

    ++subnet_num;
    if (subnet_num > NUM_SUBNETS)
    {
      LogE(kClassName, __func__, "Received too many subnet "
           "specifications.\n");
      subnet_num = NUM_SUBNETS;
    }
  }

  paths_[0][path_num].num_subnets = subnet_num;
  paths_[1][path_num].num_subnets = subnet_num;
}

//============================================================================
void LinkEm::SetInUse(uint8_t path_num, uint8_t if_num)
{
  uint8_t  counter_start = 0;
  uint8_t  counter_end   = 0;

  if (if_num == 0)
  {
    counter_start = 1;
    counter_end   = 3;
  }
  else
  {
    counter_start = if_num;
    counter_end   = if_num + 1;
  }

  for (uint8_t i = counter_start; i < counter_end; ++i)
  {
    uint8_t  if_index = i - 1;

    if (!paths_[if_index][path_num].in_use)
    {
      paths_[if_index][path_num].in_use = true;
    }
  }
}

//============================================================================
string LinkEm::AddressToString(in_addr_t address) const
{
  char  addr_str[INET_ADDRSTRLEN];

  if (inet_ntop(AF_INET, &address, addr_str, INET_ADDRSTRLEN) == NULL)
  {
    LogE(kClassName, __func__, "Error converting IPv4 address to string\n");
    return "?.?.?.?";
  }

  return addr_str;
}

//============================================================================
string LinkEm::ToString() const
{
  string  ret_str;

  // Add the Access Link information to the string.
  for (uint8_t i = 0; i < 2; i++)
  {
    ret_str.append(StringUtils::FormatString(
                     256, "AccessLink.%" PRIu8 ":t=%f\n", i + 1,
                     access_links_[i][0].throttle));
  }

  // Add the Path information to the string.
  for (uint8_t i = 0; i < NUM_PATHS; i++)
  {
    for (uint8_t j = 0; j < NUM_IFS; j++)
    {
      if (paths_[j][i].in_use)
      {
        ret_str.append(
          StringUtils::FormatString(256, "Path%d.%d:s=", i, j + 1));

        for (uint8_t k = 0; k < paths_[j][i].num_subnets; k++)
        {
          if (k != 0)
          {
            ret_str.append(",");
          }

          ret_str.append(
            StringUtils::FormatString(
              256, "%s/%d",
              AddressToString(paths_[j][i].subnets[k].address).c_str(),
              paths_[j][i].subnets[k].prefix));
        }
        ret_str.append(";");

        if (paths_[j][i].error_model)
        {
          ret_str.append(StringUtils::FormatString(
                           256, "%s;",
                           paths_[j][i].error_model->ToString().c_str()));
        }
        else
        {
          ret_str.append("E=None;");
        }

        if (paths_[j][i].jitter_model)
        {
          ret_str.append(StringUtils::FormatString(
                           256, "%s;",
                           paths_[j][i].jitter_model->ToString().c_str()));
        }
        else
        {
          ret_str.append("J=None;");
        }
        ret_str.append(
          StringUtils::FormatString(256, "t=%f;d=%d;b=%d\n",
                                    paths_[j][i].throttle,
                                    (paths_[j][i].delay_ns / 1000000llu),
                                    paths_[j][i].max_sd_queue_depth));
      }
    }
  }

  return ret_str;
}

//============================================================================
int LinkEm::ProcessCliMsg(int server_socket)
{
  int                 sock = -1;
  socklen_t           addrLen;
  struct sockaddr_in  addr;

  memset(&addr, 0, sizeof(addr));
  addrLen = sizeof(addr);

  // Accept the connection from the client.
  if ((sock = accept(server_socket, (struct sockaddr*)&addr, &addrLen)) < 0)
  {
    LogE(kClassName, __func__, "accept error: %s\n", strerror(errno));
    return -1;
  }

  // Receive the message from the client.
  size_t  len = kMaxMsgSize;
  char    rcv_buf[kMaxMsgSize];
  memset(rcv_buf, 0, sizeof(rcv_buf));

  string  response = "";
  if (recv(sock, (void*)rcv_buf, len, 0) > 0)
  {
    // Process the received command.
    response = ProcessCmd(rcv_buf);
  }
  else
  {
    close(sock);
    return -1;
  }

  if (!response.empty())
  {
    // Send the response to the client.
    if (send(sock, (void*)response.c_str(), response.size(), 0) < 0)
    {
      close(sock);
      return -1;
    }
  }

  close(sock);
  return 0;
}

//==============================================================================
bool LinkEm::SetPromiscuous(int s, const char* interface, bool on)
{
  struct ifreq  ifr;
  memset(&ifr, 0, sizeof(ifr));

  strcpy(ifr.ifr_name, interface);
  int  result = ioctl(s, SIOCGIFFLAGS, &ifr);

  if (result == -1)
  {
    LogE(kClassName, __func__, "Error retrieving interface name: %s\n",
         strerror(errno));
    return false;
  }

  strcpy(ifr.ifr_name, interface);

  if (on)
  {
    ifr.ifr_flags |= IFF_PROMISC;
  }
  else
  {
    ifr.ifr_flags &= ~IFF_PROMISC;
  }

  result = ioctl(s, SIOCSIFFLAGS, &ifr);

  if (result == -1)
  {
    LogE(kClassName, __func__, "Error setting interface flags: %s\n",
         strerror(errno));
    return false;
  }

  LogC(kClassName, __func__, "Promiscuous mode set to %d for interface %s\n",
       on, ifr.ifr_name);

  return true;
}

//============================================================================
bool LinkEm::HasBypassBitsSet(Frame* frame)
{
  if (bypass_tos_value_ == 0)
  {
    return false;
  }

  // See if the packet is an IPv4 packet with the magic TOS bits set.
  unsigned char*  packet = frame->buffer();
  size_t          len    = frame->len();

  // Must at least be long enough to hold an IPv4 header.
  if (len < sizeof(struct ether_header) + sizeof(struct iphdr))
  {
    return false;
  }

  struct ether_header *eth  = (struct ether_header *) (packet);

  // Must be an IP packet.
  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
  {
    return false;
  }

  struct iphdr *ip   = (struct iphdr *) (packet + sizeof(struct ether_header));

  // Must be an IPv4 packet.
  if (ip->version != 4)
  {
    return false;
  }

  // Must have the magic TOS bits set.
  if (ip->tos == bypass_tos_value_)
  {
    return true;
  }

  return false;
}

//============================================================================
uint8_t LinkEm::GetPathNumber(Frame* frame, int if_num)
{
  unsigned char*  packet = frame->buffer();
  size_t          len    = frame->len();

  struct ether_header*  eth_hdr  = (struct ether_header*)(packet);

  // If the packet is not an IP packet, return the "catch all" Path 0.
  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
  {
    return 0;
  }

  // The packet must at least be long enough to hold an IPv4 header.
  if (len < sizeof(struct ether_header) + sizeof(struct iphdr))
  {
    return 0;
  }

  struct iphdr*  ip_hdr =
    (struct iphdr*)(packet + sizeof(struct ether_header));

  // Must be an IPv4 packet.
  if (ip_hdr->version != 4)
  {
    return 0;
  }

  uint32_t  addr;
  if (if_num == 0)
  {
    addr = ip_hdr->saddr;
  }
  else
  {
    addr = ip_hdr->daddr;
  }

  for (uint8_t i = 1; i < NUM_PATHS; i++)
  {
    if (paths_[if_num][i].in_use)
    {
      for (uint8_t j = 0; j < paths_[if_num][i].num_subnets; j++)
      {
        if ((addr & paths_[if_num][i].subnets[j].mask) ==
            paths_[if_num][i].subnets[j].subnet)
        {
          return i;
        }
      }
    }
  }

  return 0;
}

//============================================================================
void LinkEm::SetErrorModel(string model_name, int path_num, int if_num)
{
  string  direction = (if_num == 0) ? "(1-->2)" : "(1<--2)";

  if (paths_[if_num][path_num].error_model != NULL)
  {
    delete paths_[if_num][path_num].error_model;
    paths_[if_num][path_num].error_model = NULL;
  }

  LogC(kClassName, __func__, "MODEL: %s\n", model_name.c_str());

  paths_[if_num][path_num].error_model = ErrorModel::Create(model_name);

  LogC(kClassName, __func__, "Path%d.%d %s, using %s Error Model.\n",
       path_num, (if_num + 1), direction.c_str(),
       paths_[if_num][path_num].error_model == NULL ? "no" :
       paths_[if_num][path_num].error_model->name().c_str());
}

//============================================================================
void LinkEm::SetErrorModelFeature(std::string name, std::string value,
                                  int path_num, int if_num)
{
  std::string direction = (if_num == 0) ? "(1-->2)" : "(1<--2)";

  if (name == "QUERY")
  {
    LogC(kClassName, __func__, "LINKEM CURRENT CONFIGURATION\n");
    for (int if_num = 0; if_num < NUM_IFS; ++if_num)
    {
      string is = GetPathInfo(path_num, if_num).StringPrint();
      LogC(kClassName, "    %s\n", is.c_str());
    }
  }

  if (paths_[if_num][path_num].error_model)
  {
    LogC(kClassName, __func__, "Path%d.%d %s, Telling model to set %s to "
         "%s.\n", path_num, (if_num + 1), direction.c_str(), name.c_str(),
         value.c_str());

    paths_[if_num][path_num].error_model->SetFeature(name, value);
  }
  else
  {
    LogC(kClassName, __func__, "Path%d.%d %s, No model set. Ignoring the "
         "setting of %s to %s.\n", path_num, (if_num + 1), direction.c_str(),
         name.c_str(), value.c_str());
  }
}

//============================================================================
void LinkEm::SetJitterModel(const string& model_name, int path_num,
                            int if_num)
{
  string  direction = (if_num == 0) ? "(1-->2)" : "(1<--2)";

  if (paths_[if_num][path_num].jitter_model != NULL)
  {
    delete paths_[if_num][path_num].jitter_model;
    paths_[if_num][path_num].jitter_model = NULL;
  }

  LogC(kClassName, __func__, "JITTER MODEL: %s\n", model_name.c_str());

  paths_[if_num][path_num].jitter_model = JitterModel::Create(model_name);

  LogC(kClassName, __func__, "Path%d.%d %s, using %s Jitter Model.\n",
       path_num, (if_num + 1), direction.c_str(),
       paths_[if_num][path_num].jitter_model == NULL ? "no" :
       paths_[if_num][path_num].jitter_model->name().c_str());
}

//============================================================================
void LinkEm::SetJitterModelFeature(const string& name, const string& value,
                                   int path_num, int if_num)
{
  string  direction = (if_num == 0) ? "(1-->2)" : "(1<--2)";

  if (paths_[if_num][path_num].jitter_model)
  {
    LogC(kClassName, __func__, "Path%d.%d %s, Telling jitter model to set %s "
         "to %s.\n", path_num, (if_num + 1), direction.c_str(), name.c_str(),
         value.c_str());

    paths_[if_num][path_num].jitter_model->SetFeature(name, value);
  }
  else
  {
    LogC(kClassName, __func__, "Path%d.%d %s, No jitter model set. Unable to "
         "set %s to %s.\n", path_num, (if_num + 1),
         direction.c_str(), name.c_str(), value.c_str());
  }
}

//============================================================================
void LinkEm::SetDelay(int delay_msec, int path_num, int if_num)
{
  paths_[if_num][path_num].delay_ns  =  delay_msec * 1000000llu;
  paths_[if_num][path_num].add_delay = (delay_msec > 0);

  std::string direction = (if_num == 0) ? "(1-->2)" : "(1<--2)";

  if (paths_[if_num][path_num].add_delay)
  {
    LogC(kClassName, __func__, "Path%d.%d %s, delaying frames for %d "
         "milliseconds.\n", path_num, (if_num + 1), direction.c_str(),
         delay_msec);
  }
  else
  {
    LogC(kClassName, __func__, "Path%d.%d %s, No delay\n", path_num,
         (if_num + 1), direction.c_str());
  }
}

//============================================================================
void LinkEm::SetThrottle(double throttle_kbps, int path_num, int if_num)
{
  paths_[if_num][path_num].throttle = throttle_kbps;

  // Convert bps to Bps.
  paths_[if_num][path_num].throttle2   = throttle_kbps / 8000000.0;

  paths_[if_num][path_num].do_throttle = (throttle_kbps > 0.0);

  paths_[if_num][path_num].sd_info[0].remainder = 0.0;
  paths_[if_num][path_num].sd_info[1].remainder = 0.0;

  std::string direction = (if_num == 0) ? "(1-->2)" : "(1<--2)";

  if (paths_[if_num][path_num].do_throttle)
  {
    if (throttle_kbps >= 1000.0)
    {
      LogC(kClassName, __func__, "Path%d.%d %s, throttling to %f Mbps\n",
           path_num, (if_num + 1), direction.c_str(), (throttle_kbps / 1000.0));
    }
    else
    {
      LogC(kClassName, __func__, "Path%d.%d %s, throttling to %f Kbps\n",
           path_num, (if_num + 1), direction.c_str(), throttle_kbps);
    }
  }
  else
  {
    LogC(kClassName, __func__, "Path%d.%d %s, no throttling\n",
         path_num, (if_num + 1), direction.c_str());
  }
}

//============================================================================
void LinkEm::SetAccessLinkThrottle(double throttle_kbps, int if_num)
{
  access_links_[if_num][0].throttle = throttle_kbps;
  access_links_[if_num][1].throttle = throttle_kbps;

  // Convert bps to Bps.
  access_links_[if_num][0].throttle2 = throttle_kbps / 8000000.0;
  access_links_[if_num][1].throttle2 = throttle_kbps / 8000000.0;

  access_links_[if_num][0].remainder   = 0.0;
  access_links_[if_num][1].remainder   = 0.0;
  access_links_[if_num][0].do_throttle = (throttle_kbps > 0.0);
  access_links_[if_num][1].do_throttle = (throttle_kbps > 0.0);

  if (access_links_[if_num][0].do_throttle)
  {
    if (throttle_kbps >= 1000.0)
    {
      LogC(kClassName, __func__, "Interface %d access link, throttling to %f "
           "Mbps.\n", if_num, (throttle_kbps / 1000.0));
    }
    else
    {
      LogC(kClassName, __func__, "Interface %d access link, throttling to %f "
           "Kbps.\n", if_num, throttle_kbps);
    }
  }
  else
  {
    LogC(kClassName, __func__, "Interface %d access link, no throttling.\n");
  }
}

//============================================================================
void LinkEm::SetMaxSdBufferDepth(int buffer_size, int path_num, int if_num)
{
  paths_[if_num][path_num].max_sd_queue_depth = buffer_size;
  LogC(kClassName, __func__, "Setting Path%" PRIu8 ".%" PRIu8
       " buffer size to %d\n", path_num, (if_num + 1), buffer_size);
}

//============================================================================
void LinkEm::SetSdBufferAccountingType(const string& type, int path_num,
                                       int if_num)
{
  if (type == "BYTE")
  {
    paths_[if_num][path_num].sd_queue_size_is_in_bytes = true;
    LogC(kClassName, __func__, "Setting Path%" PRIu8 ".%" PRIu8
         " serialization delay buffer accounting method to bytes.\n",
         path_num, (if_num + 1));
  }
  else if (type == "PKT")
  {
    paths_[if_num][path_num].sd_queue_size_is_in_bytes = false;
    LogC(kClassName, __func__, "Setting Path%" PRIu8 ".%" PRIu8
         " serialization delay buffer accounting method to packets.\n",
         path_num, (if_num + 1));
  }
  else
  {
    LogW(kClassName, __func__, "Unrecognized serialization delay queue "
         "accounting type: %s\n", type.c_str());
  }
}

//============================================================================
bool LinkEm::IsLinkEmGroup(int interface)
{
  // The interfaces are the same for all the paths, so look at Path 0, which
  // we know will be there.
  return ((paths_[0][0].index == interface) ||
          (paths_[1][0].index == interface));
}

//============================================================================
int LinkEm::IndexIF(int if_index)
{
  // The interfaces are the same for all the paths, so look at Path 0, which
  // we know will be there.
  if (paths_[0][0].index == if_index)
  {
    return 0;
  }
  else
  {
    return 1;
  }
}

//============================================================================
int LinkEm::OtherIF(int if_index)
{
  // The interfaces are the same for all the paths, so look at Path 0, which
  // we know will be there.
  if (paths_[0][0].index == if_index)
  {
    return paths_[1][0].index;
  }
  else
  {
    return paths_[0][0].index;
  }
}

//============================================================================
void LinkEm::DumpStats(unsigned long long cur_time)
    {
  for (uint8_t i = 0; i < NUM_PATHS; i++)
  {
    for (uint8_t j = 0; j < NUM_IFS; j++)
    {
      if (paths_[j][i].in_use)
      {

        unsigned long long delta_time = cur_time - paths_[j][i].stats.last_dump;


        if (paths_[j][i].stats.last_dump == 0)
        {
          paths_[j][i].stats.last_dump  = cur_time;
          continue;
        }

        string  if_stats_str;

        if_stats_str.append(
          StringUtils::FormatString(256, "Path%" PRIu8 ".%" PRIu8 " stats:\n",
                i, j+1));

        if_stats_str.append(
            StringUtils::FormatString(256,
                " delta t (ns) = %llu\n", delta_time));

        if_stats_str.append(
          StringUtils::FormatString(256, " Packets Received: %llu ",
                paths_[j][i].stats.packets_rcvd));

        if_stats_str.append(
          StringUtils::FormatString(256, " Bytes Received: %llu \n",
                paths_[j][i].stats.bytes_rcvd));

        if_stats_str.append(
          StringUtils::FormatString(256, " Dropped packet count from buffer "
                "overflow: %zd", paths_[j][i].stats.dropped_q_pkt_cnt));

        if_stats_str.append(
          StringUtils::FormatString(256, " Dropped byte count from buffer "
                "overflow: %zd \n", paths_[j][i].stats.dropped_q_byte_cnt));

        if_stats_str.append(
          StringUtils::FormatString(256, " Dropped packet count from error "
                "model: %zd", paths_[j][i].stats.dropped_err_pkt_cnt));

        if_stats_str.append(
          StringUtils::FormatString(256, " Dropped byte count from error "
                "model: %zd\n", paths_[j][i].stats.dropped_err_byte_cnt));

        if_stats_str.append(
          StringUtils::FormatString(256, " Packets Sent: %llu ",
                paths_[j][i].stats.packets_sent));

        if_stats_str.append(
          StringUtils::FormatString(256, " Bytes Sent: %llu (delta %llu)\n",
                paths_[j][i].stats.bytes_sent));

        LogI(kClassName, __func__, "%s\n", if_stats_str.c_str());

        // Reset stat
        paths_[j][i].stats.last_dump = cur_time;
        paths_[j][i].stats.packets_rcvd = 0;
        paths_[j][i].stats.bytes_rcvd = 0;
        paths_[j][i].stats.dropped_q_pkt_cnt = 0;
        paths_[j][i].stats.dropped_q_byte_cnt = 0;
        paths_[j][i].stats.dropped_err_pkt_cnt = 0;
        paths_[j][i].stats.dropped_err_byte_cnt = 0;
        paths_[j][i].stats.packets_sent = 0;
        paths_[j][i].stats.bytes_sent = 0;
      }
    }
  }
}

//============================================================================
int LinkEm::SetupPmtuMsg(unsigned char* packet,unsigned int len, int max_mtu)
{
  // The packet we are going to create will need to hold an ethernet header,
  // an IP header, and ICMP header, and the first 20 bytes of the input
  // IP header

  if (len < sizeof(struct ether_header) + sizeof(struct iphdr) +
      sizeof(struct icmphdr) + sizeof(struct iphdr))
  {
    return -1;
  }

  struct ether_header* eth  = (struct ether_header*)(packet);
  struct iphdr*        ip   = (struct iphdr*)(packet +
                                              sizeof(struct ether_header));
  struct icmphdr*      icmp = (struct icmphdr*)(packet +
                                                sizeof(struct ether_header)
                                                + sizeof(struct iphdr));
  struct iphdr*        rip  = (struct iphdr*)(packet +
                                              sizeof(struct ether_header)
                                              + sizeof(struct iphdr)
                                              + sizeof(struct icmphdr));

  // Make sure this is an IP packet
  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
  {
    LogE(kClassName, __func__, "Not an IP packet.\n");
    return (-1);
  }

  // Make sure this is IPv4
  if (ip->version != 4)
  {
    LogE(kClassName, __func__, "Not an IPv4 packet: got version %d\n",
         ip->version);
    return (-1);
  }

  // Compute some sizes
  int packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) +
                    sizeof(struct iphdr) + 8;

  int total_size = sizeof(struct ether_header) + packet_size;

  // Swap destination and source MAC addresses
  u_int8_t temp[ETH_ALEN];

  memcpy((void *)&temp[0], (void *)&eth->ether_dhost[0], sizeof(temp));

  memcpy((void *)&eth->ether_dhost[0], (void *)&eth->ether_shost[0],
	 sizeof(eth->ether_dhost));

  memcpy((void *)&eth->ether_shost[0], (void *)&temp[0],
	 sizeof(eth->ether_shost));

  // Copy the IP header to the return portion of the ICMP packet at this point
  // so it is intact (we will begin modifying it shortly)
  memcpy((void *)rip, (void *)ip, sizeof(struct iphdr) + 8);

  // Set the IP header length for our reply packet to have no options
  ip->ihl = sizeof(struct iphdr) / 4;

  // Get the source and destination addresses
  u_int32_t saddr = ip->saddr;
  u_int32_t daddr = ip->daddr;

  // Set the protocol to be ICMP
  ip->tos      = 0;
  ip->tot_len  = htons(packet_size);
  ip->id       = rand();
  ip->frag_off = 0;
  ip->ttl      = 255;
  ip->protocol = IPPROTO_ICMP;
  ip->frag_off = 0;

  // Note that we are swapping source and destination IP addresses also
  ip->saddr = daddr;
  ip->daddr = saddr;

  // Compute the IP checksum
  ip->check = 0;
  ip->check = in_cksum ((unsigned short*) ip, sizeof(struct iphdr));

  // Setup the ICMP information
  icmp->type        = ICMP_DEST_UNREACH;
  icmp->code        = ICMP_FRAG_NEEDED;
  icmp->un.frag.mtu = htons((short)max_mtu);

  // Compute the ICMP checksum
  icmp->checksum = 0;
  icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) +
                                                    sizeof(struct iphdr)   +
                                                    8);

  // All set. Bounce the revised packet back to the caller.
  return (total_size);
}

//============================================================================
unsigned short LinkEm::in_cksum(unsigned short* ptr, int num_bytes)
{
  register long sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while (num_bytes > 1) {
    sum += *ptr++;
    num_bytes -= 2;
  }

  if (num_bytes == 1) {
    oddbyte = 0;
    *((u_char *) & oddbyte) = *(u_char *) ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return (answer);
}

//============================================================================
PathInfo& LinkEm::GetPathInfo(int path_num, int intf)
{
  assert(intf < NUM_IFS);
  assert(path_num < NUM_PATHS);
  return paths_[intf][path_num];
}

//============================================================================
const std::string LinkEm::MacFormat(const unsigned char mac[6]) const
{
  char   mac_str_buf[18];

  snprintf(mac_str_buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return mac_str_buf;
}

//============================================================================
std::string PathInfo::StringPrint()
{
  char  mac_buf[18];
  snprintf(mac_buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X", hardware[0],
           hardware[1], hardware[2], hardware[3], hardware[4], hardware[5]);

  string  ret_str = mac_buf;

  ret_str.append(StringUtils::FormatString(256, "Interface Record:\n"));
  ret_str.append(StringUtils::FormatString(256, "   Name: %s\n", name));
  ret_str.append(StringUtils::FormatString(256, "   MAC: %s\n", mac_buf));
  ret_str.append(StringUtils::FormatString(256, "   Index: %d\n", index));
  ret_str.append(StringUtils::FormatString(256, "   Throttle: %f\n",
                                           throttle));
  ret_str.append(StringUtils::FormatString(256, "   Delay: %ull\n",
                                           (delay_ns / 1000000llu)));

  return ret_str;
}
