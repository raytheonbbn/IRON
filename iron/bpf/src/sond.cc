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

/// \file sond.cc
///
/// The Simple Overlay Network Device (SOND) source file.
///

#include "sond.h"

#include "backpressure_fwder.h"

#include "config_info.h"
#include "iron_constants.h"
#include "list.h"
#include "log.h"
#include "packet_pool.h"
#include "string_utils.h"
#include "timer.h"

#include <string>

#include <cstring>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>


using ::iron::BPFwder;
using ::iron::ConfigInfo;
using ::iron::List;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Sond;
using ::std::string;


//
// Constants.
//
namespace
{
  /// The class name string for logging.
  const char    kClassName[]   = "Sond";

  /// The default server port number.
  const char    kDefaultPort[] = "30200";

  /// The default line rate in Kbps.
  const double  kDefLineRate   = 2.0;

  /// The default control packet transmit queue size in packets.
  const size_t  kControlQueueSize  = 100;

  /// The estimated packet delivery delay (PDD) callback default maximum time
  /// between reports, in seconds.
  const double  kPddCbMaxPeriodSec = 2.000;

  /// The default packet delivery delay (PDD) value to report, in seconds.
  const double  kDefaultPddSec = 0.0;
}


// The state transition diagram for the SOND packet transmission
// implementation is shown below.  The IDLE state occurs when there is no
// packet being transmitted.  The XMIT state occurs when there is a packet
// being transmitted.  The packet transmission timer is set to the packet's
// transmission delay.
//
//                   +----------+
//             ------| Set rate |<-------
//             |     +----------+       | R
//             |                      __|__
//             |                     /     \                                  .
//             |     -------------->| IDLE  |<---------
//             |     |               \_____/          |
//             V     | Yes              |             |
//          /------------\              | P           |
//         | Queue empty? |             |             |
//          \------------/              |             |
//             ^     | No               V             |
//             |     |          +----------------+    |
//             |     |          | Enqueue packet |    |
//             |     |          +----------------+    |
//             |     |                  |             |
//             |     |                  V             |
//             |     |             /----------\       |
//             |     ------------>| Rate > 0 ? |-------
//             |                   \----------/  No
//             |                        | Yes
//             |                        V
//      +-------------+    +--------------------------+
//      | Send packet |    | Dequeue packet           |
//      +-------------+    | Set timer for xmit delay |
//             ^           +--------------------------+
//             |                        |
//             |                      __V__
//             |                  T  /     \  R      +----------+
//             ---------------------| XMIT  |------->| Set rate |
//                                   \_____/<--------|          |
//                                     ^ |           +----------+
//                                     | | P
//                                     | V
//                              +----------------+
//                              | Enqueue packet |
//                              +----------------+
//
// States:
//   IDLE = When xmit_pkt_ptr_ is NULL.
//   XMIT = When xmit_pkt_ptr_ points to a packet.
//
// Events:
//   P = Packet arrives from BPF for transmission.
//   R = Rate change.
//   T = Timer expiration.


//============================================================================
Sond::Sond(BPFwder* bpf, PacketPool& packet_pool, Timer& timer)
    : PathController(bpf), packet_pool_(packet_pool), timer_(timer),
      max_line_rate_(kDefLineRate), local_endpt_(), remote_endpt_(),
      udp_fd_(-1), ef_data_pkt_queue_(packet_pool),
      control_pkt_queue_(packet_pool), data_pkt_queue_(packet_pool),
      qlam_pkt_ptr_(NULL), xmit_pkt_ptr_(NULL), xmit_start_time_(),
      xmit_delta_time_(0.0), xmit_timer_handle_(), total_bytes_queued_(0),
      total_bytes_sent_(0), cb_max_period_(kPddCbMaxPeriodSec),
      cb_pdd_(kDefaultPddSec), cb_prev_time_()
{
  LogI(kClassName, __func__, "Creating Sond...\n");
}

//============================================================================
Sond::~Sond()
{
  LogI(kClassName, __func__, "Destroying Sond %" PRIu32 "...\n",
       path_controller_number_);

  // Close the socket.
  if (udp_fd_ != -1)
  {
    close(udp_fd_);
    udp_fd_ = -1;
  }

  // Free any packets held in pointers.
  if (qlam_pkt_ptr_ != NULL)
  {
    packet_pool_.Recycle(qlam_pkt_ptr_);
    qlam_pkt_ptr_ = NULL;
  }

  if (xmit_pkt_ptr_ != NULL)
  {
    packet_pool_.Recycle(xmit_pkt_ptr_);
    xmit_pkt_ptr_ = NULL;
  }

  // Cancel any timers.
  timer_.CancelTimer(xmit_timer_handle_);

  // Clean up the timer callback object pools.
  CallbackNoArg<Sond>::EmptyPool();
}

//============================================================================
bool Sond::Initialize(const ConfigInfo& config_info, uint32_t config_id)
{
  LogI(kClassName, __func__, "Sond %" PRIu32 ": Initializing...\n",
       config_id);

  // Store the configuration identifier as this SOND's number.
  path_controller_number_ = config_id;

  // Construct the prefix for the configuration names.
  string  config_prefix("PathController.");
  config_prefix.append(StringUtils::ToString(static_cast<int>(config_id)));

  // Extract the label, if any.
  string  config_name = config_prefix;
  config_name.append(".Label");
  label_ = config_info.Get(config_name);

  // Extract the endpoint IPv4 addresses and optional UDP port numbers.
  config_name = config_prefix;
  config_name.append(".Endpoints");
  endpoints_str_ = config_info.Get(config_name);

  if (!ParseEndpointsString(endpoints_str_))
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Error, invalid endpoints: "
         "%s\n", path_controller_number_, endpoints_str_.c_str());
    return false;
  }

  // Extract the maximum line rate, in kilobits per second.
  config_name = config_prefix;
  config_name.append(".MaxLineRateKbps");
  max_line_rate_ = config_info.GetDouble(config_name, kDefLineRate);

  if (max_line_rate_ < 0.0)
  {
    LogE(kClassName, __func__,  "Sond %" PRIu32 ": Invalid maximum line rate "
         "%f kbps specified.\n", path_controller_number_, max_line_rate_);
    return false;
  }

  // Extract the estimated packet delivery delay (PDD) value, in seconds.
  config_name = config_prefix;
  config_name.append(".EstPddSec");
  cb_pdd_ = config_info.GetDouble(config_name, kDefaultPddSec);

  if (cb_pdd_ < 0.000001)
  {
    LogD(kClassName, __func__,  "Sond %" PRIu32 ": PDD %f seconds specified, "
         "disabling PDD reporting.\n", path_controller_number_, cb_pdd_);
  }

  // Compute and set the data packet transmit queue size in packets.
  size_t  xmit_thresh = config_info.GetUint("Bpf.XmitQueueThreshBytes",
                                            kDefaultBpfXmitQueueThreshBytes);
  size_t  data_queue_size = COMPUTE_XMIT_QUEUE_SIZE(xmit_thresh);

  ef_data_pkt_queue_.SetQueueLimits(data_queue_size);
  ef_data_pkt_queue_.set_drop_policy(NO_DROP);

  data_pkt_queue_.SetQueueLimits(data_queue_size);
  data_pkt_queue_.set_drop_policy(NO_DROP);

  // Set the maximum control packet transmit queue size, in packets.
  control_pkt_queue_.SetQueueLimits(kControlQueueSize);
  control_pkt_queue_.set_drop_policy(NO_DROP);

  // Create the UDP socket to communicate with the remote SOND.
  if ((udp_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
  {
    LogF(kClassName, __func__, "Sond %" PRIu32 ": Error creating socket: "
         "%s\n", path_controller_number_, strerror(errno));
    return false;
  }

  // Enable port number reuse on the socket.
  int  opt_val = 1;

  if (setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEPORT, &opt_val,
                 sizeof(opt_val)) < 0)
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Error enabling port number "
         "reuse: %s\n", path_controller_number_, strerror(errno));
    return false;
  }

  // Bind the socket to the local address.
  struct sockaddr_in  addr;

  local_endpt_.ToSockAddr(reinterpret_cast<struct sockaddr*>(&addr));

  if (bind(udp_fd_, reinterpret_cast<struct sockaddr*>(&addr),
           sizeof(addr)) < 0)
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Error binding local "
         "address %s: %s\n", path_controller_number_,
         local_endpt_.ToString().c_str(), strerror(errno));
    return false;
  }

  // Connect the socket to the remote address.
  remote_endpt_.ToSockAddr(reinterpret_cast<struct sockaddr*>(&addr));

  if (connect(udp_fd_, reinterpret_cast<struct sockaddr *>(&addr),
              sizeof(addr)) < 0)
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Error connecting to remote "
         "address %s: %s\n", path_controller_number_,
         remote_endpt_.ToString().c_str(), strerror(errno));
    return false;
  }

  // Log the configuration information.
  LogC(kClassName, __func__, "Sond %" PRIu32 " configuration:\n",
       path_controller_number_);

  LogC(kClassName, __func__, "Type                        : Sond\n");
  LogC(kClassName, __func__, "Label                       : %s\n",
       label_.c_str());
  LogC(kClassName, __func__, "Endpoints                   : %s->%s\n",
       local_endpt_.ToString().c_str(), remote_endpt_.ToString().c_str());
  LogC(kClassName, __func__, "Max Line Rate               : %f Kbps\n",
       max_line_rate_);
  LogC(kClassName, __func__, "EF Data Transmit Queue Size : %zu packets\n",
       data_queue_size);
  LogC(kClassName, __func__, "Data Transmit Queue Size    : %zu packets\n",
       data_queue_size);
  LogC(kClassName, __func__, "Control Transmit Queue Size : %zu packets\n",
       kControlQueueSize);
  LogC(kClassName, __func__, "PDD Maximum Period          : %f seconds\n",
       cb_max_period_);
  LogC(kClassName, __func__, "PDD Value                   : %f seconds\n",
       cb_pdd_);

  LogC(kClassName, __func__, "Sond %" PRIu32 " configuration complete.\n",
       path_controller_number_);

  bpf_->ProcessCapacityUpdate(this, (max_line_rate_ * 1000.0),
                              (max_line_rate_ * 800.0));

  return true;
}

//============================================================================
bool Sond::ConfigurePddReporting(double thresh, double min_period,
                                 double max_period)
{
  // Validate the parameters.
  if ((thresh < 0.00001) || (min_period < 0.000001) ||
      (max_period < 0.000001) || (min_period >= max_period))
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Error configuring PDD "
         "with thresh=%f min_period=%f max_period=%f.\n",
         path_controller_number_, thresh, min_period, max_period);
    return false;
  }

  // Store the new parameters.
  cb_max_period_ = max_period;

  LogC(kClassName, __func__, "Sond %" PRIu32 " PDD reconfiguration:\n",
       path_controller_number_);

  LogC(kClassName, __func__, "PDD Maximum Period : %f\n",
       cb_max_period_);

  return true;
}

//============================================================================
bool Sond::SendPacket(Packet* pkt)
{
  DoCallbacks();

  if (pkt == NULL)
  {
    return false;
  }

  // Get the packet's type.
  int  pkt_type = pkt->GetRawType();

  // Add any necessary Packet object metadata headers to the packet before it
  // is sent.
  if (NeedsMetadataHeaders(pkt))
  {
    if (!AddMetadataHeaders(pkt))
    {
      LogE(kClassName, __func__, "Sond %" PRIu32 ": Error adding necessary "
           "metadata headers to packet.\n", path_controller_number_);
    }
  }
  else
  {
    pkt->SetMetadataHeaderLengthInBytes(0);
  }

  // Get the resulting packet's length in bytes.
  size_t  pkt_len  = (pkt->GetMetadataHeaderLengthInBytes() +
                      pkt->GetLengthInBytes());
  size_t  drop_len = 0;

  // Enqueue the packet based on its type.
  switch (pkt_type)
  {
    case IPV4_PACKET:
      if (pkt->GetLatencyClass() == LOW_LATENCY)
      {
        if (!ef_data_pkt_queue_.Enqueue(pkt))
        {
          LogF(kClassName, __func__, "Sond %" PRIu32 ": EF data packet "
               "transmit queue overflow.\n", path_controller_number_);
          return false;
        }

        LogD(kClassName, __func__, "EF DATA: Enqueued in Sond %" PRIu32
             ", %zu bytes.\n", path_controller_number_, pkt_len);
      }
      else
      {
        if (!data_pkt_queue_.Enqueue(pkt))
        {
          LogF(kClassName, __func__, "Sond %" PRIu32 ": Data packet transmit "
               "queue overflow.\n", path_controller_number_);
          return false;
        }

        LogD(kClassName, __func__, "DATA: Enqueued in Sond %" PRIu32 ", %zu "
             "bytes.\n", path_controller_number_, pkt_len);
      }
      break;

    case QLAM_PACKET:
      // Store this new QLAM packet, replacing any old QLAM packet.
      if (qlam_pkt_ptr_ != NULL)
      {
        drop_len = (qlam_pkt_ptr_->GetMetadataHeaderLengthInBytes() +
                    qlam_pkt_ptr_->GetLengthInBytes());
        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        packet_pool_.Recycle(qlam_pkt_ptr_);
        qlam_pkt_ptr_ = NULL;
      }

      qlam_pkt_ptr_ = pkt;

      LogD(kClassName, __func__, "QLAM: Enqueued in Sond %" PRIu32 ", %zu "
           "bytes\n", path_controller_number_, pkt_len);
      break;

    case LSA_PACKET:
      if (!control_pkt_queue_.Enqueue(pkt))
      {
        LogF(kClassName, __func__, "Sond %" PRIu32 ": Control packet "
             "transmit queue overflow.\n", path_controller_number_);
        return false;
      }

      LogD(kClassName, __func__, "LSA: Enqueued in Sond %" PRIu32 ", %zu "
           "bytes\n", path_controller_number_, pkt_len);
      break;

    case ZOMBIE_PACKET:
      if (!data_pkt_queue_.Enqueue(pkt))
      {
        LogF(kClassName, __func__, "Sond %" PRIu32 ": Data packet transmit "
             "queue overflow.\n", path_controller_number_);
        return false;
      }

      LogD(kClassName, __func__, "ZOMBIE: Enqueued in Sond %" PRIu32 ", %zu "
           "bytes.\n", path_controller_number_, pkt_len);
      break;

    default:
      LogE(kClassName, __func__, "Sond %" PRIu32 ": Unknown packet type "
           "%d (0x%02x).\n", path_controller_number_, pkt_type,
           static_cast<unsigned int>(pkt_type));
      return false;
  }

  // Update the total number of bytes queued.  Note that this only works
  // correctly when the three PacketQueue objects have their drop policies set
  // to NO_DROP.
  total_bytes_queued_ -= drop_len;
  total_bytes_queued_ += pkt_len;

  // If we are currently IDLE and there is a non-zero rate, then reset the
  // start time and schedule the next transmission.
  if ((xmit_pkt_ptr_ == NULL) && (max_line_rate_ > 0.0))
  {
    if (xmit_start_time_.GetNow())
    {
      xmit_delta_time_ = 0.0;
      ScheduleNextPacket(xmit_start_time_);
    }
    else
    {
      LogF(kClassName, __func__, "Unable to get current time.\n");
    }
  }

  return true;
}

//============================================================================
void Sond::ServiceFileDescriptor(int fd, FdEvent event)
{
  DoCallbacks();

  if (event != kFdEventRead)
  {
    LogW(kClassName, __func__, "Only file descriptor read events are "
         "supported.\n");
    return;
  }

  Packet*  packet = packet_pool_.Get(PACKET_NOW_TIMESTAMP);

  if (packet == NULL)
  {
    LogF(kClassName, __func__, "Unable to allocate Packet.\n");
    return;
  }

  // Receive the next packet from the UDP socket.
  ssize_t  bytes_read = ::recv(fd, packet->GetBuffer(),
                               packet->GetMaxLengthInBytes(), 0);

  if (bytes_read > 0)
  {
    LogD(kClassName, __func__, "RECV: Sond %" PRIu32
         ", pkt size: %zd bytes\n", path_controller_number_, bytes_read);

    packet->SetLengthInBytes(bytes_read);

    // Process and remove any Packet object metadata headers from the packet.
    if (!ProcessMetadataHeaders(packet))
    {
      LogE(kClassName, __func__, "Sond %" PRIu32 ": Error processing "
           "metadata headers.\n", path_controller_number_);
    }

    if (bpf_ != NULL)
    {
      // Pass the packet to the BPF for processing.
      bpf_->ProcessRcvdPacket(packet, this);
    }
    else
    {
      LogF(kClassName, __func__, "BPF pointer is NULL.\n");
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(packet);
    }
  }
  else if (bytes_read == 0)
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Zero byte recv().\n",
         path_controller_number_);

    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
  }
  else
  {
    // Do not log connection refused errors.  These are caused by the peer's
    // socket not being open yet, which can happen at the beginning or end of
    // a connection.
    if (errno != ECONNREFUSED)
    {
      LogE(kClassName, __func__, "Sond %" PRIu32 ": Error in recv(): %s\n",
           path_controller_number_, strerror(errno));
    }

    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
  }
}

//============================================================================
size_t Sond::GetFileDescriptors(FdEventInfo* fd_event_array,
                                size_t array_size) const
{
  if (array_size == 0)
  {
    return 0;
  }

  fd_event_array[0].fd     = udp_fd_;
  fd_event_array[0].events = kFdEventRead;

  return 1;
}

//============================================================================
bool Sond::GetXmitQueueSize(size_t& size) const
{
  // Include all queued data and QLAM packets.
  size = total_bytes_queued_;

  return true;
}

//============================================================================
bool Sond::SetParameter(const char* name, const char* value)
{
  string  name_str(name);

  if (name_str == "MaxLineRateKbps")
  {
    return SetMaxLineRate(value);
  }

  LogE(kClassName, __func__, "Sond %" PRIu32 ": Unknown configuration "
       "parameter name \"%s\".\n", name);

  return false;
}

//============================================================================
bool Sond::GetParameter(const char* name, string& value) const
{
  string  name_str(name);

  if (name_str == "MaxLineRateKbps")
  {
    value = StringUtils::ToString(max_line_rate_);

    return true;
  }

  LogE(kClassName, __func__, "Sond %" PRIu32 ": Unknown configuration "
       "parameter name \"%s\".\n", name);

  return false;
}

//============================================================================
bool Sond::ParseEndpointsString(const string& ep_str)
{
  // The format to parse is:
  //   LOCAL_IP[:LOCAL_PORT]->REMOTE_IP[:REMOTE_PORT]

  // Start by tokenizing on the required "->" characters.
  List<string>  tokens;
  StringUtils::Tokenize(ep_str, "->", tokens);

  if (tokens.size() != 2)
  {
    return false;
  }

  string  lep_str;
  string  rep_str;
  tokens.Pop(lep_str);
  tokens.Peek(rep_str);

  // IPv4 addresses in dot-decimal notation require at least 7 characters.
  if ((lep_str.size() < 7) || (rep_str.size() < 7))
  {
    return false;
  }

  // Add the default port number if port numbers are not specified.
  if (lep_str.find(":") == string::npos)
  {
    lep_str.append(":");
    lep_str.append(kDefaultPort);
  }

  if (rep_str.find(":") == string::npos)
  {
    rep_str.append(":");
    rep_str.append(kDefaultPort);
  }

  // Convert the strings to endpoints.
  if ((!local_endpt_.SetEndpoint(lep_str)) ||
      (!remote_endpt_.SetEndpoint(rep_str)))
  {
    return false;
  }

  // The addresses and port numbers must not be zero.
  if ((local_endpt_.address() == 0) || (local_endpt_.port() == 0) ||
      (remote_endpt_.address() == 0) || (remote_endpt_.port() == 0))
  {
    return false;
  }

  return true;
}

//============================================================================
bool Sond::SetMaxLineRate(const char* value)
{
  double  rate = StringUtils::GetDouble(value, -1.0);

  if (rate < 0.0)
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Maximum line rate change "
         "failed, bad rate %f kbps specified, leaving at %f kbps.\n",
         path_controller_number_, rate, max_line_rate_);
    return false;
  }

  LogI(kClassName, __func__, "Sond %" PRIu32 ": Maximum line rate change "
       "from %f kbps to %f kbps.\n", path_controller_number_, max_line_rate_,
       rate);

  // Update the maximum line rate.
  max_line_rate_ = rate;

  // If we are currently IDLE, there is a non-zero rate, and there is a packet
  // ready to transmit, then reset the start time and schedule the next
  // transmission.
  if ((xmit_pkt_ptr_ == NULL) && (max_line_rate_ > 0.0) &&
      IsPacketReadyToXmit())
  {
    if (xmit_start_time_.GetNow())
    {
      xmit_delta_time_ = 0.0;
      ScheduleNextPacket(xmit_start_time_);
    }
    else
    {
      LogF(kClassName, __func__, "Unable to get current time.\n");
    }
  }

  bpf_->ProcessCapacityUpdate(this, (max_line_rate_ * 1000.0),
                              (max_line_rate_ * 800.0));

  return true;
}

//============================================================================
void Sond::DoCallbacks()
{
  // Get the current time.
  Time  now = Time::Now();

  // Report the estimated packet delivery delay (PDD) to the backpressure
  // forwarder if too much time has passed since the last report.
  if ((cb_pdd_ >= 0.000001) && (now > cb_prev_time_.Add(cb_max_period_)))
  {
    // Update the report time first due to possible re-entrant calls.
    cb_prev_time_ = now;

    bpf_->ProcessPktDelDelay(this, cb_pdd_, 0.0);
  }
}

//============================================================================
void Sond::ScheduleNextPacket(const Time& now)
{
  // Send as many packets that are ready for transmitting as possible until
  // either the queue is empty or a timer needs to be set.
  while (true)
  {
    // Dequeue the next QLAM, control, or data packet to transmit.
    if (qlam_pkt_ptr_ != NULL)
    {
      xmit_pkt_ptr_ = qlam_pkt_ptr_;
      qlam_pkt_ptr_ = NULL;
    }
    else if (ef_data_pkt_queue_.GetCount() > 0)
    {
      xmit_pkt_ptr_ = ef_data_pkt_queue_.Dequeue();

      if (xmit_pkt_ptr_ == NULL)
      {
        LogE(kClassName, __func__, "Sond %" PRIu32 ": Dequeued NULL packet "
             "from EF data transmit queue.\n", path_controller_number_);
        break;
      }
    }
    else if (control_pkt_queue_.GetCount() > 0)
    {
      xmit_pkt_ptr_ = control_pkt_queue_.Dequeue();

      if (xmit_pkt_ptr_ == NULL)
      {
        LogE(kClassName, __func__, "Sond %" PRIu32 ": Dequeued NULL packet "
             "from control transmit queue.\n", path_controller_number_);
        break;
      }
    }
    else if (data_pkt_queue_.GetCount() > 0)
    {
      xmit_pkt_ptr_ = data_pkt_queue_.Dequeue();

      if (xmit_pkt_ptr_ == NULL)
      {
        LogE(kClassName, __func__, "Sond %" PRIu32 ": Dequeued NULL packet "
             "from data transmit queue.\n", path_controller_number_);
        break;
      }
    }
    else
    {
      LogD(kClassName, __func__, "Sond %" PRIu32 ": Transmit queues now "
           "empty.\n", path_controller_number_);
      break;
    }

    // Update the total number of bytes queued.  Note that this only works
    // correctly when the three PacketQueue objects have their drop policies
    // set to NO_DROP.
    size_t  pkt_len = (xmit_pkt_ptr_->GetMetadataHeaderLengthInBytes() +
                       xmit_pkt_ptr_->GetLengthInBytes());

    total_bytes_queued_ -= pkt_len;

    // Compute the packet's send time, taking into account its transmission
    // delay.  It is the transmission delay for each packet that controls the
    // overall transmission rate.
    Time    xmit_time(xmit_start_time_);
    double  delta_sec = ((static_cast<double>(pkt_len) * 8.0) /
                         (max_line_rate_ * 1000.0));
    xmit_delta_time_ += delta_sec;
    xmit_time         = xmit_time.Add(xmit_delta_time_);

    LogD(kClassName, __func__, "TIMER: Sond %" PRIu32 ": Scheduling packet, "
         "now = %s, xmit_start_time_ = %s, delta_sec = %f sec, "
         "xmit_delta_time_ = %f sec, xmit_time = %s, %zu bytes.\n",
         path_controller_number_, now.ToString().c_str(),
         xmit_start_time_.ToString().c_str(), delta_sec, xmit_delta_time_,
         xmit_time.ToString().c_str(), pkt_len);

    // Compare now with the packet's transmission time.
    if (xmit_time <= now)
    {
      // No need for setting a timer.  Send the packet now.  When this
      // returns, xmit_pkt_ptr_ is guaranteed to be set to NULL.
      XmitPacket();
    }
    else
    {
      // Set a timer for the packet's transmission time.
      Time                 delta_time = xmit_time - now;
      CallbackNoArg<Sond>  cb(this, &Sond::TimerCallback);

      if (!timer_.StartTimer(delta_time, &cb, xmit_timer_handle_))
      {
        LogF(kClassName, __func__, "Sond %" PRIu32 ": Error starting timer "
           "for %s.\n", path_controller_number_, delta_time.ToString().c_str());
      }

      break;
    }
  }
}

//============================================================================
void Sond::TimerCallback()
{
  // Transmit the packet stored in xmit_pkt_ptr_ now that its transmission
  // delay is over.  When this returns, xmit_pkt_ptr_ is guaranteed to be set
  // to NULL.
  XmitPacket();

  // We are now IDLE (xmit_pkt_ptr_ is NULL).  If there is a non-zero rate,
  // and there is a packet ready to transmit, then schedule the next
  // transmission.  Do not reset the start time.
  if ((max_line_rate_ > 0.0) && IsPacketReadyToXmit())
  {
    Time  now;

    if (now.GetNow())
    {
      ScheduleNextPacket(now);
    }
    else
    {
      LogF(kClassName, __func__, "Unable to get current time.\n");
    }
  }
}

//============================================================================
void Sond::XmitPacket()
{
  if (xmit_pkt_ptr_ == NULL)
  {
    return;
  }

  // Send the packet stored in xmit_pkt_ptr_.
  size_t  pkt_len = static_cast<size_t>(
    xmit_pkt_ptr_->GetMetadataHeaderLengthInBytes() +
    xmit_pkt_ptr_->GetLengthInBytes());

  ssize_t  bytes_sent = send(udp_fd_,
                             xmit_pkt_ptr_->GetMetadataHeaderBuffer(),
                             pkt_len, 0);

  if (bytes_sent >= 0)
  {
    if (bytes_sent == static_cast<ssize_t>(pkt_len))
    {
      LogD(kClassName, __func__, "SEND: Sond %" PRIu32 ", packet size: %zd "
           "bytes.\n", path_controller_number_, bytes_sent);

      total_bytes_sent_ += static_cast<uint32_t>(bytes_sent);
    }
    else
    {
      LogE(kClassName, __func__, "Error: Sond %" PRIu32 ": sent %zd bytes of "
           "%zu byte packet.\n", path_controller_number_, bytes_sent, pkt_len);
    }
  }
  else
  {
    LogE(kClassName, __func__, "Sond %" PRIu32 ": Error in sendto(): %s.\n",
         path_controller_number_, strerror(errno));
  }

  // Delete the packet.
  packet_pool_.Recycle(xmit_pkt_ptr_);
  xmit_pkt_ptr_ = NULL;
}
