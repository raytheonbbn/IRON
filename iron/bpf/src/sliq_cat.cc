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

/// \file sliq_cat.cc
///
/// The Simple Lightweight IPv4 QUIC (SLIQ) Capacity Adaptive Tunnel (CAT)
/// source file.
///

#include "sliq_cat.h"

#include "backpressure_fwder.h"

#include "config_info.h"
#include "iron_constants.h"
#include "list.h"
#include "log.h"
#include "packet_pool.h"
#include "string_utils.h"
#include "timer.h"
#include "unused.h"

#include <string>

#include <inttypes.h>
#include <math.h>


using ::iron::ConfigInfo;
using ::iron::Ipv4Endpoint;
using ::iron::List;
using ::iron::Log;
using ::iron::PacketPool;
using ::iron::SliqCat;
using ::iron::Time;
using ::iron::Timer;
using ::sliq::CongCtrl;
using ::sliq::DeliveryMode;
using ::sliq::EndptId;
using ::sliq::PktTimestamp;
using ::sliq::RttPdd;
using ::sliq::Priority;
using ::sliq::Reliability;
using ::sliq::ReliabilityMode;
using ::sliq::StreamId;
using ::sliq::RexmitLimit;
using ::std::string;


namespace
{
  /// The class name string for logging.
  const char         kClassName[]              = "SliqCat";

  /// The default server port number.
  const char         kDefaultServerPort[]      = "30300";

  /// The QLAM packet SLIQ stream ID.
  const StreamId     kQlamStreamId             = 1;

  /// The EF data packet SLIQ stream ID.
  const StreamId     kEfDataStreamId           = 3;

  /// The system-level control packet SLIQ stream ID.
  const StreamId     kControlStreamId          = 5;

  /// The non-EF data packet and flow-level control packet SLIQ stream ID.
  const StreamId     kDataStreamId             = 7;

  /// The capacity estimate packet SLIQ stream ID.
  const StreamId     kCapEstStreamId           = 9;

  /// The QLAM packet SLIQ stream priority.
  const Priority     kQlamStreamPriority       = 2;

  /// The EF data packet SLIQ stream priority.
  const Priority     kEfDataStreamPriority     = 3;

  /// The system-level control packet SLIQ stream priority.
  const Priority     kControlStreamPriority    = 4;

  /// The non-EF data packet and flow-level control packet SLIQ stream
  /// priority.
  const Priority     kDataStreamPriority       = 5;

  /// The capacity estimate packet SLIQ stream priority.
  const Priority     kCapEstStreamPriority     = 7;

  /// The EF data packet SLIQ stream semi-reliable ARQ retransmission limit.
  const RexmitLimit  kEfDataArqRexmitLimit     = 5;

  /// The EF data packet SLIQ stream semi-reliable ARQ+FEC retransmission
  /// limit.
  const RexmitLimit  kEfDataArqFecRexmitLimit  = 30;

  /// The system-level control packet SLIQ stream semi-reliable retransmission
  /// limit.
  const RexmitLimit  kControlRexmitLimit       = 5;

  /// The non-EF data packet and flow-level control packet SLIQ stream
  /// semi-reliable retransmission limit.
  const RexmitLimit  kDataRexmitLimit          = 5;

  /// The QLAM packet transmit queue size in packets.
  const size_t       kQlamXmitQueuePkts        = 1;

  /// The default data packet transmit queue size in packets.
  const size_t       kDefaultDataXmitQueuePkts = 200;

  /// The system-level control packet transmit queue size in packets.
  const size_t       kControlXmitQueuePkts     = 100;

  /// The capacity estimate packet transmit queue size in packets.  This
  /// limits the maximum number of packets that can be sent in each callback.
  const size_t       kCapEstXmitQueuePkts      = 250;

  /// The minimum Copa constant delta value.
  const double       kMinCopaConstDelta        = 0.004;

  /// The maximum Copa constant delta value.
  const double       kMaxCopaConstDelta        = 1.0;

  /// The connection retry timer interval, in seconds.
  const int          kConnRetrySec             = 1;

  /// The number of client connection attempts before an error message.
  const int          kClientConnAttempts       = 5;

  /// The CCE packet scaling factor for storing the capacity estimate in a
  /// 24-bit field.
  const double       kCceCapEstScaleFactor     = 1000.0;

  /// The maximum capacity estimate time since the last congestion control
  /// limit event, in seconds.
  const double       kCapEstCclSec             = 20.0;

  /// The minimum capacity estimate inter-send callback time, in seconds.
  const double       kCapEstMinIstSec          = 0.001;

  /// The maximum capacity estimate inter-send callback time, in seconds.
  const double       kCapEstMaxIstSec          = 0.1;

  /// The capacity estimation default duration in seconds.
  const double       kCapEstDefDurSec          = 2.5;

  /// The capacity estimate packet size, in bytes.
  const size_t       kCapEstPktSizeBytes       = 1000;

  /// The minimum number of packets to keep in the capacity estimate stream
  /// transmit queue.
  const size_t       kCapEstMinXmitQueuePkts   = 2;

  /// The minimum CCE packet send timer interval, in seconds.
  const double       kMinCceSendSec            = 0.1;

  /// The RTT bound smoothed RTT alpha parameter.
  const double       kRttBoundAlpha            = 0.001;

  /// The RTT bound RTT variation beta parameter.
  const double       kRttBoundBeta             = 0.002;

  /// The RTT bound K parameter.
  const double       kRttBoundK                = 1.7;

  /// The smoothed packet delivery delay (PDD) alpha parameter.
  const double       kPddAlpha                 = 0.003;

  /// The number of initial PDD measurements to ignore.
  const size_t       kPddIgnoreCnt             = 4;

  /// The EF data PDD stale time, in milliseconds.
  const int64_t      kEfPddStaleTimeMsec       = 250;

  /// The PDD callback default change threshold for reporting.
  const double       kPddCbThresh              = 0.10;

  /// The PDD callback default minimum time between reports, in seconds.
  const double       kPddCbMinPeriodSec        = 0.100;

  /// The PDD callback default maximum time between reports, in seconds.
  const double       kPddCbMaxPeriodSec        = 2.000;
}


//============================================================================
SliqCat::PddInfo::PddInfo()
    : ignore_cnt_(kPddIgnoreCnt), ef_pdd_mean_(-1.0), ef_pdd_variance_(0.0),
      ef_pdd_update_time_(), norm_pdd_mean_(-1.0), norm_pdd_variance_(0.0),
      cb_change_thresh_(kPddCbThresh), cb_min_period_(kPddCbMinPeriodSec),
      cb_max_period_(kPddCbMaxPeriodSec), cb_pdd_mean_(0.0), cb_prev_time_()
{
}

//============================================================================
SliqCat::SliqCat(BPFwder* bpf, PacketPool& packet_pool, Timer& timer)
    : PathController(bpf),
      SliqApp(packet_pool, timer),
      timer_(timer),
      is_server_(false),
      is_connected_(false),
      in_destructor_(false),
      active_cap_est_(true),
      ef_rel_(),
      num_cc_alg_(0),
      cc_alg_(),
      cc_aggr_(0),
      data_xmit_queue_size_(kDefaultDataXmitQueuePkts),
      endpt_id_(-1),
      qlam_stream_id_(0),
      ef_data_stream_id_(0),
      control_stream_id_(0),
      data_stream_id_(0),
      cap_est_stream_id_(0),
      conn_retry_handle_(),
      client_conn_attempts_(0),
      qlam_xq_bytes_(0),
      ef_data_xq_bytes_(0),
      control_xq_bytes_(0),
      data_xq_bytes_(0),
      cap_est_xq_bytes_(0),
      cap_est_send_handle_(),
      cap_est_send_end_time_(),
      cap_est_send_ready_(false),
      cap_est_send_init_(false),
      cap_est_send_pkts_(kCapEstMinXmitQueuePkts),
      cap_est_send_ist_(kCapEstMaxIstSec),
      local_chan_cap_est_bps_(0.0),
      local_trans_cap_est_bps_(0.0),
      remote_chan_cap_est_bps_(0.0),
      last_chan_cap_est_bps_(-1.0),
      last_trans_cap_est_bps_(-1.0),
      cce_lock_(true),
      cce_send_handle_(),
      rtt_(),
      pdd_()
{
  LogI(kClassName, __func__, "Creating SliqCat...\n");
}

//============================================================================
SliqCat::~SliqCat()
{
  LogI(kClassName, __func__, "SliqCat %" PRIu32 ": Destroying...\n",
       path_controller_number_);

  // Disable all callbacks into the BPF while destructing the CAT.
  in_destructor_ = true;

  // Close the SLIQ endpoint if it is still open.  This will automatically
  // close any streams within them.
  if (endpt_id_ >= 0)
  {
    bool  fully_closed = false;

    Close(endpt_id_, fully_closed);
    endpt_id_ = -1;
  }

  is_connected_      = false;
  qlam_stream_id_    = 0;
  ef_data_stream_id_ = 0;
  control_stream_id_ = 0;
  data_stream_id_    = 0;
  cap_est_stream_id_ = 0;

  // Cancel any timers.
  timer_.CancelTimer(conn_retry_handle_);
  timer_.CancelTimer(cap_est_send_handle_);
  timer_.CancelTimer(cce_send_handle_);

  // Clean up the timer callback object pools.
  CallbackNoArg<SliqCat>::EmptyPool();
}

//============================================================================
bool SliqCat::Initialize(const ConfigInfo& config_info, uint32_t config_id)
{
  LogI(kClassName, __func__, "SliqCat %" PRIu32 ": Initializing...\n",
       config_id);

  // Store the configuration identifier as this SLIQ CAT's number.
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
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, invalid "
         "endpoints: %s\n", path_controller_number_, endpoints_str_.c_str());
    return false;
  }

  // Determine if this is the server or the client.  The higher IPv4 address
  // will be the server.  If the IPv4 addresses are the same, then compare the
  // UDP port numbers, with the higher port number becoming the server.
  if (local_endpt_.address() != remote_endpt_.address())
  {
    is_server_ = (ntohl(local_endpt_.address()) >
                  ntohl(remote_endpt_.address()));
  }
  else
  {
    if (local_endpt_.port() == remote_endpt_.port())
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoints "
           "addresses and port numbers are equal.\n",
           path_controller_number_);
      return false;
    }

    is_server_ = (ntohs(local_endpt_.port()) > ntohs(remote_endpt_.port()));
  }

  // Extract the EF data reliability mode setting.
  config_name = config_prefix;
  config_name.append(".EfDataRel");
  string  ef_rel_str = config_info.Get(config_name, "ARQ");

  if (!ParseEfDataRelString(ef_rel_str))
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, invalid EF data "
         "reliability mode: %s\n", path_controller_number_,
         ef_rel_str.c_str());
    return false;
  }

  // Extract the Copa3 congestion control anti-jitter setting.
  config_name = config_prefix;
  config_name.append(".AntiJitter");
  double  anti_jitter = config_info.GetUint(config_name, 0.0);

  // Extract the congestion control setting.
  config_name = config_prefix;
  config_name.append(".CongCtrl");
  string  cc_alg_str = config_info.Get(config_name, "Cubic,Copa3");

  if (!ParseCongCtrlString(cc_alg_str, anti_jitter))
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, invalid SLIQ "
         "congestion control algorithm(s): %s\n", path_controller_number_,
         cc_alg_str.c_str());
    return false;
  }

  // Extract the congestion control aggressiveness setting.
  config_name = config_prefix;
  config_name.append(".Aggr");
  cc_aggr_ = static_cast<uint32_t>(config_info.GetUint(config_name, 0));

  // Extract the active capacity estimation setting.
  config_name = config_prefix;
  config_name.append(".ActiveCapEst");
  active_cap_est_ = config_info.GetBool(config_name, false);

  // Compute and set the data packet transmit queue sizes in packets.
  size_t  xmit_thresh = config_info.GetUint("Bpf.XmitQueueThreshBytes",
                                            kDefaultBpfXmitQueueThreshBytes);
  data_xmit_queue_size_ = COMPUTE_XMIT_QUEUE_SIZE(xmit_thresh);

  // Initialize the SLIQ app.
  if (!InitializeSliqApp())
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error initializing SLIQ "
         "app.\n", path_controller_number_);
    return false;
  }

  // Set up the SLIQ endpoint.
  if (is_server_)
  {
    if (!SetupServerDataEndpoint(local_endpt_, remote_endpt_, endpt_id_))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error setting up SLIQ "
           "server from %s to %s.\n", path_controller_number_,
           local_endpt_.ToString().c_str(), remote_endpt_.ToString().c_str());
      return false;
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Establishing direct "
         "server connection from %s to %s on endpoint %d.\n",
         path_controller_number_, local_endpt_.ToString().c_str(),
         remote_endpt_.ToString().c_str(), endpt_id_);
  }
  else
  {
    if (!SetupClientDataEndpoint(local_endpt_, remote_endpt_, cc_alg_,
                                 num_cc_alg_, endpt_id_))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error setting up SLIQ "
           "client from %s to %s.\n", path_controller_number_,
           local_endpt_.ToString().c_str(), remote_endpt_.ToString().c_str());
      return false;
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Establishing direct "
         "client connection from %s to %s on endpoint %d.\n",
         path_controller_number_, local_endpt_.ToString().c_str(),
         remote_endpt_.ToString().c_str(), endpt_id_);
  }

  // Log the configuration information.
  LogC(kClassName, __func__, "SliqCat %" PRIu32 " configuration:\n",
       path_controller_number_);

  LogC(kClassName, __func__, "Type                         : SliqCat\n");
  LogC(kClassName, __func__, "Label                        : %s\n",
       label_.c_str());
  LogC(kClassName, __func__, "Endpoints                    : %s->%s\n",
       local_endpt_.ToString().c_str(), remote_endpt_.ToString().c_str());
  LogC(kClassName, __func__, "Connection Endpoint ID       : %d\n",
       endpt_id_);
  LogC(kClassName, __func__, "EF Data Reliability Mode     : %s\n",
       ef_rel_str.c_str());
  LogC(kClassName, __func__, "CongCtrl                     : %s\n",
       cc_alg_str.c_str());
  LogC(kClassName, __func__, "CongCtrl Aggressiveness      : %" PRIu32 "\n",
       cc_aggr_);
  LogC(kClassName, __func__, "Copa3 Anti-Jitter            : %0.6f\n",
       anti_jitter);
  LogC(kClassName, __func__, "Active Capacity Estimation   : %d\n",
       static_cast<int>(active_cap_est_));
  LogC(kClassName, __func__, "EF Data Transmit Queue Size  : %zu packets\n",
       data_xmit_queue_size_);
  LogC(kClassName, __func__, "Data Transmit Queue Size     : %zu packets\n",
       data_xmit_queue_size_);
  LogC(kClassName, __func__, "Control Transmit Queue Size  : %zu packets\n",
       static_cast<size_t>(kControlXmitQueuePkts));
  LogC(kClassName, __func__, "EF Data Packet Rexmit Limit  : %zu\n",
       static_cast<size_t>(ef_rel_.rexmit_limit));
  LogC(kClassName, __func__, "Data Packet Rexmit Limit     : %zu\n",
       static_cast<size_t>(kDataRexmitLimit));
  LogC(kClassName, __func__, "Control Packet Rexmit Limit  : %zu\n",
       static_cast<size_t>(kControlRexmitLimit));
  LogC(kClassName, __func__, "PDD Threshold                : %0.3f\n",
       pdd_.cb_change_thresh_);
  LogC(kClassName, __func__, "PDD Minimum Period           : %0.3f\n",
       pdd_.cb_min_period_);
  LogC(kClassName, __func__, "PDD Maximum Period           : %0.3f\n",
       pdd_.cb_max_period_);

  LogC(kClassName, __func__, "SliqCat %" PRIu32 ": Configuration complete.\n",
       path_controller_number_);

  bpf_->ProcessCapacityUpdate(this, 0.0, 0.0);

  return true;
}

//============================================================================
bool SliqCat::ConfigurePddReporting(double thresh, double min_period,
                                    double max_period)
{
  // Validate the parameters.
  if ((thresh < 0.00001) || (min_period < 0.000001) ||
      (max_period < 0.000001) || (min_period >= max_period))
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring PDD "
         "with thresh=%0.3f min_period=%0.3f max_period=%0.3f.\n",
         path_controller_number_, thresh, min_period, max_period);
    return false;
  }

  // Store the new parameters.
  pdd_.cb_change_thresh_ = thresh;
  pdd_.cb_min_period_    = min_period;
  pdd_.cb_max_period_    = max_period;

  LogC(kClassName, __func__, "SliqCat %" PRIu32 " PDD reconfiguration:\n",
       path_controller_number_);

  LogC(kClassName, __func__, "PDD Threshold      : %0.3f\n",
       pdd_.cb_change_thresh_);
  LogC(kClassName, __func__, "PDD Minimum Period : %0.3f\n",
       pdd_.cb_min_period_);
  LogC(kClassName, __func__, "PDD Maximum Period : %0.3f\n",
       pdd_.cb_max_period_);

  return true;
}

//============================================================================
bool SliqCat::SendPacket(Packet* pkt)
{
  if (pkt == NULL)
  {
    return false;
  }

  // Get the packet's type.
  int  pkt_type = pkt->GetRawType();

  // The BPF is not allowed to send CCE packets.
  if ((pkt_type == CAT_CAPACITY_EST_PACKET) && cce_lock_)
  {
    LogF(kClassName, __func__, "SliqCat %" PRIu32 ": BPF is not allowed to "
         "send CCE packets.\n", path_controller_number_);
    return false;
  }

  // The SLIQ connection must be established first.
  if (!is_connected_)
  {
    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Packet dropped due to "
         "no connection.\n", path_controller_number_);

    // QLAM packets are always being sent, so dropping them while a connection
    // is being established is OK.
    if (pkt_type == QLAM_PACKET)
    {
      TRACK_EXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(pkt);
      return true;
    }
    return false;
  }

  // Determine which stream to use for sending the packet.
  StreamId  stream_id = 0;
  StreamId  curr_id   = 0;

  switch (pkt_type)
  {
    case IPV4_PACKET:
      if (pkt->GetLatencyClass() == LOW_LATENCY)
      {
        stream_id = kEfDataStreamId;
        curr_id   = ef_data_stream_id_;
      }
      else
      {
        stream_id = kDataStreamId;
        curr_id   = data_stream_id_;
      }
      break;

    case QLAM_PACKET:
      stream_id = kQlamStreamId;
      curr_id   = qlam_stream_id_;
      break;

    case CAT_CAPACITY_EST_PACKET:
    case LSA_PACKET:
      stream_id = kControlStreamId;
      curr_id   = control_stream_id_;
      break;

    case ZOMBIE_PACKET:
      stream_id = kDataStreamId;
      curr_id   = data_stream_id_;
      break;

    default:
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Unknown packet type "
           "0x%02x.\n", path_controller_number_,
           static_cast<unsigned int>(pkt_type));
      return false;
  }

  // Create the SLIQ stream over the connection if necessary.
  if (curr_id == 0)
  {
    if (is_server_)
    {
      LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Packet dropped due to "
           "no stream on server yet.\n", path_controller_number_);

      // QLAM packets are always being sent, so dropping them while a
      // connection is being established is OK.
      if (pkt_type == QLAM_PACKET)
      {
        TRACK_EXPECTED_DROP(kClassName, packet_pool_);
        packet_pool_.Recycle(pkt);
        return true;
      }
      return false;
    }

    if (!CreateStreams())
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Packet dropped due to "
           "error creating stream.\n", path_controller_number_);
      return false;
    }
  }

  // Add any necessary Packet object metadata headers to the packet before it
  // is sent.
  if (NeedsMetadataHeaders(pkt))
  {
    if (!AddMetadataHeaders(pkt))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error adding "
           "necessary metadata headers to packet.\n",
           path_controller_number_);
    }
  }
  else
  {
    pkt->SetMetadataHeaderLengthInBytes(0);
  }

  // Send the packet over the stream.  On success, the packet becomes owned by
  // SLIQ.
  if (!Send(endpt_id_, stream_id, pkt))
  {
    if (stream_id != kQlamStreamId)
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Transmit queue "
           "overflow or send error on stream %" PRIu8 ".\n",
           path_controller_number_, stream_id);
    }
    return false;
  }

  LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Sent packet type 0x%02x "
       "size %zu bytes (ID %s) on stream %" PRIu8 ".\n",
       path_controller_number_, static_cast<unsigned int>(pkt_type),
       (pkt->GetMetadataHeaderLengthInBytes() + pkt->GetLengthInBytes()),
       pkt->GetPacketMetadataString().c_str(), stream_id);

  return true;
}

//============================================================================
void SliqCat::ServiceFileDescriptor(int fd, FdEvent event)
{
  // Call into SLIQ.
  SvcFileDescriptor(fd, event);
}

//============================================================================
size_t SliqCat::GetFileDescriptors(FdEventInfo* fd_event_array,
                                   size_t array_size) const
{
  // Call into SLIQ.
  return GetFileDescriptorList(fd_event_array, array_size);
}

//============================================================================
bool SliqCat::SetParameter(const char* name, const char* value)
{
  return false;
}

//============================================================================
bool SliqCat::GetParameter(const char* name, string& value) const
{
  return false;
}

//============================================================================
bool SliqCat::ProcessConnectionRequest(
  EndptId server_endpt_id, EndptId data_endpt_id,
  const Ipv4Endpoint& client_address)
{
  // Only direct connections are used, so this callback should never occur.
  LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, received "
       "connection request, ignoring.\n", path_controller_number_);
  return false;
}

//============================================================================
void SliqCat::ProcessConnectionResult(EndptId endpt_id, bool success)
{
  if (is_server_)
  {
    // If the connection failed, then set a timer to try again later.
    if (!success)
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, connection "
           "failed on server, retrying.\n", path_controller_number_);

      is_connected_ = false;
      endpt_id_     = -1;

      StartConnectionRetryTimer();
      return;
    }

    if (is_connected_)
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, already "
           "connected to a client.\n", path_controller_number_);
      return;
    }

    if (endpt_id != endpt_id_)
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint ID "
           "mismatch, opened %d got %d.\n", path_controller_number_,
           endpt_id_, endpt_id);
      return;
    }

    is_connected_ = true;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Now connected to client "
         "%s on data endpoint %d.\n", path_controller_number_,
         remote_endpt_.ToString().c_str(), endpt_id_);
  }
  else
  {
    // If the connection failed, then set a timer to try again later.
    if (!success)
    {
      client_conn_attempts_++;

      if (client_conn_attempts_ >= kClientConnAttempts)
      {
        LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, connection "
             "failed on client, retrying.\n", path_controller_number_);
      }

      is_connected_ = false;
      endpt_id_     = -1;

      StartConnectionRetryTimer();
      return;
    }

    client_conn_attempts_ = 0;

    if (is_connected_)
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, already "
           "connected to a server.\n", path_controller_number_);
      return;
    }

    if (endpt_id != endpt_id_)
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint ID "
           "mismatch, opened %d got %d.\n", path_controller_number_,
           endpt_id_, endpt_id);
      return;
    }

    is_connected_ = true;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Now connected to server "
         "%s on data endpoint %d.\n", path_controller_number_,
         remote_endpt_.ToString().c_str(), endpt_id_);
  }

  // Set the congestion control aggressiveness.
  if (cc_aggr_ > 0)
  {
    if (!ConfigureTcpFriendliness(endpt_id_, cc_aggr_))
    {
      LogW(kClassName, __func__, "SliqCat %" PRIu32 ": Unable to configure "
           "congestion control aggressiveness.\n", path_controller_number_);
    }
  }

  // Cancel any connection retry timer.
  timer_.CancelTimer(conn_retry_handle_);
}

//============================================================================
void SliqCat::ProcessNewStream(EndptId endpt_id, StreamId stream_id,
                               Priority prio, const Reliability& rel,
                               DeliveryMode del_mode)
{
  if (endpt_id != endpt_id_)
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint %d != "
         "data endpoint %d.\n", path_controller_number_, endpt_id, endpt_id_);
  }

  // This is called on the server.  Record the stream ID for the new stream
  // created by the client and configure the transmit queues.
  if (stream_id == kQlamStreamId)
  {
    qlam_stream_id_ = stream_id;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Server detected the new "
         "QLAM stream %" PRIu8 " created by the client.\n",
         path_controller_number_, stream_id);

    if (!ConfigureTransmitQueue(endpt_id_, qlam_stream_id_,
                                kQlamXmitQueuePkts, sliq::FIFO_QUEUE,
                                sliq::HEAD_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "QLAM packet transmit queue.\n", path_controller_number_);
    }
  }
  else if (stream_id == kEfDataStreamId)
  {
    ef_data_stream_id_ = stream_id;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Server detected the new "
         "EF data stream %" PRIu8 " created by the client.\n",
         path_controller_number_, stream_id);

    if (!ConfigureTransmitQueue(endpt_id_, ef_data_stream_id_,
                                data_xmit_queue_size_, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "EF data packet transmit queue.\n", path_controller_number_);
    }

    if ((rel.mode == sliq::SEMI_RELIABLE_ARQ) &&
        (rel.rexmit_limit != kEfDataArqRexmitLimit))
    {
      if (!ConfigureRetransmissionLimit(endpt_id_, ef_data_stream_id_,
                                        kEfDataArqRexmitLimit))
      {
        LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
             "EF data packet delivery retransmission limit for ARQ.\n",
             path_controller_number_);
      }
    }

    if ((rel.mode == sliq::SEMI_RELIABLE_ARQ_FEC) &&
        (rel.rexmit_limit != kEfDataArqFecRexmitLimit))
    {
      if (!ConfigureRetransmissionLimit(endpt_id_, ef_data_stream_id_,
                                        kEfDataArqFecRexmitLimit))
      {
        LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
             "EF data packet delivery retransmission limit for ARQ+FEC.\n",
             path_controller_number_);
      }
    }
  }
  else if (stream_id == kControlStreamId)
  {
    control_stream_id_ = stream_id;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Server detected the new "
         "control stream %" PRIu8 " created by the client.\n",
         path_controller_number_, stream_id);

    if (!ConfigureTransmitQueue(endpt_id_, control_stream_id_,
                                kControlXmitQueuePkts, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "control packet transmit queue.\n", path_controller_number_);
    }

    if (!ConfigureRetransmissionLimit(endpt_id_, control_stream_id_,
                                      kControlRexmitLimit))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "control packet delivery retransmission limit.\n",
           path_controller_number_);
    }
  }
  else if (stream_id == kDataStreamId)
  {
    data_stream_id_ = stream_id;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Server detected the new "
         "data stream %" PRIu8 " created by the client.\n",
         path_controller_number_, stream_id);

    if (!ConfigureTransmitQueue(endpt_id_, data_stream_id_,
                                data_xmit_queue_size_, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "data packet transmit queue.\n", path_controller_number_);
    }

    if (!ConfigureRetransmissionLimit(endpt_id_, data_stream_id_,
                                      kDataRexmitLimit))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "data packet delivery retransmission limit.\n",
           path_controller_number_);
    }
  }
  else if (stream_id == kCapEstStreamId)
  {
    cap_est_stream_id_ = stream_id;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Server detected the new "
         "capacity estimate stream %" PRIu8 " created by the client.\n",
         path_controller_number_, stream_id);

    if (!ConfigureTransmitQueue(endpt_id_, cap_est_stream_id_,
                                kCapEstXmitQueuePkts, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "capacity estimate packet transmit queue.\n",
           path_controller_number_);
    }

    // Start the sending of packets for capacity estimation.
    StartCapEstSendTimer();
  }
  else
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, stream %" PRIu8
         " is not recognized.\n", path_controller_number_, stream_id);
  }
}

//============================================================================
void SliqCat::Recv(EndptId endpt_id, StreamId stream_id, Packet* data)
{
  if (data == NULL)
  {
    return;
  }

  // Do not report anything to the BPF if currently destructing the CAT.
  if (in_destructor_)
  {
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(data);
    return;
  }

  if (endpt_id != endpt_id_)
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint %d != "
         "data endpoint %d.\n", path_controller_number_, endpt_id, endpt_id_);
  }

  LogD(kClassName, __func__, "SliqCat %" PRIu32 ": RECV: Received %zu "
       "bytes\n", path_controller_number_, data->GetLengthInBytes());

  // Process and remove any Packet object metadata headers from the packet.
  if (!ProcessMetadataHeaders(data))
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error processing "
         "metadata headers.\n", path_controller_number_);
  }

  // If this is a capacity estimate packet, then drop it.
  if (stream_id == kCapEstStreamId)
  {
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(data);
    return;
  }

  // Get the packet's type.
  int  pkt_type = data->GetRawType();

  // If this is a CAT Capacity Estimate (CCE) packet, then handle it locally
  // now.
  if (pkt_type == CAT_CAPACITY_EST_PACKET)
  {
    ProcessCatCapEstPkt(data);
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(data);
    return;
  }

  // Pass the received packet to the the backpressure forwarder for
  // processing.  It takes ownership of the packet.
  bpf_->ProcessRcvdPacket(data, this);
}

//============================================================================
void SliqCat::ProcessPacketDrop(EndptId endpt_id, StreamId stream_id,
                                Packet* data)
{
  // Only log drops of UDP packets, which are sent on the EF data and data
  // streams.
  if ((data != NULL) && (endpt_id == endpt_id_) &&
      ((stream_id == kDataStreamId) || (stream_id == kEfDataStreamId)))
  {
    uint32_t  fec_group = 0;

    // GetGroupId verifies that the packet is a UDP packet.
    if (data->GetGroupId(fec_group))
    {
      uint32_t  fec_slot = 0;

      if (data->GetSlotId(fec_slot))
      {
        LogA(kClassName, __func__, "PktDrop: FECMap: Group <%" PRIu32
             "> Slot <%" PRIu32 "> %s (SLIQ Drop).\n", fec_group, fec_slot,
             data->GetPacketMetadataString().c_str());
      }
    }
  }
}

//============================================================================
void SliqCat::ProcessTransmitQueueSize(EndptId endpt_id, StreamId stream_id,
                                       size_t bytes)
{
  if (endpt_id != endpt_id_)
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint %d != "
         "data endpoint %d.\n", path_controller_number_, endpt_id, endpt_id_);
  }

  // Store the current transmit queue size.
  if (stream_id == kDataStreamId)
  {
    data_xq_bytes_ = bytes;
  }
  else if (stream_id == kEfDataStreamId)
  {
    ef_data_xq_bytes_ = bytes;
  }
  else if (stream_id == kQlamStreamId)
  {
    qlam_xq_bytes_ = bytes;
  }
  else if (stream_id == kControlStreamId)
  {
    control_xq_bytes_ = bytes;
  }
  else if (stream_id == kCapEstStreamId)
  {
    cap_est_xq_bytes_ = bytes;
  }
  else
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, stream %" PRIu8
         " is not recognized.\n", path_controller_number_, stream_id);
  }
}

//============================================================================
void SliqCat::ProcessCapacityEstimate(EndptId endpt_id,
                                      double chan_cap_est_bps,
                                      double trans_cap_est_bps,
                                      double ccl_time_sec)
{
  // Do not report anything to the BPF if currently destructing the CAT.
  if (in_destructor_)
  {
    return;
  }

  if (endpt_id != endpt_id_)
  {
    if (endpt_id_ != -1)
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint %d != "
           "data endpoint %d.\n", path_controller_number_, endpt_id,
           endpt_id_);
    }
    return;
  }

  LogA(kClassName, __func__, "SliqCat %" PRIu32 ": New local capacity "
       "estimate: channel %f Mbps transport %f Mbps CCL time %f sec.\n",
       path_controller_number_, (chan_cap_est_bps / 1.0e6),
       (trans_cap_est_bps / 1.0e6), ccl_time_sec);

  // If the channel capacity estimate has changed and the CCE send timer is
  // not currently set, then start the timer to send a CCE packet.
  if ((chan_cap_est_bps != local_chan_cap_est_bps_) &&
      (!timer_.IsTimerSet(cce_send_handle_)))
  {
    // Start a timer for two times the RTT bound.
    double  duration = (2.0 * rtt_.rtt_bound_);

    if (duration < kMinCceSendSec)
    {
      duration = kMinCceSendSec;
    }

    CallbackNoArg<SliqCat>  cbna(this, &SliqCat::SendCatCapEstPkt);
    Time                    delta_time(duration);

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Starting CCE send timer "
         "for %f sec.\n", path_controller_number_, duration);

    if (!timer_.StartTimer(delta_time, &cbna, cce_send_handle_))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error starting "
           "CCE send timer.\n", path_controller_number_);
    }
  }

  // Handle starting or stopping of the capacity estimation send timer.
  if (timer_.IsTimerSet(cap_est_send_handle_))
  {
    // Check if the capacity estimation send timer should be stopped.
    if (IsInOutage(endpt_id_) ||
        ((ccl_time_sec < kCapEstCclSec) &&
         (Time::Now() > cap_est_send_end_time_)))
    {
      timer_.CancelTimer(cap_est_send_handle_);

      LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Stopping capacity "
           "estimate send timer.\n", path_controller_number_);
    }
  }
  else
  {
    // Check if the capacity estimation send timer should be started.
    if (active_cap_est_ && (!IsInOutage(endpt_id_)) &&
        (ccl_time_sec >= kCapEstCclSec))
    {
      LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Active capacity "
           "estimate start event.\n", path_controller_number_);

      // Start the sending of packets for capacity estimation.
      StartCapEstSendTimer();
    }
  }

  // Store the new local capacity estimate.
  local_chan_cap_est_bps_  = chan_cap_est_bps;
  local_trans_cap_est_bps_ = trans_cap_est_bps;

  // Possibly report the capacity estimate and the PDD to the BPF.
  if (cce_lock_)
  {
    ReportCapEstPddToBpf();
  }
}

//============================================================================
void SliqCat::ProcessRttPddSamples(EndptId endpt_id, uint32_t num_samples,
                                   const RttPdd* samples)
{
  int     pri_cnt = 0;
  int     alt_cnt = 0;
  double  rtt     = 0.0;
  double  diff    = 0.0;
  double  incr    = 0.0;

  // Do not report anything to the BPF if currently destructing the CAT.
  if (in_destructor_)
  {
    return;
  }

  if (endpt_id != endpt_id_)
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint %d != "
         "data endpoint %d.\n", path_controller_number_, endpt_id, endpt_id_);
  }

  // Update the RTT and PDD parameters for the streams included in the
  // samples.
  for (uint32_t i = 0; i < num_samples; ++i)
  {
    // Update the RTT.
    rtt = (static_cast<double>(samples[i].rtt_usec) * 0.000001);

    if (rtt_.srtt_ < 0.0)
    {
      rtt_.srtt_          = rtt;
      rtt_.rtt_variation_ = 0.0;
    }
    else
    {
      rtt_.rtt_variation_ = (((1.0 - kRttBoundBeta) * rtt_.rtt_variation_) +
                             (kRttBoundBeta * fabs(rtt_.srtt_ - rtt)));
      rtt_.srtt_          = (((1.0 - kRttBoundAlpha) * rtt_.srtt_) +
                             (kRttBoundAlpha * rtt));
    }

    rtt_.rtt_bound_ = (rtt_.srtt_ + (kRttBoundK * rtt_.rtt_variation_));

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": RTT %f %f %f %f\n",
         path_controller_number_, rtt, rtt_.srtt_, rtt_.rtt_variation_,
         rtt_.rtt_bound_);

    // Skip the first few PDD updates, or any PDD if the stream ID is zero.
    if ((pdd_.ignore_cnt_ > 0) || (samples[i].stream_id == 0))
    {
      LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Ignoring PDD %" PRIu32
           " from stream %" PRIStreamId "\n", path_controller_number_,
           samples[i].pdd_usec, samples[i].stream_id);

      if (pdd_.ignore_cnt_ > 0)
      {
        --pdd_.ignore_cnt_;
      }
      continue;
    }

    // Update the PDD based on the stream ID.
    if (samples[i].stream_id == kEfDataStreamId)
    {
      if (pdd_.ef_pdd_mean_ < 0.0)
      {
        pdd_.ef_pdd_mean_     =
          (static_cast<double>(samples[i].pdd_usec) * 0.000001);
        pdd_.ef_pdd_variance_ = 0.0;
      }
      else
      {
        diff = ((static_cast<double>(samples[i].pdd_usec) * 0.000001) -
                pdd_.ef_pdd_mean_);
        incr = (kPddAlpha * diff);

        pdd_.ef_pdd_mean_    += incr;
        pdd_.ef_pdd_variance_ = ((1.0 - kPddAlpha) *
                                 (pdd_.ef_pdd_variance_ + (diff * incr)));
      }

      LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Pri PDD %f %f %f %f\n",
           path_controller_number_,
           (static_cast<double>(samples[i].pdd_usec) * 0.000001),
           pdd_.ef_pdd_mean_, pdd_.ef_pdd_variance_,
           sqrt(pdd_.ef_pdd_variance_));

      ++pri_cnt;
    }
    else if ((samples[i].stream_id == kQlamStreamId) ||
             (samples[i].stream_id == kDataStreamId))
    {
      if (pdd_.norm_pdd_mean_ < 0.0)
      {
        pdd_.norm_pdd_mean_     =
          (static_cast<double>(samples[i].pdd_usec) * 0.000001);
        pdd_.norm_pdd_variance_ = 0.0;
      }
      else
      {
        diff = ((static_cast<double>(samples[i].pdd_usec) * 0.000001) -
                pdd_.norm_pdd_mean_);
        incr = (kPddAlpha * diff);

        pdd_.norm_pdd_mean_    += incr;
        pdd_.norm_pdd_variance_ = ((1.0 - kPddAlpha) *
                                   (pdd_.norm_pdd_variance_ + (diff * incr)));
      }

      LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Alt PDD %f %f %f %f\n",
           path_controller_number_,
           (static_cast<double>(samples[i].pdd_usec) * 0.000001),
           pdd_.norm_pdd_mean_, pdd_.norm_pdd_variance_,
           sqrt(pdd_.norm_pdd_variance_));

      ++alt_cnt;
    }
  }

  // If the EF data PDD was updated, then record the current time.
  if (pri_cnt > 0)
  {
    pdd_.ef_pdd_update_time_ = Time::Now();
  }

  // Check if any reportable PDD estimate has been updated or not.
  if ((pri_cnt + alt_cnt) > 0)
  {
    // Report the PDD to the BPF.
    ReportCapEstPddToBpf();
  }
}

//============================================================================
void SliqCat::ProcessCloseStream(EndptId endpt_id, StreamId stream_id,
                                 bool fully_closed)
{
  if (endpt_id != endpt_id_)
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint %d != "
         "data endpoint %d.\n", path_controller_number_, endpt_id, endpt_id_);
  }

  // The stream is now closed.
  if (stream_id == kQlamStreamId)
  {
    qlam_stream_id_ = 0;
  }
  else if (stream_id == kEfDataStreamId)
  {
    ef_data_stream_id_ = 0;
  }
  else if (stream_id == kControlStreamId)
  {
    control_stream_id_ = 0;
  }
  else if (stream_id == kDataStreamId)
  {
    data_stream_id_ = 0;
  }
  else if (stream_id == kCapEstStreamId)
  {
    cap_est_stream_id_ = 0;
  }
  else
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, stream %" PRIu8
         " is not recognized.\n", path_controller_number_, stream_id);
  }
}

//============================================================================
void SliqCat::ProcessClose(EndptId endpt_id, bool fully_closed)
{
  if (endpt_id != endpt_id_)
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, endpoint %d != "
         "data endpoint %d.\n", path_controller_number_, endpt_id, endpt_id_);
  }

  // The connection (along with any streams) is now closed.
  is_connected_      = false;
  endpt_id_          = -1;
  qlam_stream_id_    = 0;
  ef_data_stream_id_ = 0;
  control_stream_id_ = 0;
  data_stream_id_    = 0;
  cap_est_stream_id_ = 0;
  qlam_xq_bytes_     = 0;
  ef_data_xq_bytes_  = 0;
  control_xq_bytes_  = 0;
  data_xq_bytes_     = 0;
  cap_est_xq_bytes_  = 0;

  // Start a timer to try to connect again later.
  StartConnectionRetryTimer();
}

//============================================================================
void SliqCat::ProcessFileDescriptorChange()
{
  // Do nothing until epoll() is used in the backpressure forwarder.
}

//============================================================================
bool SliqCat::ParseEndpointsString(const string& ep_str)
{
  // The format to parse is:
  //   LOCAL_IP[:LOCAL_PORT]->REMOTE_IP[:REMOTE_PORT]

  // Start by tokenizing on the required "->" characters.
  List<string> tokens;
  StringUtils::Tokenize(ep_str, "->", tokens);

  if (tokens.size() != 2)
  {
    return false;
  }

  string  lep_str;
  tokens.Pop(lep_str);
  string  rep_str;
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
    lep_str.append(kDefaultServerPort);
  }

  if (rep_str.find(":") == string::npos)
  {
    rep_str.append(":");
    rep_str.append(kDefaultServerPort);
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
bool SliqCat::ParseEfDataRelString(const string& ef_rel_str)
{
  double  time_limit = 0.0;
  double  recv_prob  = 0.0;

  // Parse the setting string.
  if (ef_rel_str.substr(0, 7) == "ARQFEC(")
  {
    string        tok;
    string        fec_str = ef_rel_str.substr(7, (ef_rel_str.size() - 8));
    List<string>  fec_val;
    StringUtils::Tokenize(fec_str, ",", fec_val);

    if (fec_val.size() != 2)
    {
      return false;
    }

    if (!fec_val.Pop(tok))
    {
      return false;
    }

    time_limit = StringUtils::GetDouble(tok, -1.0);

    if (!fec_val.Pop(tok))
    {
      return false;
    }

    recv_prob = StringUtils::GetDouble(tok, -1.0);

    if ((time_limit < 0.001) || (time_limit > 64.0) ||
        (recv_prob < 0.5) || (recv_prob > 0.999))
    {
      return false;
    }

    ef_rel_.SetSemiRelArqFecUsingTime(kEfDataArqFecRexmitLimit, recv_prob,
                                      time_limit);
  }
  else if (ef_rel_str == "ARQ")
  {
    ef_rel_.SetSemiRelArq(kEfDataArqRexmitLimit);
  }
  else
  {
    return false;
  }

  return true;
}

//============================================================================
bool SliqCat::ParseCongCtrlString(const string& cc_alg_str,
                                  double anti_jitter)
{
  // Parse the list of congestion control names, separated by ','.
  string        conf(cc_alg_str);
  List<string>  tokens;
  StringUtils::Tokenize(conf, ",", tokens);
  size_t        num_tokens = tokens.size();

  if ((num_tokens < 1) || (num_tokens > kMaxCcAlgPerConn))
  {
    return false;
  }

  // Loop over each token.
  for (size_t i = 0; i < num_tokens; ++i)
  {
    string  cc_tok;
    tokens.Pop(cc_tok);

    if (cc_tok == "Cubic")
    {
      cc_alg_[i].SetTcpCubic();
    }
    else if (cc_tok == "CopaM")
    {
      cc_alg_[i].SetCopaM(false);
    }
    else if (cc_tok == "DetCopaM")
    {
      cc_alg_[i].SetCopaM(true);
    }
    else if (cc_tok.substr(0, 5) == "Copa_")
    {
      double  delta = StringUtils::GetDouble(cc_tok.substr(5));

      if ((delta < kMinCopaConstDelta) || (delta > kMaxCopaConstDelta))
      {
        return false;
      }

      cc_alg_[i].SetCopa(delta, false);
    }
    else if (cc_tok.substr(0, 8) == "DetCopa_")
    {
      double  delta = StringUtils::GetDouble(cc_tok.substr(8));

      if ((delta < kMinCopaConstDelta) || (delta > kMaxCopaConstDelta))
      {
        return false;
      }

      cc_alg_[i].SetCopa(delta, true);
    }
    else if (cc_tok == "Copa2")
    {
      cc_alg_[i].SetCopa2();
    }
    else if (cc_tok == "Copa3")
    {
      cc_alg_[i].SetCopa3(anti_jitter);
    }
    else if (cc_tok.substr(0, 10) == "FixedRate_")
    {
      uint64_t  rate = StringUtils::GetUint64(cc_tok.substr(10),
                                              (UINT32_MAX + 1));

      if ((rate < 1) || (rate > UINT32_MAX))
      {
        return false;
      }

      cc_alg_[i].SetFixedRate(rate);
    }
    else
    {
      return false;
    }
  }

  num_cc_alg_ = num_tokens;

  return true;
}

//============================================================================
bool SliqCat::CreateStreams()
{
  Reliability  rel;

  // Only the client creates the streams.  The server must wait for the
  // ProcessNewStream() callbacks.
  if (is_server_)
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Stream should be "
         "created by the client, not the server.\n", path_controller_number_);
    return false;
  }

  // Create five streams: one for QLAM packets, one for EF data packets, one
  // for system-level control packets, one for data packets and flow-level
  // control packets, and one for capacity estimate packets.
  if (qlam_stream_id_ == 0)
  {
    qlam_stream_id_ = kQlamStreamId;

    rel.SetBestEffort();

    if (!AddStream(endpt_id_, qlam_stream_id_, kQlamStreamPriority, rel,
                   sliq::UNORDERED_DELIVERY))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error creating QLAM "
           "stream %" PRIu8 ".\n", path_controller_number_, qlam_stream_id_);
      qlam_stream_id_ = 0;
      return false;
    }

    if (!ConfigureTransmitQueue(endpt_id_, qlam_stream_id_,
                                kQlamXmitQueuePkts, sliq::FIFO_QUEUE,
                                sliq::HEAD_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "QLAM packet transmit queue.\n", path_controller_number_);
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Created new QLAM "
         "stream %" PRIu8 " on endpoint %d.\n", path_controller_number_,
         qlam_stream_id_, endpt_id_);
  }

  if (ef_data_stream_id_ == 0)
  {
    ef_data_stream_id_ = kEfDataStreamId;

    if (!AddStream(endpt_id_, ef_data_stream_id_, kEfDataStreamPriority,
                   ef_rel_, sliq::UNORDERED_DELIVERY))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error creating EF "
           "data stream %" PRIu8 ".\n", path_controller_number_,
           ef_data_stream_id_);
      ef_data_stream_id_ = 0;
      return false;
    }

    if (!ConfigureTransmitQueue(endpt_id_, ef_data_stream_id_,
                                data_xmit_queue_size_, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring EF "
           "data packet transmit queue.\n", path_controller_number_);
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Created new EF data "
         "stream %" PRIu8 " on endpoint %d.\n", path_controller_number_,
         ef_data_stream_id_, endpt_id_);
  }

  if (control_stream_id_ == 0)
  {
    control_stream_id_ = kControlStreamId;

    rel.SetSemiRelArq(kControlRexmitLimit);

    if (!AddStream(endpt_id_, control_stream_id_, kControlStreamPriority, rel,
                   sliq::UNORDERED_DELIVERY))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error creating "
           "control stream %" PRIu8 ".\n", path_controller_number_,
           control_stream_id_);
      control_stream_id_ = 0;
      return false;
    }

    if (!ConfigureTransmitQueue(endpt_id_, control_stream_id_,
                                kControlXmitQueuePkts, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "control packet transmit queue.\n", path_controller_number_);
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Created new control "
         "stream %" PRIu8 " on endpoint %d.\n", path_controller_number_,
         control_stream_id_, endpt_id_);
  }

  if (data_stream_id_ == 0)
  {
    data_stream_id_ = kDataStreamId;

    rel.SetSemiRelArq(kDataRexmitLimit);

    if (!AddStream(endpt_id_, data_stream_id_, kDataStreamPriority, rel,
                   sliq::UNORDERED_DELIVERY))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error creating data "
           "stream %" PRIu8 ".\n", path_controller_number_, data_stream_id_);
      data_stream_id_ = 0;
      return false;
    }

    if (!ConfigureTransmitQueue(endpt_id_, data_stream_id_,
                                data_xmit_queue_size_, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "data packet transmit queue.\n", path_controller_number_);
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Created new data stream "
         "%" PRIu8 " on endpoint %d.\n", path_controller_number_,
         data_stream_id_, endpt_id_);
  }

  if (cap_est_stream_id_ == 0)
  {
    cap_est_stream_id_ = kCapEstStreamId;

    rel.SetBestEffort();

    if (!AddStream(endpt_id_, cap_est_stream_id_, kCapEstStreamPriority, rel,
                   sliq::UNORDERED_DELIVERY))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error creating "
           "capacity estimate stream %" PRIu8 ".\n", path_controller_number_,
           cap_est_stream_id_);
      cap_est_stream_id_ = 0;
      return false;
    }

    if (!ConfigureTransmitQueue(endpt_id_, cap_est_stream_id_,
                                kCapEstXmitQueuePkts, sliq::FIFO_QUEUE,
                                sliq::NO_DROP))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error configuring "
           "capacity estimate packet transmit queue.\n",
           path_controller_number_);
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Created new capacity "
         "estimate stream %" PRIu8 " on endpoint %d.\n",
         path_controller_number_, cap_est_stream_id_, endpt_id_);

    // Start the sending of packets for capacity estimation.
    StartCapEstSendTimer();
  }

  return true;
}

//============================================================================
void SliqCat::StartConnectionRetryTimer()
{
  // Cancel any existing timer first.
  timer_.CancelTimer(conn_retry_handle_);

  LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Client starting "
       "connection retry timer for %d sec.\n", path_controller_number_,
       kConnRetrySec);

  // Start a timer for the retry period.
  CallbackNoArg<SliqCat>  cbna(this, &SliqCat::ConnectionRetryTimeout);
  Time                    delta_time(kConnRetrySec);

  if (!timer_.StartTimer(delta_time, &cbna, conn_retry_handle_))
  {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error starting "
           "connection retry timer.\n", path_controller_number_);
  }
}

//============================================================================
void SliqCat::ConnectionRetryTimeout()
{
  // If this endpoint is already connected, then do nothing.
  if (is_connected_)
  {
    return;
  }

  // Set up the SLIQ endpoint.
  if (is_server_)
  {
    if (!SetupServerDataEndpoint(local_endpt_, remote_endpt_, endpt_id_))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error setting up SLIQ "
           "server from %s to %s.\n", path_controller_number_,
           local_endpt_.ToString().c_str(), remote_endpt_.ToString().c_str());
      StartConnectionRetryTimer();
      return;
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Establishing direct "
         "server connection from %s to %s on endpoint %d.\n",
         path_controller_number_, local_endpt_.ToString().c_str(),
         remote_endpt_.ToString().c_str(), endpt_id_);
  }
  else
  {
    if (!SetupClientDataEndpoint(local_endpt_, remote_endpt_, cc_alg_,
                                 num_cc_alg_, endpt_id_))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error setting up SLIQ "
           "client from %s to %s.\n", path_controller_number_,
           local_endpt_.ToString().c_str(), remote_endpt_.ToString().c_str());
      StartConnectionRetryTimer();
      return;
    }

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Establishing direct "
         "client connection from %s to %s on endpoint %d.\n",
         path_controller_number_, local_endpt_.ToString().c_str(),
         remote_endpt_.ToString().c_str(), endpt_id_);
  }
}

//============================================================================
void SliqCat::StartCapEstSendTimer(bool start_flag)
{
  if (!active_cap_est_)
  {
    return;
  }

  // Reset the send parameters if starting the first timer.
  if (start_flag)
  {
    cap_est_send_init_ = false;
  }

  // Cancel any existing timer first.
  if (timer_.IsTimerSet(cap_est_send_handle_))
  {
    timer_.CancelTimer(cap_est_send_handle_);
  }

  // If the stream is not created yet or the connection is in an outage, then
  // do not start the timer.
  if ((cap_est_stream_id_ == 0) || IsInOutage(endpt_id_))
  {
    return;
  }

  // If needed, check if the CAT is ready to send capacity estimate packets.
  if (!cap_est_send_ready_)
  {
    cap_est_send_ready_ = IsStreamEstablished(endpt_id_, cap_est_stream_id_);
  }

  // Set the necessary send timer parameters.
  if (cap_est_send_ready_)
  {
    if (cap_est_send_init_)
    {
      // If the transmit queue is empty, then attempt to send faster.
      if (cap_est_xq_bytes_ == 0)
      {
        if (cap_est_send_ist_ > kCapEstMinIstSec)
        {
          // Halve the inter-send time.
          cap_est_send_ist_ = (cap_est_send_ist_ / 2.0);

          if (cap_est_send_ist_ < kCapEstMinIstSec)
          {
            cap_est_send_ist_ = kCapEstMinIstSec;
          }
        }
        else
        {
          // Double the target number of packets in the transmit queue.
          cap_est_send_pkts_ = (cap_est_send_pkts_ * 2);

          if (cap_est_send_pkts_ > kCapEstXmitQueuePkts)
          {
            cap_est_send_pkts_ = kCapEstXmitQueuePkts;
          }
        }
      }
    }
    else
    {
      cap_est_send_end_time_ = (Time::Now() + Time(kCapEstDefDurSec));
      cap_est_send_init_     = true;
      cap_est_send_pkts_     = kCapEstMinXmitQueuePkts;
      cap_est_send_ist_      = kCapEstMaxIstSec;

      LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Setting capacity "
           "estimate end time to %f sec.\n", path_controller_number_,
           kCapEstDefDurSec);

      if (local_chan_cap_est_bps_ > 0)
      {
        // Send packets at twice the current estimated channel capacity rate.
        // This is done in case the current estimated rate is low.
        cap_est_send_ist_ = (static_cast<double>(8.0 * kCapEstPktSizeBytes) /
                             (2.0 * local_chan_cap_est_bps_));

        if (cap_est_send_ist_ < kCapEstMinIstSec)
        {
          cap_est_send_ist_ = kCapEstMinIstSec;
        }

        if (cap_est_send_ist_ > kCapEstMaxIstSec)
        {
          cap_est_send_ist_ = kCapEstMaxIstSec;
        }

        // Compute the number of packets to keep enqueued in order to keep the
        // channel full given the lower limit on inter-send time.
        double  rate_thresh = (static_cast<double>(8.0 * kCapEstPktSizeBytes)
                               / (2.0 * kCapEstMinIstSec));

        if (local_chan_cap_est_bps_ > rate_thresh)
        {
          cap_est_send_pkts_ = static_cast<size_t>(
            ceil(kCapEstMinXmitQueuePkts *
                 (local_chan_cap_est_bps_ / rate_thresh)));

          if (cap_est_send_pkts_ > kCapEstXmitQueuePkts)
          {
            cap_est_send_pkts_ = kCapEstXmitQueuePkts;
          }
        }
      }
    }

    // Send the necessary number of dummy capacity estimate packets.
    SendCapEstDummyPkts();
  }
  else
  {
    // The stream is not estabished yet.  Use the send timer to check again in
    // a little while.
    cap_est_send_end_time_ = (Time::Now() + Time(kCapEstDefDurSec));
    cap_est_send_init_     = false;
    cap_est_send_pkts_     = kCapEstMinXmitQueuePkts;
    cap_est_send_ist_      = kCapEstMaxIstSec;
  }

  LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Starting capacity "
       "estimate send timer for %f sec, target %zu pkts.\n",
       path_controller_number_, cap_est_send_ist_, cap_est_send_pkts_);

  // Start the timer.
  CallbackNoArg<SliqCat>  cbna(this, &SliqCat::CapEstSendCallback);
  Time                    delta_time(cap_est_send_ist_);

  if (!timer_.StartTimer(delta_time, &cbna, cap_est_send_handle_))
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error starting "
         "capacity estimate send timer.\n", path_controller_number_);
  }
}

//============================================================================
void SliqCat::CapEstSendCallback()
{
  StartCapEstSendTimer(false);
}

//============================================================================
void SliqCat::SendCapEstDummyPkts()
{
  // Compute the number of packets in the capacity estimate packet transmit
  // queue.
  size_t  curr_num_pkts = (cap_est_xq_bytes_ / kCapEstPktSizeBytes);

  LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Target capacity estimate "
       "pkts %zu current %zu pkts.\n", path_controller_number_,
       cap_est_send_pkts_, curr_num_pkts);

  // Send enough packets to fill the capacity estimate packet transmit queue
  // up to the target level.
  while (curr_num_pkts < cap_est_send_pkts_)
  {
    // Get a Packet to use.
    Packet*  pkt = packet_pool_.Get();

    if (pkt == NULL)
    {
      LogF(kClassName, __func__, "Unable to get a Packet.\n");
    }

    // Zero the initial bytes to clear any header type information.
    memset(reinterpret_cast<void*>(pkt->GetBuffer(0)), 0, 20);
    pkt->SetLengthInBytes(kCapEstPktSizeBytes);

    // Send the packet over the capacity estimate stream.  On success, the
    // packet becomes owned by SLIQ.
    if (!Send(endpt_id_, cap_est_stream_id_, pkt))
    {
      LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Transmit queue "
           "overflow or send error on capacity estimate stream %" PRIu8 ".\n",
           path_controller_number_, cap_est_stream_id_);

      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(pkt);
    }

    ++curr_num_pkts;
  }
}

//============================================================================
void SliqCat::SendCatCapEstPkt()
{
  // Do not report anything to the BPF if currently destructing the CAT.
  if (in_destructor_)
  {
    return;
  }

  // Get a Packet to use.
  Packet*  pkt = packet_pool_.Get();

  if (pkt == NULL)
  {
    LogF(kClassName, __func__, "Unable to get a Packet.\n");
  }

  // Create the CAT Capacity Estimate (CCE) packet.  Its format is:
  //
  // \verbatim
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |     Type      |               Capacity Estimate               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  // Note that the Capacity Estimate field is an unsigned integer field stored
  // in network byte order, and records the capacity estimate in units of 1000
  // bits per second.  The capacity estimate is always rounded up to the next
  // 1000 bits per second value before scaling it.
  uint32_t  rate = 1;

  if (local_chan_cap_est_bps_ > 0.0)
  {
    rate = static_cast<uint32_t>(ceil(local_chan_cap_est_bps_ /
                                      kCceCapEstScaleFactor));

    if (rate > 0xffffff)
    {
      LogW(kClassName, __func__, "SliqCat %" PRIu32 ": Warning, capacity "
           "estimate %f overflow.\n", path_controller_number_,
           local_chan_cap_est_bps_);
      rate = 0xffffff;
    }
  }

  uint32_t  msg_nbo = htonl(((static_cast<uint32_t>(CAT_CAPACITY_EST_PACKET) &
                              0xff) << 24)
                            | (rate & 0xffffff));

  memcpy(reinterpret_cast<void*>(pkt->GetBuffer(0)),
         reinterpret_cast<const void*>(&msg_nbo), sizeof(msg_nbo));
  pkt->SetLengthInBytes(sizeof(msg_nbo));

  LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Sending capacity "
       "estimate %f.\n", path_controller_number_, local_chan_cap_est_bps_);

  // Send the CCE packet over the correct stream.  On success, the packet
  // becomes owned by SLIQ.
  cce_lock_ = false;
  if (!SendPacket(pkt))
  {
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(pkt);
  }
  cce_lock_ = true;

  // Since ProcessCapacityEstimate() may have been called during the
  // SendPacket() call above, attempt to report the capacity estimate and the
  // PDD to the BPF.
  ReportCapEstPddToBpf();
}

//============================================================================
void SliqCat::ProcessCatCapEstPkt(Packet* pkt)
{
  uint32_t  msg_nbo = 0;

  // Verify the CCE packet size.
  if (pkt->GetLengthInBytes() != sizeof(msg_nbo))
  {
    LogE(kClassName, __func__, "SliqCat %" PRIu32 ": Error, CCE packet "
         "length %zu bytes is incorrect.\n", path_controller_number_,
         pkt->GetLengthInBytes());
    return;
  }

  // Parse the CCE packet to obtain the remote capacity estimate.
  memcpy(reinterpret_cast<void*>(&msg_nbo),
         reinterpret_cast<const void*>(pkt->GetBuffer(0)), sizeof(msg_nbo));

  remote_chan_cap_est_bps_ = (static_cast<double>(ntohl(msg_nbo) & 0xffffff) *
                              kCceCapEstScaleFactor);

  LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Received capacity "
       "estimate %f.\n", path_controller_number_, remote_chan_cap_est_bps_);

  // Possibly report the capacity estimate and the PDD to the BPF.
  ReportCapEstPddToBpf();
}

//============================================================================
void SliqCat::ReportCapEstPddToBpf()
{
  // Do not report anything to the BPF if currently destructing the CAT.
  if (in_destructor_)
  {
    return;
  }

  // Get the current time.
  Time  now = Time::Now();

  // Assuming that the network is symmetric, always report the greater of the
  // local and remote capacity estimates to the BPF.  However, if there is an
  // outage, always report zero.
  double  chan_cap_est_report  = 0.0;
  double  trans_cap_est_report = 0.0;

  if (!IsInOutage(endpt_id_))
  {
    if (local_chan_cap_est_bps_ >= remote_chan_cap_est_bps_)
    {
      // Use the local estimates for the report.
      chan_cap_est_report  = local_chan_cap_est_bps_;
      trans_cap_est_report = local_trans_cap_est_bps_;
    }
    else
    {
      // Use the remote channel estimate for the reported channel estimate.
      // Subtract the amount of local transport overhead from the remote
      // channel estimate for the reported transport estimate.
      chan_cap_est_report  = remote_chan_cap_est_bps_;
      trans_cap_est_report = (remote_chan_cap_est_bps_ +
                              local_trans_cap_est_bps_ -
                              local_chan_cap_est_bps_);
    }
  }

  // Avoid repeating reports to the BPF.
  if ((chan_cap_est_report != last_chan_cap_est_bps_) ||
      (trans_cap_est_report != last_trans_cap_est_bps_))
  {
    LogA(kClassName, __func__, "SliqCat %" PRIu32 ": Reporting capacity "
         "estimate: channel %f Mbps (local %f, remote %f) transport %f "
         "Mbps.\n", path_controller_number_, (chan_cap_est_report / 1.0e6),
         (local_chan_cap_est_bps_ / 1.0e6),
         (remote_chan_cap_est_bps_ / 1.0e6),
         (trans_cap_est_report / 1.0e6));

    bpf_->ProcessCapacityUpdate(this, chan_cap_est_report,
                                trans_cap_est_report);
    last_chan_cap_est_bps_  = chan_cap_est_report;
    last_trans_cap_est_bps_ = trans_cap_est_report;
  }

  // Determine the packet delivery delay (PDD) estimate to be reported.
  double  pdd_mean_report     = pdd_.ef_pdd_mean_;
  double  pdd_variance_report = pdd_.ef_pdd_variance_;

  if ((pdd_mean_report < 0.0) ||
      ((now - pdd_.ef_pdd_update_time_).GetTimeInMsec() >
       kEfPddStaleTimeMsec))
  {
    // If there is no PDD estimate yet, then return.
    if (pdd_.norm_pdd_mean_ < 0.0)
    {
      return;
    }

    // There has not been any EF data traffic PDD to report, so use the QLAM
    // and normal data traffic PDD estimate until there is EF data traffic
    // once again.
    pdd_mean_report     = pdd_.norm_pdd_mean_;
    pdd_variance_report = pdd_.norm_pdd_variance_;

    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Using normal PDD mean "
         "%f variance %f standard deviation %f\n", path_controller_number_,
         pdd_.norm_pdd_mean_, pdd_.norm_pdd_variance_,
         sqrt(pdd_.norm_pdd_variance_));
  }
  else
  {
    LogD(kClassName, __func__, "SliqCat %" PRIu32 ": Using EF PDD mean %f "
         "variance %f standard deviation %f\n", path_controller_number_,
         pdd_.ef_pdd_mean_, pdd_.ef_pdd_variance_,
         sqrt(pdd_.ef_pdd_variance_));
  }

  // If currently in an outage, then report UINT32_MAX microseconds.
  if (IsInOutage(endpt_id_))
  {
    pdd_mean_report     = (static_cast<double>(UINT32_MAX) / 1.0e6);
    pdd_variance_report = 0.0;
  }

  // Report the resulting PDD estimate to the backpressure forwarder if
  // either:
  //   - the percent change in PDD is large enough and enough time has passed
  //     since the last report, or
  //   - too much time has passed since the last report.
  if (((fabs(pdd_mean_report - pdd_.cb_pdd_mean_) >=
        (pdd_.cb_change_thresh_ * pdd_.cb_pdd_mean_)) &&
       (now > pdd_.cb_prev_time_.Add(pdd_.cb_min_period_))) ||
      (now > pdd_.cb_prev_time_.Add(pdd_.cb_max_period_)))
  {
    // Update the report time first due to possible re-entrant calls.
    pdd_.cb_pdd_mean_  = pdd_mean_report;
    pdd_.cb_prev_time_ = now;

    LogA(kClassName, __func__, "SliqCat %" PRIu32 ": Reported PDD is mean %f "
         "sec variance %f sec^2 standard deviation %f sec.\n",
         path_controller_number_, pdd_mean_report, pdd_variance_report,
         sqrt(pdd_variance_report));

    bpf_->ProcessPktDelDelay(this, pdd_mean_report, pdd_variance_report);
  }
}
