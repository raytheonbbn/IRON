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

#include "sliq_app.h"

#include "fd_event.h"
#include "ipv4_endpoint.h"
#include "itime.h"
#include "list.h"
#include "log.h"
#include "packet.h"
#include "packet_pool_heap.h"
#include "rng.h"
#include "string_utils.h"
#include "timer.h"

#include <string>

#include <cstdio>
#include <cstring>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>


using ::iron::FdEvent;
using ::iron::FdEventInfo;
using ::iron::Ipv4Endpoint;
using ::iron::List;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketPoolHeap;
using ::iron::RNG;
using ::iron::StringUtils;
using ::iron::Time;
using ::iron::Timer;
using ::sliq::CongCtrl;
using ::sliq::DeliveryMode;
using ::sliq::DequeueRule;
using ::sliq::DropRule;
using ::sliq::EndptId;
using ::sliq::PktTimestamp;
using ::sliq::Priority;
using ::sliq::Reliability;
using ::sliq::ReliabilityMode;
using ::sliq::RttPdd;
using ::sliq::SliqApp;
using ::sliq::StreamId;
using ::sliq::RexmitLimit;
using ::std::string;


namespace
{
  const char*   kName        = "TestApp";
  const size_t  kMaxFdCnt    = 33;
  const size_t  kMaxStreams  = 33;
  const size_t  kPktPoolSize = 131072;
  const size_t  kMaxCcAlg    = 8;
  const int     kMinPayload  = 1;
  const int     kMaxPayload  = 1452;  // 1500 - 20 - 8 - 20 = 1452
}


class TestApp;


//============================================================================
class TestStats
{

public:

  TestStats();
  virtual ~TestStats();

  void SentPkt(size_t pkt_len, const Time& now);
  void RecvPkt(size_t pkt_len, const Time& now);
  void PktLat(double pkt_lat);
  void PrintStats(const char* name, int id);

  size_t  sent_pkts_;
  size_t  sent_bytes_;
  Time    sent_start_time_;
  Time    sent_end_time_;
  size_t  recv_pkts_;
  size_t  recv_bytes_;
  Time    recv_start_time_;
  Time    recv_end_time_;
  size_t  lat_pkts_;
  double  lat_min_;
  double  lat_max_;
  double  lat_sum_;
}; // end class TestStats


//============================================================================
class TestStream
{

public:

  TestStream(StreamId stream_id, Priority prio, const Reliability& rel,
             DeliveryMode del_mode, PacketPool& packet_pool);
  virtual ~TestStream();

  void ConfigXmitQueue(size_t size, DequeueRule dequeue_rule,
                       DropRule drop_rule);
  void ConfigSending(bool limit_pkts, size_t pkt_cnt, bool rand_pkt_len,
                     size_t min_pkt_len, size_t max_pkt_len,
                     int64_t wait_usec);
  void TrackLatency(bool steady_state);
  bool AllocatePackets();
  void GetNextWaitTime(const Time& now, Time& wait_time);
  bool SendNextPacket(TestApp* app, EndptId endpt_id, const Time& now,
                      bool rate_change);
  bool CreateStream(TestApp* app, EndptId endpt_id);
  void SetupStreamForReceiving();
  bool SetupStreamForSending(TestApp* app, EndptId endpt_id);
  void Close(TestApp* app, EndptId endpt_id);
  void GotFullyClosed();

  PacketPool&      pkt_pool_;
  RNG              rng_;
  bool             is_established_;
  StreamId         stream_id_;
  Priority         prio_;
  Reliability      rel_;
  DeliveryMode     del_mode_;
  size_t           xmit_queue_size_;
  DequeueRule      xmit_queue_dequeue_rule_;
  DropRule         xmit_queue_drop_rule_;
  bool             limit_pkts_;
  size_t           pkt_cnt_;
  Time             end_time_;
  bool             rand_pkt_len_;
  size_t           min_pkt_len_;
  size_t           max_pkt_len_;
  Packet*          pkt_;
  Packet*          cloned_pkt_;
  Time             wait_;
  Time             send_time_;
  bool             track_latency_;
  bool             ss_latency_;
  TestStats        stream_stats_;
}; // end class TestStream


//============================================================================
class TestApp : public SliqApp
{

public:

  TestApp(PacketPool& packet_pool, Timer& timer);
  virtual ~TestApp();

  // ----- TestApp API Methods -----
  bool Init(int argc, char** argv);
  void Run();
  void PrintStats();
  void SentPkt(size_t pkt_len, const Time& now);
  void UpdateSendTime(const Time& now, const Time& wait, Time& send_time);

  // ----- SliqApp API Methods -----
  virtual bool ProcessConnectionRequest(EndptId server_endpt_id,
                                        EndptId data_endpt_id,
                                        const Ipv4Endpoint& client_address);
  virtual void ProcessConnectionResult(EndptId endpt_id, bool success);
  virtual void ProcessNewStream(EndptId endpt_id, StreamId stream_id,
                                Priority prio, const Reliability& rel,
                                DeliveryMode del_mode);
  virtual void Recv(EndptId endpt_id, StreamId stream_id, Packet* data);
  virtual void ProcessCapacityEstimate(EndptId endpt_id,
                                       double chan_cap_est_bps,
                                       double trans_cap_est_bps,
                                       double ccl_time_sec);
  virtual void ProcessRttPddSamples(EndptId endpt_id, uint32_t num_samples,
                                    const RttPdd* samples);
  virtual void ProcessCloseStream(EndptId endpt_id, StreamId stream_id,
                                  bool fully_closed);
  virtual void ProcessClose(EndptId endpt_id, bool fully_closed);
  virtual void ProcessFileDescriptorChange();

private:

  void Usage(const char* prog_name);
  bool ParseCongCtrlConfig(const char* cc_config);
  bool ParseDirectConnConfig(const char* dir_conn_config);
  bool ParseStreamConfig(const char* stream_config);
  bool ParseLatencySensitiveStreamIds(const char* lss_config);
  bool ActAsServer(const Ipv4Endpoint& server_address);
  bool ActAsClient(const Ipv4Endpoint& server_address);
  void CloseClient();

  PacketPool&      pkt_pool_;
  Timer&           timer_;
  bool             is_server_;
  bool             direct_conn_;
  bool             is_connected_;
  bool             should_terminate_;
  bool             rate_change_;
  bool             lat_sens_stream_[kMaxStreams];
  bool             limit_latency_;
  string           direct_local_addr_;
  string           direct_remote_addr_;
  string           server_addr_;
  string           server_port_;
  size_t           num_cc_alg_;
  CongCtrl         cc_algorithm_[kMaxCcAlg];
  unsigned int     cc_flows_;
  EndptId          listen_endpt_id_;
  EndptId          data_endpt_id_;
  Time             close_time_;
  Time             rate_change_wait_;
  size_t           num_client_streams_;
  size_t           num_server_streams_;
  StreamId         client_stream_ids_[kMaxStreams];
  StreamId         server_stream_ids_[kMaxStreams];
  TestStream*      stream_[kMaxStreams];
  TestStats        connection_stats_;
}; // end class TestApp


//============================================================================
TestStats::TestStats()
    : sent_pkts_(0),
      sent_bytes_(0),
      sent_start_time_(),
      sent_end_time_(),
      recv_pkts_(0),
      recv_bytes_(0),
      recv_start_time_(),
      recv_end_time_(),
      lat_pkts_(0),
      lat_min_(0.0),
      lat_max_(0.0),
      lat_sum_(0.0)
{
}

//============================================================================
TestStats::~TestStats()
{
}

//============================================================================
void TestStats::SentPkt(size_t pkt_len, const Time& now)
{
  if (sent_pkts_ == 0)
  {
    sent_start_time_ = now;
  }

  sent_pkts_++;
  sent_bytes_   += pkt_len;
  sent_end_time_ = now;
}

//============================================================================
void TestStats::RecvPkt(size_t pkt_len, const Time& now)
{
  if (recv_pkts_ == 0)
  {
    recv_start_time_ = now;
  }

  recv_pkts_++;
  recv_bytes_   += pkt_len;
  recv_end_time_ = now;
}

//============================================================================
void TestStats::PktLat(double pkt_lat)
{
  if (lat_pkts_ == 0)
  {
    lat_min_ = pkt_lat;
    lat_max_ = pkt_lat;
  }
  else
  {
    if (pkt_lat < lat_min_)
    {
      lat_min_ = pkt_lat;
    }
    if (pkt_lat > lat_max_)
    {
      lat_max_ = pkt_lat;
    }
  }

  lat_sum_ += pkt_lat;
  lat_pkts_++;
}

//============================================================================
void TestStats::PrintStats(const char* name, int id)
{
  if ((sent_pkts_ == 0) && (recv_pkts_ == 0))
  {
    return;
  }

  if (id >= 0)
  {
    printf("%s %d:\n\n", name, id);
  }
  else
  {
    printf("%s:\n\n", name);
  }

  if (sent_pkts_ > 0)
  {
    printf("  Send statistics:\n");
    printf("    Packets: %zu\n", sent_pkts_);
    printf("    Bytes:   %zu\n", sent_bytes_);

    if (sent_pkts_ > 1)
    {
      Time    duration = (sent_end_time_ - sent_start_time_);
      double  rate     = (((double)sent_bytes_ * 8.0) /
                          ((double)duration.GetTimeInUsec()));

      printf("    Time:    %s seconds\n", duration.ToString().c_str());
      printf("    Rate:    %f Mbps\n", rate);
    }

    printf("\n");
  }

  if (recv_pkts_ > 0)
  {
    printf("  Receive statistics:\n");
    printf("    Packets: %zu\n", recv_pkts_);
    printf("    Bytes:   %zu\n", recv_bytes_);

    if (recv_pkts_ > 1)
    {
      Time    duration = (recv_end_time_ - recv_start_time_);
      double  rate     = (((double)recv_bytes_ * 8.0) /
                          ((double)duration.GetTimeInUsec()));

      printf("    Time:    %s seconds\n", duration.ToString().c_str());
      printf("    Rate:    %f Mbps\n", rate);
    }

    if (lat_pkts_ > 0)
    {
      double  lat_mean = (lat_sum_ / (double)lat_pkts_);

      printf("    Latency: min %0.6f / mean %0.6f / max %0.6f seconds\n",
             lat_min_, lat_mean, lat_max_);
    }

    printf("\n");
  }

  printf("\n");
}


//============================================================================
TestStream::TestStream(StreamId stream_id, Priority prio,
                       const Reliability& rel, DeliveryMode del_mode,
                       PacketPool& packet_pool)
    : pkt_pool_(packet_pool),
      rng_(),
      is_established_(false),
      stream_id_(stream_id),
      prio_(prio),
      rel_(rel),
      del_mode_(del_mode),
      xmit_queue_size_(16),
      xmit_queue_dequeue_rule_(sliq::FIFO_QUEUE),
      xmit_queue_drop_rule_(sliq::NO_DROP),
      limit_pkts_(true),
      pkt_cnt_(0),
      end_time_(),
      rand_pkt_len_(false),
      min_pkt_len_(1000),
      max_pkt_len_(1000),
      pkt_(NULL),
      cloned_pkt_(NULL),
      wait_(),
      send_time_(),
      track_latency_(false),
      ss_latency_(false),
      stream_stats_()
{
  LogD(kName, __func__, "TestStream %" PRIStreamId " object created.\n",
       stream_id_);
}

//============================================================================
TestStream::~TestStream()
{
  LogD(kName, __func__, "TestStream %" PRIStreamId " object destroyed.\n",
       stream_id_);

  if (pkt_ != NULL)
  {
    pkt_pool_.Recycle(pkt_);
    pkt_ = NULL;
  }

  if (cloned_pkt_ != NULL)
  {
    pkt_pool_.Recycle(cloned_pkt_);
    cloned_pkt_ = NULL;
  }
}

//============================================================================
void TestStream::ConfigXmitQueue(size_t size, DequeueRule dequeue_rule,
                                 DropRule drop_rule)
{
  xmit_queue_size_         = size;
  xmit_queue_dequeue_rule_ = dequeue_rule;
  xmit_queue_drop_rule_    = drop_rule;
}

//============================================================================
void TestStream::ConfigSending(bool limit_pkts, size_t pkt_cnt,
                               bool rand_pkt_len, size_t min_pkt_len,
                               size_t max_pkt_len, int64_t wait_usec)
{
  limit_pkts_   = limit_pkts;
  pkt_cnt_      = pkt_cnt;
  end_time_     = (Time::Now() + Time::FromSec(pkt_cnt + 2));
  rand_pkt_len_ = rand_pkt_len;
  min_pkt_len_  = min_pkt_len;
  max_pkt_len_  = max_pkt_len;
  wait_         = Time::FromUsec(wait_usec);
}

//============================================================================
void TestStream::TrackLatency(bool steady_state)
{
  track_latency_ = true;
  ss_latency_    = steady_state;
}

//============================================================================
bool TestStream::AllocatePackets()
{
  // Create the packet to send over and over if needed.
  if ((pkt_cnt_ > 0) && (pkt_ == NULL))
  {
    pkt_ = pkt_pool_.Get();

    if (pkt_ == NULL)
    {
      LogE(kName, __func__, "Error allocating packet.\n");
      return false;
    }

    memset(pkt_->GetBuffer(), stream_id_, max_pkt_len_);
    pkt_->SetLengthInBytes(max_pkt_len_);
  }

  return true;
}

//============================================================================
void TestStream::GetNextWaitTime(const Time& now, Time& wait_time)
{
  // Check if there are still packets to be sent.
  bool  not_done = (limit_pkts_ ? (stream_stats_.sent_pkts_ < pkt_cnt_) :
                    (now < end_time_));

  if (is_established_ && (pkt_cnt_ > 0) && (not_done))
  {
    if (now >= send_time_)
    {
      // Don't wait.
      wait_time.Zero();
    }
    else
    {
      // Wait until the send time.
      wait_time = Time::Min(wait_time, (send_time_ - now));
    }
  }
}

//============================================================================
bool TestStream::SendNextPacket(TestApp* app, EndptId endpt_id,
                                const Time& now, bool rate_change)
{
  // If the stream is not established yet, then return if this stream is
  // configured to send packets.
  if (!is_established_)
  {
    return (pkt_cnt_ > 0);
  }

  // Check if there are still packets to be sent.
  bool  not_done = (limit_pkts_ ? (stream_stats_.sent_pkts_ < pkt_cnt_) :
                    (now < end_time_));

  if ((pkt_cnt_ > 0) && (not_done))
  {
    // Check if it is time to send.
    if (now >= send_time_)
    {
      // Get the packet length in bytes.
      size_t  pkt_len = max_pkt_len_;

      if (rand_pkt_len_)
      {
        pkt_len = (rng_.GetInt(max_pkt_len_ - min_pkt_len_) + min_pkt_len_);
      }

      // Disabled to minimize the debug log file size.
      // LogD(kName, __func__, "TestApp stream %" PRIStreamId " attempting "
      //      "to send %zu bytes to peer.\n", stream_id_, pkt_len);

      // Get a clone of the packet to send if there is not already one.
      if (cloned_pkt_ == NULL)
      {
        cloned_pkt_ = pkt_pool_.Clone(pkt_, false, iron::PACKET_NO_TIMESTAMP);
      }

      // Set the receive time and TTG of the cloned packet if needed.
      if (track_latency_)
      {
        // Use a TTG value of 1 second.
        Time  ttg(1);

        cloned_pkt_->set_recv_time(now);
        cloned_pkt_->set_track_ttg(true);
        cloned_pkt_->SetTimeToGo(ttg, true);
      }

      // Set the length of the cloned packet if it is random.
      if (rand_pkt_len_)
      {
        cloned_pkt_->SetLengthInBytes(pkt_len);
      }

      // Set the packet number.
      uint32_t  pkt_num_hbo = static_cast<uint32_t>(stream_stats_.sent_pkts_);
      uint32_t  pkt_num_nbo = htonl(pkt_num_hbo);

      memcpy(cloned_pkt_->GetBuffer(), &pkt_num_nbo, sizeof(pkt_num_nbo));

      // Set the packet timestamp if needed.
      if (track_latency_)
      {
        uint32_t  pkt_ts_nbo = 0;

        // Avoid sending the packet timestamp at the very beginning and the
        // very end of the run if configured to do so.
        if ((!ss_latency_) ||
            ((stream_stats_.sent_pkts_ >= 1024) &&
             (((limit_pkts_) &&
               ((int)stream_stats_.sent_pkts_ < ((int)pkt_cnt_ - 1024))) ||
              ((!limit_pkts_) && ((now + Time(1)) < end_time_)))))
        {
          timespec  t_spec;

          if (clock_gettime(CLOCK_REALTIME, &t_spec) == 0)
          {
            Time      p_now(t_spec);
            uint32_t  pkt_ts_hbo =
              static_cast<uint32_t>(p_now.GetTimeInUsec());

            if (pkt_ts_hbo == 0)
            {
              pkt_ts_hbo = 1;
            }

            pkt_ts_nbo = htonl(pkt_ts_hbo);
          }
        }

        memcpy(cloned_pkt_->GetBuffer(sizeof(pkt_num_nbo)), &pkt_ts_nbo,
               sizeof(pkt_ts_nbo));
      }

      // Attempt to send the data.  On success, SLIQ takes ownership of the
      // cloned packet.  If this fails, it is not an error and we still own
      // the cloned packet.
      if (app->Send(endpt_id, stream_id_, cloned_pkt_))
      {
        LogI(kName, __func__, "Sent packet %zu length %zu bytes on stream %"
             PRIStreamId "\n", stream_stats_.sent_pkts_, pkt_len,
             stream_id_);

        // SLIQ now owns the cloned packet.
        cloned_pkt_ = NULL;

        // Update the statistics.
        stream_stats_.SentPkt(pkt_len, now);
        app->SentPkt(pkt_len, now);

        // Update the time to send the next packet.
        if (rate_change)
        {
          app->UpdateSendTime(now, wait_, send_time_);
        }
        else
        {
          send_time_ += wait_;
        }
      }
    }

    // If there are more packets to send, then return true.
    not_done = (limit_pkts_ ? (stream_stats_.sent_pkts_ < pkt_cnt_) :
                (now < end_time_));

    return not_done;
  }

  return false;
}

//============================================================================
bool TestStream::CreateStream(TestApp* app, EndptId endpt_id)
{
  LogD(kName, __func__, "TestApp object attempting to create stream %"
       PRIStreamId ".\n", stream_id_);

  if (!app->AddStream(endpt_id, stream_id_, prio_, rel_, del_mode_))
  {
    LogE(kName, __func__, "Error creating stream %" PRIStreamId ".\n",
         stream_id_);
    return false;
  }

  if (!app->ConfigureTransmitQueue(endpt_id, stream_id_, xmit_queue_size_,
                                   xmit_queue_dequeue_rule_,
                                   xmit_queue_drop_rule_))
  {
    LogE(kName, __func__, "Error configuring transmit queue.\n");
    return false;
  }

  Time  now = Time::Now();

  is_established_ = true;
  if (!limit_pkts_)
  {
    end_time_ = (now + Time::FromSec(pkt_cnt_ + 2));
  }
  send_time_ = (now + Time::FromSec(2));

  return true;
}

//============================================================================
void TestStream::SetupStreamForReceiving()
{
  is_established_ = true;
}

//============================================================================
bool TestStream::SetupStreamForSending(TestApp* app, EndptId endpt_id)
{
  if (!app->ConfigureTransmitQueue(endpt_id, stream_id_, xmit_queue_size_,
                                   xmit_queue_dequeue_rule_,
                                   xmit_queue_drop_rule_))
  {
    LogE(kName, __func__, "Error configuring transmit queue.\n");
    return false;
  }

  if ((rel_.mode == sliq::SEMI_RELIABLE_ARQ) ||
      (rel_.mode == sliq::SEMI_RELIABLE_ARQ_FEC))
  {
    if (!app->ConfigureRetransmissionLimit(endpt_id, stream_id_,
                                           rel_.rexmit_limit))
    {
      LogE(kName, __func__, "Error configuring delivery retransmission "
           "limit.\n");
      return false;
    }
  }

  Time  now = Time::Now();

  is_established_ = true;
  if (!limit_pkts_)
  {
    end_time_ = (now + Time::FromSec(pkt_cnt_ + 2));
  }
  send_time_ = (now + Time::FromSec(2));

  return true;
}

//============================================================================
void TestStream::Close(TestApp* app, EndptId endpt_id)
{
  bool  is_fully_closed = false;

  if (!app->CloseStream(endpt_id, stream_id_, is_fully_closed))
  {
    LogE(kName, __func__, "Error, cannot close stream %" PRIStreamId ".\n",
         stream_id_);
    return;
  }

  if (is_fully_closed)
  {
    is_established_ = false;
  }

  LogD(kName, __func__, "Closed stream %" PRIStreamId " fully_closed %s.\n",
       stream_id_, (is_fully_closed ? "true" : "false"));
}

//============================================================================
void TestStream::GotFullyClosed()
{
  is_established_ = false;
}


//============================================================================
TestApp::TestApp(PacketPool& packet_pool, Timer& timer)
    : SliqApp(packet_pool, timer),
      pkt_pool_(packet_pool),
      timer_(timer),
      is_server_(true),
      direct_conn_(false),
      is_connected_(false),
      should_terminate_(false),
      rate_change_(false),
      lat_sens_stream_(),
      limit_latency_(false),
      direct_local_addr_(),
      direct_remote_addr_(),
      server_addr_("0.0.0.0"),
      server_port_("22123"),
      num_cc_alg_(1),
      cc_algorithm_(),
      cc_flows_(0),
      listen_endpt_id_(-1),
      data_endpt_id_(-1),
      close_time_(Time::Infinite()),
      rate_change_wait_(),
      num_client_streams_(0),
      num_server_streams_(0),
      client_stream_ids_(),
      server_stream_ids_(),
      stream_(),
      connection_stats_()
{
  LogD(kName, __func__, "TestApp object created.\n");

  num_cc_alg_ = 1;

  cc_algorithm_[0].SetCopa3();

  for (size_t i = 0; i < kMaxStreams; ++i)
  {
    lat_sens_stream_[i]   = false;
    client_stream_ids_[i] = 0;
    server_stream_ids_[i] = 0;
    stream_[i]            = NULL;
  }
}

//============================================================================
TestApp::~TestApp()
{
  LogD(kName, __func__, "TestApp object destroyed.\n");

  for (size_t i = 0; i < kMaxStreams; ++i)
  {
    if (stream_[i] != NULL)
    {
      delete stream_[i];
      stream_[i] = NULL;
    }
  }
}

//============================================================================
bool TestApp::Init(int argc, char** argv)
{
  extern char*  optarg;
  extern int    optind;

  int     c           = 0;
  double  anti_jitter = 0.0;

  // Log the command line.
  string  cmd;

  for (int i = 0; i < argc; ++i)
  {
    if (i > 0)
    {
      cmd.append(" ");
    }

    cmd.append(argv[i]);
  }

  LogC(kName, __func__, "Command: %s\n", cmd.c_str());

  // Parse the command line arguments.
  while ((c = getopt(argc, argv, "C:a:j:D:p:R:s:l:Lqvdh")) != -1)
  {
    switch (c)
    {
      case 'C':
        if (!ParseCongCtrlConfig(optarg))
        {
          LogE(kName, __func__, "Invalid congestion control config: %s\n",
               optarg);
          return false;
        }
        break;

      case 'a':
        cc_flows_ = StringUtils::GetUint(optarg);
        if ((cc_flows_ < 1) || (cc_flows_ == UINT_MAX))
        {
          LogE(kName, __func__, "Invalid congestion control aggressiveness: "
               "%s\n", optarg);
          return false;
        }
        break;

      case 'j':
        anti_jitter = StringUtils::GetDouble(optarg, 1.0);
        if ((anti_jitter < 0.0) || (anti_jitter >= 1.0))
        {
          LogE(kName, __func__, "Invalid Copa3 anti-jitter value: %s\n",
               optarg);
          return false;
        }
        break;

      case 'D':
        if (!ParseDirectConnConfig(optarg))
        {
          LogE(kName, __func__, "Invalid direct connection addresses: %s\n",
               optarg);
          return false;
        }
        break;

      case 'p':
        server_port_ = optarg;
        break;

      case 'R':
        rate_change_      = true;
        rate_change_wait_ = Time::FromMsec((time_t)atoi(optarg));
        break;

      case 's':
        if (!ParseStreamConfig(optarg))
        {
          LogE(kName, __func__, "Invalid stream config: %s\n", optarg);
          return false;
        }
        break;

      case 'l':
        if (!ParseLatencySensitiveStreamIds(optarg))
        {
          LogE(kName, __func__, "Invalid stream config: %s\n", optarg);
          return false;
        }
        break;

      case 'L':
        limit_latency_ = true;
        break;

      case 'q':
        Log::SetDefaultLevel("FEW");
        break;

      case 'v':
        Log::SetDefaultLevel("FEWIA");
        break;

      case 'd':
        Log::SetDefaultLevel("FEWIAD");
        break;

      case 'h':
      default:
        Usage(argv[0]);
    }
  }

  // Get any server address specified.
  if ((argc - optind) > 1)
  {
    LogE(kName, __func__, "Too many server addresses specified.\n");
    return false;
  }

  if ((argc - optind) == 1)
  {
    // Act as a client, connecting to the specified server.
    is_server_   = false;
    server_addr_ = argv[optind];
  }

  LogD(kName, __func__, "TestApp object is being initialized.\n");

  // Set the Copa3 anti-jitter if specified.
  if (anti_jitter != 0.0)
  {
    for (size_t i = 0; i < num_cc_alg_; ++i)
    {
      if (cc_algorithm_[i].algorithm == sliq::COPA3_CC)
      {
        cc_algorithm_[i].copa3_anti_jitter = anti_jitter;
      }
    }
  }

  // Allow the streams to allocate packets.
  for (size_t i = 0; i < kMaxStreams; ++i)
  {
    if (stream_[i] != NULL)
    {
      stream_[i]->AllocatePackets();

      // Set the packet latency measurement option if specified.
      if (lat_sens_stream_[i])
      {
        stream_[i]->TrackLatency(limit_latency_);
      }
    }
  }

  // Initialize the parent SliqApp object.
  if (!InitializeSliqApp())
  {
    LogE(kName, __func__, "Error initializing SliqApp.\n");
    return false;
  }

  // Initialize the client or server side.
  if (is_server_)
  {
    // Set up the server.
    string        endpoint_str = "0.0.0.0:" + server_port_;
    Ipv4Endpoint  endpoint(endpoint_str);

    if (!ActAsServer(endpoint))
    {
      LogE(kName, __func__, "Error setting up server %s.\n",
           endpoint.ToString().c_str());
      return false;
    }
  }
  else
  {
    // Connect to the server.
    string        endpoint_str = server_addr_ + ":" + server_port_;
    Ipv4Endpoint  endpoint(endpoint_str);

    if (!ActAsClient(endpoint))
    {
      LogE(kName, __func__, "Error setting up client for server %s.\n",
           endpoint.ToString().c_str());
      return false;
    }
  }

  return true;
}

//============================================================================
void TestApp::Run()
{
  TestStream*  stream      = NULL;
  Time         now         = Time::Now();
  Time         term_time   = Time::Infinite();
  fd_set       read_fds;
  fd_set       write_fds;
  FdEventInfo  fd_event_info[kMaxFdCnt];

  while (true)
  {
    // Prepare for the select() call.  Add the SLIQ file descriptors to the
    // read and write sets.
    size_t  num_fds = GetFileDescriptorList(fd_event_info, kMaxFdCnt);
    int     max_fd  = -1;

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    for (size_t  i = 0; i < num_fds; ++i)
    {
      if ((fd_event_info[i].events == iron::kFdEventRead) ||
          (fd_event_info[i].events == iron::kFdEventReadWrite))
      {
        FD_SET(fd_event_info[i].fd, &read_fds);
      }

      if ((fd_event_info[i].events == iron::kFdEventWrite) ||
          (fd_event_info[i].events == iron::kFdEventReadWrite))
      {
        FD_SET(fd_event_info[i].fd, &write_fds);
      }

      if (max_fd < fd_event_info[i].fd)
      {
        max_fd = fd_event_info[i].fd;
      }
    }

    // Figure out the backstop time for the select() call.
    Time  wait_time = timer_.GetNextExpirationTime(Time(0.5));

    if (is_connected_)
    {
      for (size_t  i = 0; i < num_client_streams_; ++i)
      {
        stream = stream_[client_stream_ids_[i]];
        if (stream != NULL)
        {
          stream->GetNextWaitTime(now, wait_time);
        }
      }

      for (size_t  i = 0; i < num_server_streams_; ++i)
      {
        stream = stream_[server_stream_ids_[i]];
        if (stream != NULL)
        {
          stream->GetNextWaitTime(now, wait_time);
        }
      }
    }

    timeval  wait_tv = wait_time.ToTval();

    // Do the select() call.
    int  rv = ::select((max_fd + 1), &read_fds, &write_fds, NULL, &wait_tv);

    // Handle the select() call results.
    if (rv < 0)
    {
      LogE(kName, __func__, "select() error %s.\n", strerror(errno));
    }
    else if (rv > 0)
    {
      FdEvent  event = iron::kFdEventRead;

      // Process the file descriptors that are ready.
      for (size_t  i = 0; i < num_fds; ++i)
      {
        bool  read_flag  = (FD_ISSET(fd_event_info[i].fd, &read_fds) != 0);
        bool  write_flag = (FD_ISSET(fd_event_info[i].fd, &write_fds) != 0);

        if (read_flag)
        {
          if (write_flag)
          {
            event = iron::kFdEventReadWrite;
          }
          else
          {
            event = iron::kFdEventRead;
          }
        }
        else
        {
          if (write_flag)
          {
            event = iron::kFdEventWrite;
          }
          else
          {
            continue;
          }
        }

        // Disabled to minimize the debug log file size.
        // LogD(kName, __func__, "Servicing fd %d event %d.\n",
        //      fd_event_info[i].fd, event);

        SvcFileDescriptor(fd_event_info[i].fd, event);
      }
    }

    // Process the timer callbacks.
    timer_.DoCallbacks();

    now.GetNow();

    // Do any packet sends.
    if (is_connected_)
    {
      int  cnt = 0;

      for (size_t  i = 0; i < num_client_streams_; ++i)
      {
        stream = stream_[client_stream_ids_[i]];
        if (stream != NULL)
        {
          if (stream->SendNextPacket(this, data_endpt_id_, now, rate_change_))
          {
            cnt++;
          }
        }
      }

      for (size_t  i = 0; i < num_server_streams_; ++i)
      {
        stream = stream_[server_stream_ids_[i]];
        if (stream != NULL)
        {
          if (stream->SendNextPacket(this, data_endpt_id_, now, rate_change_))
          {
            cnt++;
          }
        }
      }

      if ((!is_server_) && (cnt > 0))
      {
        close_time_ = (now + 2);
      }
    }

    // Do a close if it is time.
    if ((!is_server_) && (now > close_time_))
    {
      close_time_ = Time::Infinite();
      CloseClient();
      term_time   = (now + 16);
    }

    // End if it is time.
    if ((should_terminate_) || (now > term_time))
    {
      break;
    }
  }
}

//============================================================================
void TestApp::PrintStats()
{
  printf("\n\n---------------------------------------------------------------"
         "-------------\n\n");

  connection_stats_.PrintStats("Connection", -1);

  for (size_t i = 0; i < kMaxStreams; ++i)
  {
    if (stream_[i] != NULL)
    {
      stream_[i]->stream_stats_.PrintStats("Stream", i);
    }
  }
}

//============================================================================
void TestApp::SentPkt(size_t pkt_len, const Time& now)
{
  connection_stats_.SentPkt(pkt_len, now);
}

//============================================================================
void TestApp::UpdateSendTime(const Time& now, const Time& wait,
                             Time& send_time)
{
  // This is set up for the following rate change pattern as a function of
  // time:
  //
  // Maximum Rate -   ----+    +----+                   +----
  //                      |    |    |                   |
  // Reduced Rate -       |    |    +---------+    +----+
  //                      |    |              |    |
  // Zero Rate    -       +----+              +----+
  //                  0   4    8   12   16   20   24   28
  //
  //   0-4 seconds:    Send at full rate.
  //   4-8 seconds:    Stop sending.
  //   8-12 seconds:   Send at full rate.
  //   12-20 seconds:  Send at a reduced rate (use rate change wait time).
  //   20-24 seconds:  Stop sending.
  //   24-28 seconds:  Send at a reduced rate (use rate change wait time).
  //   28+ seconds:    Send at full rate.
  if (connection_stats_.sent_pkts_ > 0)
  {
    // Figure out which stage the current time is in.
    Time    delta_time = now.Subtract(connection_stats_.sent_start_time_);
    time_t  stage      = (delta_time.GetTimeInSec() / 4);

    if ((stage == 1) || (stage == 5))
    {
      // Stop sending, and wait until the next "on" time to send again.
      send_time = connection_stats_.sent_start_time_.Add((stage + 1) * 4.0);
      return;
    }

    if (((stage == 3) || (stage == 4) || (stage == 6)) &&
        (wait < rate_change_wait_))
    {
      // Send at a reduced rate.
      send_time += rate_change_wait_;
      return;
    }
  }

  // Send at the full rate.
  send_time += wait;
}

//============================================================================
bool TestApp::ProcessConnectionRequest(EndptId server_endpt_id,
                                       EndptId data_endpt_id,
                                       const Ipv4Endpoint& client_address)
{
  LogD(kName, __func__, "Request for connection, server endpt %" PRIEndptId
       ", data endpt %" PRIEndptId ", client %s.\n", server_endpt_id,
       data_endpt_id, client_address.ToString().c_str());

  // Accept the connection from the client.
  data_endpt_id_ = data_endpt_id;

  return true;
}

//============================================================================
void TestApp::ProcessConnectionResult(EndptId endpt_id, bool success)
{
  // Record the result.
  is_connected_ = success;

  if (success)
  {
    LogD(kName, __func__, "Connection result for endpt %" PRIEndptId " is "
         "success.\n", endpt_id);

    // Check the endpoint ID.
    if (endpt_id != data_endpt_id_)
    {
      LogE(kName, __func__, "Bad endpoint, expected %" PRIEndptId " but got %"
           PRIEndptId ".\n", data_endpt_id_, endpt_id);
      should_terminate_ = true;
      return;
    }

    if (cc_flows_ > 0)
    {
      // Set the congestion control aggressiveness.
      if (!ConfigureTcpFriendliness(data_endpt_id_, cc_flows_))
      {
        LogW(kName, __func__, "Unable to configure congestion control "
             "aggressiveness.\n");
      }
    }

    // Create the necessary streams.
    if (is_server_)
    {
      for (size_t  i = 0; i < num_server_streams_; ++i)
      {
        TestStream*  stream = stream_[server_stream_ids_[i]];
        if (stream != NULL)
        {
          if (!stream->CreateStream(this, data_endpt_id_))
          {
            should_terminate_ = true;
            return;
          }
        }
      }
    }
    else
    {
      for (size_t  i = 0; i < num_client_streams_; ++i)
      {
        TestStream*  stream = stream_[client_stream_ids_[i]];
        if (stream != NULL)
        {
          if (!stream->CreateStream(this, data_endpt_id_))
          {
            should_terminate_ = true;
            return;
          }
        }
      }
    }
  }
  else
  {
    LogE(kName, __func__, "Connection result for endpt %" PRIEndptId " is "
         "failure.\n", endpt_id);
    should_terminate_ = true;
  }
}

//============================================================================
void TestApp::ProcessNewStream(EndptId endpt_id, StreamId stream_id,
                               Priority prio, const Reliability& rel,
                               DeliveryMode del_mode)
{
  LogD(kName, __func__, "New stream %" PRIStreamId " created by peer, endpt %"
       PRIEndptId " prio %" PRIPriority " rel %d rx_lim %" PRIRexmitLimit
       " tgt_rcv_prob %f del_time %d tgt_rnds %" PRIRexmitRounds " tgt_time "
       "%f del %d.\n", stream_id, endpt_id, prio, rel.mode, rel.rexmit_limit,
       rel.fec_target_pkt_recv_prob, static_cast<int>(rel.fec_del_time_flag),
       rel.fec_target_pkt_del_rounds, rel.fec_target_pkt_del_time_sec,
       del_mode);

  // Check the endpoint ID.
  if (endpt_id != data_endpt_id_)
  {
    LogE(kName, __func__, "Bad endpoint, expected %" PRIEndptId " but got %"
         PRIEndptId ".\n", data_endpt_id_, endpt_id);
    should_terminate_ = true;
    return;
  }

  // Add or update the stream.
  if (is_server_)
  {
    // This should be a client stream ID, which are odd numbers.
    if ((static_cast<int>(stream_id) % 2) != 1)
    {
      LogE(kName, __func__, "Invalid stream %" PRIStreamId " created by "
           "peer.\n", stream_id);
      should_terminate_ = true;
      return;
    }

    TestStream*  stream = stream_[stream_id];

    if (stream == NULL)
    {
      // Create the stream.  It will not send any packets.
      stream = new TestStream(stream_id, prio, rel, del_mode, pkt_pool_);

      if (stream == NULL)
      {
        LogE(kName, __func__, "Memory allocation error.\n");
        should_terminate_ = true;
        return;
      }

      stream->SetupStreamForReceiving();

      stream_[stream_id] = stream;

      client_stream_ids_[num_client_streams_] = stream_id;
      num_client_streams_++;
    }
    else
    {
      // Set up the stream for sending packets.
      if (!stream->SetupStreamForSending(this, data_endpt_id_))
      {
        should_terminate_ = true;
        return;
      }
    }

    // Set the packet latency measurement option if specified.
    if (lat_sens_stream_[stream_id])
    {
      stream->TrackLatency(limit_latency_);
    }
  }
  else
  {
    // This should be a server stream ID, which are even numbers.
    if ((static_cast<int>(stream_id) % 2) != 0)
    {
      LogE(kName, __func__, "Invalid stream %" PRIStreamId " created by "
           "peer.\n", stream_id);
      should_terminate_ = true;
      return;
    }

    TestStream*  stream = stream_[stream_id];

    if (stream == NULL)
    {
      // Create the stream.  It will not send any packets.
      stream = new TestStream(stream_id, prio, rel, del_mode, pkt_pool_);

      if (stream == NULL)
      {
        LogE(kName, __func__, "Memory allocation error.\n");
        should_terminate_ = true;
        return;
      }

      stream->SetupStreamForReceiving();

      stream_[stream_id] = stream;

      server_stream_ids_[num_server_streams_] = stream_id;
      num_server_streams_++;
    }
    else
    {
      // Set up the stream for sending packets.
      if (!stream->SetupStreamForSending(this, data_endpt_id_))
      {
        should_terminate_ = true;
        return;
      }
    }

    // Set the packet latency measurement option if specified.
    if (lat_sens_stream_[stream_id])
    {
      stream->TrackLatency(limit_latency_);
    }
  }
}

//============================================================================
void TestApp::Recv(EndptId endpt_id, StreamId stream_id, Packet* data)
{
  // Check the endpoint ID.
  if (endpt_id != data_endpt_id_)
  {
    LogE(kName, __func__, "Bad endpoint, expected %" PRIEndptId " but got %"
         PRIEndptId ".\n", data_endpt_id_, endpt_id);
    should_terminate_ = true;
  }
  else
  {
    // Get the current time.
    Time  now;
    now.GetNow();

    // Find the stream.
    TestStream*  stream = stream_[stream_id];

    if (stream != NULL)
    {
      // Get the packet size, packet number (set by the sender), and packet
      // timestamp (also set by the sender).
      size_t    pkt_len     = data->GetLengthInBytes();
      uint32_t  pkt_num_nbo = 0;
      uint32_t  pkt_num_hbo =
        static_cast<uint32_t>(stream->stream_stats_.recv_pkts_);
      uint32_t  pkt_ts_nbo  = 0;
      uint32_t  pkt_ts_hbo  = 0;
      double    pkt_lat     = -1.0;

      if (pkt_len >= sizeof(pkt_num_hbo))
      {
        memcpy(&pkt_num_nbo, data->GetBuffer(), sizeof(pkt_num_nbo));
        pkt_num_hbo = ntohl(pkt_num_nbo);
      }

      if (lat_sens_stream_[stream_id] &&
          (pkt_len > (sizeof(pkt_num_hbo) + sizeof(pkt_ts_hbo))))
      {
        memcpy(&pkt_ts_nbo, data->GetBuffer(sizeof(pkt_num_nbo)),
               sizeof(pkt_ts_nbo));
        pkt_ts_hbo = ntohl(pkt_ts_nbo);
      }

      if (pkt_ts_hbo != 0)
      {
        timespec  t_spec;

        if (clock_gettime(CLOCK_REALTIME, &t_spec) == 0)
        {
          Time      p_now(t_spec);
          uint32_t  p_now_ts = static_cast<uint32_t>(p_now.GetTimeInUsec());

          pkt_lat = (static_cast<double>(p_now_ts - pkt_ts_hbo) * 0.000001);
        }
      }

      if (pkt_lat > 0.0)
      {
        // Only update the packet latency statistics if this packet is not
        // "late" (i.e., it was received within the target amount of time).
        if (!data->recv_late())
        {
          stream->stream_stats_.PktLat(pkt_lat);
          connection_stats_.PktLat(pkt_lat);

          if (data->track_ttg())
          {
            double  ttg  = (0.000001 *
                            static_cast<double>(data->time_to_go_usec()));
            double  dttg = (1.0 - ttg);

            LogI(kName, __func__, "Received packet %" PRIu32 " length %zu "
                 "bytes on stream %" PRIStreamId " latency %0.6f ttg %0.6f "
                 "delta_ttg %0.6f ttg_error %0.6f\n", pkt_num_hbo, pkt_len,
                 stream_id, pkt_lat, ttg, dttg, (pkt_lat - dttg));
          }
          else
          {
            LogI(kName, __func__, "Received packet %" PRIu32 " length %zu "
                 "bytes on stream %" PRIStreamId " latency %0.6f\n",
                 pkt_num_hbo, pkt_len, stream_id, pkt_lat);
          }
        }
        else
        {
          LogI(kName, __func__, "Received packet %" PRIu32 " length %zu "
               "bytes on stream %" PRIStreamId " latency %0.6f LATE\n",
               pkt_num_hbo, pkt_len, stream_id, pkt_lat);
        }
      }
      else
      {
        LogI(kName, __func__, "Received packet %" PRIu32 " length %zu bytes "
             "on stream %" PRIStreamId "\n", pkt_num_hbo, pkt_len,
             stream_id);
      }

      stream->stream_stats_.RecvPkt(pkt_len, now);
      connection_stats_.RecvPkt(pkt_len, now);

      if (!is_server_)
      {
        close_time_ = (now + 2);
      }
    }
    else
    {
      LogE(kName, __func__, "Bad stream %" PRIStreamId".\n", stream_id);
      should_terminate_ = true;
    }
  }

  // Release the packet.
  pkt_pool_.Recycle(data);
}

//============================================================================
void TestApp::ProcessCapacityEstimate(EndptId endpt_id,
                                      double chan_cap_est_bps,
                                      double trans_cap_est_bps,
                                      double ccl_time_sec)
{
  LogA(kName, __func__, "New endpt %" PRIEndptId " capacity estimate: "
       "channel %f Mbps transport %f Mbps CCL %f sec.\n", endpt_id,
       (chan_cap_est_bps / 1.0e6), (trans_cap_est_bps / 1.0e6), ccl_time_sec);

  // Check the endpoint ID.
  if (endpt_id != data_endpt_id_)
  {
    LogE(kName, __func__, "Bad endpoint, expected %" PRIEndptId " but got %"
         PRIEndptId ".\n", data_endpt_id_, endpt_id);
    should_terminate_ = true;
    return;
  }
}

//============================================================================
void TestApp::ProcessRttPddSamples(EndptId endpt_id, uint32_t num_samples,
                                   const RttPdd* samples)
{
  for (uint32_t i = 0; i < num_samples; ++i)
  {
    LogA(kName, __func__, "New endpt %" PRIEndptId " stream %" PRIStreamId
         " samples: rtt %" PRIu32 " usec pdd %" PRIu32 " usec.\n", endpt_id,
         samples[i].stream_id, samples[i].rtt_usec, samples[i].pdd_usec);
  }

  // Check the endpoint ID.
  if (endpt_id != data_endpt_id_)
  {
    LogE(kName, __func__, "Bad endpoint, expected %" PRIEndptId " but got %"
         PRIEndptId ".\n", data_endpt_id_, endpt_id);
    should_terminate_ = true;
    return;
  }
}

//============================================================================
void TestApp::ProcessCloseStream(EndptId endpt_id, StreamId stream_id,
                                 bool fully_closed)
{
  LogD(kName, __func__, "Close stream received from peer, endpt %" PRIEndptId
       " stream %" PRIStreamId " fully_closed %s.\n", endpt_id, stream_id,
       (fully_closed ? "true" : "false"));

  // Check the endpoint ID.
  if (endpt_id != data_endpt_id_)
  {
    LogE(kName, __func__, "Bad endpoint, expected %" PRIEndptId " but got %"
         PRIEndptId ".\n", data_endpt_id_, endpt_id);
    return;
  }

  // We should still be connected.
  if (!is_connected_)
  {
    LogE(kName, __func__, "Error, not connected.\n");
    return;
  }

  if (is_server_)
  {
    // Close the stream.
    TestStream*  stream = stream_[stream_id];

    if (stream != NULL)
    {
      LogD(kName, __func__, "Step #2: TestApp server is closing stream %"
           PRIStreamId ".\n", stream_id);
      stream->Close(this, data_endpt_id_);
    }
  }
  else
  {
    // The stream should be fully closed now.
    if (!fully_closed)
    {
      LogE(kName, __func__, "Error, stream %" PRIStreamId " should be fully "
           "closed.\n", stream_id);
    }

    // Close the stream.
    TestStream*  stream = stream_[stream_id];

    if (stream != NULL)
    {
      LogD(kName, __func__, "Step #3: TestApp client is closing stream %"
           PRIStreamId ".\n", stream_id);
      stream->GotFullyClosed();
    }

    // If all of the streams have been closed, then close the connection.
    bool  all_closed = true;

    for (size_t i = 0; i < kMaxStreams; ++i)
    {
      if ((stream_[i] != NULL) && (stream_[i]->is_established_))
      {
        all_closed = false;
        break;
      }
    }

    if (all_closed)
    {
      LogD(kName, __func__, "Step #4: TestApp client is closing client "
           "connection.\n");

      bool  is_fully_closed = false;

      if (!Close(data_endpt_id_, is_fully_closed))
      {
        LogE(kName, __func__, "Error, cannot close client connection.\n");
      }
      else
      {
        LogD(kName, __func__, "Closed client connection, fully_closed "
             "%s.\n", (is_fully_closed ? "true" : "false"));
      }
    }
  }
}

//============================================================================
void TestApp::ProcessClose(EndptId endpt_id, bool fully_closed)
{
  LogD(kName, __func__, "Close received from peer, endpt %" PRIEndptId
       " fully_closed %s.\n", endpt_id, (fully_closed ? "true" : "false"));

  // Check the endpoint ID.
  if (endpt_id != data_endpt_id_)
  {
    LogE(kName, __func__, "Bad endpoint, expected %" PRIEndptId " but got %"
         PRIEndptId ".\n", data_endpt_id_, endpt_id);
    return;
  }

  // We should still be connected.
  if (!is_connected_)
  {
    LogE(kName, __func__, "Error, not connected.\n");
    return;
  }

  if (is_server_)
  {
    LogD(kName, __func__, "Step #5: TestApp server is closing server side "
         "connection.\n");

    bool  is_fully_closed = false;

    if (!Close(data_endpt_id_, is_fully_closed))
    {
      LogE(kName, __func__, "Error, cannot close server side connection.\n");
    }
    else
    {
      LogD(kName, __func__, "Closed server connection, fully_closed "
           "%s.\n", (is_fully_closed ? "true" : "false"));
    }

    data_endpt_id_    = -1;
    is_connected_     = false;
    should_terminate_ = true;
  }
  else
  {
    // The connection should be fully closed now.
    if (!fully_closed)
    {
      LogE(kName, __func__, "Error, connection should be fully closed.\n");
    }

    LogD(kName, __func__, "Step #6: TestApp client is now closed.\n");

    data_endpt_id_    = -1;
    is_connected_     = false;
    should_terminate_ = true;
  }
}

//============================================================================
void TestApp::ProcessFileDescriptorChange()
{
  // Note: Not integrated for this test application.  The main processing loop
  // grabs all of the file descriptors each time through the loop.
  LogD(kName, __func__, "File descriptors have changed.\n");
}

//============================================================================
void TestApp::Usage(const char* prog_name)
{
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s [options] [server]\n", prog_name);
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -C <cc>    The congestion control types to use (cubic, "
          "copam, detcopam,\n             copa_<delta>, detcopa_<delta>, "
          "copa2, copa3, gubic,\n             gubicpacing, reno, "
          "renopacing, fixedrate_<bps>, none)\n             (default "
          "copa3).\n");
  fprintf(stderr, "  -a <flws>  The congestion control aggressiveness in "
          "number of TCP flows\n             (default 1).\n");
  fprintf(stderr, "  -j <sec>   The Copa3 congestion control anti-jitter "
          "setting in seconds\n             (default 0.0).\n");
  fprintf(stderr, "  -D <addr>  Direct connect using local,remote "
          "addresses.\n");
  fprintf(stderr, "  -p <port>  The server port number (default 22123).\n");
  fprintf(stderr, "  -R <msec>  Enable 28 second rate change pattern using "
          "wait time in msec.\n");
  fprintf(stderr, "  -s <conf>  Stream configuration, see below "
          "(id:pkts:len:wait:...).\n");
  fprintf(stderr, "  -l <strs>  Measure packet latencies on comma-separated "
          "streams.\n");
  fprintf(stderr, "  -L         Do not include start/end packets in latency "
          "measurements.\n");
  fprintf(stderr, "  -q         Turn off logging.\n");
  fprintf(stderr, "  -v         Turn on verbose logging.\n");
  fprintf(stderr, "  -d         Turn on debug logging.\n");
  fprintf(stderr, "  -h         Print out usage information.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Stream Configuration: a colon-separated list of the "
          "following:\n");
  fprintf(stderr, "  id        The stream ID (odd on client, even on server, "
          "1-32).\n");
  fprintf(stderr, "  pkts      The number of packets to send, or duration "
          "with trailing s.\n");
  fprintf(stderr, "  len       The packet length in bytes (int, rand[lo,hi]) "
          "(default 1000).\n");
  fprintf(stderr, "  wait      The wait time between packet sends in "
          "usec (default 0).\n");
  fprintf(stderr, "  prio      The priority (0=highest, 7=lowest) (default "
          "3).\n");
  fprintf(stderr, "  rel       The reliability mode (beffort, rel_arq, "
          "srel_arq[rx_lim],\n            srel_arqfec[rx_lim,tgt_rnds,"
          "tgt_rcv_prob]) (default rel_arq).\n");
  fprintf(stderr, "  del       The delivery mode (ord, unord) (default "
          "ord).\n");
  fprintf(stderr, "  q_size    The transmit queue size in packets (default "
          "16).\n");
  fprintf(stderr, "  q_deq     The transmit queue dequeue rule (fifo, lifo) "
          "(default fifo).\n");
  fprintf(stderr, "  q_drop    The transmit queue drop rule (none, head, "
          "tail) (default none).\n");

  fprintf(stderr, "\n");

  exit(2);
}

//============================================================================
bool TestApp::ParseCongCtrlConfig(const char* cc_config)
{
  // Parse the list of congestion control names, separated by ','.
  string        conf(cc_config);
  List<string>  tokens;
  size_t        num_tokens = 0;

  StringUtils::Tokenize(conf, ",", tokens);
  num_tokens = tokens.size();

  if ((num_tokens < 1) || (num_tokens > kMaxCcAlg))
  {
    return false;
  }

  // Loop over each token.
  for (size_t i = 0; i < num_tokens; ++i)
  {
    string  tok;

    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Missing congestion control token.\n");
      return false;
    }

    const char*  cc_tok = tok.c_str();

    if (strncmp(cc_tok, "cubic", 5) == 0)
    {
      cc_algorithm_[i].SetTcpCubic();
    }
    else if (strncmp(cc_tok, "copam", 5) == 0)
    {
      cc_algorithm_[i].SetCopaM(false);
    }
    else if (strncmp(cc_tok, "detcopam", 8) == 0)
    {
      cc_algorithm_[i].SetCopaM(true);
    }
    else if (strncmp(cc_tok, "copa_", 5) == 0)
    {
      const char*  beg_ptr = &(cc_tok[5]);
      char*        end_ptr = NULL;
      double       delta   = strtod(beg_ptr, &end_ptr);

      if (end_ptr == beg_ptr)
      {
        LogE(kName, __func__, "Invalid delta value: %s\n", cc_tok);
        return false;
      }

      cc_algorithm_[i].SetCopa(delta, false);
    }
    else if (strncmp(cc_tok, "detcopa_", 8) == 0)
    {
      const char*  beg_ptr = &(cc_tok[8]);
      char*        end_ptr = NULL;
      double       delta   = strtod(beg_ptr, &end_ptr);

      if (end_ptr == beg_ptr)
      {
        LogE(kName, __func__, "Invalid delta value: %s\n", cc_tok);
        return false;
      }

      cc_algorithm_[i].SetCopa(delta, true);
    }
    else if (strncmp(cc_tok, "copa2", 5) == 0)
    {
      cc_algorithm_[i].SetCopa2();
    }
    else if (strncmp(cc_tok, "copa3", 5) == 0)
    {
      cc_algorithm_[i].SetCopa3();
    }
    else if (strncmp(cc_tok, "gubicpacing", 11) == 0)
    {
      cc_algorithm_[i].SetGoogleTcpCubic(true);
    }
    else if (strncmp(cc_tok, "gubic", 5) == 0)
    {
      cc_algorithm_[i].SetGoogleTcpCubic(false);
    }
    else if (strncmp(cc_tok, "renopacing", 10) == 0)
    {
      cc_algorithm_[i].SetGoogleTcpReno(true);
    }
    else if (strncmp(cc_tok, "reno", 4) == 0)
    {
      cc_algorithm_[i].SetGoogleTcpReno(false);
    }
    else if (strncmp(cc_tok, "fixedrate_", 10) == 0)
    {
      const char*  beg_ptr = &(cc_tok[10]);
      char*        end_ptr = NULL;
      uint64_t     rate    = static_cast<uint64_t>(
        strtoull(beg_ptr, &end_ptr, 10));

      if (end_ptr == beg_ptr)
      {
        LogE(kName, __func__, "Invalid rate value: %s\n", cc_tok);
        return false;
      }

      cc_algorithm_[i].SetFixedRate(rate);
    }
    else if (strncmp(cc_tok, "none", 4) == 0)
    {
      cc_algorithm_[i].SetNoCc();
    }
    else
    {
      LogE(kName, __func__, "Invalid congestion control: %s\n", cc_tok);
      return false;
    }
  }

  // All of the tokens were parsed successfully.
  num_cc_alg_ = num_tokens;

  return true;
}

//============================================================================
bool TestApp::ParseDirectConnConfig(const char* dir_conn_config)
{
  // Tokenize the direct connection address string, which should contain two
  // IP addresses separated by ','.
  string        conf(dir_conn_config);
  List<string>  tokens;
  size_t        num_tokens = 0;

  StringUtils::Tokenize(conf, ",", tokens);
  num_tokens = tokens.size();

  if (num_tokens != 2)
  {
    return false;
  }

  // Store the IP addresses.
  if (!tokens.Pop(direct_local_addr_))
  {
    return false;
  }

  if (!tokens.Pop(direct_remote_addr_))
  {
    return false;
  }

  // Use a direct connection.
  direct_conn_ = true;

  return true;
}

//============================================================================
bool TestApp::ParseStreamConfig(const char* stream_config)
{
  // Set the default stream configuration parameters.
  int              val        = 0;
  int64_t          wval       = 0;
  StreamId         stream_id  = 0;
  bool             lim_pkts   = true;
  int              pkts       = 0;
  bool             rand_len   = false;
  int              min_len    = 1000;
  int              max_len    = 1000;
  int64_t          wait       = 0;
  Priority         prio       = 3;
  Reliability      rel;
  RexmitLimit      limit      = 2;
  DeliveryMode     del_mode   = sliq::ORDERED_DELIVERY;
  int              q_size     = 16;
  DequeueRule      q_deq_pol  = sliq::FIFO_QUEUE;
  DropRule         q_drop_pol = sliq::NO_DROP;

  // Tokenize the stream configuration string.
  string        tok;
  string        conf(stream_config);
  List<string>  tokens;
  size_t        num_tokens = 0;

  StringUtils::Tokenize(conf, ":", tokens);
  num_tokens = tokens.size();

  // Must have at least the stream ID and the number of packets to send.
  if (num_tokens < 2)
  {
    return false;
  }

  // Stream ID.
  if (!tokens.Pop(tok))
  {
    LogE(kName, __func__, "Stream ID tokenization error.\n");
    return false;
  }
  num_tokens--;
  val = StringUtils::GetInt(tok, -1);
  if ((val < 1) || (val > 32))
  {
    LogE(kName, __func__, "Invalid stream ID: %s\n", tok.c_str());
    return false;
  }
  if (stream_[val] != NULL)
  {
    LogE(kName, __func__, "Duplicate stream ID: %s\n", tok.c_str());
    return false;
  }
  stream_id = static_cast<StreamId>(val);

  // Number of packets to send.
  if (!tokens.Pop(tok))
  {
    LogE(kName, __func__, "Number of packets tokenization error.\n");
    return false;
  }
  num_tokens--;
  if (tok.substr(tok.size() - 1, 1) == "s")
  {
    val = StringUtils::GetInt(tok.substr(0, tok.size() - 1), -1);
    if (val < 0)
    {
      LogE(kName, __func__, "Invalid number of seconds: %s\n", tok.c_str());
      return false;
    }
    lim_pkts = false;
  }
  else
  {
    val = StringUtils::GetInt(tok, -1);
    if (val < 0)
    {
      LogE(kName, __func__, "Invalid number of packets: %s\n", tok.c_str());
      return false;
    }
    lim_pkts = true;
  }
  pkts = val;

  // Packet size in bytes.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Packet size tokenization error.\n");
      return false;
    }
    num_tokens--;
    if (tok.substr(0, 5) == "rand[")
    {
      string        rand_str = tok.substr(5, (tok.size() - 6));
      List<string>  rand_lim;
      StringUtils::Tokenize(rand_str, ",", rand_lim);
      if (rand_lim.size() != 2)
      {
        LogE(kName, __func__, "Invalid random packet size format: %s\n",
             rand_str.c_str());
        return false;
      }
      if (!rand_lim.Pop(tok))
      {
        LogE(kName, __func__, "Minimum length tokenization error.\n");
        return false;
      }
      min_len = StringUtils::GetInt(tok, -1);
      if (!rand_lim.Pop(tok))
      {
        LogE(kName, __func__, "Maximum length tokenization error.\n");
        return false;
      }
      max_len = StringUtils::GetInt(tok, -1);
      if ((min_len < kMinPayload) || (min_len > (kMaxPayload - 1)) ||
          (max_len < (kMinPayload + 1)) || (max_len > kMaxPayload) ||
          (min_len >= max_len))
      {
        LogE(kName, __func__, "Invalid random packet size limits: %s\n",
             rand_str.c_str());
        return false;
      }
      rand_len = true;
    }
    else
    {
      val = StringUtils::GetInt(tok, -1);
      if ((val < kMinPayload) || (val > kMaxPayload))
      {
        LogE(kName, __func__, "Invalid packet size: %s\n", tok.c_str());
        return false;
      }
      min_len = val;
      max_len = val;
    }
  }

  // Wait time between packet sends in microseconds.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Wait time tokenization error.\n");
      return false;
    }
    num_tokens--;
    wval = StringUtils::GetInt64(tok, -1);
    if (wval < 0)
    {
      LogE(kName, __func__, "Invalid wait time: %s\n", tok.c_str());
      return false;
    }
    wait = wval;
  }

  // Priority.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Priority tokenization error.\n");
      return false;
    }
    num_tokens--;
    val = StringUtils::GetInt(tok, -1);
    if ((val < 0) || (val > 7))
    {
      LogE(kName, __func__, "Invalid priority: %s\n", tok.c_str());
      return false;
    }
    prio = static_cast<Priority>(val);
  }

  // Reliability mode.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Reliability mode tokenization error.\n");
      return false;
    }
    num_tokens--;
    if (tok == "rel_arq")
    {
      rel.SetRelArq();
    }
    else if (tok.substr(0, 9) == "srel_arq[")
    {
      val = StringUtils::GetInt(tok.substr(9, (tok.size() - 10)), -1);
      if ((val < 1) || (val > 255))
      {
        LogE(kName, __func__, "Invalid semi-reliable ARQ retransmission "
             "limit: %s\n", tok.c_str());
        return false;
      }
      limit = static_cast<RexmitLimit>(val);
      rel.SetSemiRelArq(limit);
    }
    else if (tok.substr(0, 12) == "srel_arqfec[")
    {
      string        mix_str = tok.substr(12, (tok.size() - 13));
      List<string>  mix_val;
      StringUtils::Tokenize(mix_str, ",", mix_val);
      if (mix_val.size() != 3)
      {
        LogE(kName, __func__, "Invalid semi-reliable ARQ/FEC format: %s\n",
             mix_str.c_str());
        return false;
      }
      if (!mix_val.Pop(tok))
      {
        LogE(kName, __func__, "Semi-reliable ARQ/FEC retransmission limit "
             "tokenization error.\n");
        return false;
      }
      val = StringUtils::GetInt(tok, -1);
      if ((val < 0) || (val > 255))
      {
        LogE(kName, __func__, "Invalid semi-reliable ARQ/FEC retransmission "
             "limit: %s\n", tok.c_str());
        return false;
      }
      limit = static_cast<RexmitLimit>(val);
      if (!mix_val.Pop(tok))
      {
        LogE(kName, __func__, "Semi-reliable ARQ/FEC target rounds "
             "tokenization error.\n");
        return false;
      }
      val = StringUtils::GetInt(tok, 0);
      if ((val < 1) || (val > static_cast<int>(limit + 1)))
      {
        LogE(kName, __func__, "Invalid semi-reliable ARQ/FEC target rounds: "
             "%s\n", tok.c_str());
        return false;
      }
      RexmitLimit  tgt_rounds = static_cast<RexmitLimit>(val);
      if (!mix_val.Pop(tok))
      {
        LogE(kName, __func__, "Semi-reliable ARQ/FEC target receive "
             "probability tokenization error.\n");
        return false;
      }
      double  rcv_p = StringUtils::GetDouble(tok, 1.0);
      if ((rcv_p <= 0.0) || (rcv_p > 0.999))
      {
        LogE(kName, __func__, "Invalid semi-reliable ARQ/FEC target receive "
             "probability: %s\n", tok.c_str());
        return false;
      }
      rel.SetSemiRelArqFecUsingRounds(limit, rcv_p, tgt_rounds);
    }
    else if (tok == "beffort")
    {
      rel.SetBestEffort();
    }
    else
    {
      LogE(kName, __func__, "Invalid reliability mode: %s\n", tok.c_str());
      return false;
    }
  }

  // Delivery mode.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Delivery mode tokenization error.\n");
      return false;
    }
    num_tokens--;
    if (tok == "ord")
    {
      del_mode = sliq::ORDERED_DELIVERY;
    }
    else if (tok == "unord")
    {
      del_mode = sliq::UNORDERED_DELIVERY;
    }
    else
    {
      LogE(kName, __func__, "Invalid delivery mode: %s\n", tok.c_str());
      return false;
    }
  }

  // Transmit queue size in packets.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Transmit queue size tokenization error.\n");
      return false;
    }
    num_tokens--;
    val = StringUtils::GetInt(tok, -1);
    if (val < 1)
    {
      LogE(kName, __func__, "Invalid transmit queue size: %s\n", tok.c_str());
      return false;
    }
    q_size = val;
  }

  // Transmit queue dequeueing rule.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Transmit queue dequeueing rule tokenization "
           "error.\n");
      return false;
    }
    num_tokens--;
    if (tok == "fifo")
    {
      q_deq_pol = sliq::FIFO_QUEUE;
    }
    else if (tok == "lifo")
    {
      q_deq_pol = sliq::LIFO_QUEUE;
    }
    else
    {
      LogE(kName, __func__, "Invalid transmit dequeueing rule: %s\n",
           tok.c_str());
      return false;
    }
  }

  // Transmit queue drop rule.
  if (num_tokens > 0)
  {
    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Transmit queue drop rule tokenization error.\n");
      return false;
    }
    num_tokens--;
    if (tok == "none")
    {
      q_drop_pol = sliq::NO_DROP;
    }
    else if (tok == "head")
    {
      q_drop_pol = sliq::HEAD_DROP;
    }
    else if (tok == "tail")
    {
      q_drop_pol = sliq::TAIL_DROP;
    }
    else
    {
      LogE(kName, __func__, "Invalid transmit drop rule: %s\n",
           tok.c_str());
      return false;
    }
  }

  // Create the stream.
  TestStream*  stream = new TestStream(stream_id, prio, rel, del_mode,
                                       pkt_pool_);

  if (stream == NULL)
  {
    LogE(kName, __func__, "Memory allocation error.\n");
    return false;
  }

  // Configure the stream for sending.
  stream->ConfigXmitQueue(q_size, q_deq_pol, q_drop_pol);
  stream->ConfigSending(lim_pkts, pkts, rand_len, min_len, max_len, wait);

  // Store the stream.  Odd stream IDs are client-side, even stream IDs are
  // server-side.
  stream_[stream_id] = stream;

  if ((static_cast<int>(stream_id) % 2) == 1)
  {
    client_stream_ids_[num_client_streams_] = stream_id;
    num_client_streams_++;
  }
  else
  {
    server_stream_ids_[num_server_streams_] = stream_id;
    num_server_streams_++;
  }

  return true;
}

//============================================================================
bool TestApp::ParseLatencySensitiveStreamIds(const char* lss_config)
{
  // Parse the list of latency sensitive stream IDs, separated by ','.
  string        conf(lss_config);
  List<string>  tokens;
  size_t        num_tokens = 0;

  StringUtils::Tokenize(conf, ",", tokens);
  num_tokens = tokens.size();

  if ((num_tokens < 1) || (num_tokens >= kMaxStreams))
  {
    return false;
  }

  // Loop over each token.
  for (size_t i = 0; i < num_tokens; ++i)
  {
    string  tok;

    if (!tokens.Pop(tok))
    {
      LogE(kName, __func__, "Missing latency sensitive stream ID token.\n");
      return false;
    }

    StreamId  stream_id = StringUtils::GetUint(tok, kMaxStreams);

    if ((stream_id < 1) || (stream_id >= kMaxStreams))
    {
      LogE(kName, __func__, "Invalid latency sensitive stream ID: %s\n",
           tok.c_str());
      return false;
    }

    // Mark the stream as latency-sensitive.
    lat_sens_stream_[stream_id] = true;
  }

  return true;
}

//============================================================================
bool TestApp::ActAsServer(const Ipv4Endpoint& server_address)
{
  LogD(kName, __func__, "TestApp object will act as a SERVER.\n");

  if (direct_conn_)
  {
    // Set up a server data endpoint directly.
    string        endpoint_str = direct_local_addr_ + ":" + server_port_;
    Ipv4Endpoint  server_addr(endpoint_str);

    endpoint_str = direct_remote_addr_ + ":" + server_port_;
    Ipv4Endpoint  client_addr(endpoint_str);

    if (!SetupServerDataEndpoint(server_addr, client_addr, data_endpt_id_))
    {
      LogE(kName, __func__, "Error in SetupServerDataEndpoint().\n");
      return false;
    }

    LogD(kName, __func__, "TestApp object has direct server connection from "
         "%s to %s on endpoint %" PRIEndptId ".\n",
         server_addr.ToString().c_str(), client_addr.ToString().c_str(),
         data_endpt_id_);
  }
  else
  {
    // Listen on the specified server address and port number.  The
    // ProcessConnectionRequest() method will be called for each client
    // connection request.
    if (!Listen(server_address, listen_endpt_id_))
    {
      LogE(kName, __func__, "Error in Listen().\n");
      return false;
    }

    LogD(kName, __func__, "TestApp object is listening for connections at "
         "address %s on endpoint %" PRIEndptId ".\n",
         server_address.ToString().c_str(), listen_endpt_id_);
  }

  return true;
}

//============================================================================
bool TestApp::ActAsClient(const Ipv4Endpoint& server_address)
{
  LogD(kName, __func__, "TestApp object will act as a CLIENT.\n");

  if (direct_conn_)
  {
    // Set up a client data endpoint directly.
    string        endpoint_str = direct_local_addr_ + ":" + server_port_;
    Ipv4Endpoint  client_addr(endpoint_str);

    endpoint_str = direct_remote_addr_ + ":" + server_port_;
    Ipv4Endpoint  server_addr(endpoint_str);

    if (!SetupClientDataEndpoint(client_addr, server_addr, cc_algorithm_,
                                 num_cc_alg_, data_endpt_id_))
    {
      LogE(kName, __func__, "Error in SetupClientDataEndpoint().\n");
      return false;
    }

    LogD(kName, __func__, "TestApp object has direct client connection from "
         "%s to %s on endpoint %" PRIEndptId ".\n",
         client_addr.ToString().c_str(), server_addr.ToString().c_str(),
         data_endpt_id_);
  }
  else
  {
    // Initiate a connection to the server.  The ProcessConnectionResult()
    // method will be called with the result later.
    if (!Connect(server_address, cc_algorithm_, num_cc_alg_, data_endpt_id_))
    {
      LogE(kName, __func__, "Error in Connect().\n");
      return false;
    }

    LogD(kName, __func__, "TestApp object is connecting to server %s on "
         "endpoint %" PRIEndptId ".\n", server_address.ToString().c_str(),
         data_endpt_id_);
  }

  return true;
}

//============================================================================
void TestApp::CloseClient()
{
  for (size_t i = 0; i < kMaxStreams; ++i)
  {
    if (stream_[i] != NULL)
    {
      LogD(kName, __func__, "Step #1: TestApp client is closing stream "
           "%zu.\n", i);
      stream_[i]->Close(this, data_endpt_id_);
    }
  }
}

//============================================================================
int main(int argc, char** argv)
{
  // Create the PacketPool, Timer, and TestApp objects.
  PacketPoolHeap*  pkt_pool = new (std::nothrow) PacketPoolHeap();

  if ((pkt_pool == NULL) || (!pkt_pool->Create(kPktPoolSize)))
  {
    LogE("main", __func__, "Error creating PacketPool.\n");
    exit(1);
  }

  Timer*  timer = new (std::nothrow) Timer();

  if (timer == NULL)
  {
    LogE("main", __func__, "Error creating Timer.\n");
    delete pkt_pool;
    exit(1);
  }

  TestApp*  test_app = new (std::nothrow) TestApp(*pkt_pool, *timer);

  if (test_app == NULL)
  {
    LogE("main", __func__, "Error creating TestApp.\n");
    delete pkt_pool;
    delete timer;
    exit(1);
  }

  // Initialize the TestApp object.
  if (!test_app->Init(argc, argv))
  {
    LogE("main", __func__, "Error initializing TestApp.\n");
    exit(1);
  }

  // Run!!
  test_app->Run();

  // Print out the resulting statistics.
  test_app->PrintStats();

  // Destroy the TestApp objects.
  delete test_app;
  test_app = NULL;

  delete timer;
  timer = NULL;

  delete pkt_pool;
  pkt_pool = NULL;

  // Clean up common components.
  Log::Destroy();

  return 0;
}
