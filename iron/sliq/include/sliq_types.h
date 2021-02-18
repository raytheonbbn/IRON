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

#ifndef IRON_SLIC_TYPES_H
#define IRON_SLIC_TYPES_H

#include "itime.h"

#include <stdint.h>
#include <inttypes.h>


namespace sliq
{

  typedef uint64_t  Capacity;      ///< Capacity in bits/second
  typedef int       EndptId;       ///< Endpoint identifier
  typedef uint8_t   Priority;      ///< Stream priority
  typedef uint8_t   StreamId;      ///< Stream identifier
  typedef uint8_t   RexmitLimit;   ///< Packet retransmit limit
  typedef uint8_t   RexmitRounds;  ///< Packet retransmit rounds
  typedef uint32_t  PktTimestamp;  ///< Packet timestamp

  // Macros for printing format specifiers.
#define PRICapacity      PRIu64
#define PRIEndptId       "d"
#define PRIPriority      PRIu8
#define PRIStreamId      PRIu8
#define PRIRexmitLimit   PRIu8
#define PRIRexmitRounds  PRIu8
#define PRIPktTimestamp  PRIu32

  /// All possible SLIQ endpoint types.
  enum EndptType
  {
    UNKNOWN_ENDPOINT,  ///< Invalid endpoint
    SERVER_LISTEN,     ///< Server-side listen endpoint
    SERVER_DATA,       ///< Server-side data endpoint
    CLIENT_DATA        ///< Client-side data endpoint
  };

  /// The SLIQ congestion control algorithms.  Up to 256 may be defined.
  enum CongCtrlAlg
  {
    NO_CC = 0,                 ///< No congestion control
    TCP_CUBIC_BYTES_CC = 1,    ///< Google's TCP Cubic using bytes
    TCP_RENO_BYTES_CC = 2,     ///< Google's TCP Reno using bytes
    TCP_CUBIC_CC = 3,          ///< Linux kernel's TCP Cubic using bytes
    COPA1_CONST_DELTA_CC = 4,  ///< MIT's Copa Beta 1 with constant delta
    COPA1_M_CC = 5,            ///< MIT's Copa Beta 1 with IRON's maximum
                               ///< throughput policy controller
    COPA2_CC = 6,              ///< MIT's Copa Beta 2
    COPA_CC = 7,               ///< MIT's Copa (final version)

    FIXED_RATE_TEST_CC = 15,   ///< Fixed send rate instead of congestion
                               ///< control, for testing only

    DEFAULT_CC = 256           ///< Use SLIQ's default congestion control
  };

  /// The SLIQ congestion control specification.
  ///
  /// Note the following:
  /// - cubic_reno_pacing is only applicable to the TCP_CUBIC_BYTES_CC and
  ///   TCP_RENO_BYTES_CC algoritms.
  /// - deterministic_copa is only applicable to the COPA1_CONST_DELTA_CC and
  ///   COPA1_M_CC algorithms.  It is highly suggested that this always be set
  ///   to true for these algorithms.
  /// - copa_delta is only applicable to the COPA1_CONST_DELTA_CC algorithm.
  ///   This value must be between 0.004 and 1.0 (inclusive) for this
  ///   algorithm.
  /// - copa_anti_jitter is only applicable to the COPA_CC algorithm.  This
  ///   value is specified in seconds and must be between 0.0 and 1.0.
  /// - fixed_send_rate is only applicable to the FIXED_RATE_TEST_CC
  ///   algorithm.  This value is specified in bits/second and must be greater
  ///   than 0.  The value is shared between endpoints, and is currently set
  ///   to the same value on each end.
  struct CongCtrl
  {
    CongCtrl()
        : algorithm(DEFAULT_CC), cubic_reno_pacing(false),
          deterministic_copa(false), copa_delta(0.0), copa_anti_jitter(0.0),
          fixed_send_rate(0)
    {}

    virtual ~CongCtrl()
    {}

    void SetNoCc()
    {
      algorithm          = NO_CC;
      cubic_reno_pacing  = false;
      deterministic_copa = false;
      copa_delta         = 0.0;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = 0;
    }

    void SetGoogleTcpCubic(bool send_pacing = true)
    {
      algorithm          = TCP_CUBIC_BYTES_CC;
      cubic_reno_pacing  = send_pacing;
      deterministic_copa = false;
      copa_delta         = 0.0;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = 0;
    }

    void SetGoogleTcpReno(bool send_pacing = true)
    {
      algorithm          = TCP_RENO_BYTES_CC;
      cubic_reno_pacing  = send_pacing;
      deterministic_copa = false;
      copa_delta         = 0.0;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = 0;
    }

    void SetTcpCubic()
    {
      algorithm          = TCP_CUBIC_CC;
      cubic_reno_pacing  = false;
      deterministic_copa = false;
      copa_delta         = 0.0;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = 0;
    }

    void SetCopaBeta1(double delta, bool deterministic = true)
    {
      algorithm          = COPA1_CONST_DELTA_CC;
      cubic_reno_pacing  = false;
      deterministic_copa = deterministic;
      copa_delta         = delta;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = 0;
    }

    void SetCopaBeta1M(bool deterministic = true)
    {
      algorithm          = COPA1_M_CC;
      cubic_reno_pacing  = false;
      deterministic_copa = deterministic;
      copa_delta         = 0.0;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = 0;
    }

    void SetCopaBeta2()
    {
      algorithm          = COPA2_CC;
      cubic_reno_pacing  = false;
      deterministic_copa = false;
      copa_delta         = 0.0;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = 0;
    }

    void SetCopa(double anti_jitter_sec = 0.0)
    {
      algorithm          = COPA_CC;
      cubic_reno_pacing  = false;
      deterministic_copa = false;
      copa_delta         = 0.0;
      copa_anti_jitter   = anti_jitter_sec;
      fixed_send_rate    = 0;
    }

    void SetFixedRate(Capacity send_rate_bps)
    {
      algorithm          = FIXED_RATE_TEST_CC;
      cubic_reno_pacing  = false;
      deterministic_copa = false;
      copa_delta         = 0.0;
      copa_anti_jitter   = 0.0;
      fixed_send_rate    = send_rate_bps;
    }

    bool operator==(const CongCtrl& cc)
    {
      return ((algorithm == cc.algorithm) &&
              (((algorithm != TCP_CUBIC_BYTES_CC) &&
                (algorithm != TCP_RENO_BYTES_CC)) ||
               (cubic_reno_pacing == cc.cubic_reno_pacing)) &&
              (((algorithm != COPA1_CONST_DELTA_CC) &&
                (algorithm != COPA1_M_CC)) ||
               (deterministic_copa == cc.deterministic_copa)) &&
              ((algorithm != COPA1_CONST_DELTA_CC) ||
               (static_cast<int>(copa_delta * 1000.0) ==
                static_cast<int>(cc.copa_delta * 1000.0))) &&
              ((algorithm != COPA_CC) ||
               (static_cast<int>((copa_anti_jitter * 1000000.0) + 0.5) ==
                static_cast<int>((cc.copa_anti_jitter * 1000000.0) +
                                 0.5))) &&
              ((algorithm != FIXED_RATE_TEST_CC) ||
               (fixed_send_rate == cc.fixed_send_rate)));
    }

    bool operator!=(const CongCtrl& cc)
    {
      return (!(*this == cc));
    }

    /// Congestion control algorithm
    CongCtrlAlg  algorithm;

    /// Cubic/Reno pacing flag setting
    bool         cubic_reno_pacing;

    /// Deterministic Copa Beta 1 flag setting
    bool         deterministic_copa;

    /// Copa Beta 1 constant delta value
    double       copa_delta;

    /// Copa anti-jitter value, in seconds
    double       copa_anti_jitter;

    /// Fixed send rate value, in bits/second
    Capacity     fixed_send_rate;
  };

  /// The SLIQ reliability modes.  Up to 16 may be defined.
  ///
  /// The supported modes are:
  /// - BEST_EFFORT mode does not send any data packet retransmissions or
  ///   encoded data packets to the receiver.
  /// - SEMI_RELIABLE_ARQ mode only sends a limited number of data packet
  ///   retransmissions when data packets are reported as missing in an
  ///   attempt to deliver each data packet to the receiver.
  /// - SEMI_RELIABLE_ARQ_FEC mode sends some number of data packets and/or
  ///   encoded data packets as transmissions and retransmissions in an
  ///   attempt to achieve a set of desired receive characteristics.
  /// - RELIABLE_ARQ mode sends as many data packet retransmissions as needed
  ///   to make sure that each data packet is delivered to the receiver.
  enum ReliabilityMode
  {
    BEST_EFFORT = 0,            ///< Single transmission, no ARQ or FEC
    SEMI_RELIABLE_ARQ = 1,      ///< Semi-reliable using ARQ
    SEMI_RELIABLE_ARQ_FEC = 2,  ///< Semi-reliable using FEC and ARQ
    RELIABLE_ARQ = 4            ///< Fully reliable using ARQ
  };

  /// The SLIQ reliability specification.
  ///
  /// Note the following:
  /// - The mode setting specifies the reliability mode.
  /// - The rexmit_limit setting is only applicable to the SEMI_RELIABLE_ARQ
  ///   and SEMI_RELIABLE_ARQ_FEC modes.  It specifies the maximum number of
  ///   retransmissions allowed before a data packet is given up on by the
  ///   sender, and must be (1 <= rexmit_limit <= 255) for SEMI_RELIABLE_ARQ
  ///   mode or (0 <= rexmit_limit <= 255) for SEMI_RELIABLE_ARQ_FEC mode.
  /// - The fec_target_pkt_recv_prob setting is only applicable to the
  ///   SEMI_RELIABLE_ARQ_FEC mode.  It specifies the target packet receive
  ///   probability at the peer, and must be
  ///   (0.95 <= fec_target_pkt_recv_prob <= 0.999).
  /// - The fec_del_time_flag setting is only applicable to the
  ///   SEMI_RELIABLE_ARQ_FEC mode.  It determines if the target packet
  ///   delivery limit is specified as a number of rounds or a time.
  /// - The fec_target_pkt_del_rounds setting is only applicable to the
  ///   SEMI_RELIABLE_ARQ_FEC mode.  It specifies the target number of
  ///   transmission/retransmission rounds allowed in order to achieve the
  ///   target packet receive probability, and must be
  ///   (1 <= fec_target_pkt_del_rounds <= (rexmit_limit + 1)).
  /// - The fec_target_pkt_del_time_sec setting is only applicable to the
  ///   SEMI_RELIABLE_ARQ_FEC mode.  It specifies the target number of seconds
  ///   allowed in order to achieve the target packet receive probability.
  struct Reliability
  {
    Reliability()
        : mode(RELIABLE_ARQ), rexmit_limit(0), fec_target_pkt_recv_prob(0.0),
          fec_del_time_flag(false), fec_target_pkt_del_rounds(0),
          fec_target_pkt_del_time_sec(0.0)
    {}

    virtual ~Reliability()
    {}

    Reliability(ReliabilityMode m, RexmitLimit rx_lim, double recv_prob,
                bool del_time, RexmitRounds recv_rounds, double recv_time)
        : mode(m), rexmit_limit(rx_lim), fec_target_pkt_recv_prob(recv_prob),
          fec_del_time_flag(del_time), fec_target_pkt_del_rounds(recv_rounds),
          fec_target_pkt_del_time_sec(recv_time)
    {}

    void SetBestEffort()
    {
      mode                        = BEST_EFFORT;
      rexmit_limit                = 0;
      fec_target_pkt_recv_prob    = 0.0;
      fec_del_time_flag           = false;
      fec_target_pkt_del_rounds   = 0;
      fec_target_pkt_del_time_sec = 0.0;
    }

    void SetSemiRelArq(RexmitLimit rx_lim)
    {
      mode                        = SEMI_RELIABLE_ARQ;
      rexmit_limit                = rx_lim;
      fec_target_pkt_recv_prob    = 0.0;
      fec_del_time_flag           = false;
      fec_target_pkt_del_rounds   = 0;
      fec_target_pkt_del_time_sec = 0.0;
    }

    void SetSemiRelArqFecUsingRounds(RexmitLimit rx_lim, double recv_prob,
                                     RexmitRounds recv_rounds)
    {
      mode                        = SEMI_RELIABLE_ARQ_FEC;
      rexmit_limit                = rx_lim;
      fec_target_pkt_recv_prob    = recv_prob;
      fec_del_time_flag           = false;
      fec_target_pkt_del_rounds   = recv_rounds;
      fec_target_pkt_del_time_sec = 0.0;
    }

    void SetSemiRelArqFecUsingTime(RexmitLimit rx_lim, double recv_prob,
                                   double recv_time_sec)
    {
      mode                        = SEMI_RELIABLE_ARQ_FEC;
      rexmit_limit                = rx_lim;
      fec_target_pkt_recv_prob    = recv_prob;
      fec_del_time_flag           = true;
      fec_target_pkt_del_rounds   = 0;
      fec_target_pkt_del_time_sec = recv_time_sec;
    }

    void SetRelArq()
    {
      mode                        = RELIABLE_ARQ;
      rexmit_limit                = 0;
      fec_target_pkt_recv_prob    = 0.0;
      fec_del_time_flag           = false;
      fec_target_pkt_del_rounds   = 0;
      fec_target_pkt_del_time_sec = 0.0;
    }

    bool operator==(const Reliability& r)
    {
      return ((mode == r.mode) &&
              (((mode != SEMI_RELIABLE_ARQ) &&
                (mode != SEMI_RELIABLE_ARQ_FEC)) ||
               (rexmit_limit == r.rexmit_limit)) &&
              ((mode != SEMI_RELIABLE_ARQ_FEC) ||
               ((static_cast<int>((fec_target_pkt_recv_prob *
                                   10000.0) + 0.5) ==
                 static_cast<int>((r.fec_target_pkt_recv_prob *
                                   10000.0) + 0.5)) &&
                (fec_del_time_flag == r.fec_del_time_flag) &&
                ((fec_del_time_flag) ||
                 (fec_target_pkt_del_rounds ==
                  r.fec_target_pkt_del_rounds)) &&
                ((!fec_del_time_flag) ||
                 (static_cast<int>((fec_target_pkt_del_time_sec *
                                    1000.0) + 0.5) ==
                  static_cast<int>((r.fec_target_pkt_del_time_sec *
                                    1000.0) + 0.5))))));
    }

    bool operator!=(const Reliability& r)
    {
      return (!(*this == r));
    }

    /// Reliability mode
    ReliabilityMode  mode;

    /// Retransmission limit
    RexmitLimit      rexmit_limit;

    /// FEC target packet receive probability
    double           fec_target_pkt_recv_prob;

    /// Flag controlling if the FEC target packet delivery limit is specified
    /// as rounds (false) or time (true)
    bool             fec_del_time_flag;

    /// FEC target packet delivery transmission/retransmission rounds
    RexmitRounds     fec_target_pkt_del_rounds;

    /// FEC target packet delivery time in seconds
    double           fec_target_pkt_del_time_sec;
  };

  /// The SLIQ delivery modes.  Up to 16 may be defined.
  ///
  /// The supported modes are:
  /// - UNORDERED_DELIVERY means that data packets may be delivered to the
  ///   receiving application in a different order than the order in which
  ///   they were sent by the sending application.
  /// - ORDERED_DELIVERY means that data packets are delivered to the
  ///   receiving application in the same order that they were sent by the
  ///   sending application.
  ///
  /// Note the following:
  /// - When in RELIABLE_ARQ reliability mode, either ORDERED_DELIVERY or
  ///   UNORDERED_DELIVERY may be selected.
  /// - When in any other reliability mode, only UNORDERED_DELIVERY may be
  ///   selected.
  enum DeliveryMode
  {
    UNORDERED_DELIVERY = 0,  ///< Packets may not be delivered in order
    ORDERED_DELIVERY = 1     ///< Packets delivered in order
  };

  /// The SLIQ dequeueing rules for the packet transmit queue.
  enum DequeueRule
  {
    FIFO_QUEUE = 0,  ///< First in, first out queue
    LIFO_QUEUE = 1   ///< Last in, first out queue
  };

  /// The SLIQ drop rules for the packet transmit queue.
  enum DropRule
  {
    NO_DROP = 0,    ///< Enqueue will fail when queue is full
    HEAD_DROP = 1,  ///< Enqueue will drop head packet when queue is full
    TAIL_DROP = 2   ///< Enqueue will drop tail packet when queue is full
  };

  /// The SLIQ RTT and packet delivery delay (PDD) structure.
  struct RttPdd
  {
    RttPdd()
        : stream_id(0), rtt_usec(0), pdd_usec(0)
    {}

    virtual ~RttPdd()
    {}

    /// Stream ID
    StreamId  stream_id;

    /// RTT in usec
    uint32_t  rtt_usec;

    /// Packet delivery delay in usec
    uint32_t  pdd_usec;
  };

} // namespace sliq

#endif // IRON_SLIC_TYPES_H
