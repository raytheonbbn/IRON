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

#include "cong_ctrl_vj.h"
#include "itime.h"
#include "log.h"
#include "socket.h"
#include "unused.h"

#include <netinet/tcp.h>

using ::iron::Time;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "VJCongCtrlAlg";
}


//============================================================================
VJCongCtrlAlg::VJCongCtrlAlg(Socket* s)
  : CongCtrlAlg(s)
{
}

//============================================================================
VJCongCtrlAlg::VJCongCtrlAlg(const VJCongCtrlAlg& other, Socket* s)
  : CongCtrlAlg(s)
{
}

//============================================================================
void VJCongCtrlAlg::Init()
{
}

//============================================================================
void VJCongCtrlAlg::AckRcvd(uint32_t ack_num, int bytes_acked)
{
  if (!selected_)
  {
    return;
  }

  // Credit our cwnd for the value of the data acked.
  //
  // This should only be called if you are not in a fast recovery epoch.
  if (!(socket_->funct_flags() & FUNCT_HIGH_SEQ))
  {
    if ((socket_->funct_flags() & FUNCT_HIGH_CONGESTION_SEQ) &&
        (SEQ_LEQ(ack_num, socket_->high_cong_seq())))
    {
      // No soup for you!
    }
    else
    {
      // [VF010.2]
      // Correct condition: removed diff from calculation
      // Simplified if-else
      // Added cast to int to take care of sequence wrap
      // Replaced maxseg with maxdata

      if ((int)(socket_->seq_sent() - ack_num) <=
          (int)socket_->snd_prev_cwnd())
      {
        socket_->snd_cwnd() += MAX(socket_->max_data(), bytes_acked);
      }

      //
      // Always cap snd_cwnd to snd_prevcwnd when you are NOT in an epoch.
      //

      socket_->set_snd_cwnd(MIN(socket_->snd_cwnd(),
                                socket_->snd_prev_cwnd()));
    }
  }

  // Moving sendUna forward gets us out of fast retransmit if sendUna moves
  // across sock->highSeq. Otherwise, we remain in fast retransmit mode,
  // trying to recover 1 lost packet per RTT.
  if ((socket_->funct_flags() & FUNCT_HIGH_SEQ) &&
      SEQ_GEQ(ack_num, socket_->high_seq()))
  {
    // We're transitioning out of Fast Recovery. Give ourselves a full
    // (1/2 of previous) sendCwnd bucket of credit. Since ssthresh gets
    // cut later in this function we have to fake it.  If you clip
    // tmp_prevcwnd to the CURRENT window, then if, when exiting the
    // congestion eopoch the offered window is small, you get no prevcwnd
    // credit and essentially go into very slow growth.
    //
    // Behavior on exiting fast retransmit:
    //
    // If the number of packets in flight is less than prevcwnd, (which is
    // the maximum number of packets you may have when exiting a
    // congestion epoch) then you may emit as many packets as necessary so
    // the number of packets in flight equal to the prevcwnd.
    socket_->set_snd_cwnd(MAX(0, socket_->snd_prev_cwnd() -
                              (socket_->seq_sent() - ack_num)));
    socket_->funct_flags() &= ~FUNCT_HIGH_CONGESTION_SEQ;
    socket_->set_high_cong_seq(0);

    LogD(kClassName, __func__, "Out of FR, snd_cwnd(%ld) relative ackHBO "
         "(%ld) prevcwnd (%ld) \n", socket_->snd_cwnd(),
         ack_num - socket_->initial_seq_num(), socket_->snd_prev_cwnd());

    socket_->set_funct_flags(socket_->funct_flags() & (~FUNCT_HIGH_SEQ));
    socket_->set_high_seq(0);
    socket_->set_pkts_ack_in_epoch(0);
  }
  else if (!(socket_->funct_flags() & FUNCT_HIGH_SEQ))
  {
    // Get sendCwnd credit
    if (socket_->snd_prev_cwnd() < socket_->snd_ssthresh())
    {
      // We're in exponential VJ mode.
      socket_->snd_prev_cwnd() += socket_->max_data();
      socket_->snd_cwnd()      += socket_->max_data();
    }
    else
    {
      // Linear VJ mode.
      //
      // We give ourselves credit here if ack_num is greater than
      // highCongSeq.
      if ((!(socket_->funct_flags() & FUNCT_HIGH_CONGESTION_SEQ)) ||
          ((socket_->funct_flags() & FUNCT_HIGH_CONGESTION_SEQ) &&
           SEQ_GT(ack_num, socket_->high_cong_seq())))
      {
        // [VF021] Corrected: if condition was negated by mistake
        if (socket_->snd_prev_cwnd())
        {
          socket_->snd_prev_cwnd() += ((socket_->max_data() *
                                        socket_->max_data()) /
                                       socket_->snd_prev_cwnd());
          socket_->snd_cwnd()      += ((socket_->max_data() *
                                        socket_->max_data()) /
                                       socket_->snd_prev_cwnd());
        }
        else
        {
          socket_->snd_prev_cwnd() += socket_->max_data();
          socket_->snd_cwnd()      += ((socket_->max_data() *
                                        socket_->max_data()) /
                                       socket_->snd_prev_cwnd());
        }
      }
    }

    // Clip socket_->sendPrevCwnd to the offered window.
    socket_->set_snd_prev_cwnd(MIN(socket_->snd_prev_cwnd(),
                                   TCP_MAXWIN << socket_->snd_scale()));
  }

  if (socket_->funct_flags() & FUNCT_HIGH_SEQ)
  {
    socket_->set_pkts_ack_in_epoch(bytes_acked / socket_->max_data());
  }
}

//============================================================================
void VJCongCtrlAlg::SnackRcvd(const struct tcphdr* tcp_hdr, int data_len,
                              int bytes_acked)
{
  if (!selected_)
  {
    return;
  }

  uint32_t  ack_num = ntohl(tcp_hdr->th_ack);

  // Clip CWND to the amount of data in flight first.
  socket_->set_snd_prev_cwnd(MIN(socket_->snd_prev_cwnd(),
                                 socket_->seq_sent() - socket_->snd_una()));
  socket_->set_snd_prev_cwnd(MIN(socket_->snd_prev_cwnd(),
                                 (ntohs(tcp_hdr->th_win) <<
                                  socket_->snd_scale())));
  socket_->set_snd_ssthresh(MAX((socket_->max_data() << 1),
                                (socket_->snd_prev_cwnd() >> 1)));

  // Round down prevcwnd to a multiple of maxdata. This allows VJ
  // congestion control algorithm to perform a bit better.
  if ((int)socket_->snd_ssthresh() ==
      ((int)((socket_->snd_ssthresh()) / socket_->max_data())) *
      socket_->max_data())
  {
    socket_->set_snd_prev_cwnd(
      (((int)((socket_->snd_ssthresh()) / socket_->max_data())) *
       socket_->max_data()));
  }
  else
  {
    socket_->set_snd_prev_cwnd(
      (((int)((socket_->snd_ssthresh()) / socket_->max_data())) *
       socket_->max_data()) + socket_->max_data());
  }
  socket_->set_snd_ssthresh(MIN(socket_->snd_ssthresh(),
                                socket_->snd_prev_cwnd()));

  // When we enter a congestion epoch, we cut ssthresh in half AND set
  // cwnd to 1 packet. If this dup ack does not increase the
  // advertised window then we will set cwnd to 1 packet. If this is a
  // pure dup ack, then the cwnd will be incremented a little later.
  if (((socket_->last_uwe_in() !=
        (ack_num + (ntohs(tcp_hdr->th_win) << socket_->snd_scale()))) ||
       (bytes_acked > 0)) &&
      (data_len == 0))
  {
    socket_->set_snd_cwnd(socket_->max_data());
  }
  else
  {
    socket_->set_snd_cwnd(0);
  }
}

//============================================================================
void VJCongCtrlAlg::DupAckRcvd(const struct tcphdr* tcp_hdr, int data_len)
{
  bool  enter_fast_rexmit_from_dup_ack = false;

  if (!selected_)
  {
    return;
  }

  uint32_t  ack_num = ntohl(tcp_hdr->th_ack);

  // Increment cwnd by one mss regardless, a segment has left the network.
  // But, if this has a window update, it is *not* a duplicate ACK,
  if ((socket_->last_uwe_in() ==
       (ack_num + (ntohs(tcp_hdr->th_win) << socket_->snd_scale()))) &&
      (data_len == 0))
  {
    // CWND INFLATION
    //
    // Don't clip s->sendCwnd to s->sendPrevCwnd. Chances of this actually being
    // a problem are low.
    socket_->pkts_ack_in_epoch()--;
    if ((socket_->pkts_ack_in_epoch() * socket_->max_data() <
         socket_->snd_ssthresh() + (DUPACK_THRESH * socket_->max_data())) ||
        (socket_->t_dupacks() < DUPACK_THRESH))
    {
      socket_->pkts_ack_in_epoch()++;
      socket_->snd_cwnd() += socket_->max_data();
    }
  }

  PktInfo* send_buf_snd_una = socket_->send_buf()->snd_una();
  if ((socket_->funct_flags() & FUNCT_HIGH_SEQ) &&
      (socket_->t_dupacks() <= DUPACK_THRESH) &&
      (send_buf_snd_una))
  {
    // Round down prevcwnd to a multiple of maxdata. This allows VJ
    // congestion control algorithm to perform a bit better.
    socket_->set_snd_ssthresh(
      MAX(socket_->snd_ssthresh(),
          (socket_->seq_sent() - send_buf_snd_una->seq_num +
           socket_->max_data()) >> 1));
    if (socket_->snd_ssthresh() ==
        (((socket_->snd_ssthresh()) / socket_->max_data())) *
        socket_->max_data())
    {
      socket_->set_snd_prev_cwnd((((int)((socket_->snd_ssthresh()) /
                                         socket_->max_data())) *
                                  socket_->max_data()));
    }
    else
    {
      socket_->set_snd_prev_cwnd((((int)((socket_->snd_ssthresh()) /
                                         socket_->max_data())) *
                                  socket_->max_data()) + socket_->max_data());
    }
    socket_->set_snd_ssthresh(MAX(socket_->snd_ssthresh(),
                                  socket_->snd_prev_cwnd()));
  }

  if (send_buf_snd_una && (socket_->t_dupacks() >= DUPACK_THRESH))
  {
    // Need to modify this so that we only send a single Fast-Retransmit per
    // rtt, otherwise noisy channels will really guber us up!
    //
    // How to do this?
    //
    // Add a rxmit_last value to the tpcb structure (ugh!)  that has the
    // clock value for the last retrans of this packet. This is set to 0
    // when snduna moves forward and dup_ack_cnt is cleared; When the nth
    // duplicate ack arrives and current_time > (rtt_curr + rxmit_last) we
    // do a fast retransmit, clear the dup_ack_cnt and that's that.
    if (!(socket_->funct_flags() & FUNCT_HIGH_SEQ))
    {
      enter_fast_rexmit_from_dup_ack = true;

      socket_->set_pkts_ack_in_epoch(
        (socket_->seq_sent() - send_buf_snd_una->seq_num) /
        socket_->max_data());
      socket_->set_funct_flags(socket_->funct_flags() | FUNCT_HIGH_SEQ);
      socket_->set_high_seq(socket_->snd_max());
      socket_->set_snd_cwnd(socket_->snd_prev_cwnd() + ack_num -
                            socket_->snd_max());

      // [VF011]
      //
      // cwnd can get negative and thus a big unsigned number.
      //

      socket_->set_snd_cwnd(MAX(socket_->snd_cwnd(), 0));
      socket_->set_snd_prev_cwnd(MIN(socket_->snd_prev_cwnd(),
                                     (ntohs(tcp_hdr->th_win) <<
                                      socket_->snd_scale())));
      socket_->set_snd_ssthresh(MAX(socket_->max_data() << 1,
                                    (socket_->snd_prev_cwnd() >> 1)));

      // Round down prevcwnd to a multiple of maxdata. This allows
      // VJ congestion control algorithm to perform a bit better.
      if (socket_->snd_ssthresh() ==
          (((socket_->snd_ssthresh()) / socket_->max_data())) *
          socket_->max_data())
      {
        socket_->set_snd_prev_cwnd(
          (((int)((socket_->snd_ssthresh()) / socket_->max_data())) *
           socket_->max_data()));
      }
      else
      {
        socket_->snd_prev_cwnd() =
          (((int)((socket_->snd_ssthresh()) / socket_->max_data())) *
           socket_->max_data()) + socket_->max_data();
      }
      socket_->set_snd_ssthresh(MIN(socket_->snd_ssthresh(),
                                    socket_->snd_prev_cwnd()));

      LogD(kClassName, __func__, "Entering FR, high_seq(%lu) snduna(%lu) "
           "cwnd(%lu) ssthresh(%lu), prevcwnd(%lu)\n",
           socket_->high_seq() - socket_->initial_seq_num(),
           socket_->snd_una() - socket_->initial_seq_num(),
           socket_->snd_cwnd(), socket_->snd_ssthresh(),
           socket_->snd_prev_cwnd());
    }

    // Force out the retransmission by making it a hole and calling
    // TpProcessor::Send().

    if (send_buf_snd_una)
    {
      send_buf_snd_una->rexmit_time = Time::Now();
    }

    // XXX
    // socket_->sendBuf->holes =
    //   socket_->sendBuf->addHole(socket_->sendBuf->holes, socket_->sendBuf->snd_una_,
    //                          socket_->sendBuf->snd_una_->m_ext.len,
    //                          socket_->maxSeqSent, snackDelay);

    // On the third dupack, force out the retransmission. Make sure that we
    // have enough sendCwnd credit to send the packet.
    if ((socket_->t_dupacks() == DUPACK_THRESH)  &&
        (enter_fast_rexmit_from_dup_ack) &&
        ((socket_->funct_flags() & FUNCT_HIGH_SEQ)))
    {
      int  oldCwnd = socket_->snd_cwnd();

      socket_->set_snd_cwnd(socket_->max_data());
      socket_->Send(NULL, false);
      socket_->set_snd_cwnd(oldCwnd);
    }
  }
}

//============================================================================
void VJCongCtrlAlg::Timeout()
{
  // We had a retransmission timeout, so knock down ssThresh and reenter
  // slow-start.
  //
  // On an RTO set sendSsThresh to the max of half the congestion window
  // sendPrevCwnd (for VJ) and 2 segments.
  socket_->set_snd_ssthresh(MAX((socket_->snd_prev_cwnd() >> 1),
                                (socket_->max_data() << 1)));
  socket_->set_snd_cwnd(0);
  socket_->set_snd_prev_cwnd(socket_->max_data());
}
