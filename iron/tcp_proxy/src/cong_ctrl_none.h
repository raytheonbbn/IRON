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

#ifndef IRON_TCP_PROXY_NO_CONG_CTRL_ALG_H
#define IRON_TCP_PROXY_NO_CONG_CTRL_ALG_H

#include "cong_ctrl_alg.h"
#include "log.h"


class TpSocket;


/// A Congestion Control Algorithm that does no congestion control.
class NoCongCtrlAlg : public CongCtrlAlg
{
  public:

  /// \brief Constructor.
  ///
  /// \param  s  The Socket associated with the No Congestion Control
  ///            algorithm.
  NoCongCtrlAlg(Socket* s)
      : CongCtrlAlg(s)
  {
    LogD("NoCongCtrlAlg", __func__, "Created...\n");
  }

  /// \brief Copy constructor.
  ///
  /// \param  other  The NoCongCtrlAlg that will be used to create the new
  ///                NoCongCtrlAlg.
  /// \param  s      The Socket associated with the No Congestion
  ///                Control algorithm.
  NoCongCtrlAlg(const NoCongCtrlAlg& other, Socket* s)
      : CongCtrlAlg(s)
  {
    LogD("NoCongCtrlAlg", __func__, "Created...\n");
  }

  /// \brief Destructor.
  virtual ~NoCongCtrlAlg()
  {
    LogD("NoCongCtrlAlg", __func__, "Destroyed...\n");
  }

  /// \brief Initialize TCP No Congestion Control Algorithm.
  void Init() { }

  /// \brief Called when the Retransmit timer expires.
  void Timeout() { }

  /// \brief Invoked when an ACK is received.
  ///
  /// \param  ack_num      The received Ack number.
  /// \param  bytes_acked  The number of bytes being acked.
  void AckRcvd(uint32_t ack_num, int bytes_acked) { }

  /// \brief Invoked when a SNACK is received.
  ///
  /// \param  tcp_hdr      The received TCP header.
  /// \param  data_len     The length of the received data.
  /// \param  bytes_acked  The number of bytes being acked.
  void SnackRcvd(const struct tcphdr* tcp_hdr, int data_len, int bytes_acked)
  { }

  /// \brief Invoked when a duplicate ACK is received.
  ///
  /// \param  tcp_hdr   The received TP Header.
  /// \param  data_len  The length of the received data.
  void DupAckRcvd(const struct tcphdr* tcp_hdr, int data_len) { }

  protected:

  /// \brief Constructor.
  NoCongCtrlAlg() { }

  private:

  /// \brief Copy constructor.
  NoCongCtrlAlg(const NoCongCtrlAlg& nocc);

  /// \brief Copy operator.
  NoCongCtrlAlg& operator=(const NoCongCtrlAlg& nocc);

}; // end class NoCongCtrlAlg

#endif // IRON_TCP_PROXY_NO_CONG_CTRL_ALG_H
