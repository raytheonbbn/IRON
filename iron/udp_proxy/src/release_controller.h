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

#ifndef IRON_UDP_PROXY_RELEASE_CONTROLLER_H
#define	IRON_UDP_PROXY_RELEASE_CONTROLLER_H

#include "itime.h"
#include "packet.h"

class DecodingState;

/// \brief An abstract base class for Release Controllers.
///
/// Release Controllers are responsible for releasing packets, that have been
/// received from a remote UDP Proxy, to the local applications.
class ReleaseController
{
  public:

  /// \brief Constructor.
  ReleaseController(DecodingState& decoding_state)
    : decoding_state_(decoding_state)
  {
  }

  /// \brief Destructor.
  virtual ~ReleaseController()
  {
  }

  /// \brief Service the release control events.
  ///
  /// \param  now  The current time.
  virtual void SvcEvents(iron::Time& now) = 0;

  /// \brief Handle an IRON packet.
  ///
  /// \param  pkt  The packet to handle.
  ///
  /// \return True if the packet is handled successfully (and this class
  ///         assumes ownership of the packet), false otherwise (and the
  ///         calling object retains ownership of the packet).
  virtual bool HandlePkt(iron::Packet* pkt) = 0;

  protected:

  /// Reference to the flow's Decoding State.
  DecodingState&  decoding_state_;

  private:

  /// \brief No-arg constructor.
  ReleaseController();

  /// \brief Copy constructor.
  ReleaseController(const ReleaseController& rc);

  /// \brief Assignment operator.
  ReleaseController& operator=(const ReleaseController& rc);

}; // end class ReleaseController

#endif // IRON_UDP_PROXY_RELEASE_CONTROLLER_H
