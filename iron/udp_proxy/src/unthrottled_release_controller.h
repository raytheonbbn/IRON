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

#ifndef IRON_UDP_PROXY_UNTHROTTLED_RELEASE_CONTROLLER_H
#define	IRON_UDP_PROXY_UNTHROTTLED_RELEASE_CONTROLLER_H

#include "release_controller.h"

/// \brief A Release Controller that releases packets to the local application
/// as they are received.
///
/// This is a child class implementation of the ReleaseController base class
/// that releases packets to the local applications as they are received.
class UnthrottledReleaseController : public ReleaseController
{
  public:

  /// \brief Constructor.
  ///
  /// \param  decoding_state  Reference to the Decoding State.
  UnthrottledReleaseController(DecodingState& decoding_state);

  /// \brief Destructor.
  virtual ~UnthrottledReleaseController();

  /// \brief Service the release control events.
  ///
  /// \param  now  The current time.
  virtual void SvcEvents(iron::Time& now);

  /// \brief Handle an IRON packet.
  ///
  /// \param  pkt  The packet to handle.
  ///
  /// \return True if the packet is handled successfully (and this class
  ///         assumes ownership of the packet), false otherwise (and the
  ///         calling object retains ownership of the packet).
  virtual bool HandlePkt(iron::Packet* pkt);

  private:

  /// \brief No-arg constructor.
  UnthrottledReleaseController();

  /// \brief Copy constructor.
  UnthrottledReleaseController(const UnthrottledReleaseController& urc);

  /// \brief Assignment operator.
  UnthrottledReleaseController& operator=(
    const UnthrottledReleaseController& urc);

}; // end class UnthrottledReleaseController

#endif // IRON_UDP_PROXY_UNTHROTTLED_RELEASE_CONTROLLER_H
