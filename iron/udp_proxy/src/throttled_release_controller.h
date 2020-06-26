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

#ifndef IRON_UDP_PROXY_THROTTLED_RELEASE_CONTROLLER_H
#define	IRON_UDP_PROXY_THROTTLED_RELEASE_CONTROLLER_H

#include "packet_pool.h"
#include "packet_queue.h"
#include "release_controller.h"
#include "src_rate_estimator.h"

/// \brief A Release Controller that throttles the rate of release of
/// packets to the local applications.
///
/// This is a child class implementation of the ReleaseController base class
/// that throttles the release of packets to the local applications. The
/// throttling mechanism tries to maintain the packet spacing upon release
/// as seen upon entry into IRON.

/// The technique used for tracking the traversal time.
typedef enum
{
  MAX_TT = 0,  // Track the maximum traversal time seen thus far.
  AVG_TT,      // Track the average traversal time.
  BURST,       // Track the maximum traversal time, but emit bursts to
  UNDEFINED    //       keep the latency low.
} TraversalTracking;


class ThrottledReleaseController : public ReleaseController
{
  public:

  /// \brief Constructor.
  ///
  /// \param  decoding_state      Reference to the Decoding State.
  /// \param  packet_pool         Reference to the packet pool.
  ThrottledReleaseController(DecodingState& decoding_state,
                             iron::PacketPool& packet_pool);

  /// \brief Destructor.
  virtual ~ThrottledReleaseController();

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
  ThrottledReleaseController();

  /// \brief Copy constructor.
  ThrottledReleaseController(const ThrottledReleaseController& trc);

  /// \brief Assignment operator.
  ThrottledReleaseController& operator=(
    const ThrottledReleaseController& trc);

  /// Reference to the packet pool.
  iron::PacketPool&  packet_pool_;

  /// Queue to store packets until they are released.
  iron::PacketQueue  release_pkts_queue_;

  /// The maximum packet traversal time.
  int64_t            traversal_time_;

  /// The origin timestamp of the last received packet.
  uint16_t           last_origin_ts_ms_;

  /// Rollover origin ts.
  int64_t            origin_rollover_ms_;

  /// The traversal tracking technique used.
  TraversalTracking  tracking_;

}; // end class ThrottledReleaseController

#endif // IRON_UDP_PROXY_THROTTLED_RELEASE_CONTROLLER_H
