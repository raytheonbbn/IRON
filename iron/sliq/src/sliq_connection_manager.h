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

#ifndef IRON_SLIQ_CONNECTION_MANAGER_H
#define IRON_SLIQ_CONNECTION_MANAGER_H

#include "sliq_private_types.h"
#include "sliq_types.h"

#include "ipv4_endpoint.h"
#include "timer.h"


namespace sliq
{

  class Connection;

  class ConnectionManager
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  timer  A reference to the timer object.
    ConnectionManager(iron::Timer& timer);

    /// \brief Destructor.
    virtual ~ConnectionManager();

    /// \brief Add a new connection object.
    ///
    /// The connection manager takes ownership of the object.  Any connection
    /// with the same endpoint ID is destroyed.
    ///
    /// \param  endpt_id  The connection's assigned endpoint ID.
    /// \param  conn      A pointer to the connection object.
    ///
    /// \return  True if the connection object was added successfully, or
    ///          false otherwise.
    bool AddConnection(EndptId endpt_id, Connection* conn);

    /// \brief Get a connection by its endpoint ID.
    ///
    /// The object remains owned by the connection manager.  This is a very
    /// fast lookup.
    ///
    /// \param  endpt_id  The endpoint ID of the connection to find.
    ///
    /// \return  A pointer to the connection object if it is found, or NULL
    ///          otherwise.
    Connection* GetConnection(EndptId endpt_id);

    /// \brief Get a connection by its peer.
    ///
    /// The object remains owned by the connection manager.  This is a slower
    /// lookup.
    ///
    /// \param  peer  The peer's IPv4 address and UDP port number of the
    ///               connection to find.
    ///
    /// \return  A pointer to the connection object if it is found, or NULL
    ///          otherwise.
    Connection* GetConnectionByPeer(const iron::Ipv4Endpoint& peer);

    /// \brief Schedule a connection for deletion.
    ///
    /// The connection object, if found, is scheduled to be destroyed at a
    /// later time.  This makes it safe to be called from the connection
    /// object that needs to be destroyed.
    ///
    /// \param  endpt_id  The endpoint ID of the connection to be destroyed.
    ///
    /// \return  True if the connection object was found and scheduled for
    ///          destruction, or false otherwise.
    bool DeleteConnection(EndptId endpt_id);

   private:

    /// \brief Copy constructor.
    ConnectionManager(const ConnectionManager& cm);

    /// \brief Assignment operator.
    ConnectionManager& operator=(const ConnectionManager& cm);

    /// \brief Process a reaper timer callback.
    void ReaperTimeout();

    /// The number of connections in each block.
    static const size_t  kNumConnsPerBlock = 64;

    /// The number of blocks of connections.
    static const size_t  kNumBlocks        = 16;

    /// The number of elements in the reaper list.
    static const size_t  kMaxReaperSize    = 16;

    /// The timer.
    iron::Timer&         timer_;

    /// A 2D array of all connections objects for fast lookups.
    Connection**         connections_[kNumBlocks];

    /// The number of connections to be destroyed.
    size_t               reaper_size_;

    /// An array of connections to be destroyed.
    EndptId              reaper_list_[kMaxReaperSize];

    /// The reaper timer handle.
    iron::Timer::Handle  reaper_timer_;

  }; // end class ConnectionManager

}  // namespace sliq

#endif // IRON_SLIQ_CONNECTION_MANAGER_H
