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

#ifndef IRON_TCP_PROXY_SOCKET_MGR_H
#define IRON_TCP_PROXY_SOCKET_MGR_H

#include "four_tuple.h"
#include "hash_table.h"
#include "packet_pool.h"
#include "socket.h"
#include "tcp_context.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <map>
#include <list>

class TcpProxy;

/// Manages the TCP Proxy's sockets.
class SocketMgr
{
  public:

  /// \brief Constructor.
  SocketMgr();

  /// \brief Destructor.
  ~SocketMgr();

  /// \brief Add a socket to the list of managed sockets.
  ///
  /// NOTE: Must be called before starting the proxy.
  /// Method exists because TcpProxy also needs a reference to
  /// this instance.
  ///
  /// \param  tcp_proxy TCP Proxy instacne.
  void SetTcpProxy(TcpProxy* tcp_proxy);

  /// \brief Add a socket to the list of managed sockets.
  ///
  /// \param  sock  The Socket to be added to the list of managed sockets.
  void AddSocket(Socket* sock);

  /// \brief Get pointer to an existing Socket that matches the values from a
  /// recently received packet.
  ///
  /// NOTE: This class retains ownership of the memory, so the calling object
  /// must not delete the returned Socket.
  ///
  /// \param  ft  The flow's 4-tuple. This is used to find any existing
  ///             internal proxy state for the flow.
  ///
  /// \return Pointer to the existing Socket, or NULL if an Socket does
  ///         not exist that meets the search criteria.

  inline Socket* GetExistingSocket(iron::FourTuple ft) const
  {
    Socket*  rv = NULL;
    sockmap_.Find(ft, rv);
    return rv;
  }

  /// \brief Close a Socket and perform any required associated cleanup.
  ///
  /// \param  sock  The Socket to close.
  void CloseSocket(Socket* sock);

  /// \brief Get the hash table containing the Sockets.
  ///
  /// \return The hash table containing the Sockets.
  inline iron::HashTable<iron::FourTuple, Socket*>& GetSockets()
  {
    return sockmap_;
  }

  /// \brief Get the list of sockets.
  ///
  /// This is useful if the sockets have to be iterated over. It is much more
  /// efficient to iterate over this list than to iterate over the hashtable
  /// of sockets.
  ///
  /// \return The list of sockets.
  inline Socket* GetSocketList()
  {
    return socket_list_;
  }

  /// \brief Remove all Sockets.
  ///
  /// This is typically called when the process is terminating. This enables
  /// us to delete the dynamically allocated Sockets and not rely on the
  /// order that the static Singleton SocketMgr is deleted. We do this because
  /// the Sockets have timers, which should be cleared from the static
  /// Singleton TimerMgr.
  void RemoveAllSockets();

  /// \brief Remove the provided socket from the collection of Sockets and
  /// clean up the Socket's state.
  ///
  /// \param  sock  The Socket to remove.
  void RemoveSocket(Socket* sock);

  /// \brief Add the provided socket to the list for subsequent removal
  ///
  /// \param  s  The Socket to remove.
  void MarkSocketForRemoval(Socket* s);

  /// \brief Remove all sockets slate for removal
  ///
  void RemoveMarkedSockets();

  /// \brief Update the scheduled packet admission events in the sockets.
  void UpdateScheduledAdmissionEvents();

  /// \brief Update the scheduled packet admission events for the sockets that
  /// have the provided bin id.
  ///
  /// \param  bin_idx  The target bin index.
  void UpdateScheduledAdmissionEvents(iron::BinIndex bin_idx);

  /// \brief Get the Socket that matches the provided 4-tuple.
  ///
  /// \param  four_tuple  The four_tuple that will be used in the search.
  ///
  /// \return A pointer to the Socket that matches the provided
  ///         4-tuple. NULL is returned if no match is found.
  Socket* GetSocket(iron::FourTuple& four_tuple);

  /// \brief Process a received Service Definition update.
  ///
  /// \param  context  The TCP context that is to be applied to all
  ///                  TpSockets.
  void ProcessSvcDefUpdate(const TcpContext* context);

  /// \brief Write the collected TCP Proxy stats to the log file and/or the
  /// JSON writer.
  ///
  /// \param  writer  The JSON writer that is used to create the JSON
  ///                 message.
  void WriteStats(rapidjson::Writer<rapidjson::StringBuffer>* writer = NULL);

  private:

  /// \brief Copy constructor.
  SocketMgr(const SocketMgr& sm);

  /// \brief Copy operator.
  SocketMgr& operator=(const SocketMgr& sm);

  /// The TCP Proxy instance.
  TcpProxy*                                  tcp_proxy_;

  /// Map of TCP Proxy sockets.
  iron::HashTable<iron::FourTuple, Socket*>  sockmap_;

  /// Doubly linked list of sockets. This will be used when the sockets need
  /// to be iterated over. It is more efficient to "walk" this list than
  /// "walk" the hashtable of sockets.
  Socket*                                    socket_list_;

  /// A collection of sockets to be deleted.
  std::list<Socket*>                         expired_sock_list_;

}; // end class SocketMgr

#endif // IRON_TCP_PROXY_SOCKET_MGR_H
