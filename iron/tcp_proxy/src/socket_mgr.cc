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

#include "socket_mgr.h"
#include "clock.h"
#include "cong_ctrl_alg.h"
#include "itime.h"
#include "log.h"
#include "string_utils.h"
#include "tcp_proxy.h"
#include "unused.h"

#include <inttypes.h>
#include <netinet/tcp.h>

using ::iron::BinId;
using ::iron::FourTuple;
using ::iron::HashTable;
using ::iron::StringUtils;
using ::iron::Time;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;
using ::std::string;
using ::std::list;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "SocketMgr";

  /// The number of buckets in the socket hash table.  This value supports
  /// fast lookups with up to 10,000 flows.
  const size_t  kSockMapHashTableBuckets = 32768;
}

//============================================================================
SocketMgr::SocketMgr()
    : tcp_proxy_(NULL),
      sockmap_(),
      socket_list_(NULL),
      expired_sock_list_()
{
  // Initialize the hash table.
  if (!sockmap_.Initialize(kSockMapHashTableBuckets))
  {
    LogF(kClassName, __func__, "Unable to initialize hash table.\n");
  }
}

//============================================================================
void SocketMgr::SetTcpProxy(TcpProxy* tcp_proxy)
{
  tcp_proxy_ = tcp_proxy;
}

//============================================================================
SocketMgr::~SocketMgr()
{
  HashTable<FourTuple, Socket*>::WalkState  walk_state;
  FourTuple                                 four_tuple;
  Socket*                                   sock = NULL;

  while (sockmap_.EraseNextPair(walk_state, four_tuple, sock))
  {
    if (sock != NULL)
    {
      delete sock;
    }
  }

  sockmap_.Clear();

  socket_list_ = NULL;
}

//============================================================================
void SocketMgr::AddSocket(Socket* sock)
{
  FourTuple ft(sock->his_addr().s_addr,
               sock->his_port(),
               sock->my_addr().s_addr,
               sock->my_port());

  if (!sockmap_.Insert(ft, sock))
  {
    LogE(kClassName, __func__, "Error adding socket for four-tuple %s.\n",
         ft.ToString().c_str());
  }

  // Add the socket to the socket_list_.
  sock->set_next(socket_list_);
  sock->set_prev(NULL);
  if (socket_list_ != NULL)
  {
    socket_list_->set_prev(sock);
  }

  socket_list_ = sock;
}

//============================================================================
void SocketMgr::CloseSocket(Socket* sock)
{
  // Invoke the close() method on the socket.
  if (!sock->Close())
  {
    return;
  }

  // Remove the socket from the collection of sockets if the socket's state is
  // suitable for the removal and destruction of the socket.
  if ((sock->state() == TCP_LISTEN) || (sock->state() == TCP_NASCENT) ||
      (sock->state() == TCP_SYN_SENT))
  {
    RemoveSocket(sock);
  }
}

//============================================================================
void SocketMgr::RemoveAllSockets()
{
  HashTable<FourTuple, Socket*>::WalkState  walk_state;
  FourTuple                                 four_tuple;
  Socket*                                   sock = NULL;

  while (sockmap_.EraseNextPair(walk_state, four_tuple, sock))
  {
    if (sock != NULL)
    {
      delete sock;
    }
  }

  sockmap_.Clear();
}

//============================================================================
void SocketMgr::RemoveSocket(Socket* s)
{
  LogI(kClassName, __func__, "%s, removing socket.\n", s->flow_id_str());

  // Remove the socket from the socket map.
  FourTuple ft(s->his_addr().s_addr,
               s->his_port(),
               s->my_addr().s_addr,
               s->my_port());

  // Erase the entry for the four-tuple in the hash table.
  if (sockmap_.Erase(ft) < 1)
  {
    LogE(kClassName, __func__, "Error finding socket in hash table.\n");
  }

  // Remove the socket from the socket_list_ also.
  Socket*  iter = socket_list_;
  while (iter != NULL)
  {
    if ((s->his_addr().s_addr == iter->his_addr().s_addr) &&
        (s->his_port() == iter->his_port()) &&
        (s->my_addr().s_addr == iter->my_addr().s_addr) &&
        (s->my_port() == iter->my_port()))
    {
      if (iter->next() != NULL)
      {
        iter->next()->set_prev(iter->prev());
      }

      if (iter->prev() != NULL)
      {
        iter->prev()->set_next(iter->next());
      }

      if (iter == socket_list_)
      {
        socket_list_ = iter->next();
      }

      break;
    }

    iter = iter->next();
  }

  // Now, we can destroy the socket.
  delete s;
}

//============================================================================
void SocketMgr::MarkSocketForRemoval(Socket* s)
{
  LogI(kClassName, __func__, "%s, marking socket for removal.\n",
       s->flow_id_str());

  list<Socket*>::iterator sock_iter = expired_sock_list_.begin();
  while (sock_iter != expired_sock_list_.end())
  {
    if (s == *sock_iter)
    {
      return;
    }

    ++sock_iter;
  }
  expired_sock_list_.push_back(s);
}

//============================================================================
void SocketMgr::RemoveMarkedSockets()
{
  list<Socket*>::iterator sock_iter = expired_sock_list_.begin();

  while (sock_iter != expired_sock_list_.end())
  {
    Socket *s = (*sock_iter);

    expired_sock_list_.erase(sock_iter++);

    LogI(kClassName, __func__, "%s, removing marked socket.\n",
         s->flow_id_str());

    RemoveSocket(s);
  }
}

//============================================================================
void SocketMgr::UpdateScheduledAdmissionEvents()
{
  HashTable<FourTuple, Socket*>::WalkState  walk_state;
  FourTuple                                 four_tuple;
  Socket*                                   sock = NULL;

  while (sockmap_.GetNextPair(walk_state, four_tuple, sock))
  {
    if ((sock != NULL) && (sock->cfg_if_id() == WAN))
    {
      Time  now = Time::Now();
      sock->UpdateScheduledAdmissionEvent(now);
    }
  }
}

//============================================================================
void SocketMgr::UpdateScheduledAdmissionEvents(iron::BinIndex bin_idx)
{
  HashTable<FourTuple, Socket*>::WalkState  walk_state;
  FourTuple                                 four_tuple;
  Socket*                                   sock = NULL;

  while (sockmap_.GetNextPair(walk_state, four_tuple, sock))
  {
    if ((sock != NULL) && (sock->cfg_if_id() == WAN) &&
        (sock->bin_idx() == bin_idx))
    {
      Time  now = Time::Now();
      sock->UpdateScheduledAdmissionEvent(now);
    }
  }
}

//============================================================================
Socket* SocketMgr::GetSocket(FourTuple& four_tuple)
{
  // This method finds a socket that matches the provided 4-tuple. This
  // 4-tuple is normally received from the Admission Planner and should match
  // a LAN side socket. The comparison depends on whether the current socket
  // is active or passive. See the class level comment in socket.h for an
  // example that illustrates why the 4-tuple matches are tested as they are
  // below.

  LogD(kClassName, __func__, "Target 4-tuple: (%" PRIu32
       ", %" PRIu16 ", %" PRIu32 ", %" PRIu16 ").\n",
       four_tuple.src_addr_nbo(),four_tuple.src_port_nbo(),
       four_tuple.dst_addr_nbo(),four_tuple.dst_port_nbo());

  Socket*  sock = NULL;

  if (sockmap_.Find(four_tuple, sock))
  {
    if ((sock != NULL) && (sock->is_active()))
    {
      LogW(kClassName, __func__, "Socket 4-tuple: (%" PRIu32
           ", %" PRIu16 ", %" PRIu32 ", %" PRIu16 ").\n", sock->my_addr(),
           ntohs(sock->my_port()), sock->his_addr(), ntohs(sock->his_port()));

      // We have a match.
      LogW(kClassName, __func__, "Found matching socket.\n");

      return sock;
    }
  }

  // Swap the source and destination info and search again
  FourTuple flipped_four_tuple (four_tuple.dst_addr_nbo(),
                                four_tuple.dst_port_nbo(),
                                four_tuple.src_addr_nbo(),
                                four_tuple.src_port_nbo());

  if (sockmap_.Find(flipped_four_tuple, sock))
  {
    LogW(kClassName, __func__, "Socket 4-tuple: (%" PRIu32
         ", %" PRIu16 ", %" PRIu32 ", %" PRIu16 ").\n", sock->my_addr(),
         ntohs(sock->my_port()), sock->his_addr(), ntohs(sock->his_port()));

    if (sock->is_active())
    {
      // We have a match
      LogW(kClassName, __func__, "Found matching socket.\n");

      return sock;
    }
  }

  // No match was found.
  LogW(kClassName, __func__, "No matching socket found.\n");

  return NULL;
}

//============================================================================
void SocketMgr::ProcessSvcDefUpdate(const TcpContext* tcp_context)
{
  HashTable<FourTuple, Socket*>::WalkState  walk_state;
  FourTuple                                 four_tuple;
  Socket*                                   sock = NULL;

  while (sockmap_.GetNextPair(walk_state, four_tuple, sock))
  {
    if ((sock != NULL) && (sock->cfg_if_id() == WAN))
    {
      if (sock->is_active())
      {
        if (sock->peer() == NULL)
        {
          continue;
        }

        if ((ntohs(sock->peer()->my_port()) >= tcp_context->lo_port()) &&
            (ntohs(sock->peer()->my_port()) <= tcp_context->hi_port()))
        {
          // The current socket ports fall within the range of the context that
          // has been modified. Figure out if the utility function definition
          // needs to be updated. It will be if there is not an existing Flow
          // level utility function defined. See the class level documentation
          // in socket.h for an example that illustrates why the 4-tuple is
          // initialized this way.
          FourTuple  four_tuple(sock->peer()->his_addr().s_addr,
                                sock->peer()->his_port(),
                                sock->peer()->my_addr().s_addr,
                                sock->peer()->my_port());

          if (tcp_proxy_->HasFlowUtilityFnDef(four_tuple))
          {
            // There is an existing Flow definition for the current socket. This
            // takes precedence over any Service level utility function
            // definition. So, don't make any changes to the current socket.
            LogW(kClassName, __func__, "Socket with port %" PRIu16 " has an "
                 "active flow definition. Not modifying.\n",
                 ntohs(sock->peer()->my_port()));

            continue;
          }

          LogW(kClassName, __func__, "Applying new Service Definition update to "
               "port(%" PRIu16 ").\n", ntohs(sock->peer()->my_port()));

          // There is no Flow definition for the current socket so update its
          // utility function definition (as the Service level definition has
          // changed).
          sock->ResetUtilityFn(tcp_context->util_fn_defn(),
                               tcp_proxy_->GetQueueDepths());
        }
      }
      else
      {
        if ((ntohs(sock->peer()->his_port()) >= tcp_context->lo_port()) &&
            (ntohs(sock->peer()->his_port()) <= tcp_context->hi_port()))
        {
          // The current socket ports fall within the range of the context that
          // has been modified. Figure out if the utility function definition
          // needs to be updated. It will be if there is not an existing Flow
          // level utility function defined. See the class level documentation
          // in socket.h for an example that illustrates why the 4-tuple is
          // initialized this way.
          FourTuple  four_tuple(sock->peer()->my_addr().s_addr,
                                sock->peer()->my_port(),
                                sock->peer()->his_addr().s_addr,
                                sock->peer()->his_port());

          if (tcp_proxy_->HasFlowUtilityFnDef(four_tuple))
          {
            // There is an existing Flow definition for the current socket. This
            // takes precedence over any Service level utility function
            // definition. So, don't make any changes to the current socket.
            LogW(kClassName, __func__, "Socket with port %" PRIu16 " has an "
                 "active flow definition. Not modifying.\n",
                 ntohs(sock->peer()->his_port()));

            continue;
          }

          LogW(kClassName, __func__, "Applying new Service Definition update to "
               "port(%" PRIu16 ").\n", ntohs(sock->peer()->his_port()));

          // There is no Flow definition for the current socket so update its
          // utility function definition (as the Service level definition has
          // changed).
          sock->peer()->ResetUtilityFn(tcp_context->util_fn_defn(),
                                       tcp_proxy_->GetQueueDepths());
        }
      }
    }
  }
}

//============================================================================
void SocketMgr::WriteStats(Writer<StringBuffer>* writer)
{
  // Stats "keyvals" format.
  //  "stats" :
  //  {
  //    "Flows" :
  //    [
  //      {
  //        "flow_id" : "xxx.xxx.xxx.xxx:aaaaa -> yyy.yyy.yyy.yyy:bbbb",
  //        "priority" : xx.xx,
  //        "cumulative_sent_pkt_cnt" : xx,
  //        "cumulative_sent_bytes_cnt" : xx,
  //        "send_rate_bps" : xx.xx,
  //        "send_rate_pps" : xx.xx,
  //        "cumulative_rcvd_pkt_cnt" : xx,
  //        "cumulative_rcvd_bytes_cnt" : xx,
  //        "recv_rate_bps" : xx.xx,
  //        "recv_rate_pps" : xx.xx,
  //        "ave_instantaneous_utility" : xx.xx
  //      },
  //    ],
  //    "NumActiveFlows" : xx,
  //    "CumulativeAveInstantaneousUtility": xx.xx,
  //    "CumulativeAggregateUtility": xx.xx
  //  }

  bool log_stats = tcp_proxy_->log_stats();
  if (log_stats)
  {
    LogI(kClassName, __func__, "-- TCP Proxy Stats --------------\n");
  }

  if (writer)
  {
    // Append "stats" : {
    writer->Key("stats");
    writer->StartObject();
  }

  string  log_str;

  // Append the "Flows" statistics. This will be an array of objects
  // containing key/value pairs for each active flow.
  if (log_stats)
  {
    log_str.append("FlowStats=");
  }

  if (writer)
  {
    // Append "Flows" : [
    writer->Key("Flows");
    writer->StartArray();
  }

  bool     first                        = true;
  double   cumulative_ave_utility       = 0.0;
  double   cumulative_aggregate_utility = 0.0;
  uint8_t  active_flow_cnt              = 0;

  HashTable<FourTuple, Socket*>::WalkState  walk_state;
  FourTuple                                 four_tuple;
  Socket*                                   s = NULL;

  while (sockmap_.GetNextPair(walk_state, four_tuple, s))
  {
    if ((s != NULL) && (s->cfg_if_id() == WAN) &&
        ((s->peer()) && (s->peer()->peer()) && (s->peer()->peer() == s)))
    {
      active_flow_cnt++;

      if (writer)
      {
        // Start the current flow with the '{' character.
        writer->StartObject();
      }

      if (first)
      {
        first = false;
      }
      else
      {
        log_str.append(",");
      }

      s->WriteStats(log_str, writer);

      if (writer)
      {
        // End the current flow with the '}' character.
        writer->EndObject();
      }

      cumulative_ave_utility       += s->ave_utility();
      cumulative_aggregate_utility += s->cumulative_utility();
    }
  }

  if (log_stats)
  {
    LogI(kClassName, __func__, "%s\n", log_str.c_str());
  }

  if (writer)
  {
    // End the "flows" array with the ']' character.
    writer->EndArray();
  }

  // Log the NumActiveFlows statistic, if required.
  if (log_stats)
  {
    log_str.clear();
    log_str.append(
      StringUtils::FormatString(256, "NumActiveFlows=%" PRIu8,
                                active_flow_cnt));

    LogI(kClassName, __func__, "%s\n", log_str.c_str());
  }

  // Append the "NumActiveFlows" statistic, if required.
  if (writer)
  {
    // Append "NumActiveFlows" : xx
    writer->Key("NumActiveFlows");
    writer->Uint(active_flow_cnt);
  }

  // Log the CumulativeAveInstantaneousUtility statistic, if required.
  if (log_stats)
  {
    log_str.clear();
    log_str.append("AggStats=");
    log_str.append(
      StringUtils::FormatString(256, "'CumulativeUtility':'%f',",
                                cumulative_ave_utility));
  }

  // Append the "CumulativeAveInstantaneousUtility" statistic, if required.
  if (writer)
  {
    // Append "CumulativeAveInstantaneousUtility" : xx.xx
    writer->Key("CumulativeAveInstantaneousUtility");
    writer->Double(cumulative_ave_utility);
  }

  // Log the CumulativeAggregateUtility statistic, if required.
  if (log_stats)
  {
    log_str.append(
      StringUtils::FormatString(256, "'HistoricAggregateUtility':'%f'",
                                cumulative_aggregate_utility));

    LogI(kClassName, __func__, "%s\n", log_str.c_str());
  }

  // Append the "CumulativeAggregateUtility" statistic, if required.
  if (writer)
  {
    // Append "CumulativeAggregateUtility" : xx.xx
    writer->Key("CumulativeAggregateUtility");
    writer->Double(cumulative_aggregate_utility);

    // End keyvals object with '}' character.
    writer->EndObject();
  }

  if (log_stats)
  {
    LogI(kClassName, __func__, "-------------- TCP Proxy Stats --\n");
  }
}
