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

#include "sliq_connection_manager.h"

#include "sliq_connection.h"

#include "callback.h"
#include "itime.h"
#include "timer.h"
#include "unused.h"

#include <cstring>


using ::sliq::Connection;
using ::sliq::ConnectionManager;
using ::iron::CallbackNoArg;
using ::iron::Ipv4Endpoint;
using ::iron::Time;
using ::iron::Timer;

namespace
{

  /// The class name for logging.
  const char*     UNUSED(kClassName)  = "ConnectionManager";

  /// The reaper timer duration in seconds.
  const double    kReaperTimerSec     = 0.001;

}

//============================================================================
ConnectionManager::ConnectionManager(Timer& timer)
    : timer_(timer), connections_(), reaper_size_(0), reaper_list_(),
      reaper_timer_()
{
  for (size_t i = 0; i < kNumBlocks; ++i)
  {
    connections_[i] = NULL;
  }

  memset(reaper_list_, 0, sizeof(reaper_list_));
}

//============================================================================
ConnectionManager::~ConnectionManager()
{
  // Destroy all of the connections.
  for (size_t i = 0; i < kNumBlocks; ++i)
  {
    if (connections_[i] != NULL)
    {
      for (size_t j = 0; j < kNumConnsPerBlock; ++j)
      {
        Connection*  conn = connections_[i][j];

        if (conn != NULL)
        {
          conn->DisableCallbacks();
          delete conn;
          connections_[i][j] = NULL;
        }
      }

      delete [] connections_[i];
      connections_[i] = NULL;
    }
  }

  // Cancel any timers.
  timer_.CancelTimer(reaper_timer_);

  // Clean up the timer callback object pools.
  CallbackNoArg<ConnectionManager>::EmptyPool();
}

//============================================================================
bool ConnectionManager::AddConnection(EndptId endpt_id, Connection* conn)
{
  if ((endpt_id < 0) || (conn == NULL))
  {
    return false;
  }

  // Make sure that the new connection object will fit in the 2D array.
  if ((endpt_id < 0) ||
      (static_cast<size_t>(endpt_id) >= (kNumBlocks * kNumConnsPerBlock)))
  {
    LogE(kClassName, __func__, "Endpoint ID %" PRIEndptId " cannot be "
         "stored.\n", endpt_id);
    return false;
  }

  // Compute the location for this connection pointer.
  size_t  block_index = (static_cast<size_t>(endpt_id) / kNumConnsPerBlock);
  size_t  conn_index  = (static_cast<size_t>(endpt_id) % kNumConnsPerBlock);

  // Add a new block of connection pointers if needed.
  if (connections_[block_index] == NULL)
  {
    connections_[block_index] = new (std::nothrow)
      Connection*[kNumConnsPerBlock];

    if (connections_[block_index] == NULL)
    {
      LogE(kClassName, __func__, "Error allocating block of connection "
           "pointers.\n");
      return false;
    }

    for (size_t i = 0; i < kNumConnsPerBlock; ++i)
    {
      connections_[block_index][i] = NULL;
    }
  }

  // Destroy any existing connection object at the index.
  Connection*  old_conn = connections_[block_index][conn_index];

  if (old_conn != NULL)
  {
    LogF(kClassName, __func__, "Existing connection object found for "
         "endpoint ID %" PRIEndptId ".\n", endpt_id);
    delete old_conn;
  }

  // Store the connection pointer.
  connections_[block_index][conn_index] = conn;

  return true;
}

//============================================================================
Connection* ConnectionManager::GetConnection(EndptId endpt_id)
{
  Connection*  conn = NULL;

  if ((endpt_id >= 0) &&
      (static_cast<size_t>(endpt_id) < (kNumBlocks * kNumConnsPerBlock)))
  {
    size_t  block_index = (static_cast<size_t>(endpt_id) / kNumConnsPerBlock);

    if (connections_[block_index] != NULL)
    {
      size_t  conn_index = (static_cast<size_t>(endpt_id) %
                            kNumConnsPerBlock);

      conn = connections_[block_index][conn_index];
    }
  }

  return conn;
}

//============================================================================
Connection* ConnectionManager::GetConnectionByPeer(const Ipv4Endpoint& peer)
{
  for (size_t i = 0; i < kNumBlocks; ++i)
  {
    if (connections_[i] != NULL)
    {
      for (size_t j = 0; j < kNumConnsPerBlock; ++j)
      {
        Connection*  conn = connections_[i][j];

        if ((conn != NULL) && (conn->GetPeerEndpoint() == peer))
        {
          return conn;
        }
      }
    }
  }

  return NULL;
}

//============================================================================
bool ConnectionManager::DeleteConnection(EndptId endpt_id)
{
  if ((endpt_id >= 0) &&
      (static_cast<size_t>(endpt_id) < (kNumBlocks * kNumConnsPerBlock)))
  {
    size_t  block_index = (static_cast<size_t>(endpt_id) / kNumConnsPerBlock);

    if (connections_[block_index] != NULL)
    {
      size_t  conn_index = (static_cast<size_t>(endpt_id) %
                            kNumConnsPerBlock);

      if (connections_[block_index][conn_index] != NULL)
      {
        // The connection object was found.  Add the connection to the reaper
        // stack to be destroyed later.
        if (reaper_size_ >= kMaxReaperSize)
        {
          LogF(kClassName, __func__, "Reaper list size exceeded.\n");
          return false;
        }

        reaper_list_[reaper_size_] = endpt_id;
        ++reaper_size_;

        // If the reaper timer has not been started already, then start it
        // now.
        if (!timer_.IsTimerSet(reaper_timer_))
        {
          Time                              duration(kReaperTimerSec);
          CallbackNoArg<ConnectionManager>  callback(
            this, &ConnectionManager::ReaperTimeout);

          if (!timer_.StartTimer(duration, &callback, reaper_timer_))
          {
            LogE(kClassName, __func__, "Error starting reaper timer.\n");
            return false;
          }
        }

        return true;
      }
    }
  }

  LogE(kClassName, __func__, "Error, connection for endpoint ID %" PRIEndptId
       " not found.\n", endpt_id);

  return false;
}

//============================================================================
void ConnectionManager::ReaperTimeout()
{
  // Destroy all of the connections on the reaper stack.
  for (size_t i = 0; i < reaper_size_; ++i)
  {
    EndptId  endpt_id = reaper_list_[i];

    if ((endpt_id >= 0) &&
        (static_cast<size_t>(endpt_id) < (kNumBlocks * kNumConnsPerBlock)))
    {
      size_t  block_index = (static_cast<size_t>(endpt_id) /
                             kNumConnsPerBlock);

      if (connections_[block_index] != NULL)
      {
        size_t       conn_index = (static_cast<size_t>(endpt_id) %
                                   kNumConnsPerBlock);
        Connection*  conn       = connections_[block_index][conn_index];

        if (conn != NULL)
        {
          delete conn;
          connections_[block_index][conn_index] = NULL;
        }
        else
        {
          LogE(kClassName, __func__, "Error, connection to be reaped is "
               "missing.\n");
        }
      }
      else
      {
        LogE(kClassName, __func__, "Error, block for connection to be reaped "
             "is missing.\n");
      }
    }
    else
    {
      LogE(kClassName, __func__, "Error, connection to be reaped has "
           "invalid endpoint ID %" PRIEndptId ".\n", endpt_id);
    }

    reaper_list_[i] = -1;
  }

  reaper_size_ = 0;
}
