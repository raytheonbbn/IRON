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

/// Provides the IRON software with a pool of FecState class.

#ifndef IRON_UDP_PROXY_FECSTATE_POOL_H
#define IRON_UDP_PROXY_FECSTATE_POOL_H

#include <pthread.h>

#include "packet_pool.h"

#include <stack>
#include <stdint.h>
#include <stdlib.h>


class FecState;

/// A class for the creation of a FecState pool. The Get() method must be
/// called when a new FecState object is required. The FecState are returned
/// to the pool (they cannot be deleted) with Recycle().
class FecStatePool
{
  public:

  /// \brief Constructor.
  ///
  /// \param  packet_pool  Pool containing packets to use.
  FecStatePool(iron::PacketPool& packet_pool);

  /// \brief Destructor.
  ///
  /// Purges all the FecState objects in the pool and deletes mutex.
  virtual ~FecStatePool();

  /// \brief Get a FecState object that is initialized to default values.
  ///
  /// \return A pointer to the reused or newly allocated FecState object. Does
  ///         not return NULL (throws a LogF and aborts if there is an
  ///         error).
  FecState* Get();

  /// \brief  Recycle a FecState so that it may be reused later.
  ///
  /// \param  fec_state  Pointer to the FecState object to be returned to the
  ///                    pool.
  void Recycle(FecState* fec_state);

  /// \brief  Get the number of FecState objects in the pool.
  ///
  /// \return The number of FecState objects in the pool.
  size_t GetSize();

  /// \brief  Deletes all FecState objects in the pool.
  void Purge();

  private:

  /// The pool of FecState objects.
  std::stack<FecState*>   pool_;

  /// Pool containing packets to use.
  iron::PacketPool&       packet_pool_;

  /// The mutex to protect pool access.
  pthread_mutex_t         pool_mutex_;

}; // end class FecStatePool

#endif //IRON_UDP_PROXY_FECSTATE_POOL_H
