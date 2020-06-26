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

/// \brief LatencyCacheShm header file
///
/// This storage class is responsible for maintaining the minimum latency
/// to every destination in the network. This information is based in the
/// LSAs and CAT measurements.

#ifndef IRON_COMMON_LATENCY_CACHE_SHM_H
#define IRON_COMMON_LATENCY_CACHE_SHM_H

#include "bin_indexable_array_shm.h"
#include "bin_map.h"
#include "iron_constants.h"
#include "iron_types.h"
#include "shared_memory.h"

namespace iron
{
  /// The weight applied to the current measurement of latency.
  const double  kCurLatencyWeight = 1.0;

  /// \brief LatencyCacheShm stores the latency of the quickest path to every
  /// destination using each CAT.
  ///
  /// This information is shared between the BPF and the UDP proxy.  The BPF
  /// updates the table while the proxy only reads from it.
  class LatencyCacheShm
  {
   public:

    /// \brief Default Constructor
    ///
    /// \param  bin_map  A reference to the bin map.
    /// \param  role     Whether we're creating the shared memory or attaching
    ///                  to it. (Or not using shared memory, for testing
    ///                  purposes, when that feature is supported.)
    LatencyCacheShm(BinMap& bin_map, ShmType role);

    /// \brief Destructor
    virtual ~LatencyCacheShm();

    /// \brief Initialize the state, including creating or attaching to shared
    /// memory.
    ///
    /// \return  True if initialization was successful, or false on error.
    bool Initialize();

    /// \brief Accessor function for initialized flag.
    ///
    /// \return  True if Initialize() has completed successfully, or false
    ///          otherwise.
    inline bool initialized()
    {
      return initialized_;
    };

    /// \brief Set the minimum latency for a destination.
    ///
    /// \param  dst  The destination bin index.
    /// \param  lat  The minimum latency to this destination in microseconds.
    inline void SetMinLatency(BinIndex dst, uint32_t lat)
    {
      min_latency_[dst] = ((lat * kCurLatencyWeight) +
                           (min_latency_[dst] * (1.0 - kCurLatencyWeight)));
    }

    /// \brief Get the minimum latency for a destination.
    ///
    /// This can be configured to be a weighted average by setting
    /// kCurLatencyWeight to a value less that 1.
    ///
    /// \param  dst  The destination bin index.
    ///
    /// \return  The latency, in microseconds, to the destination.
    inline uint32_t GetMinLatency(BinIndex dst) const
    {
      return min_latency_[dst];
    }

   private:

    /// Disallow empty constructor.
    LatencyCacheShm();

    /// Disallow copy constructor.
    LatencyCacheShm(const LatencyCacheShm& other);

    /// Disallow assignment.
    LatencyCacheShm operator=(const LatencyCacheShm& other);

    /// The bin map.
    BinMap&                             bin_map_;

    /// An array of minimum latencies, indexed by destination bin index.  The
    /// latency is measured in microseconds.
    BinIndexableArrayShm<uint32_t>      min_latency_;

    /// Our role with regards to initializing shared memory.
    ShmType                             role_;

    /// Shared memory where the data is stored.
    SharedMemoryIF*                     shared_memory_;

    /// True if Initialize() has completed.
    bool                                initialized_;

  }; // class LatencyCacheShm
} // namespace iron

#endif // IRON_COMMON_LATENCY_CACHE_SHM_H
