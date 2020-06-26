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

/// \brief QueueDepths Header File
///
/// This class serves as storage for queue depth information for the local
/// node. It maintains the current depth, in bytes, of each of the node's
/// backpressure bins in a map container. It also implements the serialize and
/// deserialize function used to create and parse QLAMs respectively.

#ifndef IRON_COMMON_QUEUE_DEPTHS_H
#define IRON_COMMON_QUEUE_DEPTHS_H

#include "bin_indexable_array.h"
#include "bin_indexable_array_shm.h"
#include "bin_map.h"
#include "packet.h"
#include "shared_memory_if.h"
#include "itime.h"

#include <string>

#include <stdint.h>
#include <sys/types.h>

namespace iron
{
  class QueueDepthsShmStats;

  /// \brief The QueueDepths class stores queue depth information for a set of
  /// bins.
  ///
  /// Each QueueDepths object contains information for some number of bins.
  /// Bins are locally indexed by unique unsigned integer values (BinIndex).
  /// The information stored for each bin is the current queue depth, in
  /// bytes, for the actual packet queue for the bin, which is stored
  /// elsewhere.  QueueDepths objects may be serialized to be sent over a
  /// network connection, and may be deserialized back into an object at the
  /// receiving end. Most functions (as well as serialization) index the queue
  /// depths by BinId, which is a universally understood identifier that can
  /// be translated internally to the BinIndex using the BinMap.
  class QueueDepths
  {

  public:

    /// \brief Constructor.
    ///
    /// \param bin_map Mapping of IRON bins.
    QueueDepths(BinMap& bin_map);

    /// \brief Destructor.
    virtual ~QueueDepths();

    /// \brief Configures local pointer into shared memory.
    ///
    /// Calling this function configures this QueueDepths instance to use
    /// direct shared memory access instead of using a copy of the data in
    /// local memory. Once this has been called, the internal depths array
    /// will no longer be used. Instead, the queue depths pointer will be set
    /// up to point into shared memory, so that all accesses to queue depth
    /// information will use the shared memory version directly.
    ///
    /// \return True if initialization is successful. (Note: this currently
    ///         always returns true or blocks forever if we cannot attach to the
    ///         shared memory.)
    bool InitializeShmDirectAccess(SharedMemoryIF* shared_memory);

    /// \brief Sets up shared memory statistics object.
    ///
    /// To be called if and only if this set of queue depths will be written
    /// to shared memory. Sets up the statistics object to track how stale the
    /// values get over time.
    ///
    /// Note: This does nothing unless SHM_STATS is defined in the common
    /// makefile.
    ///
    /// \return True if initialization is successful.
    bool InitializeShmStats();

    /// \brief Get depth of a bin, in bytes, for a given traffic type.
    ///
    /// \param  bin_idx  The bin index to query.  May be a unicast or
    ///                  multicast destination bin index.
    /// \param  lat      The traffic type (latency-sensitive or insensitive)
    ///                  for which to get the bin depth (NORMAL by default).
    ///
    /// \return  The depth of the bin, in bytes.  If the bin index is invalid,
    ///          then an error is logged and an unknown value is returned.
    uint32_t GetBinDepthByIdx(BinIndex bin_idx,
                              LatencyClass lat=NORMAL_LATENCY) const;

    /// \brief Set the depth of a bin, in bytes.
    ///
    /// WARNING: If direct shared memory access is being used, then the LS
    /// depth will clobber the normal depth!!
    ///
    /// \param  bin_idx   The bin index of the bin depth to be set.  May be a
    ///                   unicast or multicast destination bin index.
    /// \param  depth     The value of depth, in bytes, to be assigned to the
    ///                   bin.
    /// \param  ls_depth  The value of depth, in bytes, to be assigned to the
    ///                   bin for latency-sensitive traffic.
    inline void SetBinDepthByIdx(iron::BinIndex bin_idx, uint32_t depth,
                                 uint32_t ls_depth)
    {
      SetBinDepthByIdx(bin_idx, depth);
      SetBinDepthByIdx(bin_idx, ls_depth, LOW_LATENCY);
    }

    /// \brief Set the depth of a bin, in bytes.
    ///
    /// \param  bin_idx  The bin index of the bin depth to be set.  May be a
    ///                  unicast or multicast destination bin index.
    /// \param  depth    The value of depth, in bytes, to be assigned to the
    ///                  bin.
    /// \param  lat      The traffic type (latency-sensitive or insensitive)
    ///                  for which to set the bin depth (NORMAL by default).
    void SetBinDepthByIdx(iron::BinIndex bin_idx, uint32_t depth,
                          iron::LatencyClass lat = NORMAL_LATENCY);

    /// \brief Increase or decrease the size, in bytes, of a bin.
    ///
    /// This is a shortcut for calling Increment or Decrement.
    ///
    /// \param  bin_idx       The bin index of the bin depth to be adjusted.
    ///                       May be a unicast or multicast destination bin
    ///                       index.
    /// \param  amt_bytes     Number of bytes by which to increment or
    ///                       decrement the normal latency depth.  Negative to
    ///                       decrement.
    /// \param  ls_amt_bytes  Number of bytes by which to increment or
    ///                       decrement the latency-sensitive depth.  Negative
    ///                       to decrement.  Note that
    ///                       |ls_incr_amt_bytes| <= |incr_amt_bytes| (and
    ///                       both must be positive or both negative).
    void AdjustByAmt(BinIndex bin_idx, int64_t amt_bytes,
                     int64_t ls_amt_bytes = 0);

    /// \brief Increase the size, in bytes, of a bin.
    ///
    /// This will be updated as packets are enqueued.
    ///
    /// \param  bin_idx            The bin index of the bin to be incremented.
    ///                            May be a unicast or multicast destination
    ///                            bin index.
    /// \param  incr_amt_bytes     Number of bytes by which to increment the
    ///                            normal latency depth.
    /// \param  ls_incr_amt_bytes  Number of bytes by which to increment the
    ///                            latency-sensitive depth.  Note that
    ///                            ls_incr_amt_bytes <= incr_amt_bytes.
    void Increment(BinIndex bin_idx, uint32_t incr_amt_bytes,
                   uint32_t ls_incr_amt_bytes = 0);

    /// \brief Decrease the size, in bytes, of a bin.
    ///
    /// This will be updated as packets are dequeued.
    ///
    /// \param  bin_idx            The bin index of the bin to be decremented.
    ///                            May be a unicast or multicast destination
    ///                            bin index.
    /// \param  decr_amt_bytes     Number of bytes by which to decrement the
    ///                            normal latency depth.
    /// \param  ls_decr_amt_bytes  Number of bytes by which to decrement the
    ///                            latency-sensitive depth.  Note that
    ///                            ls_decr_amt_bytes <= decr_amt_bytes.
    void Decrement(BinIndex bin_idx, uint32_t decr_amt_bytes,
                   uint32_t ls_decr_amt_bytes = 0);

    /// \brief Clear all the depths for all bins without removing any bin.
    ///
    /// The depths are all set to 0.
    void ClearAllBins();

    /// \brief Get the number of bins configured in the system.
    ///
    /// The number returned will include any bins with any queue length, even
    /// zero-length queues.
    ///
    /// \return  The total number of bins.
    inline uint32_t GetNumQueues() const
    {
      // MCAST TODO: it would be better if we could have queue depths arrays
      // sized only for destination bins.
      return (bin_map_.GetNumUcastBinIds() + bin_map_.GetNumMcastIds());
    }

    /// \brief Get the number of non-zero destination bins currently in the
    /// QueueDepth object.
    ///
    /// The number returned only includes destination bins with
    /// non-zero-length queues.  Note that this excludes multicast group
    /// queues, since these aren't used for anything except the "own group"
    /// convenience count which double counts bytes already counted per
    /// destination.
    ///
    /// Note: This counts the bins every time it is called.  It is really only
    /// to be used for testing.
    ///
    /// \return  The number of bins with non-zero queue lengths.
    uint32_t GetNumNonZeroQueues() const;

    /// \brief Serialize the queue depths information into a buffer.
    ///
    /// Note that this method currently supresses zero-length bins.
    ///
    /// Used for adding all of the destination bin identifiers, normal queue
    /// depths, and latency-sensitive queue depths for a single group to a
    /// QLAM packet.  The destination bin identifier takes up 1 byte in the
    /// buffer, and each queue depth takes up 4 bytes in the buffer (in
    /// network byte order).
    ///
    /// Both the Serialize() and Deserialize() methods share a single,
    /// internal sequence number.  For this reason, each QueueDepth object
    /// should only use either Serialize() or Deserialize() calls.
    ///
    /// This MUST NOT be called if shared memory direct access is in use
    /// (i.e., if InitializeShmDirectAccess has been called).  This decision
    /// was made because serialization/deserialization would require that the
    /// shared memory structure be locked for too long.
    ///
    /// \param  ret        A pointer to the buffer where the resulting
    ///                    serialized data will be written.
    /// \param  max_len    The maximum length, in bytes, that can be written
    ///                    to this buffer.
    /// \param  num_pairs  The number of pairs written, to be returned.
    ///
    /// \return  The number of bytes written to the buffer.  If zero is
    ///          returned, then the serialization has failed.
    size_t Serialize(uint8_t* ret, size_t max_len, uint8_t& num_pairs);

    /// \brief Deserialize a buffer into a QueueDepth object.
    ///
    /// The bytes are converted to host byte order upon successful
    /// deserialization.  The QueueDepth object is overwritten with the
    /// deserialized information only if a non-zero value is returned.
    ///
    /// Both the Serialize() and Deserialize() methods share a single,
    /// internal sequence number.  For this reason, each QueueDepth object
    /// should only use either Serialize() or Deserialize() calls.
    ///
    /// See the documentation for Serialize() for details on the serialization
    /// format used.
    ///
    /// This MUST NOT be called if shared memory direct access is in use
    /// (i.e., if InitializeShmDirectAccess has been called).  This decision
    /// was made because serialization/deserialization would require that the
    /// shared memory structure be locked for too long.
    ///
    /// \param  depths     A pointer to the buffer containing the serialized
    ///                    data.
    /// \param  len        The length of the serialized data in bytes.
    /// \param  num_pairs  The number of (dest_bin, byte count) pairs to
    ///                    deserialize.
    ///
    /// \return  Returns the number of bytes deserialized.  0 for error.
    size_t Deserialize(const uint8_t* depths, size_t len, uint8_t num_pairs);

    /// \brief Return the size needed to share queue depths.
    ///
    /// \return  The number of bytes needed in shared memory.
    inline size_t GetShmSize() const
    {
      return shm_queue_depths_.GetMemorySizeInBytes();
    }

    /// \brief Store the queue depth array into shared memory.
    ///
    /// This includes all necessary locking, unlocking, and waiting (if the
    /// shared memory segment is in use).  It copies just the array of queue
    /// depths (and it copies the entire array, including values that have not
    /// changed as well as values that have).
    ///
    /// This MUST NOT be called if shared memory direct access is in use
    /// (i.e., if InitializeShmDirectAccess has been called).
    ///
    /// \param  shared_memory  A reference to the shared memory destination.
    ///
    /// \return  True if the copy succeeded, false if it failed.
    bool CopyToShm(SharedMemoryIF& shared_memory);

    /// \brief Fetch the queue depth array from shared memory.
    ///
    /// This includes all necessary locking, unlocking, and waiting (if the
    /// shared memory segment is in use).  It copies the entire array of queue
    /// depths, overwriting whatever in the local array.
    ///
    /// This MUST NOT be called if shared memory direct access is in use
    /// (i.e., if InitializeShmDirectAccess has been called).
    ///
    /// \param  shared_memory  A reference to the shared memory source.
    ///
    /// \return  True if the copy succeeded, false if it failed.
    bool CopyFromShm(SharedMemoryIF& shared_memory);

    /// \brief Print the queue depths for the stat dump.
    ///
    /// \return  A string object with the bin_id:queue-depth pairs without the
    ///          leading legend, contrary to ToString.
    std::string StatDump() const;

    /// \brief Convert the QueueDepth object into a string.
    ///
    /// Returns a string representation the bin-id:queue-depth pair for all
    /// pairs in the queue depth object.
    ///
    /// \return  A string object with the bin-id:queue-depth pairs of the
    ///          queue_depth object.
    std::string ToString() const;

    /// \brief Generate a python dictionary of bin id: queue depths pair.
    ///
    /// \return  A string representation of a python dictionary.
    std::string ToQdDict() const;

   private:

    /// Disallow copy constructor.
    QueueDepths(const QueueDepths& qd);

    /// Disallow assignment.
    QueueDepths operator=(const QueueDepths& qd);

    /// \brief Internal queue depth get method.
    ///
    /// \param  bin_idx  The bin index.
    ///
    /// \return  The bin depth.
    inline uint32_t IntGet(BinIndex bin_idx) const
    {
      uint32_t depth = 0;

      if (access_shm_directly_)
      {
        depth = shm_queue_depths_[bin_idx];
      }
      else
      {
        depth = local_queue_depths_[bin_idx];
      }

      return depth;
    }

    /// \brief Internal queue depth set method.
    ///
    /// \param  bin_idx  The bin index.
    /// \param  depth    The bin depth.
    inline void IntSet(BinIndex bin_idx, uint32_t depth)
    {
      if (access_shm_directly_)
      {
        shm_queue_depths_[bin_idx] = depth;
      }
      else
      {
        local_queue_depths_[bin_idx] = depth;
      }
    }

    /// \brief Internal shared memory locking method.
    inline void IntLock() const
    {
      if (access_shm_directly_)
      {
        shm_if_->Lock();
      }
    }

    /// \brief Internal shared memory unlocking method.
    inline void IntUnlock() const
    {
      if (access_shm_directly_)
      {
        shm_if_->Unlock();
      }
    }

    /// Mapping of IRON bins.
    BinMap&                         bin_map_;

    /// Flag controlling where queue depths are directly accessed from.  If
    /// true, then the queue depths are accessed directly in shared memory
    /// using shm_queue_depths_.  If false, then the queue depths are accessed
    /// directly in local memory using local_queue_depths_.  Note that if
    /// true, then all accesses must be properly locked and unlocked.
    bool                            access_shm_directly_;

    /// Array of queue depths for latency-sensitive traffic in local memory,
    /// keyed by bin index.
    BinIndexableArray<uint32_t>     local_ls_queue_depths_;

    /// Array of queue depths for all traffic in local memory, keyed by bin
    /// index.
    BinIndexableArray<uint32_t>     local_queue_depths_;

    /// The shared memory interface object when directly accessing the queue
    /// depths from shared memory.  Not owned by this class.
    SharedMemoryIF*                 shm_if_;

    /// Array of queue depths for all traffic in shared memory, keyed by bin
    /// index.
    BinIndexableArrayShm<uint32_t>  shm_queue_depths_;

    /// The shared memory statistics object for tracking how much the current
    /// value differs from the last value.  Owned by this class.
    QueueDepthsShmStats*            shm_stats_;

  }; // end class QueueDepths

} // namespace iron

#endif  // IRON_COMMON_QUEUE_DEPTHS_H
