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

///
/// Provides the IRON software with a pool of Packet objects in shared memory.
///


#ifndef IRON_COMMON_PACKET_POOL_SHM_H
#define IRON_COMMON_PACKET_POOL_SHM_H

#include "packet_pool.h"

#include "itime.h"
#include "shared_memory.h"

#include <map>
#include <string>


namespace iron
{

  class Packet;

  /// \brief The number of packets in the shared memory packet pool.
  ///
  /// This MUST not be larger than the largest number representable in type
  /// PktMemIndex.
  const uint32_t  kShmPPNumPkts = 0x20FFF;

  /// \brief The number of packets in the local memory packet pool.
  ///
  /// This MUST not be larger than the largest number representable in type
  /// PktMemIndex. This MUST be small enough that each required process can
  /// have this many packets from the pool without exceeding ShmPPNumPkts.
  const uint16_t  kLocalPPNumPkts = 1024;

  /// A class for the creation of a packet pool in shared memory.
  class PacketPoolShm : public PacketPool
  {

   public:

    /// \brief Default constructor.
    PacketPoolShm();

    /// \brief Constructor specifying the packet owner for packet tracking.
    ///
    /// \param  owner  The component who owns this packet pool.
    PacketPoolShm(PacketOwner owner);

    /// \brief Destructor.
    ///
    /// Purges all the packets in the shared memory pool and deletes the
    /// mutex.
    virtual ~PacketPoolShm();

    /// \brief Create the shared memory segment for the Packets.
    ///
    /// \param  key   The key for identifying the semaphore used for locking
    ///               and unlocking the shared memory.
    /// \param  name  The shared memory name.  Must be of the form "/name",
    ///               with a leading "/" character followed by a unique name.
    ///
    /// \return True on success, or false on error.  If this process has
    ///         already created or attached to shared memory, true is
    ///         returned.
    bool Create(key_t key, const char* name);

    /// \brief Access the shared memory segment for the Packets.
    ///
    /// This method does not create the shared memory segment, it only
    /// accesses it after it has been created by one process calling Create().
    /// It may fail until the process creating the shared memory segment has
    /// completed calling Create().
    ///
    /// This method does not block.
    ///
    /// \param  key   The key for identifying the semaphore used for locking
    ///               and unlocking the shared memory.
    /// \param  name  The shared memory name.  Must be of the form "/name",
    ///               with a leading "/" character followed by a unique name.
    ///
    /// \return Currently always returns true.  Does not return at all if the
    ///         inner Attach to shared memory fails, since we can't tell the
    ///         difference between a failure because the memory hasn't been
    ///         created versus failure for other reasons.
    bool Attach(key_t key, const char* name);

    /// \brief Get a Packet object from the pool.
    ///
    /// This will zero the length of the Packet object before returning it.
    ///
    /// Note that PACKET_COPY_TIMESTAMP is not a valid option for this method
    /// and will result in a fatal log message.
    ///
    /// \param  timestamp  Specifies how the returned Packet object's receive
    ///                    time is set:
    ///                    PACKET_NO_TIMESTAMP : Do not set the receive time.
    ///                    PACKET_NOW_TIMESTAMP : Set the receive time to now.
    ///                    Optional.  Defaults to PACKET_NO_TIMESTAMP.
    ///
    /// \return A pointer to the Packet object. If packet cannot be found,
    ///         this method creates a fatal log message and expects an abort.
    virtual Packet* Get(PacketRecvTimeMode timestamp =
                        PACKET_NO_TIMESTAMP);

    /// \brief Make a shallow copy of a Packet.
    ///
    /// This is a wrapper around the ShallowCopy function in the Packet class,
    /// necessary to accomplish packet tracking functionality within the pool.
    ///
    /// This is generally utilized when one thread/process needs to keep a
    /// reference to the Packet and pass the Packet to another thread/process
    /// for processing.  The result of this is an increase in the reference
    /// count.
    ///
    /// Note that if it is the case that more than one thread/process has a
    /// reference to the Packet, modifications to the contents of the Packet
    /// are not protected.  Modifications to the reference counts are the only
    /// protected operations.
    ///
    /// \param  packet  A pointer to the Packet object to copy.
    virtual void PacketShallowCopy(Packet* packet);

    /// \brief Create a deep copy of a Packet.
    ///
    /// \param  to_clone   A pointer to the Packet object to copy.
    /// \param  full_copy  If true, this will copy all internal state in the
    ///                    packet so that both copies have the same
    ///                    transmission state (e.g., for multicast splits). If
    ///                    false, only header and data is copied (e.g., for
    ///                    retransmissions).
    /// \param  timestamp  Specifies how the returned Packet object's receive
    ///                    time is set:
    ///                    PACKET_NO_TIMESTAMP : Do not set the receive time.
    ///                    PACKET_NOW_TIMESTAMP : Set the receive time to now.
    ///                    PACKET_COPY_TIMESTAMP : Copy the receive time from
    ///                                            the original packet.
    ///
    /// \return A pointer to the new Packet object.
    virtual Packet* Clone(Packet* to_clone,
                          bool full_copy,
                          PacketRecvTimeMode timestamp);

    /// \brief Create a deep copy of a Packet's header.
    ///
    /// \param  to_clone   A pointer to the Packet object to copy.
    /// \param  timestamp  Specifies how the returned Packet object's receive
    ///                    time is set:
    ///                    PACKET_NO_TIMESTAMP : Do not set the receive time.
    ///                    PACKET_NOW_TIMESTAMP : Set the receive time to now.
    ///                    PACKET_COPY_TIMESTAMP : Copy the receive time from
    ///                                            the original packet.
    ///
    /// \return A pointer to the new Packet object.
    virtual Packet* CloneHeaderOnly(Packet* to_clone,
                                    PacketRecvTimeMode timestamp);

    /// \brief Get the Packet for a specific memory index.
    ///
    /// \param  index  The index that locates the Packet object.
    ///
    /// \return A pointer to the Packet object.  If an error occurs, this
    ///         method creates a fatal log message and expects an abort.
    virtual Packet* GetPacketFromIndex(PktMemIndex index);

    /// \brief Return a Packet to the pool for reuse.
    ///
    /// \param  packet  A pointer to the Packet object to be returned to the
    ///                 pool.
    virtual void Recycle(Packet* packet);

    /// \brief Get the number of Packets in the pool.
    ///
    /// \return The number of Packet objects in the pool.
    virtual size_t GetSize();

#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)

    /// \brief Keep track of when a Packet is released from this component.
    ///
    /// \param  packet      A pointer to the Packet object being released.
    ///                     Used for packet tracking in the Packet object.
    /// \param  next_owner  The next owner of the Packet.
    virtual void TrackPacketRelease(Packet* packet, PacketOwner next_owner);

    /// \brief Keep track of when a Packet is claimed by this component.
    ///
    /// \param  packet      A pointer to the Packet object being claimed.
    ///                     Used for packet tracking in the Packet object.
    /// \param  prev_owner  The previous owner of the Packet.
    virtual void TrackPacketClaim(Packet* packet, PacketOwner prev_owner);

    /// \brief Keep track of when a copy is made of a Packet within the same
    ///        component.
    ///
    /// \param  packet  A pointer to the Packet object being copied.  Used for
    ///                 packet tracking in the Packet object.
    virtual void TrackPacketCopy(Packet* packet);

#endif // PKT_LEAK_DETECT || PACKET_TRACKING

    /// \brief Generate a unique 16-bit index for a given file name and line
    ///        number.
    ///
    /// This is intended to be called using the NEW_PKT_LOC macro.  The
    /// returned unique index can be stored in the Packet using
    /// Packet::NewPacketLocation(), so that if a Packet is deemed "stuck"
    /// (owned by the same component for a long time), we can tell which
    /// location (file and line) last saw the Packet.
    ///
    /// \param  file  The string returned by __FILE__, representing the place
    ///               from which this function is called.
    /// \param  line  The integer returned by __LINE__, representing the place
    ///               from which this function is called.
    /// \param  held  True if this location in the code is one where we expect
    ///               to hold onto Packets indefinitely.  If a "stuck" Packet
    ///               is found that was last seen here, that Packet is ignored
    ///               when reporting stuckness.  Defaults to false.
    /// \param  expected_drop  True if this location in the code is one where
    ///               we expect packets to be dropped if the right conditions
    ///               apply (i.e., not an error condition). Defaults to true.
    ///
    /// \return A unique 16-bit unsigned integer that can be stored in the
    ///         Packet to track this location, and can be dereferenced back
    ///         to the file name and line number using DerefLocation.
    virtual uint16_t GetLocationRef(const char* file, int line,
                                    bool held = false,
                                    bool expected_drop = true);

    /// \brief Translate the location index back into a string representation
    ///        of the correponding file name and line number.
    ///
    /// \param  location  The 16-bit unsigned integer that uniquely (per
    ///                   component) refers back to a file name and line
    ///                   number location from which this location was logged.
    ///
    /// \return A string representation of the file name and line number
    ///         (plus an indication if we expect packets to be held at this
    ///         location indefinitely).
    virtual std::string DerefLocation(uint16_t location);

    /// \brief  Count a packet drop from this code location.
    ///
    /// Expected to be called from macros TRACK_EXPECTED_DROP and
    /// TRACK_UNEXPECTED_DROP.
    ///
    /// \param  location  The 16-bit unsigned integer that uniquely (per
    ///                   component) refers back to a file name and line
    ///                   number where this packet was dropped.
    virtual void RecordDrop(uint16_t location);

    /// \brief Class for storing Packet references in the shared memory packet
    ///        pool.
    ///
    /// The implementations ShmPPCircBuf and LocalPPCircBuf are almost
    /// identical.  The Get() and Put() methods are exactly identical.
    /// However, these must still be separate classes because (a) we need
    /// statically allocated arrays so we can use these in shared memory, and
    /// (b) we can't use inheritence to achieve code reuse without having
    /// virtual functions, and virtual functions would result in a vtable that
    /// throws off our shared memory allocation and pointer manipulation.
    ///
    /// This class is public so it can be tested in packet_pool_test.cc.
    class LocalPPCircBuf
    {

     public:

      /// \brief Default constructor.
      LocalPPCircBuf();

      /// \brief Destructor.
      virtual ~LocalPPCircBuf();

      /// \brief Get the oldest value in the buffer.
      ///
      /// \param  val  The value is returned via this parameter.
      ///
      /// \return True on success, or false if the buffer is empty.
      bool Get(PktMemIndex& val);

      /// \brief Add the given value to the buffer.
      ///
      /// \param  val  The value to add to the buffer.
      ///
      /// \return True on success, or false if the buffer is full.
      bool Put(PktMemIndex val);

      /// \brief Get the number of packets currently in the buffer.
      ///
      /// \return The number of packets in the shared memory buffer.
      inline size_t GetCurrentCount() const
      {
        return count_;
      }

     private:

      // The constructor and destructor are private because we never want to
      // allocate this outside of shared memory.
      LocalPPCircBuf(const LocalPPCircBuf&);
      LocalPPCircBuf& operator=(const LocalPPCircBuf&);

      /// The set of packet indices in the local pool.
      PktMemIndex  data_[kLocalPPNumPkts];

      /// Stores index of first empty cell (or oldest data if buffer is full).
      /// This is type PktMemIndex because we cannot have more entries in the
      /// circular buffer than we have packets in the pool.
      PktMemIndex  index_;

      /// Stores the number of valid items currently in the buffer.  Note that
      /// [index_-count_] through [index_-1] (modulo size_) are valid entries.
      /// This is type PktMemIndex because we cannot have more entries in the
      /// circular buffer than we have packets in the pool.
      PktMemIndex  count_;

    }; // end class LocalPPCircBuf

   private:

    /// \brief Copy constructor.
    PacketPoolShm(const PacketPoolShm&);

    /// \brief Copy operator.
    PacketPoolShm& operator=(const PacketPoolShm&);

    /// \brief Class for storing Packet references in the shared memory packet
    ///        pool.
    ///
    /// The implementations ShmPPCircBuf and LocalPPCircBuf are almost
    /// identical.  The Get() and Put() methods are exactly identical.
    /// However, these must still be separate classes because (a) we need
    /// statically allocated arrays so we can use these in shared memory, and
    /// (b) we can't use inheritence to achieve code reuse without having
    /// virtual functions, and virtual functions would result in a vtable that
    /// throws off our shared memory allocation and pointer manipulation.
    class ShmPPCircBuf
    {

     public:

      /// \brief Get the oldest value in the buffer.
      ///
      /// \param  val  The value is returned via this parameter.
      ///
      /// \return True on success, or false if the buffer is empty.
      bool Get(PktMemIndex& val);

      /// \brief Add the given value to the buffer.
      ///
      /// \param  val  The value to add to the buffer.
      ///
      /// \return True on success, or false if the buffer is full.
      bool Put(PktMemIndex val);

      /// \brief Get the number of packets currently in the buffer.
      ///
      /// \return The number of packets in the shared memory buffer.
      inline size_t GetCurrentCount() const
      {
        return count_;
      }

     private:

      // The constructor and destructor are private because we never want to
      // allocate this outside of shared memory.
      ShmPPCircBuf();
      ~ShmPPCircBuf();
      ShmPPCircBuf(const ShmPPCircBuf&);
      ShmPPCircBuf& operator=(const ShmPPCircBuf&);

      /// The set of packet indices in the shared memory pool.
      PktMemIndex  data_[kShmPPNumPkts];

      /// Stores index of first empty cell (or oldest data if buffer is full).
      /// This is type PktMemIndex because we cannot have more entries in the
      /// circular buffer than we have packets in the pool.
      PktMemIndex  index_;

      // Stores the number of valid items currently in the buffer.  Note that
      // [index_-count_] through [index_-1] (modulo size_) are valid entries.
      // This is type PktMemIndex because we cannot have more entries in the
      // circular buffer than we have packets in the pool.
      PktMemIndex  count_;

    }; // end class ShmPPCircBuf

    /// \brief Log the stats for where packets were dropped.
    ///
    /// Called from the destructor.
    void LogPacketDrops();

#ifdef PKT_LEAK_DETECT

    /// \brief Perform periodic leak detection processing.
    ///
    /// Checks whether it's time to run LogPacketsOwned(), and if so, runs it.
    /// This is a callback-free way to do imprecise periodic functions.
    void DoPeriodicTracking();

    /// \brief Log the current ownership statistics for this component.
    ///
    /// Called by a periodic timer.
    ///
    /// \param  warn_if_nonzero  Controls if the logging should be at the
    ///                          warning level and should only occur if there
    ///                          are outstanding packets.
    void LogPacketsOwned(bool warn_if_nonzero = false);

#endif // PKT_LEAK_DETECT

#ifdef PACKET_TRACKING

    /// \brief Perform stuck Packet checks.
    ///
    /// This method skims through all packets currently in use (i.e., NOT in
    /// the pool) and checks whether each one is stuck.  Logs how many are
    /// stuck for each packet owner.
    void PacketTrackingStuckCheck();

#endif // PACKET_TRACKING

    /// The shared memory segment where we keep the circular buffer and the
    /// packets.
    SharedMemory    packet_shared_memory_;

    /// The packet pool circular buffer placed in shared memory.  This is
    /// initialized to NULL and should be checked to be valid to verify the
    /// shared memory segment was created.
    ShmPPCircBuf*   shm_packet_buffer_;

    /// The packet pool circular buffer kept locally (cache).
    LocalPPCircBuf  local_packet_buffer_;

    /// The memory location where the packets are stored in shared memory.
    /// Also, the location of the packet with index 0.
    Packet*         packet_buffer_start_;

    /// The smallest number of available packets in the packet pool
    /// encountered thus far.
    size_t          pool_low_water_mark_;

#ifdef PKT_LEAK_DETECT

    /// Keep track of how many packets are owned by the current process.
    int32_t   packets_owned_;

    /// Keep track of how many times this process has passed packets off to
    /// each other process. The indexes are the values of enum PacketOwner.
    uint32_t  next_owner_[NUM_PACKET_OWNERS];

    /// Keep track of how many times this process has accepted packets from
    /// each other process. The indexes are the values of enum PacketOwner.
    uint32_t  previous_owner_[NUM_PACKET_OWNERS];

    /// At which time did we last log packet ownership counts?
    Time      last_owner_log_time_;

#endif // PKT_LEAK_DETECT

    /// Maximum number of places in the code that have NEW_PKT_LOC calls
    static const uint16_t            kMaxLocations = 64;

    /// The next available (unused) location reference number
    uint16_t                         next_location_ref_;

    /// Map from file+line to location reference id. The location reference
    /// IDs are stored in the packets themselves (in shared memory), but can
    /// be dereferenced for developer/debugging purposes using the
    /// location_deref_ table. Note: the location reference IDs are
    /// component-specific.
    std::map<std::string, uint16_t>  location_ref_;

    /// Array, keyed by location reference Id, of location information (file,
    /// line, and whether or not this is an expected "held" packet).
    std::string                      location_deref_[kMaxLocations];

    /// Array, keyed by location reference ID, of whether or not a drop at
    /// this location is expected (i.e., not an error condition).
    bool                             location_deref_expected_[kMaxLocations];

    /// Array, keyed by location reference ID, of the number of times a packet
    /// was dropped at this code location.
    uint32_t                         drop_count_[kMaxLocations];

#ifdef PACKET_TRACKING

    /// Array, keyed by location reference ID, of whether or not this is an
    /// expected "held" packet location.  If so, then we can ignore packets
    /// that have sat at this location for a long time.
    bool                             location_deref_held_[kMaxLocations];

    /// Keep a record of which packets are currently out of the pool and in
    /// use by this component (tracked via Get, Recycle, and use of the packet
    /// fifos to pass packets between components).  This is an uint8_t instead
    /// of a bool because we may own multiple copies.
    uint8_t                          owned_[kShmPPNumPkts];

    /// Minimum index ever owned by this component.  This is a potential
    /// performance improvement for packet tracking, since as long as the
    /// packet indices haven't wrapped, the segment of packets that have been
    /// used will be smaller than the entire block of packets in shared
    /// memory.
    PktMemIndex                      min_owned_;

    /// Maximum index ever owned by this component.  This is a potential
    /// performance improvement for packet tracking, since as long as the
    /// packet indices haven't wrapped, the segment of packets that have been
    /// used will be smaller than the entire block of packets in shared
    /// memory.
    PktMemIndex                      max_owned_;

#endif // PACKET_TRACKING

  }; // end class PacketPoolShm

} // namespace iron

#endif // IRON_COMMON_PACKET_POOL_SHM_H
