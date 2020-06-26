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
/// The abstract base class for all pools of Packet objects.
///


#ifndef IRON_COMMON_PACKET_POOL_H
#define IRON_COMMON_PACKET_POOL_H

#include "packet.h"

#include <string>
#include "rng.h"

#include <inttypes.h>
#include <stdint.h>


/// \brief Macro for tracking expected packet drops.
///
/// This macro is intended to help determine where packets are being dropped.
/// This should be used every time we drop a packet someplace expected: i.e.,
/// when it's the IRON algorithms deciding to drop packets, rather than an
/// error condition or resource bound overflow. After running packets through
/// the system, the packet pool will contain an array of counts for where in
/// the code the packets were dropped.
///
/// This does NOT call Recycle, since some places in the code reuse packets
/// rather that returning them to the pool.
///
/// \param  class_name  Used to log the packet drop.
/// \param  pkt_pool    A reference to the PacketPool.
#ifdef DROP_TRACKING
#define TRACK_EXPECTED_DROP(class_name, pkt_pool)                       \
  {                                                                     \
    uint16_t ref = pkt_pool.GetLocationRef(                             \
      __FILE__, __LINE__, false, true);                                 \
    LogD(class_name, __func__,                                          \
         "Expected packet drop (%" PRIu16 ").\n", ref);                 \
    pkt_pool.RecordDrop(ref);                                           \
  }
#else // !DROP_TRACKING
#define TRACK_EXPECTED_DROP(class_name, pkt_pool) {}
#endif // DROP_TRACKING


/// \brief Macro for tracking unexpected (error condition) packet drops.
///
/// This macro is intended to help determine where packets are being dropped.
/// This should be used every time we drop a packet someplace unexpected:
/// i.e., when there's an unavailable resource, as opposed to when the IRON
/// algorithm decides to drop packets. After running packets through
/// the system, the packet pool will contain an array of counts for where in
/// the code the packets were dropped.
///
/// This does NOT call Recycle, since some places in the code reuse packets
/// rather that returning them to the pool.
///
/// \param  class_name  Used to log the packet drop.
/// \param  pkt_pool    A reference to the PacketPool.
#define TRACK_UNEXPECTED_DROP(class_name, pkt_pool)                     \
  {                                                                     \
    uint16_t ref = pkt_pool.GetLocationRef(                             \
      __FILE__, __LINE__, false, false);                                \
    if (ref != 0)                                                       \
    {                                                                   \
      pkt_pool.RecordDrop(ref);                                         \
    }                                                                   \
    LogI(class_name, __func__,                                          \
         "Unexpected packet drop (%" PRIu16 ").\n", ref);               \
  }

/// \brief Macro for tracking a packet's location in the code path.
///
/// This macro is intended to help debug packet leaks.  Sprinkle calls to this
/// throughout the potentially leaky code.  After running packets through the
/// system, each Packet object will contain a reference to a location (file
/// and line) where the packet was last seen by each component.
///
/// If the packet location is expected to keep packets objects indefinitely,
/// use NEW_HELD_PKT_LOC instead.
///
/// \param  pkt_pool  A reference to the PacketPool.  Used to get the owning
///                   component of the packet as well as to translate the file
///                   and line into the packet location reference.
/// \param  packet    A pointer to the Packet to be tracked.
#define NEW_PKT_LOC(pkt_pool, packet)                                      \
  {                                                                        \
    packet->NewPacketLocation(pkt_pool.packet_owner(),                     \
                              pkt_pool.GetLocationRef(__FILE__,__LINE__)); \
  }

/// \brief Macro for tracking a packet's location when the packets are
///        expected to be held onto indefinitely.
///
/// See NEW_PKT_LOC.  In addition, this function flags the location as one
/// where packet objects are expected to remain indefinitely.  Packets in this
/// location will not be flagged as "stuck."
///
/// \param  pkt_pool  A reference to the PacketPool.  Used to get the owning
///                   component of the packet as well as to translate the file
///                   and line into the packet location reference.
/// \param  packet    A pointer to the Packet to be tracked.
#define NEW_HELD_PKT_LOC(pkt_pool, packet)                              \
  {                                                                     \
    packet->NewPacketLocation(pkt_pool.packet_owner(),                  \
                              pkt_pool.GetLocationRef(                  \
                                __FILE__,__LINE__, true));              \
  }


namespace iron
{

  /// The abstract base class for all packet pools.  The Get() method is
  /// called when a new Packet object is required.  The packets are returned
  /// to the pool with Recycle(), as they cannot be deleted.
  class PacketPool
  {

   public:

    /// \brief Default constructor.
    PacketPool()
        : packet_owner_(PACKET_OWNER_NONE),
          rng_(),
          packet_id_counter_(0),
          ip_id_counter_(0)
    {
      // Initialize the packet_id generator.
      packet_id_counter_  = static_cast<uint32_t>(rng_.GetInt(
                                                    iron::kMaxPacketId));
      // Initialize the IP ID generator.
      ip_id_counter_  = static_cast<uint16_t>(
        rng_.GetInt(std::numeric_limits<uint16_t>::max()));
    }

    /// \brief Constructor specifying the packet owner for packet tracking.
    ///
    /// \param  owner  The component who owns this packet pool.
    PacketPool(PacketOwner owner)
        : packet_owner_(owner),
          rng_(),
          packet_id_counter_(0),
          ip_id_counter_(0)
    {
      // Initialize the packet_id generator.
      packet_id_counter_  = static_cast<uint32_t>(rng_.GetInt(
                                                    iron::kMaxPacketId));

      // Initialize the IP ID generator.
      ip_id_counter_  = static_cast<uint16_t>(
        rng_.GetInt(std::numeric_limits<uint16_t>::max()));
    }

    /// \brief Destructor.
    virtual ~PacketPool()
    { }

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
    /// \return A pointer to the Packet object.  If a packet cannot be found,
    ///         this method creates a fatal log message and expects an abort.
    virtual Packet* Get(PacketRecvTimeMode timestamp =
                        PACKET_NO_TIMESTAMP) = 0;

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
    virtual void PacketShallowCopy(Packet* packet) = 0;

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
                          PacketRecvTimeMode timestamp) = 0;

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
                                    PacketRecvTimeMode timestamp) = 0;

    /// \brief Get the Packet for a specific memory index.
    ///
    /// \param  index  The index that locates the Packet object.
    ///
    /// \return A pointer to the Packet object.  If an error occurs, this
    ///         method creates a fatal log message and expects an abort.
    virtual Packet* GetPacketFromIndex(PktMemIndex index) = 0;

    /// \brief Return a Packet to the pool for reuse.
    ///
    /// \param  packet  A pointer to the Packet object to be returned to the
    ///                 pool.
    virtual void Recycle(Packet* packet) = 0;

    /// \brief Get the number of Packets in the pool.
    ///
    /// \return The number of Packet objects in the pool.
    virtual size_t GetSize() = 0;

#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)

    /// \brief Keep track of when a Packet is released from this component.
    ///
    /// \param  packet      A pointer to the Packet object being released.
    ///                     Used for packet tracking in the Packet object.
    /// \param  next_owner  The next owner of the Packet.
    virtual void TrackPacketRelease(Packet* packet,
                                    PacketOwner next_owner) = 0;

    /// \brief Keep track of when a Packet is claimed by this component.
    ///
    /// \param  packet      A pointer to the Packet object being claimed.
    ///                     Used for packet tracking in the Packet object.
    /// \param  prev_owner  The previous owner of the Packet.
    virtual void TrackPacketClaim(Packet* packet, PacketOwner prev_owner) = 0;

    /// \brief Keep track of when a copy is made of a Packet within the same
    ///        component.
    ///
    /// \param  packet  A pointer to the Packet object being copied.  Used for
    ///                 packet tracking in the Packet object.
    virtual void TrackPacketCopy(Packet* packet) = 0;

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
                                    bool expected_drop = true) = 0;

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
    virtual std::string DerefLocation(uint16_t location) = 0;

    /// \brief  Count a packet drop from this code location.
    ///
    /// Expected to be called from macros TRACK_EXPECTED_DROP and
    /// TRACK_UNEXPECTED_DROP.
    ///
    /// \param  location  The 16-bit unsigned integer that uniquely (per
    ///                   component) refers back to a file name and line
    ///                   number where this packet was dropped.
    virtual void RecordDrop(uint16_t location) = 0;

    /// \brief Get the component who will own packets taken from this pool
    ///        instance.
    ///
    /// \return The component who owns this packet pool.
    inline PacketOwner packet_owner()
    {
      return packet_owner_;
    }

    /// \brief Puts the next available packet id in the packet.
    ///
    /// Updates the counter for the next packet.
    ///
    /// \param   packet  To be assigned an Id.
    inline void AssignPacketId(Packet* packet)
    {
      packet->set_packet_id(packet_id_counter_);
      ++packet_id_counter_;
      if (packet_id_counter_ > iron::kMaxPacketId)
      {
        packet_id_counter_ = 1;
      }
    }

    /// \brief Returns the next available IP ID value
    ///
    /// Updates the counter for the next packet.
    ///
    /// \return The ID value.
    inline uint16_t GetNextIpId()
    {
      uint16_t next_id = ip_id_counter_;
      if (ip_id_counter_ == std::numeric_limits<uint16_t>::max())
      {
        ip_id_counter_ = 0;
      }
      else
      {
        ip_id_counter_++;
      }
      return next_id;
    }

   protected:

    /// The owner of the packet pool.
    PacketOwner  packet_owner_;

   private:

    /// Random Number Generator object.
    ::iron::RNG       rng_;

    /// Counter to generate 20-bit packet id.
    uint32_t          packet_id_counter_;

    /// Counter to generate the next IP id value for locally-generated/sourced
    /// IP packets.
    uint16_t          ip_id_counter_;
  }; // end class PacketPool

} // namespace iron

#endif // IRON_COMMON_PACKET_POOL_H
