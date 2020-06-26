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
/// Provides the IRON software with a pool of Packet objects on the heap.
///


#ifndef IRON_TESTTOOLS_PACKET_POOL_HEAP_H
#define IRON_TESTTOOLS_PACKET_POOL_HEAP_H

#include "packet_pool.h"


namespace iron
{

  class Packet;

  /// A class for the creation of a packet pool on the heap.
  class PacketPoolHeap : public PacketPool
  {

   public:

    /// \brief Default constructor.
    PacketPoolHeap();

    /// \brief Destructor.
    virtual ~PacketPoolHeap();

    /// \brief Create the packet pool.
    ///
    /// \param  num_pkts  The number of Packets to create in the packet pool.
    ///
    /// \return True on success, or false on error.
    bool Create(size_t num_pkts);

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
    virtual void TrackPacketRelease(Packet* packet, PacketOwner next_owner)
    { }

    /// \brief Keep track of when a Packet is claimed by this component.
    ///
    /// \param  packet      A pointer to the Packet object being claimed.
    ///                     Used for packet tracking in the Packet object.
    /// \param  prev_owner  The previous owner of the Packet.
    virtual void TrackPacketClaim(Packet* packet, PacketOwner prev_owner)
    { }

    /// \brief Keep track of when a copy is made of a Packet within the same
    ///        component.
    ///
    /// \param  packet  A pointer to the Packet object being copied.  Used for
    ///                 packet tracking in the Packet object.
    virtual void TrackPacketCopy(Packet* packet)
    { }

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
                                    bool expected_drop = true)
    {
      return 0;
    }

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
    virtual std::string DerefLocation(uint16_t location)
    {
      return "";
    }

    /// \brief  Count a packet drop from this code location.
    ///
    /// Expected to be called from macros TRACK_EXPECTED_DROP and
    /// TRACK_UNEXPECTED_DROP.
    ///
    /// \param  location  The 16-bit unsigned integer that uniquely (per
    ///                   component) refers back to a file name and line
    ///                   number where this packet was dropped.
    virtual void RecordDrop(uint16_t location) {};

   private:

    /// \brief Copy constructor.
    PacketPoolHeap(const PacketPoolHeap&);

    /// \brief Copy operator.
    PacketPoolHeap& operator=(const PacketPoolHeap&);

    /// The size of the packet pool.
    PktMemIndex   num_pkts_;

    /// The first empty packet index entry in pool_.
    PktMemIndex   index_;

    /// The number of currently available packet index entries in pool_.
    PktMemIndex   count_;

    /// The array of available packet indices in the local pool.
    PktMemIndex*  pool_;

    /// The array of Packet objects accessed by packet index.
    Packet*       pkt_buf_;

  }; // end class PacketPoolHeap

} // namespace iron

#endif // IRON_TESTTOOLS_PACKET_POOL_HEAP_H
