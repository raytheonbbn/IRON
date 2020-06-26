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

#ifndef IRON_BPF_PATH_CONTROLLER_H
#define IRON_BPF_PATH_CONTROLLER_H

#include "fd_event.h"
#include "ipv4_address.h"
#include "itime.h"
#include "packet_pool.h"

#include <string>

#include <stdint.h>

/// Macro for computing the transmit queue size (in packets) for the path
/// controller, based on the transmit threshold size (in bytes) for the BPF.
/// This is the threshold divided by the smallest bytes per packet (using the
/// size of an empty UDP packet for this). Add in an extra 32 packets for
/// safety.
#define COMPUTE_XMIT_QUEUE_SIZE(size_t_xmit_thresh)     \
  (((size_t_xmit_thresh) / 28) + 32)


namespace iron
{
  class BPFwder;
  class ConfigInfo;
  class Packet;
  class PacketPool;

  /// The header types for CAT packets and headers.  Determined by the first
  /// byte in the buffer.
  ///
  /// All CAT packet and header type values are one byte long, and are within
  /// the following hexadecimal range:
  ///
  ///   Range 0x30-0x3f (decimal 48-63)
  ///
  /// This leaves the following ranges for other components:
  ///
  ///   Range 0x00-0x0f (decimal 0-15) for SLIQ headers.
  ///   Range 0x10-0x1f (decimal 16-31) for BPF packets.
  ///   Range 0x20-0x2f (decimal 32-47) for SLIQ headers.
  ///   Range 0x40-0x4f (decimal 64-79) for IPv4 headers.
  ///
  /// WARNING: Any changes to these header types must not conflict with the
  /// HeaderType definition in iron/sliq/src/sliq_framer.h and the PacketType
  /// definition in iron/common/include/packet.h.
  enum CatHeaderType
  {
    // CAT packets.  Includes the CAT Capacity Estimate (CCE) packet.
    CAT_CAPACITY_EST_PACKET  = 48,  // 0x30

    // CAT packet object metadata headers.
    CAT_PKT_DST_VEC_HEADER = 52,  // 0x34
    CAT_PKT_ID_HEADER      = 53,  // 0x35
    CAT_PKT_HISTORY_HEADER = 54,  // 0x36
    CAT_PKT_LATENCY_HEADER = 55   // 0x37
  };

  /// The CAT Capacity Estimate (CCE) header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |               Capacity Estimate               |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x30)
  ///   Capacity Estimate (24 bits)
  /// \endverbatim
  ///
  /// Note that the Capacity Estimate field is an unsigned integer field
  /// stored in network byte order, and records the capacity estimate in units
  /// of 1000 bits per second.  The capacity estimate is always rounded up to
  /// the next 1000 bits per second value before scaling it.
  ///
  /// Length = 4 bytes.

  /// The CAT packet destination vector header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |            Destination Bit Vector             |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x34)
  ///   Destination Bit Vector (24 bits)
  /// \endverbatim
  ///
  /// Length = 4 bytes.
  struct PktDstVecHeader
  {
    uint32_t  type_dst_vec;
  } __attribute__((packed));

  /// The size of the CAT packet destination vector header in bytes.
  const size_t  kPktDstVecHdrSize = sizeof(struct PktDstVecHeader);

  /// The CAT packet ID header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      | BinId |               PacketId                |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x35)
  ///   Source Bin Identifier (4 bits)
  ///   Packet Identifier (20 bits)
  /// \endverbatim
  ///
  /// Length = 4 bytes.
  struct PktIdHeader
  {
    uint32_t  type_bin_id_pkt_id;
  } __attribute__((packed));

  /// The size of the CAT packet ID header in bytes.
  const size_t  kPktIdHdrSize = sizeof(struct PktIdHeader);

  /// The CAT packet history header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |Node Bin ID #0 |Node Bin ID #1 |Node Bin ID #2 |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |Node Bin ID #3 |Node Bin ID #4 |Node Bin ID #5 |Node Bin ID #6 |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |Node Bin ID #7 |Node Bin ID #8 |Node Bin ID #9 |Node Bin ID #10|
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x36)
  ///   Series of 11 Node Bin IDs:
  ///     Node Bin ID of node already visited, set to 0 if not used (1 byte)
  /// \endverbatim
  ///
  /// Length = 12 bytes
  struct PktHistoryHeader
  {
    uint8_t  type;
    uint8_t  history[11];
  } __attribute__((packed));

  /// The size of the CAT packet history header in bytes.
  const size_t  kPktHistHdrSize = sizeof(struct PktHistoryHeader);

  /// The CAT packet latency header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |   Unused    |V|       Origin Timestamp        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                          Time-To-Go                           |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x37)
  ///   Flags (1 byte) (uuuuuuuv)
  ///     u - Unused (7 bits)
  ///     v - Time-To-Go Valid (1 bit)
  ///   Origin Timestamp in Milliseconds (16 bits)
  ///   Time-To-Go in Microseconds (32 bits)
  /// \endverbatim
  ///
  /// Length = 8 bytes.
  ///
  /// \todo TODO: Remove flags and time_to_go from this header, as the TTG
  ///             information is now contained in the SLIQ data packet
  ///             headers.
  struct PktLatencyHeader
  {
    uint8_t   type;
    uint8_t   flags;
    uint16_t  origin_ts;
    uint32_t  time_to_go;
  } __attribute__((packed));

  /// The size of the CAT packet latency header in bytes.
  const size_t  kPktLatHdrSize = sizeof(struct PktLatencyHeader);

  /// \brief Abstract base class for Path Controllers.
  ///
  /// Packets that are sent by the path controller may be prioritized as it
  /// sees fit.
  ///
  /// Following are the configurable parameters for a Path Controller.  The
  /// format of the entries is PathController.x.configurable_parameter_name,
  /// where x is a number from 0 to (NumPathControllers - 1).
  ///
  /// - PathController.x.Type : The name of the Path Controller\n
  ///                           implementation class.
  class PathController
  {

  public:

    /// \brief Constructor.
    ///
    /// \param  bpf  Pointer to backpressure forwarder.
    PathController(BPFwder* bpf)
      : bpf_(bpf), remote_bin_id_(0), remote_bin_idx_(kInvalidBinIndex),
        label_(), path_controller_number_(0), endpoints_str_(), ready_(false)
    {
    }

    /// \brief Destructor.
    virtual ~PathController()
    {
      bpf_ = NULL;
    }

    /// \brief Initialize the Path Controller.
    ///
    /// \param  config_info  The configuration information.
    /// \param  config_id    The ID used to construct the parameter names to
    ///                      extract from the configuration information.  This
    ///                      becomes the path controller integer identifier
    ///                      returned by path_controller_number().
    ///
    /// \return  True if the initialization is successful, false otherwise.
    virtual bool Initialize(const ConfigInfo& config_info,
                            uint32_t config_id) = 0;

    /// \brief Configure the reporting of estimated packet delivery delay
    /// (PDD) values for low-latency (aka expedited forwarding, or EF)
    /// packets.
    ///
    /// \param  thresh      The amount of change, as a decimal, to trigger a
    ///                     PDD report.  A threshold of +/- 10% would be
    ///                     specified as 0.10.
    /// \param  min_period  The minimum time between PDD reports, in seconds.
    ///                     Reports are guaranteed not to occur with less than
    ///                     this period between them.
    /// \param  max_period  The maximum time between PDD reports, in seconds.
    ///                     Reports will occur with no more than this period
    ///                     (plus some small error) between them.
    ///
    /// \return  True if the configuration is successful, false otherwise.
    virtual bool ConfigurePddReporting(double thresh, double min_period,
                                       double max_period) = 0;

    /// \brief Send a packet.
    ///
    /// If the packet is enqueued or sent successfully, the Path Controller
    /// assumes ownership of the packet.  If the insertion fails, the caller
    /// keeps ownership of the packet.
    ///
    /// \param  pkt  Pointer to the packet to be sent.
    ///
    /// \return  True if the packet was enqueued or sent successfully, false
    ///          otherwise (i.e., if the transmit queue was at its capacity).
    virtual bool SendPacket(Packet* pkt) = 0;

    /// \brief Called when a file descriptor has an event that is of interest
    /// to the Path Controller.
    ///
    /// \param  fd     The file descriptor.
    /// \param  event  The event(s) for the file descriptor.
    virtual void ServiceFileDescriptor(int fd, FdEvent event) = 0;

    /// \brief Get the Path Controller's file descriptor information.
    ///
    /// Used for including the file descriptors in a read and/or write mask
    /// for a select() call within the main processing loop.
    ///
    /// \param  fd_event_array  A pointer to an array of fd event information
    ///                         structures.
    /// \param  array_size      The number of elements in the event
    ///                         information structure array.
    ///
    /// \return  The number of Path Controller file descriptor information
    ///          elements returned.
    virtual size_t GetFileDescriptors(FdEventInfo* fd_event_array,
                                      size_t array_size) const = 0;

    /// \brief Get the current size of the Path Controller's transmit queue in
    /// bytes.
    ///
    /// This includes all queued QLAM, control, and data packets.
    ///
    /// \param  size  A reference where the current transmit queue size, in
    ///               bytes, is placed on success.
    ///
    /// \return  True on success.
    virtual bool GetXmitQueueSize(size_t& size) const = 0;

    /// \brief Set a configurable parameter value.
    ///
    /// \param  name   The parameter name.
    /// \param  value  The parameter value.
    ///
    /// \return  True on success, false otherwise.
    virtual bool SetParameter(const char* name, const char* value)
    {
      return false;
    }

    /// \brief Get a configurable parameter value.
    ///
    /// \param  name   The parameter name.
    /// \param  value  A reference to where the parameter value will be
    ///                returned on success.
    ///
    /// \return  True on success, false otherwise.
    virtual bool GetParameter(const char* name, std::string& value) const
    {
      return false;
    }

    /// \brief  Get the per-QLAM header overhead in bytes.
    ///
    /// \return The number of bytes added to each QLAM.
    virtual uint32_t GetPerQlamOverhead() const = 0;

    /// \brief Set the bin identifier and index of the IRON Node.
    ///
    /// \param  bin_id   The bin identifier of the remote IRON Node.
    /// \param  bin_idx  The bin index of the remote IRON Node.
    inline void set_remote_bin_id_idx(BinId bin_id, BinIndex bin_idx)
    {
      remote_bin_id_  = bin_id;
      remote_bin_idx_ = bin_idx;

      if (bin_idx != kInvalidBinIndex)
      {
        ready_  = true;
      }
      else
      {
        ready_  = false;
      }
    }

    /// \brief Set the path controller label.
    ///
    /// \param  label  The path controller label.
    inline void set_label(const std::string& label)
    {
      label_ = label;
    }

    /// \brief Get the bin identifier of the remote IRON.
    ///
    /// \return  The bin identifier of the remote IRON node.
    inline BinId remote_bin_id() const
    {
      return remote_bin_id_;
    }

    /// \brief Get the bin index of the remote IRON.
    ///
    /// \return  The bin index of the remote IRON node.  Returns
    ///          kInvalidBinIndex if the bin index has not been assigned to
    ///          the path controller yet.
    inline BinIndex remote_bin_idx() const
    {
      return remote_bin_idx_;
    }

    /// \brief Get the path controller label.
    ///
    /// \return  The path controller label (empty if none).
    inline std::string label() const
    {
      return label_;
    }

    /// \brief Get the Path Controller's number, which was set at
    /// initialization time.
    ///
    /// \return  The Path Controller's number.
    inline uint32_t path_controller_number() const
    {
      return path_controller_number_;
    }

    /// \brief Get the Path Controller's endpoints string, which was set at
    /// initialization time.
    ///
    /// \return  The Path Controller's endpoints string.
    inline std::string endpoints_str() const
    {
      return endpoints_str_;
    }

    /// \brief  Verified if the path controller has been initialized yet with a
    ///         proper remote iron node address and bin index.
    ///
    /// \return True if the path controller is ready, false otherwise.
    inline bool ready()
    {
      return ready_;
    }

  protected:

    /// A pointer to the BPF that owns the Path Controller.
    BPFwder*     bpf_;

    /// The remote node's bin identifier.  This is simply stored in the Path
    /// Controller for the backpressure forwarder's convenience.
    BinId        remote_bin_id_;

    /// The remote node's bin index.  This is simply stored in the Path
    /// Controller for the backpressure forwarder's convenience.
    BinIndex     remote_bin_idx_;

    /// The label associated with this particular path controller (for
    /// instance, to differentiate between multiple path controllers to the
    /// same remote node).
    std::string  label_;

    /// The number assigned to this Path Controller during initialization.
    uint32_t     path_controller_number_;

    /// The endpoint IPv4 addresses and optional UDP port numbers.
    std::string  endpoints_str_;

    /// Whether this path controller has been initialized with remote IRON nbr
    /// and its bin index.
    bool         ready_;

    /// \brief Check if any Packet object metadata headers needs to be
    /// prepended to the packet to allow recreating the object at the far
    /// side.
    ///
    /// This includes the CAT packet ID, CAT packet latency, CAT packet
    /// history, and CAT packet destination vector headers.
    ///
    /// \param  pkt  A pointer to the Packet object.
    ///
    /// \return  True if Packet object metadata headers are needed, or false
    ///          if not.
    virtual bool NeedsMetadataHeaders(Packet* pkt);

    /// \brief Prepend any necessary Packet object metadata headers to the
    /// packet to allow recreating the object at the far side.
    ///
    /// This includes the CAT packet ID, CAT packet latency, CAT packet
    /// history, and CAT packet destination vector headers.
    ///
    /// \param  pkt  A pointer to the Packet object.
    ///
    /// \return  True on success, or false if there is not enough space to
    ///          prepend all of the necessary headers.
    virtual bool AddMetadataHeaders(Packet* pkt);

    /// \brief Process and remove any Packet object metadata headers from the
    /// packet, applying the metadata to the object.
    ///
    /// This includes the CAT packet ID, CAT packet latency, CAT packet
    /// history, and CAT packet destination vector headers.
    ///
    /// \param  pkt  A pointer to the Packet object.
    ///
    /// \return  True on success, or false if a parsing error occurs.
    virtual bool ProcessMetadataHeaders(Packet* pkt);

  private:

    /// No-arg constructor.
    PathController();

    /// Copy constructor.
    PathController(const PathController& other);

    /// Copy operator.
    PathController& operator=(const PathController& other);

  }; // end class PathController

} // namespace iron

#endif // IRON_BPF_PATH_CONTROLLER_H
