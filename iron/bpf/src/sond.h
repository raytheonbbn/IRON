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

#ifndef IRON_BPF_SOND_H
#define IRON_BPF_SOND_H

/// \file sond.h
///
/// The Simple Overlay Network Device (SOND) header file.
///

#include "packet_pool.h"
#include "path_controller.h"

#include "ipv4_endpoint.h"
#include "itime.h"
#include "packet_queue.h"
#include "timer.h"


namespace iron
{
  class BPFwder;
  class ConfigInfo;
  class Packet;
  class PacketPool;
  class Timer;

  /// \brief Simple Overlay Network Device (SOND) implementation.
  ///
  /// Backpressure forwarders in IRON nodes use SONDs to communicate with each
  /// other.  Outgoing packets are transmitted through the SONDs and incoming
  /// packets are received and sent to the backpressure forwarder.  The SOND
  /// has a network link emulator which allows control of the maximum
  /// transmission rate.
  ///
  /// IRON packets are prioritized as follows:
  ///
  /// - QLAM packets have the highest priority.
  /// - Expedited forwarding (EF) IPv4 data packets (those with LatencyClass\n
  ///     set to LOW_LATENCY) have the next highest priority.
  /// - System-level control packets (LSA and K update packets) have\n
  ///     the next highest priority.
  /// - Other IPv4 data packets and flow-level control packets (RRM packets)\n
  ///     have the lowest priority.
  ///
  /// SONDs use the following transmit queue settings:
  ///
  /// - The QLAM packet transmit queue size is set to 1 packet with a head\n
  ///     drop policy (discarding any old QLAM packet for the new one).
  /// - The EF data packet transmit queue size is automatically computed\n
  ///     from the BPF transmit queue threshold with no drop policy.
  /// - The system-level control packet transmit queue size is 100 packets\n
  ///     with no drop policy.
  /// - The other data and flow-level control packet transmit queue size is\n
  ///     automatically computed from the BPF transmit queue threshold with\n
  ///     no drop policy.
  ///
  /// Note the following details on how each SOND operates:
  ///
  /// - The SOND transmit queue size in bytes includes all transmit queues.
  /// - It is a fatal error if the data packet transmit queue ever overflows.
  /// - The current implementation emulates the proper transmission delays.
  /// - The current implementation does NOT emulate any propogation delays.
  /// - Maximum line rate changes do not affect any packet currently being
  ///     transmitted.
  ///
  /// Following are the configurable parameters for a SOND.  The format of the
  /// entries is PathController.x.configurable_parameter_name, where x is a
  /// number from 0 to (NumPathControllers - 1).  Note that NumPathControllers
  /// is a BPF configuration parameter.
  ///
  /// - Type            : The path controller type.  Must be "Sond" for\n
  ///                     creating a SOND.
  /// - Label           : The optional SOND label string.
  /// - Endpoints       : The IPv4 addresses and optional port numbers for\n
  ///                     the local and remote endpoints of the tunnel.\n
  ///                     Must use the format\n
  ///                     "LOCAL_IP[:LOCAL_PORT]->REMOTE_IP[:REMOTE_PORT]"\n
  ///                     (for example "192.168.3.4->192.168.3.5" or\n
  ///                     "1.2.3.4:5100->6.7.8.9:5100").  The port numbers\n
  ///                     default to 30200.  Required.
  /// - MaxLineRateKbps : The maximum data rate for the link between SONDs,\n
  ///                     in Kbps (kilobits per second, where 1 kbps = 1000\n
  ///                     bps).  May be an integer or a floating point\n
  ///                     number.  Default value is 2.0.
  /// - EstPddSec       : The estimated packet delivery delay (PDD) to\n
  ///                     report to the backpressure forwarder, in seconds.\n
  ///                     Disabled if set to a value less than 0.000001.\n
  ///                     Default value is 0.0 (disabled).
  class Sond : public PathController
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  bpf  Pointer to backpressure forwarder.
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  timer  Manager of all timers.
    Sond(BPFwder* bpf, PacketPool& packet_pool, Timer& timer);

    /// \brief Destructor.
    virtual ~Sond();

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
                            uint32_t config_id);

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
                                       double max_period);

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
    virtual bool SendPacket(Packet* pkt);

    /// \brief Called when a file descriptor has an event that is of interest
    /// to the Path Controller.
    ///
    /// \param  fd     The file descriptor.
    /// \param  event  The event(s) for the file descriptor.
    virtual void ServiceFileDescriptor(int fd, iron::FdEvent event);

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
                                      size_t array_size) const;

    /// \brief Get the current size of the Path Controller's transmit queue in
    /// bytes.
    ///
    /// This includes all queued QLAM, control, and data packets.
    ///
    /// \param  size  A reference where the current transmit queue size, in
    ///               bytes, is placed on success.
    ///
    /// \return  True on success.
    virtual bool GetXmitQueueSize(size_t& size) const;

    /// \brief Set a configurable parameter value.
    ///
    /// \param  name   The parameter name.
    /// \param  value  The parameter value.
    ///
    /// \return  True on success, false otherwise.
    virtual bool SetParameter(const char* name, const char* value);

    /// \brief Get a configurable parameter value.
    ///
    /// \param  name   The parameter name.
    /// \param  value  A reference to where the parameter value will be
    ///                returned on success.
    ///
    /// \return  True on success, false otherwise.
    virtual bool GetParameter(const char* name, std::string& value) const;

    /// \brief  Get the per-QLAM header overhead in bytes.
    ///
    /// 26 - Ethernet Framing (8 start of frame, 14 header, 4 CRC trailer)
    /// 20 - IPv4 Header (no options)
    ///  8 - UDP Header
    ///
    /// \return The number of bytes added to each QLAM.
    virtual uint32_t GetPerQlamOverhead() const
    {
      return 54;
    };

   private:

    /// \brief Copy constructor.
    Sond(const Sond& cat);

    /// \brief Assignment operator.
    Sond& operator=(const Sond& cat);

    /// \brief Parse the endpoints string.
    ///
    /// \param  ep_str  A reference to the string to be parsed.
    ///
    /// \return  True if the string is parsed successfully, or false
    ///          otherwise.
    bool ParseEndpointsString(const std::string& ep_str);

    /// \brief Check if there is a packet ready to transmit.
    ///
    /// \return  True if there is at least one packet ready for transmission,
    ///          or false if there are no packets ready for transmission.
    inline bool IsPacketReadyToXmit() const
    {
      return((qlam_pkt_ptr_ != NULL) ||
             (ef_data_pkt_queue_.GetCount() > 0) ||
             (control_pkt_queue_.GetCount() > 0) ||
             (data_pkt_queue_.GetCount() > 0));
    }

    /// \brief Update the maximum line rate.
    ///
    /// \param  value  The new maximum line rate in Kbps as a string.
    ///
    /// \return  True if the maximum line rate is updated successfully, or
    ///          false otherwise.
    bool SetMaxLineRate(const char* value);

    /// \ brief Do any necessary callback.
    void DoCallbacks();

    /// \brief Schedule the next packet to be sent.
    ///
    /// This method will send as many packets that are ready for transmitting
    /// as possible until either the queue is empty or a timer needs to be
    /// set.
    ///
    /// \param  now  The current time.
    void ScheduleNextPacket(const Time& now);

    /// \brief The SOND timer callback.
    ///
    /// Transmit the packet that is waiting on its transmission delay to
    /// pass.
    void TimerCallback();

    /// \brief Send the packet that is currently being transmitted.
    ///
    /// This only occurs after the packet's transmission delay period has
    /// passed.
    void XmitPacket();

    /// Pool containing packets to use.
    iron::PacketPool&    packet_pool_;

    // Manager of all timers.
    iron::Timer&         timer_;

    /// The maximum line rate in kbps.
    double               max_line_rate_;

    /// The local IPv4 address and UDP port number.
    iron::Ipv4Endpoint   local_endpt_;

    /// The remote IPv4 address and UDP port number.
    iron::Ipv4Endpoint   remote_endpt_;

    /// The file descriptor for the UDP socket.
    int                  udp_fd_;

    /// A small queue of data packets received from the BPF to be sent across
    /// the link.  Data packets are sent in order from this packet queue.
    PacketQueue          ef_data_pkt_queue_;

    /// A small queue of control packets received from the BPF to be sent
    /// across the link. Control packets are sent in order from this packet
    /// queue.
    PacketQueue          control_pkt_queue_;

    /// A small queue of data packets received from the BPF to be sent across
    /// the link.  Data packets are sent in order from this packet queue.
    PacketQueue          data_pkt_queue_;

    /// A pointer to a QLAM packet to be sent.  Only the most recent QLAM
    /// packet received from the BPF is queued up for sending.
    Packet*              qlam_pkt_ptr_;

    /// A pointer to the packet currently being transmitted.  Set to NULL when
    /// the link is idle.
    Packet*              xmit_pkt_ptr_;

    /// The start time for sending packets after an idle period.  This is an
    /// absolute time value.  Used with xmit_delta_time_ to maintain as much
    /// packet transmission timing precision as possible.
    Time                 xmit_start_time_;

    /// The time, in seconds, for the next packet transmission as an offset
    /// from xmit_start_time_.  Used to maintain as much packet transmission
    /// timing precision as possible.
    double               xmit_delta_time_;

    /// Packet transmission timer handle.
    iron::Timer::Handle  xmit_timer_handle_;

    /// The number of bytes in all of the packet queues.
    size_t               total_bytes_queued_;

    /// Internal counter of the total number of bytes sent through the UDP
    /// socket.  Not currently used.  For future use.
    uint32_t             total_bytes_sent_;

    /// The PDD callback maximum time between updates, in seconds.
    double               cb_max_period_;

    /// The PDD value to be reported, in seconds.
    double               cb_pdd_;

    /// The PDD callback previous report time.
    iron::Time           cb_prev_time_;

  }; // end class Sond

} // namespace iron

#endif // IRON_BPF_SOND_H
