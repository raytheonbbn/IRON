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

#ifndef IRON_UDP_PROXY_H
#define IRON_UDP_PROXY_H

#include "bin_indexable_array_nc.h"
#include "bin_map.h"
#include "config_info.h"
#include "debugging_stats.h"
#include "decoding_state.h"
#include "encoding_state.h"
#include "fec_state.h"
#include "fec_context.h"
#include "fec_state_pool.h"
#include "fifo.h"
#include "four_tuple.h"
#include "hash_table.h"
#include "ipv4_address.h"
#include "iron_constants.h"
#include "itime.h"
#include "k_val.h"
#include "latency_cache_shm.h"
#include "list.h"
#include "mash_table.h"
#include "packet.h"
#include "packet_fifo.h"
#include "packet_pool.h"
#include "queue.h"
#include "queue_depths.h"
#include "remote_control.h"
#include "shared_memory_if.h"
#include "timer.h"
#include "thread.h"
#include "virtual_edge_if.h"

#include <bitset>
#include <map>
#include <set>
#include <string>

#include <pthread.h>

/// Enum type definitions for FEC moidyfing or deleting FEC contexts
enum FECActionType
{
  FECModAction,
  FECDelAction
};

/// The size of the circular bitset used to track reception of the
/// most recent packet.
const size_t  kDefaultHistorySizePkts = 64;

/// The default alpha used to average the loss rate of a flow.
const double  kDefaultLossRateAlpha = 0.2;

/// The maximum packet interarrival time. If the interarrival time
/// is more than this, we assume the flow was triaged and turned
/// back on.
const double  kMaxInterarrivalTime = 3.0;

/// Debugging support function
void DumpFECTrailers(iron::Packet* qpkt);

/// This application performs packet encapsulation and deencapsulation.
class UdpProxy
{
  public:

  /// \brief Constructor.
  ///
  /// \param  packet_pool              Pool containing packet to use.
  /// \param  edge_if                  Edge interface for the TCP Proxy's
  ///                                  LAN side.
  /// \param  fecstate_pool            Pool containing fec states to use.
  /// \param  timer                    Manager of all timers.
  /// \param  weight_qd_shared_memory  Memory to share weight queue depths
  ///                                  with proxies.
  /// \param  bpf_to_udp_pkt_fifo      Unopened-fifo for receiving packets from
  ///                                  BPF.
  /// \param  udp_to_bpf_pkt_fifo      Unopened-fifo for sending packets to
  ///                                  BPF.
  UdpProxy(iron::PacketPool& packet_pool,
           iron::VirtualEdgeIf& edge_if,
           iron::BinMap& bin_map,
           FecStatePool& fecstate_pool, iron::Timer& timer,
           iron::SharedMemoryIF& weight_qd_shared_memory,
           iron::FifoIF* bpf_to_udp_pkt_fifo,
           iron::FifoIF* udp_to_bpf_pkt_fifo);

  /// \brief Destructor.
  virtual ~UdpProxy();

  /// \brief Configure the UDP Proxy.
  ///
  /// \param  ci      A reference to the configuration information.
  /// \param  prefix  The property prefix.
  ///
  /// \return True if successful, false otherwise.
  virtual bool Configure(iron::ConfigInfo& ci, const char* prefix);

  /// \brief Open the appropriate sockets for receiving and reinjecting
  ///  packets.
  ///
  /// \return True if successful, false otherwise.
  virtual bool InitSockets();

  /// \brief Attach the shared memory for queue weights.
  ///
  /// Note: The shared memory model imposes a burden on tracking certain
  /// packets handed off to the BPF.  The FEC code may build repair packets
  /// from original packets that may already be in possession of the BPF.
  /// Therefore, before each packet is placed in the admission queue, the ref
  /// count is incremented via ShallowCopy (it can never be more than 2).
  /// Ownership of the packet goes from the admission queue to the BPF.  The
  /// ref count is only decremented (Recycle) if transmission to the BPF
  /// fails.  Once the version of the UDP Proxy is no longer needed and
  /// flushed, the ref count is also decremented.  If 0, the packet is
  /// effectively recycled.
  ///
  /// \param  ci  Reference to the configuration information.
  ///
  /// \return True if successful, false otherwise.
  bool AttachSharedMemory(const iron::ConfigInfo& ci);

  /// \brief Start the UDP Proxy.
  ///
  /// The UDP Proxy runs until a Ctrl-c signal is caught.
  void Start();

  /// \brief Shutdown the UDP Proxy.
  virtual void Stop();

  /// \brief  Method to send the admitted packet to the BPF.
  ///
  /// Note: This method assumes ownership of the packet if the transmission to
  /// the BPF is successful. Otherwise the caller retains packet ownership.
  ///
  /// \param  pkt  A pointer to the packet to send to the BPF.
  ///
  /// \return True if the packet transmission is successful, false
  ///         otherwise. For successful transmissions, this class assumes
  ///         ownership of the packet. For unsuccessful transmissions, the
  ///         caller retains ownership of the packet.
  bool SendToBpf(iron::Packet* pkt);

  /// \brief Send a Packet to the LAN side interface.
  ///
  /// Note: This method assumes ownership of the packet if the transmission to
  /// the LAN is successful. Otherwise the caller retains packet ownership.
  ///
  /// \param  pkt  Pointer to the Packet to be written to the LAN side
  ///              interface.
  ///
  /// \return The number of bytes written to the LAN side interface. If 0
  ///         bytes are written to the LAN side interface, the caller retains
  ///         ownership of the packet. Otherwise, this class assumes ownership
  ///         of the packet.
  ssize_t SendToLan(iron::Packet* pkt) const;

  /// \brief The service flows timeout callback.
  void SvcFlowsTimeout();

  /// \brief Get the scheduled service flows timeout time.
  ///
  /// \return The scheduled service flows timeout time.
  inline const iron::Time& sched_service_time() const
  {
    return next_sched_svc_flows_time_;
  }

  /// \brief Query if latency checking is active.
  ///
  /// \return True if latency checking is active, false otherwise.
  inline bool do_latency_checks() const
  {
    return do_latency_checks_;
  }

  /// \brief Get the minimum latency for a bin index.
  ///
  /// \param  bin_idx  The bin index of interest.
  ///
  /// \return The minimum latency for the bin index.
  inline uint32_t GetMinLatency(iron::BinIndex bin_idx)
  {
    return shm_latency_cache_.GetMinLatency(bin_idx);
  }

  struct ReleaseRecord
  {
    /// The four tuple associated with this flow's stats.
    iron::FourTuple                       four_tuple_;

    /// The highest number of bytes sent during the record keeping.
    uint64_t                              highest_num_bytes_;

    /// The highest number of packets sent during the record keeping.
    uint32_t                              highest_num_packets_;

    /// The number of bytes correctly released to the application.
    uint32_t                              num_released_bytes_;

    /// The number of packets correctly released to the application.
    uint32_t                              num_released_packets_;

    /// A circular bit array to track the last kDefaultHistorySizePkts
    /// packets.
    std::bitset<kDefaultHistorySizePkts>  circ_release_hist_;

    /// The time the last packet was released for this flow.
    iron::Time                            last_release_time_;

    /// The time the last RRM was sent.
    iron::Time                            last_rrm_sent_;

    /// EWM Average loss rate, in bytes.
    double                                avg_byte_loss_rate_;

    /// The weight used in the averaging of the loss rate.
    double                                alpha_;

    /// Default constructor.
    ReleaseRecord()
      : four_tuple_(),
        highest_num_bytes_(0),
        highest_num_packets_(0),
        num_released_bytes_(0),
        num_released_packets_(0),
        circ_release_hist_(),
        last_release_time_(iron::Time(0)),
        last_rrm_sent_(iron::Time(0)),
        avg_byte_loss_rate_(0),
        alpha_(kDefaultLossRateAlpha)
      { }

    /// \brief Constructor.
    //
    // \todo When utility function was removed from the decoding states, the
    //       priority was removed from this constructor. Figure out what the
    //       correct thing to do here is. alpha_ used to be initialized as
    //       kDefaultLossRateAlpha/priority.
    ReleaseRecord(iron::FourTuple& four_tuple, uint32_t highest_num_bytes,
                  uint32_t highest_num_packets, uint8_t priority)
      : four_tuple_(four_tuple),
        highest_num_bytes_(highest_num_bytes),
        highest_num_packets_(highest_num_packets),
        num_released_bytes_(0),
        num_released_packets_(0),
        circ_release_hist_(),
        last_release_time_(iron::Time(0)),
        last_rrm_sent_(iron::Time(0)),
        avg_byte_loss_rate_(0),
        alpha_(kDefaultLossRateAlpha/priority)
      { }

    /// \brief Method to call before we delete a FecState, to account for the
    /// packets received and infer the missed packets.
    ///
    /// \param  fec_state  The FEC State.
    ///
    /// \return The current loss rate for this flow.
    double ReleaseFecState(FecState& fec_state);

    /// \brief Get the highest number of bytes seen, number of bytes released.
    ///
    /// \param  highest_num_bytes   Reference to store the highest number
    ///                             bytes seen at the receiver.
    /// \param  num_released_bytes  Reference to store the number of bytes
    ///                             released by the receiver.
    void GetBytes(uint64_t& highest_num_bytes, uint64_t& num_released_bytes)
    {
      highest_num_bytes  = highest_num_bytes_;
      num_released_bytes = num_released_bytes_;
    }

    /// \brief Get the highest number of packets seen and number of packets
    /// released.
    ///
    /// \param  highest_num_packets   Reference to store the highest sequence
    ///                               number seen by the receiver.
    /// \param  num_released_packets  Reference to store the number of packets
    ///                               released by the receiver.
    void GetPackets(uint32_t& highest_num_packets,
                    uint32_t& num_released_packets)
    {
      highest_num_packets = highest_num_packets_;
      num_released_packets= num_released_packets_;
    }

    /// Assignment operator.
    ReleaseRecord& operator=(const ReleaseRecord& other)
    {
      highest_num_bytes_    = other.highest_num_bytes_;
      highest_num_packets_  = other.highest_num_packets_;
      num_released_bytes_   = other.num_released_bytes_;
      num_released_packets_ = other.num_released_packets_;

      return *this;
    }

    /// Update the averaging window if there is a change in priority.
    void HandlePriorityChange(uint8_t priority)
    {
      alpha_ = kDefaultLossRateAlpha/priority;
    }
  }; // end struct ReleaseRecord

  /// \brief Add a ReleaseRecord to the collection of Release Records.
  ///
  /// \param  bin_idx           The bin index associated with the new
  ///                           ReleaseRecord.
  /// \param  four_tuple        The 4-tuple associated with the new
  ///                           ReleaseRecord.
  /// \param  total_bytes_sent  The ReleaseRecord initial total bytes sent.
  /// \param  seq_num           The ReleaseRecord initial sequence number.
  /// \param  priority          The priority of the flow, used to set
  ///                           the averaging window for the loss rate.
  ///
  /// \return True if the new release record is successfully added, false
  ///         otherwise.
  bool CreateReleaseRecord(iron::BinIndex bin_idx, iron::FourTuple& four_tuple,
                           uint64_t total_bytes_sent, uint32_t seq_num,
                           uint8_t priority);

  /// \brief Get a ReleaseRecord.
  ///
  /// \param  bin_idx         The bin index to use for the lookup.
  /// \param  four_tuple      The 4-tuple to use for the search.
  /// \param  release_record  Pointer to the found ReleaseRecord. NULL is
  ///                         returned if there is no ReleaseRecord matching
  ///                         the search criteria. Note: the UDP Proxy object
  ///                         retains ownership of the retrieved
  ///                         ReleaseRecord. The calling object MUST NOT
  ///                         delete it.
  ///
  /// \return True if a ReleaseRecord is found matching the search criteria,
  ///         false otherwise.
  bool GetReleaseRecord(iron::BinIndex bin_idx,
                        const iron::FourTuple& four_tuple,
                        ReleaseRecord*& release_record);

  /// \brief Generate and send the Receiver Report Messages.
  ///
  /// \param  now  The current time.
  void SendRRMs(iron::Time& now);

  /// \brief Return access to k (which is always maintained here).
  ///
  /// \return Reference to the K value.
  inline iron::KVal& k_val()
  {
    return k_val_;
  }

  /// \brief Query if the UDP Proxy is logging statistics.
  ///
  /// \return True if the UDP Proxy is logging statistics, false otherwise.
  inline bool log_stats() const
  {
    return log_stats_;
  }

  /// \brief Get the mgen diagnostic mode.
  ///
  /// \return A reference to the string with the diagnostic mode.
  inline const std::string& mgen_diag_mode() const
  {
    return mgen_diag_mode_;
  }

  /// \brief Increment the count of the total number of packets sent.
  inline void IncrementTotalPktsSent()
  {
    ++total_pkts_sent_;
  }

  /// \brief Increment the count of the total number of packets dropped due to
  /// full backlog.
  inline void IncrementTotalSrcDrop()
  {
    ++total_src_drop_;
  }

  /// Edge interface for the UDP Proxy's LAN side.
  iron::VirtualEdgeIf&  edge_if_;

  /// \brief Check is loss triage is enabled.
  inline bool enable_loss_triage()
  {
    return enable_loss_triage_;
  }

  protected:

  // Everything from this point to the end of the file is protected. This will
  // enable us to unit test the remaining methods by extending the
  // UdpProxy class.

  /// \brief Constructor for modifying queue depths direct access.
  ///
  /// Intended for use by unit tests.
  ///
  /// \param  packet_pool              Pool containing packets to use.
  /// \param  edge_if                  Edge interface for the TCP Proxy's
  ///                                  LAN side.
  /// \param  bin_map                  Mapping of IRON bins.
  /// \param  fecstate_pool            Pool containing fec states to use.
  /// \param  timer                    Manager of all timers.
  /// \param  weight_qd_shared_memory  Memory to share weight queue depths
  ///                                  with proxies.
  /// \param  bpf_to_udp_pkt_fifo      Unopened-fifo for receiving packets
  ///                                  from BPF. This instance takes ownership
  ///                                  of the memory.
  /// \param  udp_to_bpf_pkt_fifo      Unopened-fifo for sending packets to
  ///                                  BPF. This instance takes ownership of
  ///                                  the memory.
  /// \param  qd_direct_access         True for direct access.
  UdpProxy(iron::PacketPool& packet_pool,
           iron::VirtualEdgeIf& edge_if,
           iron::BinMap& bin_map,
           FecStatePool& fecstate_pool, iron::Timer& timer,
           iron::SharedMemoryIF& weight_qd_shared_memory,
           iron::FifoIF* bpf_to_udp_pkt_fifo,
           iron::FifoIF* udp_to_bpf_pkt_fifo,
           bool qd_direct_access);

  /// \brief Wrapper for system select()
  ///
  /// Allows test cases to operate when not using system resources to back
  /// data sources. The contract matches select(), with unused arguments
  /// removed.
  ///
  /// \param nfds Highest-numbered file descriptor in the read set, plus 1
  /// \param readfs  Set of file descriptors that will be watched to see if
  ///                characters become available for reading.
  /// \param timeout Interval that the call should block waiting for a file
  ///                descriptor to become ready.
  ///
  /// \return Number of file descriptors that are ready to read. May be
  ///         zero if the timeout expired. On error, -1 is returned, and errno
  ///         will be set to indicate the error.
  virtual int Select(int nfds, fd_set* readfs, struct timeval* timeout);

  /// \brief Get a Service context.
  ///
  /// \param  four_tuple  The FourTuple for the flow.
  /// \param  context     The found Service context.
  ///
  /// \return True if a Service context is found, false otherwise.
  bool GetContext(const iron::FourTuple& four_tuple, FECContext& context);

  /// \brief Parse a UDP service context.
  ///
  /// \param  command       The service command.
  /// \param  action        The action to take for the service command.
  /// \param  is_flow_defn  A flag to indicate this is a flow definition
  ///                       and not a service definition (i.e. it is for a
  ///                       specific four tuple, and not for a range or
  ///                       ports).
  ///
  /// \return The FECContext for the service command.
  FECContext* ParseService(char* command, FECActionType action,
                           bool is_flow_defn = false);

  /// \brief Add or modify a given service.
  ///
  /// \param  context  Pointer to the encoding context.
  ///
  /// \return True if successful, false otherwise.
  bool ModService(FECContext* context);

  /// \brief Delete a service.
  ///
  /// \param  context  A pointer to the context.
  ///
  /// \return True if successful, false otherwise.
  bool DelService(FECContext* context);

  /// \brief  Set flow definition into the collection of enabled flow
  ///         definitions.
  ///
  /// \param  four_tuple  The 4-tuple representing the flow.
  /// \param  flow_defn   The flow function definition as a FECContext.
  void SetFlowDefn(const iron::FourTuple& four_tuple, FECContext* flow_defn);

  /// \brief Inquire if there is a Flow Utility function definition that
  /// matches the provided 4-tuple.
  ///
  /// Flow Utility function definitions take precedence over Service Utility
  /// function definitions.
  ///
  /// \param  four_tuple  The 4-tuple to use for the lookup.
  ///
  /// \return True if the Flow definition cache has a Utility function
  ///         definition entry for the provided 4-tuple, false otherwise.
  inline bool HasFlowDefn(const iron::FourTuple& four_tuple)
  {
    return (flow_defn_cache_.Count(four_tuple) > 0);
  }

  /// \brief Delete flow definition from the collection of enabled
  /// flow definitions.
  ///
  /// \param  four_tuple  The target 4-tuple that is used for the deletion.
  void DelFlowDefn(const iron::FourTuple& four_tuple);

  /// \brief Get flow definition from the collection of enabled
  /// flow definitions.
  ///
  /// \param  four_tuple  The target 4-tuple that is used for the search.
  /// \param  flow_defn   The found flow definition for the provided 4-tuple.
  ///
  /// \return True if successful, false otherwise.
  inline bool GetFlowDefn(const iron::FourTuple& four_tuple,
                          FECContext*& flow_defn)
  {
    return flow_defn_cache_.Find(four_tuple, flow_defn);
  }

  /// \brief Receive packets from the BPF.
  void ReceivePktsFromBpf();

  /// \brief Process a packet that is received from the BPF.
  ///
  /// \param  pkt  The received packet.
  void ProcessPktFromBpf(iron::Packet* pkt);

  /// \brief Process a data packet received from a local application.
  ///
  /// \param  pkt  The received data packet.
  void RunEncoder(iron::Packet* pkt);

  /// \brief Get an Encoding State.
  ///
  /// If an Encoding State does not exist for the target 4-tuple, one is
  /// created and added to the collection of encoding states.
  ///
  /// \param  bin_idx     The bin idx associated with the packet.
  /// \param  four_tuple  The target 4-tuple that is used for the search.
  /// \param  state       The Encoding State.
  ///
  /// \return True if successful, false otherwise.
  bool GetEncodingState(const iron::BinIndex bin_idx,
                        const iron::FourTuple& four_tuple,
                        EncodingState*& state);

  /// \brief Get an existing Encoding State.
  ///
  /// \param  four_tuple  The target 4-tuple that is used for the search.
  /// \param  state       The Encoding State.
  ///
  /// \return True if an Encoding State exists for the 4-tuple, false
  ///         otherwise.
  inline bool GetExistingEncodingState(const iron::FourTuple& four_tuple,
                                       EncodingState*& state)
  {
    return encoding.Find(four_tuple, state);
  }

  /// \brief Reset the utility function and encoding paramters of an encoding
  /// state.
  ///
  /// \param  es  Pointer to the encoding state that should reset.
  ///
  /// \return True if the state was properly reset, false otherwise.
  bool ResetEncodingState(EncodingState* es);

  /// \brief Process a data packet, received from the BPF, whose destination
  /// is a local application.
  ///
  /// \param  pkt  The received data packet.
  void RunDecoder(iron::Packet* pkt);

  /// \brief Get a Decoding State.
  ///
  /// If a Decoding State does not exist for the target 4-tuple, one is
  /// created and added to the collection of decoding states.
  ///
  /// \param  four_tuple  The target 4-tuple that is used for the search.
  /// \param  state       The Decoding State.
  ///
  /// \return True if successful (state contains the Decoding State),
  /// false otherwise (state is NULL).
  bool GetDecodingState(const iron::FourTuple& four_tuple,
                        DecodingState*& state);

  /// \brief Get an existing Decoding State.
  ///
  /// \param  four_tuple  The target 4-tuple that is used for the search.
  /// \param  state       The Decoding State.
  ///
  /// \return True if an Decoding State exists for the 4-tuple, false
  ///         otherwise.
  inline bool GetExistingDecodingState(const iron::FourTuple& four_tuple,
                                       DecodingState*& state)
  {
    return decoding.Find(four_tuple, state);
  }

  /// \brief Reset the release controller and reordering time of a decoding
  /// state.
  ///
  /// \param  ds  Pointer to the decoding state that should reset.
  ///
  /// \return True if the decoding state is properly reset, false otherwise.
  bool ResetDecodingState(DecodingState* ds);

  /// \brief Send the given packet of the virtual interface.
  ///
  /// This function exists so that it can be overwritten to avoid sending from
  /// unit tests.
  ///
  /// \param pkt The packet to send.
  ///
  /// \return see VirtualIF::Send
  inline virtual size_t EdgeIfSend(const iron::Packet* pkt) const
  {
    return edge_if_.Send(pkt);
  }

  /// \brief Turn a flow off.
  ///
  /// No further packets will be admitted and the restart timer will not be
  /// set. This can be invoked by the supervisory control only.
  ///
  /// \param four_tuple  The target 4-tuple which identifies the flow.
  void TurnFlowOff(const iron::FourTuple& four_tuple);

  /// Information for pushing statistics to a client periodically.
  struct StatsPushInfo
  {
    StatsPushInfo()
        : is_active(false),
          client_id(0),
          msg_id(0),
          interval_sec(0.0),
          next_push_time(iron::Time::Infinite())
    { }

    bool        is_active;
    uint32_t    client_id;
    uint32_t    msg_id;
    double      interval_sec;
    iron::Time  next_push_time;

  }; // end struct StatsPushInfo

  /// \brief Process a RRM from a peer proxy.
  ///
  /// \param pkt A pointer to the RRM packet.
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     type      |               Source Bin Id
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///    Src Bin Id   |             Destination Bin Id
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///    Dst Bin Id   |  Num Tuples   |         Source Address
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///         Source Address          |       Destination Address
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///     Destination Address         |           Source Port         |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Destination Port          |         Total Bytes Sourced
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///       Total Bytes Sourced                  Total Bytes Sourced
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///       Total Bytes Sourced       |         Num Pkts Sourced
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///       Num Pkts Sourced          |         Total Bytes Released
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///      Total Bytes Released                 Total Bytes Released
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///      Total Bytes Released       |       Num Packets Released
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///       Num Packets Released      |Average Loss Rate| Source Addr
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///       Source Address......                        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// \endverbatim

  void ProcessRRM(iron::Packet* pkt);

  /// \brief Process a received remote control message.
  void ProcessRemoteControlMessage();

  /// \brief Process a received remote control SET message.
  ///
  /// Currently, the remote control messages that are supported are:
  ///
  /// - Service add
  /// - Flow add
  /// - Flow del
  ///
  /// messages that are received from the Admission Planner.
  void ProcessSetMessage();

  /// \brief Process a received Service Definition update message.
  ///
  /// \param  key       The json message key.
  /// \param  val_obj   The json message value object.
  /// \param  err_msg   The reference where the error string is to be
  ///                   written. An empty string indicates that no error
  ///                   occurred.
  ///
  /// \return True if the message is successfully processed, false otherwise.
  bool ProcessServiceDefnUpdateMsg(const std::string& key,
                                   const rapidjson::Value& val_obj,
                                   std::string& err_msg);

  /// \brief Process a received Flow Definition update message.
  ///
  /// \param  key       The json message key.
  /// \param  key_obj   The json message value object.
  /// \param  err_msg   The reference where the error string is to be
  ///                   written. An empty string indicates that no error
  ///                   occurred.
  ///
  /// \return True if the message is successfully processed, false otherwise.
  bool ProcessFlowDefnUpdateMsg(const std::string& key,
                                const rapidjson::Value& key_obj,
                                std::string& err_msg);

  /// \brief Process a received Source-based multicast destination list
  ///        message.
  ///
  /// \param  key       The json message key.
  /// \param  val_obj   The json message value object.
  /// \param  err_msg   The reference where the error string is to be
  ///                   written. An empty string indicates that no error
  ///                   occurred.
  ///
  /// \return True if the message is successfully processed, false otherwise.
  bool ProcessMcastDstListMsg(const std::string& key,
                              const rapidjson::Value& val_obj,
                              std::string& err_msg);

  /// \brief Process a received remote control GET message.
  void ProcessGetMessage();

  /// \brief Process a received remote control PUSHREQ message.
  void ProcessPushReqMessage();

  /// \brief Process a received remote control PUSHSTOP message.
  void ProcessPushStopMessage();

  /// \brief  Write stats to log and push to AMP if there is a connection.
  ///
  /// \param  is_periodic If this is true, then the timer should be set to
  ///         send another push message after the required interval.
  void PushStats(bool is_periodic);

  /// \brief  The method that dumps stats into the log file / JSON writer.
  ///
  /// \param  is_periodic  A flag to disambiguate a periodic stats push from
  ///                      an event-driven stats push.
  /// \param  writer       The JSON writer that is used to create the JSON
  ///                      message.
  void WriteStats(bool is_periodic = true,
    rapidjson::Writer<rapidjson::StringBuffer>* writer = NULL);

  /// \brief Get the utility function definition associated with a context.
  ///
  /// If the context does not have a utility function definition the default
  /// utility function definition will be used.
  ///
  /// \param  context  The context from which to get the utility function
  ///                  defintion.
  /// \param  utility_def  The utility function definition.
  ///
  /// \return True if the utility function definition is found, false
  ///         otherwise.
  bool GetUtilityFn(const FECContext& context, std::string& utility_def);

  /// \brief Updates FEC groups and sends out FEC packets.
  ///
  /// \param  now  The current time.
  void StragglerCleanupTimeout(iron::Time& now);

  /// \brief Garbage collect encoding and decoding states that are no longer
  /// active.
  ///
  /// \param  now  The current time.
  void GarbageCollectionTimeout(iron::Time& now);

  /// \brief Get the next tag to be used by a newly created encoding state.
  ///
  /// \return Integer to be used as the timer tag in the state's admission
  ///         control and to uniquely identify flows.
  uint32_t flow_tag();

  /// \brief Parse the NORM address range string.
  ///
  /// The NORM address range string is the range of multicast addresses that
  /// are used for NORM application multicast flows.
  ///
  /// \param  nar_str  The NORM address range string to be parsed.
  ///
  /// \return True if the NORM address range string is successfully parsed,
  ///         false otherwise.
  bool ParseNormAddrRangeString(const std::string& nar_str);

  /// Boolean flag that remembers if we are running or not.
  bool                        running_;

  /// Shared memory for the weights queue depths.
  iron::SharedMemoryIF&       weight_qd_shared_memory_;

  /// QueueDepths object to store weights.
  iron::QueueDepths           local_queue_depths_;

  // Mapping of IRON bins, stored in shared memory
  iron::BinMap&               bin_map_shm_;

  // Manager of all timers.
  iron::Timer&                timer_;

  /// How often do we check to see if we need to clean up old state
  unsigned long               gc_interval_sec_;

  /// Specify the decoder timeout for GC
  time_t                      decoder_timeout_sec_;

  /// Service context information stored as an std::map.
  std::map<int, FECContext*>  config;

  /// Default service definition
  FECContext*                 default_service_;

  /// Per-flow encoding state information stored in a mash table.
  iron::MashTable<iron::FourTuple, EncodingState*> encoding;

  /// Per-flow decoding state information stored in a mash table.
  iron::MashTable<iron::FourTuple, DecodingState*> decoding;

  /// The flow definition cache. This stores the service definition of a
  /// specific flow, defined by a 4-tuple (src_addr, dst_addr, src_port,
  /// dst_port). The entries in this collection take precedence over the
  /// definitions that are part ofthe Service contexts.
  iron::HashTable<iron::FourTuple, FECContext*> flow_defn_cache_;

  /// FIFO object for BPF to UDP Proxy packet passing.
  iron::PacketFifo            bpf_to_udp_pkt_fifo_;

  /// FIFO object for UDP Proxy to BPF packet passing.
  iron::PacketFifo            udp_to_bpf_pkt_fifo_;

  /// Pool containing packets to use.
  ::iron::PacketPool&         packet_pool_;

  /// Pool containing fec states to use.
  FecStatePool&               fecstate_pool_;

  /// The default Utility Function Definition.
  std::string                 default_utility_def_;

  /// Map of the bin indexes to encoding states. Each encoding state has a
  /// unique timer tag that has to be updated.
  std::map<iron::BinIndex, std::set<EncodingState*> > bin_states_map_;

  /// Backpressure queue normalization parameter (bits^2/sec).
  iron::KVal                  k_val_;

  /// The size of the encoded_packets_queue, in packets.
  uint32_t                    max_queue_depth_pkts_;

  /// The drop policy of the encoded packets queue.
  ::iron::DropPolicy          drop_policy_;

  /// Minimum burst window, in micro seconds, for admitting packets to the
  /// BPF.
  uint32_t                    bpf_min_burst_usec_;

  /// Current timer tag counter for encoding states.
  uint32_t                    flow_tag_;

  /// Indication to re-write sequence number and timestamp in MGEN packets.
  /// none: No overwrite.
  /// ow-time: Overwrite with Time timestamp.
  /// ow-wallclock: Overwrite with wall clock timestamp.
  std::string                 mgen_diag_mode_;

  /// TCP port number for remote control connection in host byte order.
  unsigned short              remote_control_port_;

  /// The object providing remote control capabilities.
  iron::RemoteControlServer   remote_control_;

  /// True if we want to access queue depth information directly from shared
  /// memory, rather than periodically copying to local memory and accessing
  /// from there.
  bool                        qd_direct_access_;

  /// The queue depth update in microseconds.
  uint32_t                    qd_update_interval_us_;

  /// Information on any active statistics pushing to a remote control
  /// client. Can only push to a single client at a time due to statistics
  /// resetting on each push.
  StatsPushInfo               stats_push_;

  /// The statistics collection interval, in milliseconds.
  uint32_t                    stats_interval_ms_;

  /// Indicate wether to log stats to a file.
  bool                        log_stats_;

  /// The total utility (for outbound flows) since proxy start.
  uint64_t                    total_utility_;

  /// The service flows timer handle.
  iron::Timer::Handle         svc_flows_timer_handle_;

  /// The next scheduled service flows event time.
  iron::Time                  next_sched_svc_flows_time_;

  /// The Receiver Report Message transmission event time.
  iron::Time                  rrm_transmission_time_;

  /// The straggler cleanup event time.
  iron::Time                  straggler_cleanup_time_;

  /// The garbage collection event time.
  iron::Time                  garbage_collection_time_;

  /// The maximum time to hold a packet while reodering.
  /// If the packet expiration time is lower, that takes preceidence.
  ::iron::Time                reorder_max_hold_time_;

  /// The collection of packets released to the application, indexed by source
  /// bin index.
  ::iron::BinIndexableArrayNc<
    iron::MashTable<iron::FourTuple, ReleaseRecord*> >  release_records_;

  /// The earliest expiration time of a packet in the reordering buffers
  /// of all the decoding states.
  ::iron::Time                next_decode_exp_time_;

  /// True if configured to perform time-to-go tracking Sliq info headers.
  bool                        do_ttg_tracking_;

  /// A list of flows that have been garbage collected and not yet reported
  /// to AMP.
  iron::List<iron::FourTuple> garbage_collected_flows_;

  /// The boolean indicating whether we are using LSA-based latency collection.
  bool                        ls_latency_collection_;

  /// A count of the total number of packets sent on time.
  uint32_t                    total_pkts_sent_;

  /// A count of the total number of packet dropped due to full backlog.
  uint32_t                    total_src_drop_;

  /// The shared memory minimum latency (in us) cache per destination.
  iron::LatencyCacheShm       shm_latency_cache_;

  /// A flag to toggle on latency checking before processing packets.
  bool                        do_latency_checks_;

  /// Object for tracking debug information over time. Not used unless
  /// DEBUG_STATS is enabled in options.mk.
  iron::DebuggingStats*       debug_stats_;

  /// The maximum queue depth seen in the current stats collection
  /// interval. Indexed by BinIndex.
  ::iron::BinIndexableArray<uint32_t> max_queue_;

  /// A flag to indicate if loss triage is enabled.
  bool                        enable_loss_triage_;

  /// The low address in the NORM flow range.
  iron::Ipv4Address           norm_low_addr_;

  /// The high address in the NORM flow range.
  iron::Ipv4Address           norm_high_addr_;

}; // end class UdpProxy

#endif // IRON_UDP_PROXY_H
