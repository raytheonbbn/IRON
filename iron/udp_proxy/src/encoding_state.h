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

#ifndef IRON_UDP_PROXY_ENCODING_STATE_H
#define IRON_UDP_PROXY_ENCODING_STATE_H

#include "bin_map.h"
#include "fec_defs.h"
#include "fec_state_pool.h"
#include "four_tuple.h"
#include "inter_process_comm.h"
#include "ipv4_address.h"
#include "iron_types.h"
#include "itime.h"
#include "k_val.h"
#include "norm_flow_controller.h"
#include "packet.h"
#include "packet_pool.h"
#include "packet_queue.h"
#include "queue_depths.h"
#include "src_info.h"
#include "src_rate_estimator.h"
#include "udp_fec_trailer.h"
#include "utility_fn_if.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <ctime>
#include <string.h>
#include <sys/types.h>

class AdmissionController;
class UdpProxy;

/// UDP proxy encoding state object.
class EncodingState
{
  public:

  /// \brief Constructor.
  ///
  /// \param  udp_proxy          Reference to the UDP Proxy.
  /// \param  queue_depths       Reference to the QueueDepths object.
  /// \param  packet_pool        Pool containing packets to use.
  /// \param  bin_map            System-wide bin map.
  /// \param  k_val              Reference to the k value.
  /// \param  four_tuple         The Encoding State's 4-tuple.
  /// \param  max_queue_depth    The maximum depth of the queue, in bytes.
  /// \param  queue_drop_policy  The queue drop policy.
  /// \param  bin_idx            The Encoding State's Bin Index.
  /// \param  flow_tag           The Encoding State's flow tag. This uniquely
  ///                            identifies the flow.
  /// \param  flow_controller    Pointer to the NORM flow controller. This
  ///                            class assumes ownership for the flow
  ///                            controller and is responsible for deleting
  ///                            it.
  EncodingState(UdpProxy& udp_proxy, iron::QueueDepths& queue_depths,
                iron::PacketPool& packet_pool,
                iron::BinMap& bin_map,
                iron::KVal& k_val,
                const iron::FourTuple& four_tuple, uint32_t max_queue_depth,
                iron::DropPolicy queue_drop_policy, iron::BinIndex bin_idx,
                uint32_t flow_tag,
                NormFlowController* flow_controller);

  /// \brief Destructor.
  virtual ~EncodingState();

  /// \brief Create the Encoding State's admission controller.
  ///
  /// Note: This will destroy any existing admission controller. This happens
  /// when changes are received from AMP.
  ///
  /// \param  utility_def   The utility definition string.
  ///
  /// \return True if the admission controller is successfully created, false
  ///       otherwise.
  bool CreateAdmissionController(std::string utility_def);

  /// \brief Handle a received packet.
  ///
  /// The Decoding State assumes ownership of the received packet.
  ///
  /// \param  pkt  The received packet.
  void HandlePkt(iron::Packet* pkt);

  /// \brief Service the encoding state's events.
  ///
  /// \param  now  The current time.
  void SvcEvents(iron::Time& now);

  /// \brief  Sends a packet to the BPF, if one is available.
  ///
  /// The proxy's admission controller has determined that a packet can be
  /// admitted. If there is a packet in the queue, send it to the BPF.
  ///
  /// \return The number of bytes admitted. 0 is returned if there are no
  ///         packets available.
  size_t AdmitPacket();

  /// \brief Send FEC packets once we have built them.
  ///
  /// \return True if successful, false otherwise.
  bool SendFecPackets();

  /// \brief Construct FEC repair chunks if sufficient original chunks are
  /// available, or if the maximum hold time has been exceeded.
  ///
  /// \param  currentTime  The current time (for testing agsints maximum hold
  ///                      time timeout conditions).
  ///
  /// \return True is FEC repair chunk packets are available for transmission,
  ///         false otherwise.
  bool UpdateFEC(struct timeval* currentTime);

  /// \brief Update the encoding parameters based on current context settings
  /// for this service.
  ///
  /// \param  baseRate     Number of chunks from original packets to construct
  ///                      FEC repair chunks from.
  /// \param  totalRate    Number of repair chunks to generate.
  /// \param  in_order     Flag indicating whether in order delivery is required.
  /// \param  maxChunkSz   Maximum payload size for a chunk.
  /// \param  maxHoldTime  Maximum hold time before forcing FEC generation.
  /// \param  timeout      Garbage collection time.
  /// \param  time_to_go   The time-to-go time.
  /// \param  ttg_valid    True if the time to go was set to something other
  ///                      than 0.
  /// \param  dscp         The DSCP value.
  /// \param  reorder_time The maximum hold time for reordering at the
  ///                      destination.
  /// \param  dst_vec      Bit vector specifying multicast destination bin IDs
  ///
  /// \return True if the update was succcessful, false otherwise.
  bool UpdateEncodingParams(int baseRate, int totalRate, bool in_order,
                            int maxChunkSz, struct timeval maxHoldTime,
                            time_t timeout, const iron::Time& time_to_go,
                            bool ttg_valid, int8_t dscp,
                            const iron::Time& reorder_time,
			    const iron::DstVec& dst_vec);

  /// \brief Flush the encoding cache and reset associated control values in
  /// preparation for encoding the next group.
  ///
  /// \return FECSTATE_OKAY if successful, error codes otherwise.
  int FlushCache();

  /// \brief Set the flow's state.
  ///
  /// \param  flow_state  The state to be set for the flow. One of the
  ///                     following:
  ///
  ///                     ON: the flow should be turned on and not triaged
  ///                       out,
  ///                     TRIAGED: the flow is temporarily off waiting for
  ///                       restart in the Proxy,
  ///                     OFF: the flow has been terminated by the supervisory
  ///                       control.
  ///                     UNREACHABLE: there is no path throught the network
  ///                       that will satisfy the latency requirements.
  virtual void set_flow_state(iron::FlowState flow_state);

  /// \brief Remove all packets from the backlog.
  inline void FlushBacklog()
  {
    encoded_pkts_queue_.Purge();
  }

  /// \brief Get the 4-tuple describing the state.
  ///
  /// \return The 4-tuple containing the source/destination addresses/ports
  ///         associated with the flow.
  inline iron::FourTuple four_tuple() const
  {
    return four_tuple_;
  }

  /// \brief Get the unique tag associated with the flow.
  ///
  /// \return The unique tag associated with the flow.
  inline uint32_t flow_tag() const
  {
    return flow_tag_;
  }

  /// \brief Get the size of the encoded packets queue.
  ///
  /// \return Size of the encoded packets queue.
  inline uint32_t GetCountFromEncodedPktsQueue() const
  {
    return encoded_pkts_queue_.GetCount();
  }

  /// \brief Get the Bin Index associated with the Encoding State.
  ///
  /// \return The Bin Index (ucast or mcast) associated with the Encoding State.
  inline iron::BinIndex bin_idx() const
  {
    return bin_idx_;
  }

  /// \brief Return access to k (which is always maintained here).
  ///
  /// \return reference to k
  inline iron::KVal& k_val()
  {
    return k_val_;
  }

  /// \brief Get the garbage collection time.
  ///
  /// \return The garbage collection time.
  inline time_t timeout() const
  {
    return timeout_;
  }

  /// \brief Get the garbage collection timeout time.
  ///
  /// \return The garbage collection timeout time.
  inline time_t last_time() const
  {
    return last_time_;
  }

  /// \brief Get the scheduled service time.
  ///
  /// \return The schedule service time.
  const iron::Time& sched_svc_time() const;

  /// \brief  Accumulates packet information into the state for stats
  /// reporting.
  ///
  /// This information is for flows whose packets were admitted to the network
  /// or sent to the BPF.
  ///
  /// \param  length_bytes  The packet size that needs to be accumulated.
  void AccumulatePacketInfo(uint64_t length_bytes);

  /// \brief Update the statistics reported by the destination proxy.
  ///
  /// \param sn The highest original packet sequence number received.
  /// \param loss_rate_pct The loss rate, as a percentage, reported
  ///        by the destination.
  void UpdateReceiverStats(uint32_t sn, uint32_t loss_rate_pct);

  /// \brief Write the collected EncodingState stats to the log file and/or
  /// the JSON writer.
  ///
  /// \param  now      The current time.
  /// \param  log_str  The string that is created for the log file.
  /// \param  writer   The JSON writer that is used to create the JSON
  ///                  message.
  void WriteStats(iron::Time& now, std::string& log_str,
                  rapidjson::Writer<rapidjson::StringBuffer>* writer = NULL);

  /// \brief Get the flow's utility.
  ///
  /// \return The flow's utility.
  inline double utility() const
  {
    return utility_;
  }

  /// \brief Get the number of bytes sent or received since the last
  /// statistics report.
  ///
  /// Note: this method is public to support unit testing.
  ///
  /// \return Number of bytes sent or received since the last statistics
  ///         report.
  inline uint64_t dump_byte_number() const
  {
    return dump_byte_number_;
  }

  /// \brief Get the number of packets sent or received since the last
  /// statistics report.
  ///
  /// Note: this method is public to support unit testing.
  ///
  /// \return Number of packets sent or received since the last statistics
  ///         report.
  inline uint64_t dump_pkt_number() const
  {
    return dump_pkt_number_;
  }

  /// \brief Clear the accumulated statistics.
  ///
  /// Note: this method is public to support unit testing.
  inline void ClearDumpStats()
  {
    dump_byte_number_ = 0;
    dump_pkt_number_  = 0;
  }

  /// \brief Update a parameter of the utility function for this state.
  ///
  /// \param key_val A key:value pair of the parameter to be updated and it's
  ///        new value.
  void UpdateUtilityFn(std::string key_val);

  /// \brief  Check if there is an event that requires stats to be pushed
  ///         to AMP immediately.
  /// \return True if stats should be pushed to AMP immediately.
  bool PushStats() const;

  /// \brief Get the sequence number of the last admitted packet.
  ///
  /// \return The sequence number of the last admitted packet.
  inline uint32_t admitted_seq_num() const
  {
    return admitted_seq_num_;
  }

  /// \brief Get the last sequence number acknowledged by the destination.
  ///
  /// \return The last sequence number acknowledged by the destination.
  inline uint32_t acked_seq_num() const
  {
    return acked_seq_num_;
  }

  /// \brief Get the loss rate, as a percentage of bytes, reported by the
  ///        destination.
  ///
  /// \return The loss rate, as a percentage of bytes, reported by the
  ///         destination.
  inline uint32_t loss_rate_pct() const
  {
    return loss_rate_pct_;
  }

  /// \brief Get the time-to-go for the flow.
  ///
  /// \return The time-to-go, if configured, 0 otherwise.
  inline iron::Time time_to_go()
  {
    if(time_to_go_valid_)
    {
      return time_to_go_;
    }
    else
    {
      return iron::Time(0);
    }
  }

  /// \brief Get a pointer to the udp proxy that owns this encoding state.
  ///
  /// \return A pointer to the udp proxy that owns this encoding state.
  inline UdpProxy* udp_proxy() const
  {
    return &udp_proxy_;
  }

  /// \brief Set a source-based multicast destination bit vector.
  ///
  /// \param  dst_vec  The source-based multicast destination bit vector.
  inline void set_mcast_dst_vec(iron::DstVec dst_vec)
  {
    mcast_dst_vec_     = dst_vec;
    has_mcast_dst_vec_ = true;
  }

  protected:

  // A note about the organization:
  //
  // FEC is performed across the contents of the orig_cache_ which consists of
  // a number of slots. Each slot may hold a single original packet, part of
  // an original packet, or multiple original packets depending on the
  // relationship of the maxchunksz to the observed packet sizes.  Each
  // original packet within an encoding group is assigned a unique
  // pktID. Within a group, pktIDs start with 0 and increment by one as each
  // additional packet is received and processed.
  //
  // When a packet is split across multiple slots, only contents from that
  // packet are used to fill each slot -- i.e., a slot will never contain
  // fragments from several packets. In this instance, each partial packet is
  // referred to as a fragment, and is assigned a fragID to assist in the
  // reassembly
  //
  // When multiple packets are contained within a slot, only complete packets
  // are contained within that slot -- i.e., a slot will never contain
  // fragments from a packet along with partial or complete portions of any
  // other packet In this instance, each multiple packet slot is considered to
  // be a blob and is (implicitly) assigned a blobID to assist in the
  // reconstitution
  //
  // To simplify the data structures, we use the term "chunk" to refer to both
  // fragments and blobs, and we use a chunkTrailer to assist in the
  // reassembly/reconstitution of both fragmented packets and multi-packet
  // constructs. When the contents of a slot contain a blob, the haveBlob flag
  // is set to true, the pktID refers to the first packet within the chunk,
  // and nChunks contains the number of packets within the chunk (blob) The
  // chunkID field is not used.
  //
  // When the contents of a slot contain a fragment, the haveBlob flag is set
  // to false, the pktID refers to the packet ID across all frgaments, nChunks
  // describes the number of fragments the original packet is spread across,
  // and the chunkID describes the position within original packet the current
  // chunk represents (i.e., which of the nChunks this fragment represents)

  /// Last time this was accessed (used for garbage collection).
  time_t                last_time_;

  /// Current group we are encoding.
  int                   group_id_;

  /// Current packet within the group.
  int                   pkt_id_;

  /// No. chunks in the orig cache -- essentially the current cache slot.
  int                   orig_count_;

  /// Boolean indicating whether current slot is partially full.
  bool                  have_blob_;

  /// Number of *payload* bytes in the current (partial) slot.
  int                   blob_sz_bytes_;

  /// Number of packets in the current blob.
  int                   blob_pkt_cnt_;

  /// Boolean indicating whether we have a straggler left over from forcing
  /// FEC generation when we had an incomplete blob.
  bool                  have_straggler_;

  /// Original packets seen so far.
  iron::Packet*         orig_cache_[MAX_FEC_RATE];

  /// No. chunks (pkts) in the fec cache.
  int                   fec_count_;

  /// Generated FEC chunks (packets).
  iron::Packet*         fec_cache_[MAX_FEC_RATE];

  /// Time first pkt in group added to cache.
  struct timeval        group_start_time_;

  /// Time when FEC cache should be flushed.
  struct timeval        flush_time_;

  /// Max time before generating FECs.
  struct timeval        max_hold_time_;

  /// Most recent base rate.
  int                   last_base_rate_;

  /// Most recent FEC rate.
  int                   last_total_rate_;

  /// Flag indicating whether in order delivery is required.
  bool                  in_order_;

  /// Most recent maximum chunk size.
  int                   max_chunk_sz_;

  /// The reordering hold time, to be relayed to the decoder.
  iron::Time            reorder_time_;

  /// Reference to the UDP Proxy.
  UdpProxy&             udp_proxy_;

  /// Reference to the queue depths.
  iron::QueueDepths&    queue_depths_;

  /// Pool containing packets to use.
  iron::PacketPool&     packet_pool_;

  /// System-wide bin map.
  iron::BinMap&         bin_map_;

  /// Four-tuple describing the flow belonging to the State.
  iron::FourTuple       four_tuple_;

  /// Unique tag to identify the flow.
  uint32_t              flow_tag_;

  /// Bin index of the flow
  iron::BinIndex       bin_idx_;

  /// Reference to the queue normalizer (maintained by the proxy).
  iron::KVal&           k_val_;

  /// Queue to store encoded traffic until they are admitted to the network.
  iron::PacketQueue     encoded_pkts_queue_;

  /// The maximum size of the encoded_packets_queue, in packets.
  uint32_t              max_encoded_pkts_queue_depth_;

  /// The admission controller.
  AdmissionController*  admission_controller_;

  /// The NORM flow controller.
  NormFlowController*   flow_controller_;

  /// The source rate estimator.
  SrcRateEstimator      src_rate_estimator_;

  /// The source information. This contains the total number of bytes sent and
  /// a reference to the queue of packets (used to determine the backlog
  /// size).
  SrcInfo               src_info_;

  /// The timeout value for the flow for cleaning up state.
  time_t                timeout_;

  /// The time-to-go time.
  iron::Time            time_to_go_;

  /// True if the time to go was set to something other than 0 (no time to go)
  bool                  time_to_go_valid_;

  /// The dscp value for all packets of this flow.
  int8_t                dscp_;

  /// The MGEN (per-flow) sequence number.
  uint32_t              mgen_seq_num_;

  /// The current sequence number for the original packets sent.
  uint32_t              original_pkt_seq_num_;

  /// The sequence number of the last admitted packet.
  uint32_t              admitted_seq_num_;

  /// The last sequence number acknowledged by the destination.
  uint32_t              acked_seq_num_;

  /// The loss rate, as a percentage of bytes, reported by the destination.
  uint32_t              loss_rate_pct_;

  /// The number of bytess sent or received since the last dump.
  uint64_t              dump_byte_number_;

  /// The number of packets sent or received since the last dump.
  uint64_t              dump_pkt_number_;

  /// The number of packets sent or received since proxy start.
  uint64_t              total_byte_number_;

  /// The number of bytes sent or received since proxy start.
  uint64_t              total_pkt_number_;

  /// The last statistics report time.
  iron::Time            last_report_time_;

  /// The utility computed when the statistics were last dumped.
  double                utility_;

  /// The utility function string for this flow.
  std::string           utility_str_;

  /// Source provided multicast destination bit vector.
  iron::DstVec          mcast_dst_vec_;

  /// Remembers if a source provided multicast destination bit vector has been
  /// provided.
  bool                  has_mcast_dst_vec_;

  private:

  /// \brief No-arg constructor.
  EncodingState();

  /// \brief Copy constructor.
  EncodingState(const EncodingState& es);

  /// \brief Assignment operator.
  EncodingState& operator=(const EncodingState& es);

  /// \brief Append a chunk trailer with a specified chunk index to the end
  /// of a chunk packet.
  ///
  /// \param  qpkt     The chunk packet to which the chunk trailer will be
  ///                  appended.
  /// \param  isBlob   Boolean indicating whether this is or is not a blob.
  /// \param  chunkID  The chunk index assigned within the chunk trailer.
  /// \param  nChunks  Total number of chunks.
  int AppendChunkTrailer(iron::Packet* qpkt, int isBlob, int chunkID,
                         int nChunks);

  /// \brief Insert a chunk packet into the cache, appending an FEC control
  /// trailer in the process.
  ///
  /// \param  qpkt  The chunk packet to which the chunk trailer will be
  ///               appended.
  ///
  /// \return  FECSTATE_OKAY on success, error code otherwise.
  // This has been superceded by the disassembleIntoCache function
  int AddToCache(::iron::Packet* qpkt);

  int HoldBlobInCache(::iron::Packet* qpkt);

  int CommitBlobToCache();

  bool WillOverrun(int paylen);

  /// \brief Insert a whole original packet into the cache by turning it into
  /// chunks, appending chunk and FEC control trailers in the process.
  ///
  /// \param  qpkt   The original (unchunked) packet to be chunked and
  ///                inserted into the cache.
  /// \param  start  Returned index of the slot within the cache holdingthe
  ///                first chunk.
  /// \param  num    Returned number of chunks resulting from the chunking
  ///                process.
  ///
  /// \return  FECSTATE_OKAY on success, error code otherwise
  bool DisassembleIntoCache(iron::Packet* qpkt, int* start, int* num);

  /// \brief Retrieve a chunk packet from the cache: no trailers are removed.
  ///
  /// \param  cacheType  Specifies whether an original or repair chunk is
  ///                    retrieved.
  /// \param  index      The slot number within the cache
  ///
  /// \return The chunk packet if successful, NULL if not.
  iron::Packet* FetchFromCache(unsigned long cacheType, int index);

  /// \brief Get the flow's state.
  ///
  /// \return The flow state.
  iron::FlowState flow_state() const;

  /// \brief Set the current encoding group.
  ///
  /// \param  group_id  The current encoding group.
  inline void set_group_id(int group_id)
  {
    group_id_ = group_id & FEC_GROUPID_MASK;
  }

  /// \brief  Update the timestamp and sequence number in the Mgen frames.
  ///
  /// \param  pkt The packet, possibly aggregated, whose Mgen header should be
  ///             updated.
  ///
  /// \param  state The encoding state from which to get the new mgen sequence
  ///               number.
  ///
  /// \param  tv  The timeval time value to update in the Mgen header(s).
  ///
  /// \return true if success, false otherwise.
  bool ResetMgen(iron::Packet* pkt, struct timeval tv);

  /// \brief Get and increment the current MGEN sequence number to be
  /// re-written.
  ///
  /// \return The current MGEN sequence number to be re-written.
  inline uint32_t GetAndIncrementMgenSeqNum()
  {
    return mgen_seq_num_++;
  }

}; // end class EncodingState

#endif // IRON_UDP_PROXY_ENCODING_STATE_H
