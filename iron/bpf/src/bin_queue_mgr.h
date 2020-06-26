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

///  \brief BinQueueMgr header file
///
/// This class contains and manages the queues for a particular multicast
/// group or unicast destination.
/// There is one set of physical queues (one queue per traffic class) for each
/// multicast group. However, the queue values used for backpressure and
/// admission control depend on the queue depths to each
/// destination. Therefore, the BinQueueMgr for a group includes a set queue
/// values and/or queue depths that are destination-specific. In the unicast
/// case, only the queue depth/value for the pertinent destination will have a
/// value.

#ifndef IRON_BPF_BIN_QUEUE_MGR_H
#define IRON_BPF_BIN_QUEUE_MGR_H

#include "asap.h"
#include "bin_indexable_array.h"
#include "bin_map.h"
#include "debugging_stats.h"
#include "gradient.h"
#include "genxplot.h"
#include "itime.h"
#include "packet_queue.h"
#include "queue.h"
#include "queue_depths.h"
#include "zlr.h"

#include <stdint.h>


namespace iron
{

  typedef struct LatencyQueue
  {
    Queue*  lat_queues[NUM_LATENCY_DEF];

    LatencyQueue() : lat_queues() {}
  } LatencyQueue;

  /// \brief Store information about a dequeued packet (or dequeued bytes for
  /// zombie queues)
  ///
  /// Used to pass information around to accounting functions, since we may or
  /// may not have a packet.
  typedef struct DequeuedInfo
  {
    LatencyClass lat;           // used for accounting
    uint32_t     dequeued_size; // used for accounting
    DstVec       dst_vec;
    bool         is_ip;         // used for determine whether to do ZLR
    uint8_t      dscp;          // used only for logging
    Time         recv_time;     // used for NPLB (not for ASAP)
    uint32_t     dst_addr;      // used if triggering a new ZLR zombie

    /// \brief Constructor for dequeuing a packet.
    DequeuedInfo(Packet * pkt, DstVec dsts) :
      lat(pkt->GetLatencyClass()),
      dequeued_size(pkt->virtual_length()),
      dst_vec(dsts),
      is_ip(pkt->HasIpHeader()),
      dscp(0),
      recv_time(pkt->recv_time()),
      dst_addr(0)
    {
      if (is_ip)
      {
        pkt->GetIpDscp(dscp);
        pkt->GetIpDstAddr(dst_addr);
      }
    };

    /// \brief Constructor for dequeuing a non-packet from a zombie queue.
    DequeuedInfo(LatencyClass dq_lat, uint32_t dq_size, DstVec dq_dst_vec) :
      lat(dq_lat),
      dequeued_size(dq_size),
      dst_vec(dq_dst_vec),
      is_ip(false),
      dscp(0),
      recv_time(Time(0)),
      dst_addr(0)
    {}
  } DequeuedInfo;

  class Packet;
  class QueueStore;

  /// The default size limit in number of enqueued objects for the entire
  /// bin queue mgr.  Not currently used.
#define DEFAULT_TOTAL_BIN_QUEUE_MGR_SIZE    2500

  /// The default limit on the number of packets allowed in a bin in the
  /// BinQueueMgr.
#define DEFAULT_MAX_BIN_DEPTH_PKTS   500

  /// \brief The BinQueueMgr class stores and manages the queues for a
  //  multicast group or unicast destination.
  ///
  /// There is a backpressure BinQueueMgr for each node in the network for
  /// each multicast group and for each unicast destination.
  /// These BinQueueMgrs are a collection of queues (one for each traffic
  /// class) along with the stored queue depths (per destination for a
  /// multicast group) and logic to support QLAM generation, sharing depths
  /// with admission control, and managing algorithm-specific queue values
  /// used for various purposes.
  class BinQueueMgr
  {
  public:

    /// \brief Default constructor.
    ///
    /// Defaults to using queues with a FIFO dequeueing policy with a HEAD
    /// drop policy, a limit of 500 packets per bin, and a limit of 2500
    /// packets total across all bins.
    ///
    /// \param  bin_idx      Bin index of the unicast destination or mcast group.
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  bin_map      Mapping of IRON bins.
    BinQueueMgr(BinIndex bin_idx, PacketPool& packet_pool, BinMap& bin_map);

    /// \brief Destructor.
    virtual ~BinQueueMgr();

    /// \brief  Set support for EF-traffic (enqueue in EF queues).
    ///
    /// \param  support True to set EF support, false not to.
    inline void set_support_ef(bool support) { support_ef_ = support; }

    /// \brief Add a packet to a bin.
    ///
    /// If the specified bin does not already exist, then the bin will be
    /// added with the dequeue policy and drop policy specified in the
    /// constructor.
    ///
    /// If the packet is successfully enqueued, then the bin queue mgr takes
    /// ownership of the memory.
    ///
    /// \param  pkt     A pointer to the packet to be enqueued.
    ///
    /// \return  True if the packet was successfully enqueued, false
    ///          otherwise.
    virtual bool Enqueue(Packet* pkt);

    /// \brief  Peek at the next packet from a specific bin looking from low
    ///         to high latency.
    ///
    /// Memory ownership of the packet stays with the queue!  The caller SHOULD
    /// NOT free the packet.
    ///
    /// \return  A pointer to the packet peeked.  May be NULL.
    Packet* Peek();

    /// \brief  Peek at the next packet from a specific bin for a specific
    ///         latency queue.
    ///
    /// Memory ownership of the packet stays with the queue!  The caller SHOULD
    /// NOT free the packet.
    ///
    /// \param  lat The latency queue where to peek for the next packet.
    ///
    /// \return  A pointer to the packet peeked.  May be NULL.
    Packet* Peek(const uint8_t lat);

    /// \brief  Determine if the bin queue mgr is associated with a multicast
    ///         destination.
    ///
    /// \return true for multicast, false for unicast.
    inline bool is_multicast() { return is_multicast_; }

    /// \brief  Get the total size of the bytes for this bin and
    ///         latency class available for dequeue.
    ///
    /// \param  lat The latency queue where to peek for the next packet size.
    ///
    /// \return  The maximum size of the next packet to be dequeued.
    size_t GetTotalDequeueSize(const uint8_t lat);

    /// \brief  Get the potential size of the next packet for this bin and
    /// latency class.
    ///
    /// \param  lat The latency queue where to peek for the next packet size.
    ///
    /// \return  The potential size of the next packet to be dequeued.
    size_t GetNextDequeueSize(const uint8_t lat);

    /// \brief  Get the potential size of the next packet for this bin and
    /// latency class.
    ///
    /// \param  lat The latency queue where to peek for the next packet size.
    /// \param  bin_index For use with multicast bins: this is the destination
    ///                   for which we want the next dequeue size.
    ///
    /// \return  The potential size of the next packet to be dequeued.
    size_t GetNextDequeueSize(const uint8_t lat, BinIndex bin_index);

    /// \brief  Prepare an iterator to the queue, starting from the back.
    ///
    /// \param  lat The latency queue where to peek for the next packet.
    ///
    /// This method MUST BE CALLED before any exploration of the queue.
    /// Sequence: PrepareIteration, PeekNext, DequeueAtCurrentIterator.
    void PrepareIteration(uint8_t lat);

    /// \brief  Peek the next element during a walk.
    ///
    /// \param  lat The latency queue where to peek for the next packet.
    /// \param  ws  The iterator where the packet was found.
    ///
    /// \return  A pointer to the packet being peeked or NULL if
    ///          there are no packets to peek.
    Packet* PeekNext(uint8_t lat, PacketQueue::QueueWalkState& ws);

    /// \brief Drop bytes from the queue for the specified latency.
    ///
    /// The packet or bytes selected to be dropped is determined by the drop
    /// policy configured with the queue.
    ///
    /// \param   lat             The latency class for which we want to drop
    ///                          bytes.
    /// \param   max_size_bytes  The maximum number of bytes to drop.
    /// \param   dst_vec         The destinations for which we want to drop
    ///                          bytes. Ignored for unicast. For non-zombie
    ///                          queues, this function will search until it
    ///                          finds a packet that matches the given
    ///                          dst_vec.
    ///
    /// \return  Returns the number of bytes dropped (may be 0)
    virtual uint32_t DropFromQueue(LatencyClass lat,
                                   uint32_t max_size_bytes,
                                   DstVec dst_vec);

    /// \brief Drop bytes from the queue for the specified latency.
    ///
    /// The packet or bytes selected to be dropped is determined by the drop
    /// policy configured with the queue.
    ///
    /// \param   lat             The latency class for which we want to drop
    ///                          bytes.
    /// \param   max_size_bytes  The maximum number of bytes to drop.
    ///
    /// \return  Returns the number of bytes dropped (may be 0)
    virtual inline uint32_t DropFromQueue(LatencyClass lat,
                                          uint32_t max_size_bytes)
    {
      return DropFromQueue(lat, max_size_bytes, 0);
    }

    /// \brief Drop bytes from the queue for the specified latency.
    ///
    /// The packet or bytes selected to be dropped is determined by the drop
    /// policy configured with the queue.
    ///
    /// \param   lat  The latency class for which we want to drop bytes.
    ///
    /// \return  Returns the number of bytes dropped (may be 0)
    virtual inline uint32_t DropFromQueue(LatencyClass lat)
    {
      return DropFromQueue(lat, UINT32_MAX, 0);
    }

    /// \brief  Dequeue the element at the iterator in the walk and set the
    ///         iterator to the next element.
    ///
    /// \param  lat The latency queue where to peek for the next packet.
    ///
    /// \return A pointer to the packet being dequeued of NULL if there are no
    ///         packets.
    Packet* DequeueAtCurrentIterator(uint8_t lat);

    /// \brief  Get the queue iterator at the front of the queue to point where
    ///         the dequeue should happen.
    ///         This method does not require to call PrepareIteration first.
    ///
    /// \param  lat The latency queue where to peek for the next packet.
    ///
    /// \return An iterator set to NULL if not found, the iterator otherwise.
    PacketQueue::QueueWalkState GetFrontIterator(uint8_t lat);

    /// \brief  Returns true if the queue for this LatencyClass doesn't store
    /// actual packets.
    ///
    /// \return  True if the given LatencyClass uses a zombie queue (without
    /// real packets), or false if it uses a queue of packets.
    static bool IsPktlessZQueue(LatencyClass lat);

    /// \brief  Get the queue iterator pointing to a given packet, where the
    ///         dequeue should happen.
    ///         Note: This does not require calling PrepareIterator first and
    ///               it walks the whole queue until it finds the packet.  This
    ///               method is intended to find the iterator where a packet was
    ///               newly enqueued in the CRITICAL queue.
    ///
    /// \param  lat The latency queue where to peek for the next packet.
    /// \param  pkt The packet to match to the returned iterator.
    /// \param  qws The iterator.
    ///
    /// \return true if iterator valid, false otherwise.
    bool GetIterator(uint8_t lat, Packet* pkt,
                     PacketQueue::QueueWalkState &qws);

    /// \brief Dequeue a packet from a specific bin.
    ///
    /// If a packet is dequeued, the caller takes ownership of the memory.
    ///
    /// \return  A pointer to the packet dequeued.  May be NULL.
    virtual Packet* Dequeue();

    /// \brief  Dequeue a packet from a specific bin from a specific latency
    ///         queue
    ///
    /// If a packet is dequeued, the caller takes ownership of the memory.
    ///
    /// \param  lat The latency queue from which to dequeue.
    /// \param  max_size_bytes  The maximum size packet to be returned.
    /// \param  dst_vec         Dequeue a packet for this dst_vec. NOTE:
    ///                         behavior is currently unspecified when
    ///                         dst_vec is passed in for a non-zombie-queue
    ///                         latency class.
    ///
    /// \return  A pointer to the packet dequeued.  May be NULL.
    virtual Packet* Dequeue(LatencyClass lat,
                            uint32_t max_size_bytes = UINT32_MAX,
                            DstVec dst_vec = 0);

    /// \brief  Turn a packet into a Zombie packet, that is serviced in last
    ///         latency queue.
    ///
    /// Memory ownership goes to the queues in case of success, to the caller
    /// otherwise.
    ///
    /// \param  pkt A pointer to the packet to turn.
    ///
    /// \return true if successfully Zombified, false otherwise and needs to be
    ///         dropped.
    bool ZombifyPacket(Packet* pkt);

    /// \brief  Turn a packet into a Critical packet, that is to be serviced in
    ///         first traffic type queue.
    ///
    /// Memory ownership goes to the queues in case of success, to the caller
    /// otherwise.
    ///
    /// \param  pkt A pointer to the packet to turn.
    ///
    /// \return true if successfully Criticalized, false otherwise and needs to
    ///         be dropped.
    bool CriticalizePacket(Packet* pkt);

    /// \brief  Dequeue the packet placed at the iterator.
    /// Memory ownership quits the queue to go with the caller.
    ///
    /// \param  lat The latency class of the packet.
    /// \param  qws The iterator from where to dequeue.
    /// \param  send_to The DstVec containing destinations to which to send
    ///                   the packet, or 0 to dequeue the entire packet (such
    ///                   as for unicast).
    ///
    /// \return A pointer to the dequeued packet, NULL if nothing found.
    virtual Packet* DequeueAtIterator(LatencyClass lat,
                                      PacketQueue::QueueWalkState& qws,
                                      DstVec send_to = 0);

    ///
    /// Get the depth of a bin in the queue container.
    ///
    /// \return  The number of packets in the specified bin.
    uint32_t depth_packets() const;

    /// \brief Returns true if the queue contains any LS (and lower latency)
    /// packets NOT INCLUDING LS zombies.
    ///
    /// \return True if there are any non-zombie bytes in the queue.
    bool ContainsNonZombies() const;

    /// \brief Returns true if the queue contains any LS (and lower latency)
    /// packets NOT INCLUDING LS zombies.
    ///
    /// \return True if there are any LS non-zombie bytes in the queue.
    bool ContainsLSNonZombies() const;

    /// \brief Returns true if the queue contains any packets in the given set
    /// of traffic types.
    ///
    /// \param ttypes_to_query An array of LatencyClass values to be included
    ///                        in the non-zero check.
    /// \param num_types_to_query The number of traffic types to query, size
    ///                        of ttypes_to_query (no more than
    ///                        NUM_LATENCY_DEF).
    ///
    /// \return True if there are any bytes in the queue with the specified
    ///                        traffic types.
    bool ContainsPacketsWithTtypes(const LatencyClass* ttypes_to_query,
                                   uint8_t num_types_to_query) const;

    /// \brief  Get the total number of bytes enqueued in a set of latency
    ///         queues.
    ///
    /// \param dst_to_get     Destination bin index for which we want the depth.
    /// \param ttypes_to_get  An array of LatencyClass values to be included
    ///                       in the returned total.
    /// \param num_types_to_get The number of traffic types to get, size
    ///                       of ttypes_to_get (no more than
    ///                       NUM_LATENCY_DEF).
    ///
    /// \return The (virtual) queue depth in bytes.
    uint32_t GetTtypeDepthBytes(BinIndex dst_to_get,
                                const LatencyClass* ttypes_to_get,
                                uint8_t num_ttypes_to_get);

    /// \brief Get the depths of all bins.
    ///
    /// \return  A pointer to an object containing the bin identifiers and
    ///          their respective depths in number of packets.
    inline QueueDepths* GetQueueDepths()
    {
      return &queue_depths_;
    }

    /// \brief  Get the queue depths for a neighbor bin index for this unicast
    ///         or multicast destination.
    ///
    /// \param  nbr_bin_idx  The neighbor bin index whose queue depth we want.
    ///                      May be a unicast destination or interior node bin
    ///                      index.
    ///
    /// \return  A pointer to an object containing the bin identifiers and
    ///          their respective depths in number of packets.
    inline QueueDepths* GetNbrQueueDepths(BinIndex nbr_bin_idx)
    {
      return nbr_queue_depths_[nbr_bin_idx];
    }

    /// \brief  Set the queue depth object for a given neighbor bin index.
    ///
    /// \param  nbr_bin_idx  The neighbor's bin index to which the queue depth
    ///                      object relates.  May be a unicast destination or
    ///                      interior node bin index.
    /// \param  qd           The queue depth object.
    void set_nbr_queue_depths(BinIndex nbr_bin_idx, QueueDepths* qd);

    ///
    /// \brief  Get the queue depths to be used to generate a QLAM to BPF.
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \return The pointer to the queue depths object to be used in QLAM.
    ///
    virtual inline QueueDepths* GetQueueDepthsForBpfQlam()
    {
      return GetQueueDepths();
    }

    ///
    /// \brief  Get the queue depths for use in the BPF algorithm.
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \return The pointer to the queue depths object for use in BPF.
    ///
    virtual inline QueueDepths* GetQueueDepthsForBpf()
    {
      return GetQueueDepths();
    }

    ///
    /// \brief  Get the single queue depth for this bin to be shared with the
    /// proxies for admission control.
    ///
    /// \return The value to be passed to the proxies for admission control.
    ///
    virtual uint32_t GetQueueDepthForProxies();

    /// \brief Adjust the queue depths for anti-starvation.
    void AdjustQueueValuesForAntiStarvation();

    /// \brief Set the default drop policy.
    ///
    /// Should be called before any bins are added or any packets are
    /// enqueued.
    ///
    /// \param  policy  The desired default drop policy for all bins.
    inline void SetDefaultDropPolicy(DropPolicy policy)
    {
      drop_policy_ = policy;
    }

    /// \brief Set the drop policy of a specific bin.
    ///
    /// The drop policy should be set in the constructor and not per-bin
    /// using this method.  This method is really only intended for unit
    /// tests.
    ///
    /// \param  policy  The desired drop policy for the bin.
    void set_drop_policy(DropPolicy policy);

    /// \brief Set the drop policy of a specific bin for a specific latency.
    ///
    /// The drop policy should be set in the constructor and not per-bin
    /// using this method.  This method is really only intended for unit
    /// tests.
    ///
    /// \param  lat     The latency-queue to change.
    /// \param  policy  The desired drop policy for the bin.
    void set_drop_policy(LatencyClass lat, DropPolicy policy);

    /// \brief Get the drop policy of a specific bin for a specific latency.
    ///
    /// \param  lat     The latency-queue to query.
    ///
    /// \return  The drop policy of the bin.
    DropPolicy drop_policy(LatencyClass lat) const;

    /// \brief Get the drop policy of a specific bin.
    ///
    /// \return  The drop policy of the bin.
    DropPolicy drop_policy() const;

    /// \brief Set the maximum number of packets allowed in a queue.
    ///
    /// Note that this value applies to each queue in each bin. So the
    /// actual max queue depth (in packets) will be this depth for each of
    /// the latency-class-specific queues.
    ///
    /// BinQueueMgr::Initialize MUST be called after this function for the
    /// change to be picked up. This will free all existing queues (if any)
    /// and reinitialize them with the new value.
    ///
    /// \param depth The maximum number of packets in a queue
    ///      in the BinQueueMgr.
    inline void set_max_bin_depth_pkts(uint32_t depth)
    {
      max_bin_depth_pkts_ = depth;
    }

    /// \brief Get the maximum bin packets allowed per bin.
    ///
    /// Note that this is the limit of the queues and not the
    /// size of the largest queue.
    ///
    /// \return The maximum number of packets allowed in a
    ///      bin in the BinQueueMgr
    inline uint32_t max_bin_depth_pkts() const
    {
      return max_bin_depth_pkts_;
    }

    /// \brief Process a capacity update from the bpf
    ///
    /// \param pc_num The path controller number
    ///
    /// \param capacity_bps The current capacity estimate in bps
    void ProcessCapacityUpdate(uint32_t pc_num, double capacity_bps);

    /// \brief Pass a new ASAP cap on to the ASAP manager.
    ///
    /// \param new_cap  The updated cap on ASAP zombies for this bin.
    /// \param is_ls    True if this is for latency sensitive traffic.
    void SetASAPCap(uint32_t new_cap, bool is_ls);

    /// \brief Set up BinQueueMgr and log configuration information.
    ///
    /// \param  config_info   The reference to the config info object used to
    ///                       initialize values.
    /// \param  node_bin_idx  The node's bin index.
    ///
    /// \return true if initialization succeeded.
    virtual bool Initialize(const ConfigInfo& config_info,
                            BinIndex node_bin_idx);

    ///
    /// \brief Set a reference to a DebuggingStats object.
    ///
    /// This will allow code in QueueStore to track values over time.
    ///
    /// \param debug_stats Pointer to existing DebuggingStats instance.
    void set_debug_stats(DebuggingStats* debug_stats)
    {
      debug_stats_ = debug_stats;
    }

    /// \brief  Check if a packet queue is ordered.
    ///
    /// \param  lat     The latency of the queue.
    ///
    /// \return true if ordered, false otherwise.
    bool IsOrdered(LatencyClass lat) const;

    /// \brief  Print a summmary of the bin queue mgr.
    void Print();

    /// \brief Get the accessor for the ongoing queue depths graph.
    ///
    /// This will allow other classes to help write to the graph. This will
    /// return NULL if we aren't configured to generate these graphs.
    ///
    /// \param  bin_index   Which unicast or multicast bin index for the graph
    ///                     we want to access.
    ///
    /// \return  A pointer to the utility object for writing to the graph, or
    ///          NULL if we weren't configured to generate these.
    inline GenXplot* GetQueueDepthsXplot(BinIndex bin_index)
    {
      return queue_depths_xplot_[bin_index];
    }

    /// \brief Handle any queue depth adjustments needed on a low-fidelity
    /// timer.
    ///
    /// Used to handle anti-starvation and by subclasses to manage other queue
    /// depth adjustements.
    ///
    /// For the base class, this just triggers anti-starvation adjustments.
    ///
    /// This will be called at least once per BPF select loop. Timing is
    /// handled internally within the function so that different queue depth
    /// managers can act at different time scales.
    virtual void PeriodicAdjustQueueValues();

    /// \brief Update the destination-specific values in response to a queue
    /// depth change.
    ///
    /// Base class does nothing.
    inline virtual void AdjustQueueValuesOnChange(BinIndex bin_idx)
    {
      // Does nothing. Subclasses use this.
    };

    /// \brief Create and enqueue zombie bytes with the given specs.
    ///
    /// This will create zombie bytes in the most efficient way possible -
    /// either by creating a packet (if we have real zombie packets for the
    /// speicifed zombie latency class) or just inserting bytes (if that class
    /// has a packetless zombie queue). If using real packets, this will
    /// create the correct number of zombies (based on the configured max
    /// zombie size) to add up to the specified byte total.
    ///
    /// \param dst_add_nbo The destination address of the zombies, in case we
    ///                    are generating real packets.
    /// \param total_zombie_bytes The total number of zombie bytes to be
    ///                    enqueued, which may be a single packet or multiple
    ///                    packets, depending on the configured max zombie
    ///                    size.
    /// \param zombie_class The latency class for the new zombie. Must be one
    ///                    of the zombie latency classes.
    /// \param dst_vec     The destination bit vector if this is a multicast
    ///                    packet. 0 for unicast.
    void AddNewZombie(
      uint32_t dst_addr_nbo,
      uint32_t total_zombie_bytes,
      LatencyClass zombie_class,
      DstVec dst_vec = 0);

    /// \brief Return the queue depth in bytes for the given bin and class.
    ///
    /// \param bin  The bin index for which to return the depth.
    /// \param lat  The latency class for which to return the depth.
    ///
    /// \return uint32_t The appropriate queue depth.
    inline uint32_t per_dst_per_lat_class_bytes(
      BinIndex bin, LatencyClass lat)
    {
      return (((lat >= 0) && (lat < NUM_LATENCY_DEF)) ?
              per_dst_per_lat_class_bytes_[lat][bin] : 0);
    }

    /// \brief Return the last dequeue time for a packet for the given bin.
    ///
    /// \param bin_index The bin index of the target destination.
    /// \return Time The last time a packet was dequeued with this destination
    ///              in its dst_vec. Or the last time a packet with this
    ///              destination was enqueued in an empty queue.
    inline Time last_dequeue_time(BinIndex bin_index)
    {
      return last_dequeue_time_[bin_index];
    }

    /// \brief Check if a latency class is a non-zombie latency class.
    bool IsNonZombieLatClass(LatencyClass lat);

    /// \brief Get the total size of non-zombie packets in the queue.
    inline uint32_t non_zombie_queue_depth_bytes(BinIndex bin_idx)
    {
      return non_zombie_queue_depth_bytes_[bin_idx];
    }

  protected:
    /// Pool containing packets to use.
    PacketPool&                       packet_pool_;

    // Mapping of IRON bins.
    BinMap&                           bin_map_;

    /// The index of this node's bin id.
    BinIndex                          my_bin_index_;

    /// True once the initialization function has been called.
    bool                              initialized_;

    /// \brief Performs any necessary cleanup and logging after a dequeue.
    ///
    /// This function is useful because we have several dequeue functions that
    /// all need the same follow-on work after successfully finding a packet,
    /// and because subclasses have algorithm-specific actions after a
    /// dequeue.
    ///
    /// \param   dq_info    Information about the packet (or bytes) that was
    ///                     dequeued.
    /// \param   cloned     True if the "dequeue" was a packet clone, leaving
    ///                     the original packet behind in the queue to send to
    ///                     other destinations. False if we removed the entire
    ///                     packet.
    virtual void OnDequeue(const DequeuedInfo& dq_info, bool cloned);

    /// \brief Performs any necessary cleanup and accounting after an enqueue.
    ///
    /// This function is useful because subclasses have algorithm-specific
    /// actions after an enqueue. Params are properties of the packet, rather
    /// than the packet itself, for the sake of thread-safety (assuming we've
    /// given up ownership of the packet as soon as it enters the queue).
    ///
    /// \param   pkt_length_bytes  Length of the enqueued packet (or virtual
    ///                            length, for zombies)
    /// \param   lat               Latency class of the enqueued packet
    /// \param   dsts              Destination bit vector for multicast
    virtual void OnEnqueue(
      uint32_t pkt_length_bytes, LatencyClass lat, DstVec dsts);

    /// Set of latency queues for this destination or multicast group.
    /// The LatencyQueue object includes an array of pointers to per-latency
    /// queues.
    LatencyQueue                      phy_queue_;

    /// The QueueDepth object for this Unicast Bin or Multicast Bins.
    /// This is an array of per-ID queue depths. For for a unicast bin,
    /// the only value that is used in the BinIndex for this bin. For
    /// multicast, the BinIndicies of the destinations for the group
    /// are used and the other values are always 0.
    QueueDepths                       queue_depths_;

    /// The node's bin index.
    BinIndex                          node_bin_idx_;

  private:

    ///
    /// \brief  Find the latency queue corresponding to a bin id and latency.
    ///
    /// \param  lat     The latency-queue to query.
    ///
    /// \return A pointer to the latency queue.
    ///
    inline Queue* FindQueue(uint8_t lat) const;

    /// \brief  Updates the queue depths counts for this destination.
    ///
    /// \param  lat The latency (matters whether this is LS or non-LS).
    /// \param  delta_bytes The number of bytes (positive or negative) by
    ///                     which to udpate.
    void UnicastAdjustDepths(LatencyClass lat, int64_t delta_bytes);

    /// \brief  Updates the queue depths counts for all destinations.
    ///
    /// \param  dst_vec The destination bit vector for destinations that
    ///                 changed.
    /// \param  lat The latency (matters whether this is LS or non-LS).
    /// \param  delta_bytes The number of bytes (positive or negative) by
    ///                     which to udpate.
    void MulticastAdjustDepths(
      DstVec dst_vec, LatencyClass lat, int64_t delta_bytes);

    /// \brief  Updates the queue depth for a given destination bin index for
    ///         a given latency, by a provided number of bytes.
    ///
    /// \param  bin_idx The bin index of the destination to update.
    /// \param  lat The latency (matters whether this is LS or non-LS).
    /// \param  delta_bytes The number of bytes (positive or negative) by
    ///                     which to udpate.
    void AdjustQueueDepth(
      BinIndex bin_idx, LatencyClass lat, int64_t delta_bytes);

    /// \brief Initialize and generate the key for a per-bin graph.
    ///
    /// \param The BinIndex for which we want to generate a plot.
    void SetUpQueueDepthsXplot(BinIndex bin_idx);

    /// \brief Adds a new set of points to the queue depths xplot graph.
    ///
    /// \param bin_idx  The position in the queue_depths_ structure for which
    ///                 we want to add a new set of points. For multicast,
    ///                 this is a particular destination whose value
    ///                 changed. For unicast, it is my_bin_index_.
    void GraphNewQueueDepths(BinIndex bin_idx);

    /// Boolean for support of EF traffic (latency-aware).
    bool                              support_ef_;

    /// Boolean indicating whether these queues are destined to a multicast
    /// group.
    bool                              is_multicast_;

    /// Boolean indicating whether to pass the max or sum of destination queue
    /// depths to the proxies for admission.
    bool                              max_dst_admission_;

    /// The drop policy for all bin queues.
    DropPolicy                        drop_policy_;

    /// The maximum depth of a latency-class-specific queue, in packets.
    uint32_t                          max_bin_depth_pkts_;

    /// The array of neighbor queue depths, indexed by neighbor bin index (a
    /// unicast destination or interior node bin index).
    BinIndexableArray<QueueDepths*>   nbr_queue_depths_;

    /// Indicates whether we're using Anti-Starvation Zombies instead
    /// of NPLB
    bool                              use_anti_starvation_zombies_;

    /// Handles all ASAP anti-starvation functionality and state.
    ASAP*                             asap_mgr_;

    /// If true, do the algorithm for latency reduction using zombie
    /// packets. If false, do not.
    bool                              do_zombie_latency_reduction_;

    /// ZLR instance responsible for managing zombie latency reduction.
    ZLR                               zlr_manager_;

    /// The time when we last performed anti starvation queue depth
    /// adjustements, used to avoid doing this too often (which could cause a
    /// performance hit).
    Time                              last_anti_starvation_time_;

    /// Byte counts per multicast destination and latency class. For unicast,
    /// only the entries for my_bin_index_ will be used.
    BinIndexableArray<uint32_t>       per_dst_per_lat_class_bytes_[
      NUM_LATENCY_DEF];

    /// Reference to a DebuggingStats object that can be used to track values
    /// over time. Will be NULL if DEBUG_STATS compile option is disabled.
    DebuggingStats*                   debug_stats_;

    /// Pointers to classes for adding to the ongoing xplot graphs of queue
    /// depths, one for each unicast or multicast destination bin index. May
    /// be NULL.
    BinIndexableArray<GenXplot*>      queue_depths_xplot_;

    /// The last dequeue time, per bin. This is used to determine if there
    /// is starvation.
    BinIndexableArray<Time>           last_dequeue_time_;

    /// The total size of non-zombie packets in the queue.
    BinIndexableArray<uint32_t>       non_zombie_queue_depth_bytes_;

  }; // end class BinQueueMgr

} // namespace iron

#endif  // IRON_BPF_BIN_QUEUE_MGR_H
