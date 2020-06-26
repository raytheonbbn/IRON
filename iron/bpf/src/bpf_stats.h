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

#ifndef IRON_BPF_STATS_H
#define IRON_BPF_STATS_H

/// \file bpf_stats.h

#include "stats.h"

#include "bin_indexable_array.h"
#include "ipv4_address.h"
#include "path_controller.h"
#include "queue_depths.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <map>


namespace iron
{

  ///
  /// \brief  BpfStats class to extend and implement the stats class
  ///         specifically for the needs of the BPF.
  ///         The base class Stats retains a modicum of methods and members
  ///         (not all pure virtual) common to all stats classes, for instance
  ///         the method to start and stop dumping, timer interval accessors,
  ///         etc.
  ///         This class was built around a singleton such that all elements of
  ///         the bpf (backpressure_fwder, Sonds, CATs, etc.) may accumulate
  ///         statistics and metrics into the same BpfStats object.
  ///         The BpfStats class provides methods to accumulate stats into class
  ///         members.  It also starts a timer, which upon expiring, dumps
  ///         these stats to the logs (as of creation of this class).
  ///
  ///         Memory ownership: all memory pertinent to BpfStats is owned (and
  ///         cleared) by this class.
  ///
  class BpfStats : public Stats
  {

   public:

    ///
    /// \brief  Constructor
    ///
    /// \param  bin_map  Mapping of IRON bins.
    BpfStats(BinMap& bin_map);

    ///
    /// \brief  Destructor.
    ///
    virtual ~BpfStats();

    ///
    /// \brief  Initialize the object.
    ///
    /// \return  True if initialization was successful, false otherwise.
    ///
    bool Initialize();

    /// Purge the stats. Currently only called by destructors
    void Purge();

    ///
    /// \brief  The method that dumps the accumulated stats into the log file
    ///         or rapidJSON writer.
    ///
    /// Memory ownership: BPF Stats does not own the memory for the writer nor
    /// does it free it.
    ///
    /// \param  writer  The rapidJSON writer object to use to fill up the stats.
    ///                 It may be NULL, which means that nothing will be copied
    ///                 in that (non-existent) JSON object.
    ///
    virtual void WriteStats(rapidjson::Writer<rapidjson::StringBuffer>* writer
                            = NULL);

    ///
    /// \brief  Increment the number of bytes of data sent on a path
    ///         controller.
    ///
    /// \param  pc         The path controller to obtain remote iron node
    ///                    address with optional -label.
    /// \param  bin_idx    The bin index to which the bytes were sent
    ///                    for this pc.
    /// \param  num_bytes  The number of bytes of data sent to the
    ///                    bin ID.
    /// \param  dst_vec    (Optional) The bit vector of bin IDs specifying
    ///                    multicast group membership for mcast bin_idxs
    ///
    /// \return True if increment was successfull, false otherwise.
    ///
    virtual bool IncrementNumDataBytesSentToBinOnPathCtrl(
      PathController* pc, BinIndex bin_idx, uint64_t num_bytes,
      DstVec dst_vec = 0);

    ///
    /// \brief  Increment the number of bytes of data received on a
    ///         path controller.  This number includes only packets for which
    ///         we could find a bin.
    ///
    /// \param  pc         The path controller to obtain remote iron node
    ///                    address with optional -label.
    /// \param  bin_idx    The bin index for which the bytes were recvd
    ///                    for this pc.
    /// \param  num_bytes  The number of bytes received for the bin_idx
    ///                    ID.
    /// \param  dst_vec    (Optional) The bit vector of bin IDs specifying
    ///                    multicast group membership for mcast bin_idxs
    ///
    /// \return True if increment was successfull, false otherwise.
    ///
    virtual bool IncrementNumDataBytesRcvdForBinOnPathCtrl(
      PathController* pc, BinIndex bin_idx, uint64_t num_bytes,
      DstVec dst_vec = 0);

    ///
    /// \brief  Increment the number of bytes of data sent to a proxy.
    ///         This number includes only packets for which we could find a
    ///         bin.
    ///
    /// \param  proxy     Protocol number of the proxy corresponding to the
    ///                   sent bytes.
    /// \param  bin_idx   The bin index for which the bytes were sent for
    ///                   proxy.
    /// \param  num_bytes The number of bytes sent for the bin idx.
    /// \param  dst_vec   (Optional) The bit vector of bin IDs specifying
    ///                   multicast group membership for mcast bin_idxs
    ///
    /// \return true if increment was successfull, false otherwise.
    ///
    virtual bool IncrementNumDataBytesSentToBinOnProxy(uint32_t proxy,
                                                       BinIndex bin_idx,
                                                       uint64_t num_bytes,
      	                                               DstVec dst_vec = 0);

    ///
    /// \brief  Increment the number of bytes of data received from a proxy.
    ///         This number includes only packets for which we could find a
    ///         bin.
    ///
    /// \param  proxy       Protocol number of the proxy corresponding to the
    ///                     received bytes.
    /// \param  bin_idx     The bin index for which the bytes were received for
    ///                     this proxy.
    /// \param  num_bytes   The number of bytes received for the bin idx.
    /// \param  dst_vec     (Optional) The bit vector of bin IDs specifying
    ///                     multicast group membership for mcast bin_idxs
    ///
    /// \return true if increment was successfull, false otherwise.
    ///
    virtual bool IncrementNumDataBytesRcvdForBinOnProxy(uint32_t proxy,
                                                        BinIndex bin_idx,
                                                        uint64_t num_bytes,
							DstVec dst_vec = 0);

    ///
    /// \brief  Report the queue depths for all bins seen by the node.
    ///         The way in which the queue depths are reported is via a pointer
    ///         to a queue depth object, which conveniently carries this info.
    ///         Note that queue depths are averaged over the number of times
    ///         this info is reported, which is with every QLAM to the proxy.
    ///
    /// \param  bin_idx  The group index being updated (0 for unicast updates)
    /// \param  qd       The pointer to the queue depth object to be added 
    ///                  to the stats.
    ///                  BpfStats does not take ownership of qd memory.
    ///
    virtual void ReportQueueDepthsForBins(BinIndex bin_idx, QueueDepths* qd);

    /// 
    /// \brief  Increment the num. of times avq_queue_depths have been updated
    ///
    inline void IncrementNumberOfQueueDepthUpdates()
    {
      ++queue_depths_incr_count_;
    }
    
    ///
    /// \brief  Report the capacity estimate for a given path controller.
    ///
    /// \param  pc                 The (uniquely-identifying) pointer to the
    ///                            path controller.
    /// \param  chan_cap_est_bps   The channel capacity estimate in bits per
    ///                            second.
    /// \param  trans_cap_est_bps  The transport capacity estimate in bits per
    ///                            second.
    ///
    virtual void ReportCapacityUpdateForPC(PathController* pc,
                                           uint64_t chan_cap_est_bps,
                                           uint64_t trans_cap_est_bps);

    ///
    /// \brief  Report the latency estimate for a given destination bin
    ///         Id through each neighbor (and therefore through each
    ///         pathcontroller).
    ///
    /// \param  bin_idx The bin index of the destination.
    /// \param  next_hop The next hop on the path to the destination to
    ///         which the latency estimate applies.
    /// \param  latency The latency to the destination over the specified
    ///         next hop, in microseconds.
    inline void ReportLatencyUpdate(BinIndex bin_idx, std::string next_hop,
                                    uint32_t latency)
    {
      latency_per_bin_per_pc_[bin_idx][next_hop] = latency;
    }

    ///
    /// \brief  Return long string recapping the stored data.
    ///
    /// \return String of the data store recaps.
    ///
    virtual std::string ToString() const;

    /// \brief  Set test override to allow testing.
    ///
    /// \param  over_ride  True to set testing mode, false otherwise.
    inline void  set_test_override(bool over_ride)
    { test_override_  = over_ride; }

    /// \brief  Set test the flag to indicate if stats is being pushed.
    ///
    /// \param  push_active  True if there is an active push request,
    ///                      false otherwise.
    inline void  set_push_active(bool push_active)
    { push_active_  = push_active; }

    ///
    /// \brief  Synthesize a remote node address for a path controller.
    ///
    /// \param  pc  The (uniquely-identifying) pointer to the path controller.
    ///
    /// \return  The synthesized IPv4 address as a string.
    ///
    std::string CreateRemoteNodeAddrForPC(const PathController* pc);

   protected:
    ///
    /// The number of bytes of data sent for each bin
    /// on a particular path controller.
    ///
    std::map<std::string, std::map<uint32_t, QueueDepths*> >
      pc_data_tx_queue_depths_;
    
    ///
    /// The number of bytes of data received for each bin
    /// on a particular path controller.
    ///
    std::map<std::string, std::map<uint32_t, QueueDepths*> >
      pc_data_rx_queue_depths_;

    ///
    /// The number of bytes of multicast data sent for each bin
    /// on a particular proxy interface.
    ///
    std::map<uint32_t, std::map<uint32_t, QueueDepths*> >
      proxy_data_tx_queue_depths_;

    ///
    /// The number of bytes of multicast data received for each bin
    /// on a particular proxy interface.
    ///
    std::map<uint32_t, std::map<uint32_t, QueueDepths*> >
      proxy_data_rx_queue_depths_;

    ///
    /// The average per-bin queue depth in bytes that can be printed with a
    /// single call to DumpStats().  The average is obtained by dividing the
    /// cumulative queue depths reported at the time of QLAM generation by the
    /// number of times the queue depth was reported.  If a queue depth was
    /// reported four times during a statistics collection interval, then the
    /// sum of the four reported queue depths are divided by four.
    ///
    std::map<BinIndex, QueueDepths*> avg_queue_depths_;

    ///
    /// The path controller capacity estimate structure.
    ///
    struct PcCapEst
    {
      PcCapEst() : chan_cap_est_bps(0), trans_cap_est_bps(0)  {}
      PcCapEst(uint64_t cce, uint64_t tce)
          : chan_cap_est_bps(cce), trans_cap_est_bps(tce)  {}
      ~PcCapEst() {}

      uint64_t  chan_cap_est_bps;   /// Channel capacity estimate in bps.
      uint64_t  trans_cap_est_bps;  /// Transport capacity estimate in bps.
    };

    ///
    /// The path controller capacity estimates in bps.
    ///
    std::map<std::string, PcCapEst>      pc_capacity_estimate_;

   private:

    ///
    /// Disallow copy constructor.
    ///
    BpfStats(const BpfStats& other_stats);

    ///
    /// Disallow the copy operator.
    ///
    BpfStats& operator= (const BpfStats& other_stats);

    // IRON bin mapping
    BinMap&                              bin_map_;

    /// The number of times the avg_queue_depths_ object was updated.
    /// This allows the code to compute a running average value as the
    /// individual updates come in. This is incremented by one after
    /// all queue depths have been updated.
    ///
    int32_t                              queue_depths_incr_count_;

    /// The latency per destination bin index, per next hop
    /// (i.e. pathcontroller).  Each entry in this array is a map that maps a
    /// next-hop IP address string to the latency estimate in microseconds.
    BinIndexableArray<
      std::map<std::string, uint32_t> >  latency_per_bin_per_pc_;

    /// Setting test override to allow adding stats.
    bool                                 test_override_;

    /// Flag to indicate BPF has an active push request.
    bool                                 push_active_;
  };      // End BpfStats Class

}         // End namespace iron

#endif    // End IRON_BPF_STATS_H
