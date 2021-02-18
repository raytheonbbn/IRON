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

#ifndef IRON_BPF_BACKPRESSURE_FWDER_H
#define IRON_BPF_BACKPRESSURE_FWDER_H

///
/// Provides the IRON software with a Backpressure Forwarder implementation.
///

#include "fifo_if.h"
#include "config_info.h"
#include "backpressure_dequeue_alg.h"
#include "bin_indexable_array.h"
#include "bpf_stats.h"
#include "genxplot.h"
#include "hash_table.h"
#include "iron_constants.h"
#include "itime.h"
#include "latency_cache_shm.h"
#include "list.h"
#include "mash_table.h"
#include "packet.h"
#include "packet_fifo.h"
#include "packet_pool.h"
#include "path_controller_info.h"
#include "queue_depths.h"
#include "bin_queue_mgr.h"
#include "remote_control.h"
#include "rng.h"
#include "timer.h"

#include <limits>
#include <map>
#include <set>
#include <string>

#include <netinet/udp.h>

namespace iron
{
  class DebuggingStats;
  class FwdAlg;
  class PacketHistoryMgr;
  class PathController;
  class QueueStore;

  /// Enumeration for indices into the broadcast packet sequence number table
  /// based on packet types.
  enum BroadcastIndex
  {
    LSA_BC_IDX = 0,
    NUM_BC_IDX = 1
  };

  /// String name of the EF Ordering enum.
  const std::string EFOrdering_Name[] = {"None", "Delivery Margin", "TTG"};

  /// The IRON Backpressure Forwarder.
  ///
  /// The IRON Backpressure Forwarder provides support for the following:
  ///
  /// - Receiving packets from Application Proxies, queueing received
  ///   packets, and transmitting received packets to remote IRON nodes via
  ///   Path Controllers.
  /// - Sending packets to Application Proxies that have been received from
  ///   remote IRON nodes via Path Controllers.
  /// - Generating and processing Queue Length Advertisement Message (QLAM)
  ///   packets.
  ///
  /// QLAM packets are sent to neighbors and received from neighbors via Path
  /// Controllers.  The frequency at which the QLAM packets are generated is
  /// run-time configurable and may be different for different Path
  /// Controllers.  By default, the number of supported Path Controllers is 0.
  ///
  /// Following are the Backpressure Forwarder's configurable parameters:
  ///
  /// - Bpf.IpAddr                   : The Backpressure Forwarder's IP
  ///                                  Address.
  /// - Bpf.RemoteControl.Port       : The remote control TCP port
  ///                                  number. Default value is 5560.
  /// - Bpf.QlamOverheadRatio        : The portion of the capacity reported
  ///                                  by each Path Controller that is used
  ///                                  for sending QLAMs.  Must be less than
  ///                                  1.0.  Defaults to 0.01.
  /// - Bpf.Alg.QDMgr                : The Bin Queue Manager class that is
  ///                                  to be used for the BPFwder.  Options
  ///                                  are "Base", "HvyBall", and "EWMA".
  ///                                  Default is "Base".  "HvyBall" will
  ///                                  require a beta value and computation
  ///                                  interval.  "EWMA" requires tau.
  /// - Bpf.XmitQueueThreshBytes     : The maximum number of bytes in the
  ///                                  Path Controller transmit buffer
  ///                                  before the forwarding algorithm will
  ///                                  no longer send to it.  Default value
  ///                                  is 3000.
  /// - Bpf.BinQueueMgr.DequeuePolicy: The default bin queue mgr dequeue
  ///                                  policy.  May be "FIFO" or "LIFO".
  ///                                  The default value is "FIFO".
  /// - Bpf.BinQueueMgr.DropPolicy   : The default bin queue mgr drop policy.
  ///                                  May be "HEAD", "TAIL", or "NO_DROP".
  ///                                  The defaul value is "NO_DROP".
  /// - Bpf.BinQueueMgr.MaxBinDepthPkts : The default bin queue mgr maximum bin
  ///                                  depth in packets.  The default value
  ///                                  is 500.
  /// - Bpf.NumPathControllers       : The number of Path Controllers.
  ///                                  The default value is 0.
  class BPFwder
  {
    public:

    /// \brief Constructor
    ///
    /// \param  packet_pool  Pool of packets to use.
    /// \param  timer        Manager of timers.
    /// \param  weight_qd_shared_memory  Memory to share weight queue depths
    ///                                  with proxies.
    /// \param  bpf_to_udp_pkt_fifo  FIFO object for BPF to UDP Proxy packet
    ///                              passing.
    /// \param  bpf_to_tcp_pkt_fifo  FIFO object for BPF to TCP Proxy packet
    ///                              passing.
    /// \param  udp_to_bpf_pkt_fifo  FIFO object for UDP to BPF Proxy packet
    ///                              passing.
    /// \param  tcp_to_bpf_pkt_fifo  FIFO object for TCP to BPF Proxy packet
    ///                              passing.
    BPFwder(PacketPool& packet_pool,
            Timer& timer,
            BinMap& bin_map,
            SharedMemoryIF& weight_qd_shared_memory,
            FifoIF* bpf_to_udp_pkt_fifo,
            FifoIF* bpf_to_tcp_pkt_fifo,
            FifoIF* udp_to_bpf_pkt_fifo,
            FifoIF* tcp_to_bpf_pkt_fifo,
            ConfigInfo& config_info);

    /// Destructor.
    virtual ~BPFwder();

    /// \brief Initialize the Backpressure Forwarder.
    ///
    /// \return  True if the initialization is successful, false otherwise.
    bool Initialize();

    /// \brief  Set a different bpfwding approach.
    void ResetFwdingAlg();

    /// \brief Start the Backpressure Forwarder.
    ///
    /// The Backpressure Forwarder runs until a Ctrl-c signal is
    /// caught. Future enhancements include the ability to stop the
    /// Backpressure Forwarder following the receipt of an out-of-band control
    /// message.
    ///
    /// \param num_pkts_to_process If non-zero, once this many packets have
    ///          been forwarded, the BPF will stop. This allows unit tests to
    ///          run the BPF long enough to test certain conditions.
    /// \param max_iterations If non-zero, the BPF will stop after this many
    ///          iterations (even if num_pkts_to_process has not been
    ///          reached). This is helpful to avoid running indefinitely in a
    ///          unit test.
    void Start(uint32_t num_pkts_to_process = 0, uint32_t max_iterations = 0);

    /// \brief Terminates the execution of the Backpressure Forwarder.
    ///
    /// Currently, the only way to terminate the execution of the Backpressure
    /// Forwarder is to send the process a Ctrl-c signal.
    void Stop();

    /// \brief  Send a non-data packet on all path controllers.
    /// Assumes ownership of the packet.
    ///
    /// \param  packet  The packet to be sent.
    ///
    /// \param  nbr_to_omit Omit the transmission on all the path controllers
    ///                     to a neighbor.  By default, send on all.
    virtual void BroadcastPacket(Packet* packet,
                                 BinIndex nbr_to_omit = kInvalidBinIndex);

    /// \brief Receive packets from a proxy.
    ///
    /// \param  fifo        The FIFO for receiving the packets.
    /// \param  proxy_name  The proxy's name for logging purposes.
    void ReceiveFromProxy(PacketFifo& fifo, const char* proxy_name);

    /// \brief Process a received packet.
    ///
    /// The Backpressure Forwarder assumes ownership of the received packet.
    ///
    /// \param  packet     The received packet.
    /// \param  path_ctrl  The Path Controller that received the packet. This
    ///                    is NULL for packets received from the TCP Proxy or
    ///                    the UDP Proxy.
    virtual void ProcessRcvdPacket(Packet* packet,
                                   PathController* path_ctrl = NULL);

    /// \brief Process a received IPv4 packet.
    ///
    /// \param  packet     The received packet.
    /// \param  path_ctrl  The Path Controller that received the packet. This
    ///                    is NULL for packets received from the TCP Proxy or
    ///                    the UDP Proxy.
    void ProcessIpv4Packet(Packet* packet, PathController* path_ctrl);

    /// \brief Process a received packet for a local application.
    ///
    /// \param  packet     The received packet.
    /// \param  protocol   The protocol number of the packet.
    /// \param  bin_idx    The BinIndex of the destination of the packet.
    void ProcessIpv4PacketForLocalApp(Packet* packet, uint8_t protocol,
                                      BinIndex bin_idx);

    /// \brief Process the update in rate estimates from a path controller.
    ///
    /// \param  path_ctrl          Pointer to the path controller updating its
    ///                            rate.
    /// \param  chan_cap_est_bps   The new channel capacity estimate in bps.
    /// \param  trans_cap_est_bps  The new transport capacity estimate in bps.
    void ProcessCapacityUpdate(PathController* path_ctrl,
                               double chan_cap_est_bps,
                               double trans_cap_est_bps);

    /// \brief Process the latest packet delivery delay (PDD) parameters for
    /// low-latency (aka expedited forwarding, or EF) data packets.
    ///
    /// \param  path_ctrl     Pointer to the path controller updating its PDD
    ///                       parameters to the neighbor.
    /// \param  pdd_mean      The new PDD mean value, in seconds.
    /// \param  pdd_variance  The new PDD variance value, in seconds squared.
    void ProcessPktDelDelay(PathController* path_ctrl, double pdd_mean,
                            double pdd_variance);

    /// \brief  Get the per path controller latency to a destination.
    ///
    /// \param  dst_idx     The bin index of the destination.
    ///
    /// \param  latency_us  The array of latency values to the destination of
    ///                     size num_path_ctrls. UINT32_MAX means no path.
    /// \param  add_src_queue_delay Whether to add the current node's queue
    ///                             delay.
    /// \param  pkt The packet to send, containing history.
    ///
    /// \return True on success, false otherwise.
    bool GetPerPcLatencyToDst(BinIndex dst_idx, uint32_t* latency_us,
                              bool add_src_queue_delay, Packet* pkt = NULL);

    /// \brief  Forward the given packet toward the given destination bin id.
    ///
    /// This method takes ownership of the packet. The packet will be enqueued
    /// or recycled.
    ///
    /// \param  packet      A pointer to the packet to be forwarded.
    /// \param  dst_bin_idx The destination group bin index of the packet.
    void ForwardPacket(Packet* packet, BinIndex dst_bin_idx);

    /// \brief  Return the next available LSA sequence number, and
    /// increment the next available counter.
    ///
    /// \return The next available sequence number.
    inline uint16_t GetAndIncrLSASeqNum()
    {
      uint16_t seq_num = broadcast_seq_nums_[LSA_BC_IDX][my_bin_idx_];
      broadcast_seq_nums_[LSA_BC_IDX][my_bin_idx_]++;
      return seq_num;
    }

    /// \brief  Add these many bytes to the count of dropped expired packets.
    ///
    /// \param  bin_idx  The bin index of the dropped packet.
    /// \param  dropped_bytes The number of bytes dropped after expiring.
    inline void AddDroppedBytes(BinIndex bin_idx, uint16_t dropped_bytes)
    {
      dropped_bytes_[bin_idx] += dropped_bytes;
    }

    /// \brief Set the flag to indicate if GRAMs to be sent.
    ///
    /// \param flag True if  GRAMs are to be sent.
    inline void set_send_grams(bool flag)
    {
      send_grams_ = flag;
    }

    /// The maximum number of packets read per FIFO receive call.
    static const size_t   kMaxPktsPerFifoRecv           = 256;

    protected:

    /// \brief Initialize the FIFOs.
    ///
    /// \return  True if the initialization is successful, false otherwise.
    virtual bool InitializeFifos();

    /// \brief Generate a new GRoup Advertisement Message (GRAM) packet.
    /// The GRAM format:
    ///
    /// \verbatim
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           IPv4 Header
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///                                                                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                            UDP Header
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///                                                                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                            Num Groups                         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                              Group 1                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                              Group 2                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///                        ......
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                              Group N                         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    void SendGram();

    /// \brief Process a GRoup Advertisement Message (GRAM).
    bool ProcessGram(iron::Packet* gram);

    /// \brief Generate a Queue Length Advertisement Message (QLAM) packet.
    ///
    /// The QLAM packet format:
    ///
    /// \verbatim
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |  Src Bin Id   |        Sequence Number
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///          Sequence Number        |          Num Groups           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                     Group Id 0 (all ucast)                    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Num Pairs   |  Dst Bin Id 0 |    Queue Depth for Bin Id 0
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    Queue Depth for Bin Id 0     |   LS Queue Depth for Bin Id 0
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  LS Queue Depth for Bin Id 0    |  Dst Bin Id 1 |QD for Bin Id 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///              Queue Depth for Bin Id 1           | LS Queue Depth
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///            LS Queue Depth for Bin Id 1          | ...           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// ~                                                               ~
    /// ~                                                               ~
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Group Id 1 (mcast)                     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Num Pairs   |  Dst Bin Id 0 |    Queue Depth for Bin Id 0
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    Queue Depth for Bin Id 0     |   LS Queue Depth for Bin Id 0
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  LS Queue Depth for Bin Id 0    |  Dst Bin Id 1 |QD for Bin Id 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///              Queue Depth for Bin Id 1           | LS Queue Depth
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///            LS Queue Depth for Bin Id 1          | ...           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// ~                                                               ~
    /// ~                                                               ~
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Group Id i (mcast)                     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Num Pairs   |  Dst Bin Id 0 |    Queue Depth for Bin Id 0
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    Queue Depth for Bin Id 0     |   LS Queue Depth for Bin Id 0
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  LS Queue Depth for Bin Id 0    |  Dst Bin Id 1 |QD for Bin Id 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///              Queue Depth for Bin Id 1           | LS Queue Depth
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///            LS Queue Depth for Bin Id 1          | ...           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///   Type (1 byte) (0x10)
    ///   Source Bin Identifier (1 byte)
    ///   Sequence Number, in Network Byte Order (4 bytes)
    ///   Number of Groups, in Network Byte Order (2 bytes)
    ///   Sequence of Group Information:
    ///     Group Identifier, in Network Byte Order (4 bytes)
    ///     Number of Queue Depth Pairs (1 byte)
    ///     Sequence of Queue Depth Pair Information:
    ///       Destination Bin Identifier (1 byte)
    ///       Queue Depth in Bytes, in Network Byte Order (4 bytes)
    ///       Latency-Sensitive Queue Depth in Bytes, in Network Byte Order (4
    ///           bytes)
    /// \endverbatim
    ///
    /// Length = (8 + (num_grps * (5 + (num_pairs[grp] * 9)))) bytes
    ///
    /// \param  packet        The packet into which the generated QLAM will be
    ///                       placed.
    /// \param  dst_bin_idx   The bin index of the destination.
    /// \param  sn            The timestamp (sequence number) to use in the
    ///                       QLAM.
    ///
    /// \return  True if the QLAM generation succeeds, false otherwise.
    bool GenerateQlam(Packet* packet, BinIndex dst_bin_idx, uint32_t sn);

    /// \brief  Generate and send an LSA, set timer (tmp feature).
    virtual void SendNewLsa();

    /// \brief  Generate and fill a Link State Advertisement packet.
    /// C: Flag indicating whether link capacity estimates are included.
    /// C = 0, estimated capacity not included.
    /// \verbatim
    ///  0              .    1          .        2      .            3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Type (LSA)   |  Src Bin Id   |         Sequence Number       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Num Nbrs    |   Num bins    |             |C|    Padding    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     BinId     |    Latency Mean (in 100us)    |  Latency Std
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Dev (in 100us) |     BinId     |         Latency Mean          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |        Latency Std Dev        |     BinId     |  Latency Mean
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// Num Bins: If 0, queue delays are not included.
    /// \endverbatim
    ///
    /// C = 1, estimated capacity included.
    /// \verbatim
    ///  0              .    1          .        2      .            3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Type (LSA)   |  Src Bin Id   |         Sequence Number       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Num Nbrs    |   Num bins    |             |C|    Padding    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     BinId     |    Latency Mean (in 100us)    |  Latency Std  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Dev (in 100us) |   Estimated Capacity (bps)    |     BinId     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Latency Mean          |        Latency Std Dev        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Estimated Capacity (bps)    |     BinId     |  Latency Mean
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// \endverbatim
    /// Each estimated capacity is encoded as: C = (i.d) x 10^e.
    /// i (4bits): Integer part (from 1 to 9).
    /// d (8bits): Decimal part (from 0 to 0.996)
    /// e (4bits): Exponential part (from 1 to 16)
    /// \return A pointer to the newly created packet on success, NULL
    ///         otherwise.
    Packet* GenerateLsa();

    /// \brief Compute the next QLAM send timer duration.
    ///
    /// \param  pc_info        A reference to the path controller information
    ///                        for which we do this calculation.
    /// \param  next_exp_time  The reference where to put the next timer
    ///                        expiration delta time.
    ///
    /// \return  Returns true if next_exp_time holds the next QLAM timer
    ///          duration, or false if the timer should not be set (i.e., do
    ///          not send any QLAMs right now).
    bool ComputeNextQlamTimer(PathCtrlInfo& pc_info, Time& next_exp_time);

    /// Generate and send a QLAM packet to a neighbor via a Path Controller.
    ///
    /// \param  path_ctrl_num  The number of the Path Controller.
    /// \param  t_usec The timestamp to use in the QLAM.
    virtual void SendQlamToPathCtrl(uint32_t path_ctrl_num, uint32_t t_usec);

    /// The structure for capturing the node information for an entry in the
    /// NodeRecord state store.  The members of this structure are organized
    /// to minimize memory usage.
    struct NodeInfo
    {
      /// The queue delay (in microseconds).
      uint32_t  queue_delay_;

      /// The mean of the neighbor's latency (in microseconds).
      uint32_t  nbr_lat_mean_;

      /// The variance of the neighbor's latency (in microseconds squared).
      uint64_t  nbr_lat_var_;

      /// The capacity (in bits/second).
      double    capacity_;

      /// \brief  Default constructor.
      ///
      /// Set the default mean latency to infinity, which means that in case
      /// the CAT has not reported the latency (because there have not been
      /// any data traffic/QLAMs sent yet), we assume this link does not exist
      /// (as would be the case for nodes who are not neighbors).
      NodeInfo() : queue_delay_(0), nbr_lat_mean_(UINT32_MAX),
                   nbr_lat_var_(0), capacity_(-1.0) { }

      /// \brief  Constructor.
      NodeInfo(uint32_t qd, uint32_t lm, uint64_t lv, double c)
          : queue_delay_(qd), nbr_lat_mean_(lm), nbr_lat_var_(lv),
            capacity_(c) { }
    };

    /// The structure for capturing all of the information for a node.  This
    /// can be for the local node or as received from any remote node.
    struct NodeRecord
    {
      /// The array of node information records, indexed by bin index.
      BinIndexableArray<NodeInfo>  records_;

      /// \brief  Default constructor.
      NodeRecord() : records_() {}

      /// \brief  Initialize the array of records.
      inline bool Initialize(BinMap& bin_map)
      {
        return records_.Initialize(bin_map);
      }

     private:

      /// \brief  Copy constructor.
      NodeRecord(const NodeRecord& other);

      /// \brief  Copy operator.
      NodeRecord& operator=(const NodeRecord& other);
    };

    /// \brief  Get or allocate a NodeRecord for a bin index.
    ///
    /// \param  bin_idx  The bin index of the Node record to access or create.
    ///
    /// \return  The pointer to the NodeRecord for the bin index on success,
    ///          or NULL on error.
    NodeRecord* AccessOrAllocateNodeRecord(BinIndex bin_idx);

    /// \brief  Print the node records.
    void PrintNodeRecords();

    /// The structure for capturing all of the path information.  Used by
    /// GetPerPcLatencyToDst() and its associated methods.
    struct PathInfo
    {
      /// \brief  Default constructor.
      PathInfo() : num_nodes_to_exclude_(0), nodes_to_exclude_(NULL),
                   max_bin_idx_(0), num_(0), a_idx_(NULL),
                   lat_mean_matrix_(NULL), lat_var_matrix_(NULL),
                   min_lat_mean_(NULL), min_lat_var_(NULL), next_hop_(NULL),
                   visited_(NULL), min_cost_(NULL) {}

      /// \brief  Initialize all of the path information.
      bool Initialize(BinMap& bin_map);

      /// \brief  Reset all of the path information matrixes.
      void ResetMatrixes();

      /// \brief  Reset all of the path information arrays.
      void ResetArrays(BinIndex src);

      /// \brief  Validate a bin index before using it.
      inline void ValidateBinIndex(BinIndex bin_idx)
      {
        if ((bin_idx > max_bin_idx_) || (a_idx_[bin_idx] >= num_))
        {
          LogF("PathInfo", "ValidateBinIndex", "Out of bounds %" PRIBinIndex
               "\n", bin_idx);
        }
      }

      /// \brief  Access a mean latency matrix entry.
      inline uint32_t& LatMean(BinIndex dst, BinIndex nbr)
      {
        return lat_mean_matrix_[((a_idx_[dst] * num_) + a_idx_[nbr])];
      }

      /// \brief  Access a latency variance matrix entry.
      inline uint64_t& LatVar(BinIndex dst, BinIndex nbr)
      {
        return lat_var_matrix_[((a_idx_[dst] * num_) + a_idx_[nbr])];
      }

      /// \brief  Access a minimum mean latency array entry.
      inline uint32_t& MinLatMean(BinIndex dst)
      {
        return min_lat_mean_[(a_idx_[dst])];
      }

      /// \brief  Access a minimum latency variance array entry.
      inline uint64_t& MinLatVar(BinIndex dst)
      {
        return min_lat_var_[(a_idx_[dst])];
      }

      /// \brief  Access a next hop array entry.
      inline uint32_t& NextHop(BinIndex dst)
      {
        return next_hop_[(a_idx_[dst])];
      }

      /// \brief  Access a visited flag array entry.
      inline bool& Visited(BinIndex dst)
      {
        return visited_[(a_idx_[dst])];
      }

      /// \brief  Access a minimum cost array entry.
      inline uint32_t& MinCost(BinIndex dst)
      {
        return min_cost_[(a_idx_[dst])];
      }

      /// \brief  Exclude a node bin index.
      inline void ExcludeNode(BinIndex bin_idx)
      {
        if (num_nodes_to_exclude_ < num_)
        {
          nodes_to_exclude_[num_nodes_to_exclude_] = bin_idx;
          ++num_nodes_to_exclude_;
        }
        else
        {
          LogE("PathInfo", __func__, "Too many node exclusions.\n");
        }
      }

      /// \brief  Destructor.
      ~PathInfo();

      /// The number of node bin indexes to exclude.
      size_t     num_nodes_to_exclude_;

      /// The array of node bin indexes to exclude.
      BinIndex*  nodes_to_exclude_;

     private:

      /// \brief  Copy constructor.
      PathInfo(const PathInfo& other);

      /// \brief  Copy operator.
      PathInfo& operator=(const PathInfo& other);

      /// The maximum bin index supported.
      BinIndex   max_bin_idx_;

      /// The number of elements in each dimension of the arrays.
      size_t     num_;

      /// The mapping of bin index values to array index values.
      BinIndex*  a_idx_;

      /// The mean latency matrix, in microseconds.
      uint32_t*  lat_mean_matrix_;

      /// The latency variance matrix, in microseconds squared.
      uint64_t*  lat_var_matrix_;

      /// The array of minimum latency values, in microseconds.
      uint32_t*  min_lat_mean_;

      /// The array of minimum latency variance values, in microseconds
      /// squared.
      uint64_t*  min_lat_var_;

      /// The array of next hop bin indexes.
      uint32_t*  next_hop_;

      /// The array of visited flags.
      bool*      visited_;

      /// The array of minimum cost values.
      uint32_t*  min_cost_;
    };

    /// \brief  Print the converted connection matrix.
    ///
    /// \param  path_info  A reference to the path information object.
    void PrintMatrix(PathInfo& path_info);

    /// \brief  Convert the LSA-based node records into a connection matrix.
    ///
    /// The matrix takes the form:
    ///   [0 x y] Node 0 to 1 has a latency of x.
    ///   [x 0 z] Node 0 to 2 has a latency of y.
    ///   [y z 0] Node 1 to 2 has a latency of z.
    ///
    /// The latency may be the max uint32_t value to signify infinity.
    void ConvertNodeRecordsToMatrix();

    /// \brief  Update the virtual queue depths based on LSAs.
    virtual void UpdateVirtQueues();

    /// \brief  Compute the min hop count to all nodes from a reference node.
    ///
    /// The reason for including the ref_bin_idx in the call is to support
    /// calculating hop counts for either this node (my_bin_idx_) or its
    /// neighbors.
    /// This algorithm excludes the use of this node in the calculation
    /// to identify "deadends" in the topology -- i.e., sending to a neighbor
    /// cannot reach a given destination without the neighbor going back
    /// through this node.
    ///
    /// The hop counts are returned in the virt_queue_info_ array, in the
    /// hop_count_ member of the structures.
    ///
    /// \param  ref_bin_idx  The bin index from which to compute the minimum
    ///                      hop counts.
    void ComputeVirtQueues(BinIndex ref_bin_idx);

    /// \brief  Compute and log the forwarding biases using virtual queue info
    ///
    /// Forwarding bias terms are added to the queue differentials to help
    /// steer low volume flows towards a destination, where there may be
    /// otherwise insufficient traffic to build up backpressure gradients
    /// for a given destination across the network. Without such bias terms,
    /// low volume flows -- e.g., a single SYN packet -- may exhbit a random
    /// walk around the network indefinitely
    ///
    /// This method is provided to report the forwarding bias terms that
    /// are being used for this purpose
    void LogForwardingBiases();

    /// \brief  Find the minimum latency path to all nodes from a source.
    ///
    /// \param  src_bin_idx  The source bin index from which to compute the
    ///                      minimum latency paths.
    void FindMinimumLatencyPath(BinIndex src_bin_idx);

    /// \brief  Clear the latency cache.
    inline void ClearLatencyCache()
    {
      latency_cache_reset_time_ = Time::Now();
    }

    /// The structure for virtual queue information.
    struct VirtQueueInfo
    {
      /// The visitied flag.
      bool      visited_;

      /// The hop count in bytes.
      uint32_t  hop_count_;

      /// \brief  Default constructor.
      VirtQueueInfo() : visited_(false), hop_count_(0) { }

      /// \brief  Constructor.
      VirtQueueInfo(bool v, uint32_t hc) : visited_(v), hop_count_(hc) { }
    };

    /// LSA-populated information for all nodes in the network.  NodeRecord
    /// structures are dynamically allocated as needed and added to the array.
    /// The array is indexed by unicast destination or interior node bin
    /// index.
    BinIndexableArray<NodeRecord*>           node_records_;

    /// Boolean flag to include queuing delays.
    bool                                     incl_queue_delays_;

    /// Boolean flag to include capacity in LSAs and allow export of  capacity.
    bool                                     incl_link_capacity_;

    /// Boolean flag that remembers if we are running or not.
    bool                                     running_;

    /// The bin id of this IRON node. (Bin ids are guaranteed to map
    /// one-to-one to IRON nodes.)
    BinId                                    my_bin_id_;

    /// The Bin Index of this IRON node.
    BinIndex                                 my_bin_idx_;

    /// The flag recording if the local node is an interior node or not.
    bool                                     is_int_node_;

    /// The number of configured PathControllers.
    size_t                                   num_path_ctrls_;

    /// The collection of PathControllers.
    PathCtrlInfo                             path_ctrls_[kMaxPathCtrls];

    /// IRON Shared memory bin map
    BinMap&                                  bin_map_shm_;

    /// FIFO object for BPF to UDP Proxy packet passing.
    PacketFifo                               bpf_to_udp_pkt_fifo_;

    /// FIFO object for BPF to TCP Proxy packet passing.
    PacketFifo                               bpf_to_tcp_pkt_fifo_;

    /// FIFO object for UDP Proxy to BPF packet passing.
    PacketFifo                               udp_to_bpf_pkt_fifo_;

    /// FIFO object for TCP Proxy to BPF packet passing.
    PacketFifo                               tcp_to_bpf_pkt_fifo_;

    /// The QueueStore interface.
    QueueStore*                              queue_store_;

    /// The Bpf pkt forwarding algorithm interface.
    BPDequeueAlg*                            bpf_dequeue_alg_;

    /// Last QLAM packet size: this is used to "predict" the size of the next
    /// QLAM and therefore compute when to send it.
    uint32_t                                 last_qlam_size_bits_;

    /// The minimum allowable path controller capacity estimate in order to
    /// keep QLAMs flowing, in bits per second.
    double                                   min_path_ctrl_cap_est_bps_;

    /// Manager for tracking and interpreting the packet history vector.
    PacketHistoryMgr*                        packet_history_mgr_;

    /// The virtual queue information array.  Indexed by unicast destination
    /// or interior node bin index.
    BinIndexableArray<VirtQueueInfo>         virt_queue_info_;

    /// The path information used for finding minimum latency paths.
    PathInfo                                 path_info_;

    private:

    /// Copy constructor.
    BPFwder(const BPFwder& other);

    /// Copy operator.
    BPFwder& operator=(const BPFwder& other);

    /// \brief Process a received QLAM packet that is received by a Path
    /// Controller.
    ///
    /// \param  packet     The received packet.
    /// \param  path_ctrl  The Path Controller that received the packet.
    void ProcessQlam(Packet* packet, PathController* path_ctrl);

    /// \brief  Process a broadcast packet received from a path controller
    ///         and forward it to neighbors if necessary.
    ///
    /// This method takes ownership of the packet.
    ///
    /// \param  packet  A pointer to the received packet.
    ///
    /// \param path_ctrl  The path controller on which the packet was received.
    void ProcessBroadcastPacket(Packet* packet, PathController* path_ctrl);

    /// \brief  Process an LSA packet received from a remote IRON node.
    ///
    /// This method does NOT take ownership of the packet.
    ///
    /// \param  src_bin_index  The bin index corresponding to the bin id from
    ///         the packet.
    ///
    /// \param  data   Pointer to the LSA-specific data in the packet.
    ///
    /// \param  data_len  The length of the data buffer in the packet,
    ///         starting with the data pointer.
    void ProcessLsa(BinIndex src_bin_index,
                    const uint8_t* data, size_t data_len);

    /// \brief  Print the contents of an LSA packet.
    ///
    /// \param  packet  The LSA packet to print.
    void PrintLsa(Packet* packet);

    /// \brief  Get the capacity and encoded to be added to LSA in
    ///         "i.(d x DI)" x 10^e form (DI = 4e-3).
    ///
    /// For 4567 = 4.567x10^3:
    /// \param  bin_idx  The bin index for the capacity returned.
    /// \param  e        The exponent part (3 in example above).
    /// \param  i        The integer part (4 in example above).
    /// \param  d        The decimal part (0.567/DI=141 in the example above).
    void GetEncodedCapacity(BinIndex bin_idx, uint8_t& e, uint8_t& i,
                            uint8_t& d);

    /// \brief  Decode the capacity.
    ///         "i.(d x DI)" x 10^e form (DI = 4e-3).
    ///
    /// For 4567 = 4.567x10^3:
    /// \param  e The exponent part (3 in example above).
    /// \param  i The integer part (4 in example above).
    /// \param  d The decimal part (0.567/DI=141 in the example above).
    ///
    /// \return The decoded capacity in bps.
    double DecodeCapacity(uint8_t e, uint8_t i, uint8_t d);

    /// Process a received packet that is received by a Path Controller. The
    /// Backpressure Forwarder assumes ownership of the received packet.
    ///
    /// \param  path_ctrl  The Path Controller that received the packet.
    /// \param  packet     The received packet.
    /// \param  ip_hdr     The received IP header.

    /// Process a received packet that is received by a Path Controller. The
    /// Backpressure Forwarder assumes ownership of the received packet.
    ///
    /// \param  path_ctrl  The Path Controller that received the packet.
    /// \param  packet     The received packet.
    /// \param  ip_hdr     The received IP header.
    void ProcessPacket(PathController* path_ctrl, Packet* packet,
                       const struct iphdr* ip_hdr);

    /// Process a received remote control message.
    void ProcessRemoteControlMessage();

    /// Process a received remote control "set" message.
    void ProcessSetMessage();

    /// Process a received remote control "get" message.
    void ProcessGetMessage();

    /// Process a received remote control "pushreq" message.
    void ProcessPushReqMessage();

    /// \brief Process a received remote control "pushreq" "stats" message.
    ///
    /// \param  client_id  The client identifier.
    /// \param  msg_id     The message identifier.
    /// \param  interval   The update interval.
    /// \param  err_msg    The reference where error strings are appended.
    ///
    /// \return True if the "pushreq" "stats" message is successfully
    ///         processed, false otherwise.
    bool ProcessPushReqStatsMessage(uint32_t client_id, uint32_t msg_id,
                                    double interval, std::string& err_msg);

    /// \brief Process a received remote control "pushreq" "flow_stats"
    /// message.
    ///
    /// \param  client_id  The client identifier.
    /// \param  msg_id     The message identifier.
    /// \param  interval   The update interval.
    /// \param  options    The "flow_stats" options.
    /// \param  err_msg    The reference where error strings are appended.
    ///
    /// \return True if the "pushreq" "stats" message is successfully
    ///         processed, false otherwise.
    bool ProcessPushReqFlowStatsMessage(uint32_t client_id, uint32_t msg_id,
                                        double interval,
                                        const std::string& options,
                                        std::string& err_msg);

    /// Process a received remote control "pushstop" message.
    void ProcessPushStopMessage();

    /// \brief Process a received remote control "set" message with a target
    /// "bpf".
    ///
    /// Check for correctness.  Might apply the set now, or could cache it for
    /// later.
    ///
    /// \param  key_vals  The json key value pairs to parse
    /// \param  err_msg   The reference where the error string must be written.
    ///                   The err_msg is "" if there are no errors.
    ///
    /// \return  A boolean for success (true) or failure (false).
    bool ProcessBpfSetMessage(const ::rapidjson::Value* key_vals,
                              std::string& err_msg);

    /// \brief Process a received remote control "set" message with a target
    /// "pc:<n>".
    ///
    /// \param  key_vals  The reference to the target string.
    /// \param  key_vals  The json key value pairs to parse
    /// \param  err_msg   The reference where the error string must be written.
    ///                   The err_msg is "" if there are no errors.
    ///
    /// \return  A boolean for success (true) or failure (false).
    bool ProcessPcSetMessage(std::string& target,
                             const ::rapidjson::Value* key_vals,
                             std::string& err_msg);

    /// Write network-wide link capacities to the rapidJSON writer.
    /// This method does not take ownership of the writer or its memory.
    ///
    /// Note: This method does not distinguish between 0-capacity and being
    ///       disconnected.
    ///
    /// \param  writer  The rapidJSON writer object to use to fill up the
    ///                 capacities
    void WriteCapacities(::rapidjson::Writer< ::rapidjson::StringBuffer >* writer);

    /// Write network-wide link capacities and latencies to the rapidJSON writer.
    /// This method does not take ownership of the writer or its memory.
    ///
    /// Note: This method does not distinguish between 0-capacity and being
    ///       disconnected.
    ///
    /// \param  writer  The rapidJSON writer object to use to fill up the
    ///                 capacities
    void WriteCapAndLat(::rapidjson::Writer< ::rapidjson::StringBuffer >* writer);

    /// \brief Compute the new set of weights for heavyball.
    void ComputeWeights();

    /// \brief  Apply the virtual queue depth for bin, nbr addr, if it can be
    ///         found in the list
    /// \param  bin_idx  Bin index for which to add virtual queue depth
    /// \param  nbr_bin_idx  Bin index of the neighbor (IRON) node who has this
    ///                 virt queue depth.
    /// \param  Depth   Queue depth to set.
    ///
    /// \return  True if the virtual queue depth could be added, or False
    ///          otherwise
    bool ApplyVirtQueueSet(
      BinIndex bin_idx, BinIndex nbr_bin_idx, uint32_t depth);

    /// \brief  The timer callback method for sending statistics to a remote
    /// control client.
    void PushStats();

    /// \brief  The timer callback method for sending flow statistics to a
    /// remote control client.
    void PushFlowStats();

    /// \brief Information for pushing statistics to a client periodically.
    struct StatsPushInfo
    {
      StatsPushInfo()
          : is_active(false), client_id(0), msg_id(0), interval_sec(0.0),
            timer_handle()
      {}

      bool           is_active;
      uint32_t       client_id;
      uint32_t       msg_id;
      double         interval_sec;
      Timer::Handle  timer_handle;
    };

    /// \brief Information for pushing flow statistics to a client
    /// periodically.
    struct FlowStatsPushInfo
    {
      FlowStatsPushInfo()
          : is_active(false), client_id(0), msg_id(0), interval_sec(0.0),
            timer_handle()
      {}

      bool           is_active;
      uint32_t       client_id;
      uint32_t       msg_id;
      double         interval_sec;
      Timer::Handle  timer_handle;
    };

    /// \brief  The caching key for latency.
    class CacheKey
    {
    public:
      /// \brief  Default constructor.
      CacheKey()
        : visited_his_map_(0)
      {}

      /// \brief  Constructor.
      ///
      /// \param  visited_history_map The bit map of index of nodes previously
      ///                             visited.
      CacheKey(uint32_t visited_history_map)
        : visited_his_map_(visited_history_map)
      {}

      /// \brief  Copy constructor.
      ///
      /// \param  other The cache key object to copy.
      CacheKey(const CacheKey& other)
        : visited_his_map_(other.visited_his_map_)
      {}

      /// \brief  Destructor.
      virtual ~CacheKey()
      {
        visited_his_map_  = 0;
      }

      /// \brief  Hash method of the cache key.
      /// The hash method takes the lowest 11bits, which are all part of the
      /// history vector.  That leaves another 3 bits from the vector and 8 for
      /// the destination bin index.  That means there could be 2^11 = 2048
      /// elements in each bucket linked list.  In reality, we expect that they
      /// will be much shorter as there are only a few destinations.
      inline size_t Hash() const
      {
        return visited_his_map_ & 0x7FF;
      }

      /// \brief  Equality operator.
      ///
      /// \param  other_key The other cache key object to compare to.
      ///
      /// \return 0 if equal, non-zero otherwise.
      int operator==(const CacheKey& other_key) const
      {
        return visited_his_map_ == other_key.visited_his_map_;
      }

      /// \brief  Copy operator.
      ///
      /// \param  other The other cache key to copy.
      ///
      /// \return This cache key, copied from the other cache key.
      CacheKey& operator=(const CacheKey& other)
      {
        if (this != &other)
        {
          visited_his_map_  = other.visited_his_map_;
        }
        return *this;
      }

      /// The bit map of the indices of the previously-visited nodes.
      uint32_t  visited_his_map_;
    };

    /// \brief  Per-path controller cached latency for a given destination bin.
    class CachedLatencyData
    {
    public:
      /// \brief  Default constructor.
      CachedLatencyData()
        : cache_time_(0),
          destination_(0),
          latencies_(NULL)
      {}

      /// \brief  Constructor.
      ///
      /// \param  dst_bin_idx The bin index of the destination node.
      /// \param  lat The array of the latencies on each path controller (the
      ///             size is num_path_ctrls_).
      /// Ownership of memory pointed by other object's lat is transferred to
      /// this object.
      CachedLatencyData(BinIndex dst_bin_idx, uint32_t* lat)
        : cache_time_(Time::Now()),
          destination_(dst_bin_idx),
          latencies_(lat)
      {}

      /// \brief  Copy constructor.
      ///
      /// \param  The other CachedLatencyData object to copy from.
      /// Ownership of memory pointed by other object's lat is transferred to
      /// this object.
      CachedLatencyData(const CachedLatencyData& other)
        : cache_time_(other.cache_time_),
          destination_(other.destination_),
          latencies_(other.latencies_)
      {}

      /// \brief  Destructor.
      virtual ~CachedLatencyData()
      {
        cache_time_   = Time::Infinite();
        destination_  = 0;
        if (latencies_)
        {
          LogW("CachedLatencyData", __func__,
               "Latencies pointer is not NULL and memory was likely lost. Was "
               "DestroyLatencies called?\n");
        }
        latencies_  = NULL;
      }

      /// \brief  Destroy (delete) the memory pointed to be latencies_.
      void DestroyLatencies()
      {
        if (latencies_)
        {
          delete[] latencies_;
          latencies_  = NULL;
        }
      }

      /// \brief  Get the time of validity of the cached data.
      ///
      /// \return The time at which the cache data was valid.
      inline const Time& cache_time() { return cache_time_; }

      /// \brief  Get the destination of the traffic for which latency is
      ///         stored.
      ///
      /// \return The bin index of the destination.
      inline BinIndex destination() { return destination_; }

      /// \brief  Get the array of latency per path controller.
      ///
      /// \return The pointer to the start of the array of per-pc latency.
      inline const uint32_t* latencies() { return latencies_; }

      /// \brief  Update the latency data for a given cached object.
      ///
      /// \param  dst_bin_idx The bin index of the destination node.
      /// \param  lat The array of the latencies on each path controller (the
      ///             size is num_path_ctrls_).
      /// Ownership of the memory pointed by lat is not transferred to this
      /// object.
      void UpdateLatencyData(BinIndex dst_bin_idx, uint32_t* lat,
        uint8_t num_pcs)
      {
        cache_time_   = Time::Now();
        destination_  = dst_bin_idx;
        memcpy(latencies_, lat, sizeof(*lat) * num_pcs);
      }

      /// \brief  Assignment operator.
      ///
      /// \param  other The other cached latency data object to copy.
      /// Ownership of memory pointed by other object's lat is transferred to
      /// this object.
      ///
      /// \return This object, copied from other.
      CachedLatencyData& operator=(const CachedLatencyData& other)
      {
        if (this != &other)
        {
          cache_time_   = other.cache_time_;
          destination_  = other.destination_;
          latencies_    = other.latencies_;
        }
        return *this;
      }

    private:
      /// The time at which the cached results are considered valid.
      Time      cache_time_;

      /// Destination node index---only used for sanity checking.
      BinIndex  destination_;

      /// Pointer to num_path_ctrls_ latencies in microseconds.
      uint32_t* latencies_;
    };

    /// Pool containing packets to use.
    PacketPool&                         packet_pool_;

    // Manger of timers.
    Timer&                              timer_;

    /// Shared memory object to share weight queue depths with proxies.
    SharedMemoryIF&                     weight_qd_shared_memory_;

    /// The per-qlam overhead (headers) to be used for computing QLAM send rate.
    uint32_t                            per_qlam_overhead_bytes_;

    /// The current sequence number of the QLAM.
    BinIndexableArray<uint32_t>         qlam_sequence_number_;

    /// The per-nbr time when a qlam was last received.
    BinIndexableArray<iron::Time>       last_qlam_time_;

    /// Whether to dequeue multiple packets.
    bool                                multi_deq_;

    /// The maximum size of the CAT xmit buffer.
    size_t                              xmit_buf_max_thresh_;

    /// BPF stats tracking
    BpfStats                            bpf_stats_;

    /// The object providing remote control capabilities.
    RemoteControlServer                 remote_control_;

    /// Information on any active statistics pushing to a remote control
    /// client.  Can only push to a single client at a time due to statistics
    /// resetting on each push.
    StatsPushInfo                       stats_push_;

    /// Information on any active flow statistics pushing to a remote control
    /// client. Can only push to a single client at a time due to flow
    /// statistics resetting on each push.
    FlowStatsPushInfo                   flow_stats_push_;

    /// The last time the BPF copied the queue depths to the shared memory
    /// segments.
    Time                                last_qd_shm_copy_time_;

    /// The number of bytes that need to change before we write the queue depths
    /// to the shared memory segments.
    uint32_t                            min_qd_change_shm_bytes_;

    /// The number of bytes processed from the TCP and UDP packets.
    uint32_t                            num_bytes_processed_;

    /// The multiplier by which to multiply number of hops to obtain virtual
    /// gradients (in bytes).
    uint32_t                            virt_queue_mult_;

    /// Tracks the latest sequence number seen for each type of broadcast
    /// packet from each source bin. Keyed by [broadcast index, bin index].
    BinIndexableArray<uint16_t>         broadcast_seq_nums_[NUM_BC_IDX];

    /// The factor by which the std dev is multiplied before added to time-to-
    /// reach (ttr) for fit aglorithm which compares time-to-go to:
    /// avg(ttr) + ttr_sigma_factor_ * sigma(ttr)
    double                              ttr_sigma_factor_;

    /// The boolean indicating whether to do latency collection on LSAs.
    bool                                ls_latency_collection_;

    /// The current sequence number to place in new LSAs.
    uint32_t                            lsa_seq_num_;

    /// Whether the anti-circulating approach is ConditionalDAG.
    bool                                conditional_dags_;

    /// The latency cache.
    /// It is a hash table that takes a key (shifted destination + history
    /// vector) and stores cached latency data (an array of size the number of
    /// path controllers).
    iron::HashTable<CacheKey, CachedLatencyData*> latency_cache_;

    /// The time at which the cache was reset.
    Time                                latency_cache_reset_time_;

    /// The shared memory latency (in us) cache per destination.
    LatencyCacheShm                     shm_latency_cache_;

    /// The last time the minimum latency cache was updated.
    uint64_t                            latency_pbpp_update_time_ms_;

    /// The LSA hold down time (to convert in ms) (min time between LSAs).
    Time                                lsa_hold_down_time_;

    /// The boolean indicating if holding down before sending LSA (true).
    uint32_t                            lsa_hold_down_;

    /// The interval between LSAs.
    uint32_t                            lsa_interval_ms_;

    /// The time at which the last LSA was sent.
    Time                                last_lsa_send_time_;

    /// The timer handle for the LSA timer.
    Timer::Handle                       lsa_timer_handle_;

    /// The node information array for generating and parsing LSAs.  Indexed
    /// by unicast destination, interior node, or multicast destination bin
    /// index.
    BinIndexableArray<NodeInfo>         lsa_info_;

    /// The interval between GRAMs.
    uint32_t                            gram_interval_ms_;

    /// The timer handle for the GRAM timer.
    Timer::Handle                       gram_timer_handle_;

    /// The ratio of the network capacity allowed for overhead (QLAMs):
    double                              overhead_ratio_;

    /// The maximum QLAM interval in usec permissible (must not exceed uint32
    /// representation!):
    uint32_t                            max_qlam_intv_usec_;

    /// The statistics collection interval, in milliseconds.
    uint32_t                            stats_interval_ms_;

    /// True if configured to send metadata that can be used for packet
    /// tracing.
    bool                                do_packet_tracing_;

    /// True if configured to track time-to-go via Sliq info headers.
    bool                                do_ttg_tracking_;

    /// The EF packet ordering approach.
    EFOrdering                          ef_ordering_;

    /// Random Number Generator object.
    RNG                                 rng_;

    /// Used for tracking values over time for debugging purposes.
    DebuggingStats*                     debugging_stats_;

    /// True if expired packets should be dropped, false if they should be
    /// Zombified.
    bool                                drop_expired_;

    /// The number of dropped bytes following expired packets.
    BinIndexableArray<uint32_t>         dropped_bytes_;

    /// True if we are configured to drop zombies when we dequeue them instead
    /// of sending them to the neighbor. Configured using
    /// Bpf.DropDequeuedZombies.
    bool                                drop_dequeued_zombies_;

    /// True if we are configured to drop any received zombies (whether
    /// they're "to" this node or not) rather than enqueuing them to later be
    /// transmitted downstream. Configured using Bpf.DropRcvdZombies.
    bool                                drop_rcvd_zombies_;

    /// Boolean to drop packets that arrive expired.
    bool                                drop_expired_rcvd_packets_;

    /// Count stale QLAMs and log during shutdown.
    uint32_t                            num_stale_qlams_rcvd_;

    /// Indicate whether multicast forwarding is on or not.
    bool                                mcast_fwding_;

    /// Indicate whether to exchange aggregate bin depths in QLAMs, use them for
    /// mcast forwarding.
    bool                                mcast_agg_;

    /// Linked list to store a list of multicast group for which the iron node
    /// is a receiver.
    iron::List<Ipv4Address>            mcast_group_memberships_;

    /// The config info object used configure the BPF. This is used for configuring
    /// Queue Managers on demand.
    iron::ConfigInfo&                  config_info_;

    // The maximum number of solutions that may be returned during each
    // execution of the dequeue algorithm.
    uint8_t                            max_num_dequeue_alg_solutions_;

    /// A flag to indicate if group advertisement messages are to be sent.
    bool                               send_grams_;
  }; // end class BPFwder

} // namespace iron

#endif // IRON_BPF_BACKPRESSURE_FWDER_H
