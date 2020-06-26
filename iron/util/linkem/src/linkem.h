//============================================================================
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
//============================================================================

#ifndef IRON_UTIL_LINKEM_LINKEM_H
#define IRON_UTIL_LINKEM_LINKEM_H

#include "error_model.h"
#include "frame.h"
#include "frame_pool.h"
#include "high_resolution_clock.h"
#include "list.h"
#include "jitter_model.h"

#include <cstring>
#include <netinet/in.h>
#include <linux/if.h>
#include <values.h>

#include <list>

/// Two interfaces. This is unlikely to ever change.
#define NUM_IFS      2

/// The number of paths supported for each interface.
#define NUM_PATHS    25

/// The number of subnets supported for each path.
#define NUM_SUBNETS  8

/// Captures the information for a subnet associated with a LinkEm Path.
struct SubnetInfo
{
  SubnetInfo()
  : address(0), mask(0), prefix(0), subnet(0)
  {
  }

  /// The subnet address.
  in_addr_t  address;

  /// The subnet mask.
  uint32_t   mask;

  /// The subnet mask prefix.
  uint32_t   prefix;

  /// The subnet.
  uint32_t   subnet;

}; // end struct SubnetInfo

/// \brief Collected statistics.
struct Statistics
{
  /// \brief Constructor.
  Statistics()
  : dropped_q_pkt_cnt(0), dropped_q_byte_cnt(0), dropped_err_pkt_cnt(0),
    dropped_err_byte_cnt(0), packets_rcvd(0), bytes_rcvd(0), packets_sent(0),
    bytes_sent(0), last_dump(0)
  {
  }

  /// Count of the number of dropped packets due to buffer overflow.
  size_t  dropped_q_pkt_cnt;
  /// Count of the number of bytes dropped due to buffer overflow.
  size_t  dropped_q_byte_cnt;
  /// Count of the number of dropped packets due to error model.
  size_t dropped_err_pkt_cnt;
  /// Count of the number of bytes dropped due to the error model.
  size_t dropped_err_byte_cnt;
  /// Total number of packets received on path
  unsigned long long packets_rcvd;
  /// Total number of bytes received on path
  unsigned long long bytes_rcvd;
  /// Total number of packets sent on path
  unsigned long long packets_sent;
  /// Total number of bytes sent on path
  unsigned long long bytes_sent;
  /// Last time stats DumpStats() was called
  unsigned long long last_dump;

}; // end struct Statistics

/// \brief Access link information.
struct AccessLinkInfo
{
  AccessLinkInfo()
  : throttle(0.0), throttle2(0.0), do_throttle(false), last_time(0),
    credit(0), remainder(0.0), next_release_time(ULLONG_MAX)
  {
  }

  /// Access link throttle value, in Kbps.
  double              throttle;

  /// Precomputed (at SetAccessThrottle) bytes/ns value.
  double              throttle2;

  /// Remembers if the access link is throttled.
  bool                do_throttle;

  /// The last time the access link credits were adjusted.
  unsigned long long  last_time;

  /// Accumulated access link credits.
  long long           credit;

  /// Fractional access link credits to carry over.
  double              remainder;

  /// The access link next packet release time.
  unsigned long long  next_release_time;

}; // end struct AccessLinkInfo

/// \brief Serialization delay modeling information.
struct SerDelayInfo
{
  public:

  /// \brief Constructor.
  SerDelayInfo()
  : credit(0), remainder(0.0), queue(), queue_size_bytes(0), last_time(0)
  {
  }

  /// Current serialization delay credit.
  long long           credit;

  /// Fractional serialization delay credits to carryover.
  double              remainder;

  /// The path's serialization delay queue.
  iron::List<Frame*>  queue;

  /// The current number of bytes in the serialization delay buffer.
  int                 queue_size_bytes;

  /// The last time serialization delay credits were adjusted.
  unsigned long long  last_time;

}; // end struct SerDelayInfo

/// \brief Information that is associated with a LinkEm Path.
struct PathInfo
{
  public:

  /// \brief Constructor.
  PathInfo()
  : mtu(0), index(0), max_sd_queue_depth(0), sd_queue_size_is_in_bytes(true),
    delay_ns(0), add_delay(false), pd_queue(), throttle(0.0), throttle2(0.0),
    do_throttle(false), error_model(NULL), jitter_model(NULL), num_subnets(0),
    in_use(false), sock(-1), stats()
  {
    memset(subnets, 0, sizeof(subnets));
  }

  /// Name of the interface.
  char                name[IFNAMSIZ];

  /// Hardware (MAC) address.
  unsigned char       hardware[IFHWADDRLEN];

  /// MTU
  int                 mtu;

  /// Index of the interface.
  int                 index;

  /// Serialization delay modeling information.
  SerDelayInfo        sd_info[2];

  /// The depth of the incoming buffer.
  int                 max_sd_queue_depth;

  /// Remembers if the serialization delay queue size is in units of bytes.
  bool                sd_queue_size_is_in_bytes;

  /// Propagation delay, in nanoseconds.
  unsigned long long  delay_ns;

  /// Remembers if we are adding propagation delay.
  bool                add_delay;

  /// The propagation delay queue.
  iron::List<Frame*>  pd_queue;

  /// Throttle value, in Kbps.
  double              throttle;

  /// Precomputed (at setThrottle) bytes/ns value.
  double              throttle2;

  /// Remembers if the path is throttled.
  bool                do_throttle;

  /// The model being emulated on this interface.
  ErrorModel*         error_model;

  /// The jitter model.
  JitterModel*        jitter_model;

  /// The number of configured subnets.
  uint8_t             num_subnets;

  /// The subnets.
  SubnetInfo          subnets[NUM_SUBNETS];

  /// Remembers if the path has been fully configured and is currently in use
  /// by the LinkEm.
  bool                in_use;

  /// The raw socket associated with the interface.
  int                 sock;

  /// Captured statistics.
  Statistics          stats;

  /// \brief Get string representation of path.
  ///
  /// \return String representation of path.
  std::string StringPrint();

}; // end struct PathInfo

/// \brief The LinkEm.
class LinkEm
{
  public:

  /// \brief Default constructor.
  LinkEm();

  /// \brief Destructor.
  virtual ~LinkEm();

  /// \brief Initialize the bridge between the two interfaces.
  ///
  /// \param  if1  Name of interface one, e.g., "eth0".
  /// \param  if2  Name of interface two, e.g., "eth1".
  ///
  /// \return True if successful, false otherwise.
  bool Initialize(const char* if1, const char* if2);

  /// \brief Configure the LinkEm.
  ///
  /// \param  file_name  The name of the configuration file.
  ///
  /// \return True if the LinkEm is successfully configured, false otherwise.
  bool Configure(const char* file_name);

  /// \brief Main service loop for the LinkEm.
  void Start();

  /// \brief Set the flag that controls when the LinkEm main loop terminates.
  ///
  /// \param  done  Indicates if the LinkEm main loop should terminate.
  inline void set_done(bool done)
  {
    done_ = done;
  }

  /// \brief Set the management listen port.
  ///
  /// \param  port  The management listen port.
  inline void set_mgmt_port(int port)
  {
    mgmt_port_ = port;
  }

  /// \brief Sets the TOS bypass value.
  ///
  /// \param bypass_tos_value  TOS value that redirects traffic to a separate
  ///                          queue.
  void set_bypass_tos_value(int bypass_tos_value);

  /// \brief Returns the interfaces to their initial state (turns off
  /// promiscuous mode).
  ///
  /// \return True if successful, false otherwise.
  bool CleanupBridge();

  private:

  /// Copy constructor.
  LinkEm(const LinkEm& other);

  /// Copy operator.
  LinkEm& operator=(const LinkEm& other);

  /// \brief Configure the default path, Path 0.
  void ConfigureDefaultPath();

  /// \brief Create the server socket that services connections from the
  /// control client.
  ///
  /// \return Server socket file descriptor if successful, -1 if there is an
  ///         error.
  int CreateServerSocket();

  /// \brief Sets up the interface lookup structures.
  ///
  /// \param  p          Index of the interface (in interfaces[]).
  /// \param  interface  Name of the interface.
  ///
  /// \return True if successful, false otherwise.
  bool InitializeInterfaceLookup(int p, const char* interface);

  /// \brief Process a received frame.
  ///
  /// \param  frame  The received frame.
  void ProcessRcvdFrame(Frame* frame);

  /// \brief Get the access link serialization delay, in nanoseconds.
  ///
  /// Accumulates access link credits and computes the access link
  /// serialization delay, in nanoseconds.
  ///
  /// \param  frame       The received frame.
  /// \param  if_num      The interface number.
  /// \param  bypass_num  The bypass indicator, 0 for normal traffic and 1 for
  ///                     bypass traffic.
  ///
  /// \return The access link serialization delay, in nanoseconds.
  unsigned long long GetAccessLinkSerDelay(Frame* frame, int if_num,
                                           int bypass_num);

  /// \brief Get the path serialization delay, in nanoseconds.
  ///
  /// Accumulates path credits and computes the path serialization delay, in
  /// nanoseconds.
  ///
  /// \param  frame       The received frame.
  /// \param  if_num      The interface number.
  /// \param  path_num    The path number.
  /// \param  bypass_num  The bypass indicator, 0 for normal traffic and 1 for
  ///                     bypass traffic.
  ///
  /// \return The path serialization delay, in nanoseconds.
  unsigned long long GetPathSerDelay(Frame* frame, int if_num, int path_num,
                                     int bypass_num);

  /// \brief Process frames that have been received on the WAN-facing
  /// interface.
  ///
  /// Thhis processing happens after the serialization delay for the frame has
  /// been modeled. The result of the processing either "bridges" the received
  /// frame to the LAN-facing interface or places the frame in the propagation
  /// delay queue.
  void TransmitFramesToLanIf();

  /// \brief Process frames that have been received on the LAN-facing
  /// interface.
  ///
  /// Thhis processing happens after the serialization delay for the frame has
  /// been modeled. The result of the processing either "bridges" the received
  /// frame to the WAN-facing interface or places the frame in the propagation
  /// delay queue.
  void TransmitFramesToWanIf();

  /// \brief Take the given frame and do error modeling (if a model is defined)
  /// and delay modeling (if a delay model is defined).
  ///
  /// If delay modeling is defined, the frame is put in the WaitingQueue for
  /// later forwarding, otherwise the frame is forwarded now. If an error
  /// model is defined, the model is applied to the frame before delay
  /// processing takes place.
  ///
  /// \param   frame     The frame on which to perform error and delay
  ///                    modeling.
  /// \param  path_num  The path to which the frame belongs.
  void ModelErrorAndDelay(Frame* frame, short path_num);

  /// \brief Transmit the frame out the destination interface.
  ///
  /// \param  frame  The frame to transmit.
  ///
  /// \return The number of bytes transmitted or -1 if an error occurs.
  int BridgeFrame(Frame* frame);

  /// \brief Process a command.
  ///
  /// The commands to process come from either: 1) the configuration file that
  /// is used to configure the LinkEm at startup or 2) the messages that are
  /// received from the LinkEmClient to change the behavior of the running
  /// LinkEm.
  ///
  /// \param  command  The received command string.
  ///
  /// \return Response to the received command. If a received command does not
  ///         generate in a response, an empty string ("") is returned.
  std::string ProcessCmd(const std::string& command);

  /// \brief Process an AccessLink command.
  ///
  /// \param  path_cmd  The received AccessLink command.
  /// \param  if_num    The interface number.
  void ProcessAccessLinkCmd(const std::string& access_link_cmd,
                            uint8_t if_num);

  /// \brief Process a Path command.
  ///
  /// \param  path_cmd  The received Path command.
  /// \param  path_num  The path number.
  /// \param  if_num    The interface number.
  void ProcessPathCmd(const std::string& path_cmd, uint8_t path_num,
                      uint8_t if_num);

  /// \brief Set the subnets for a Path.
  ///
  /// Note: This method will completely replace any existing subnet
  /// specifications for the Path.
  ///
  /// \param  subnets_str  The subnets as a string.
  /// \param  path_num     The path number.
  void SetSubnets(const std::string& subnets_str, uint8_t path_num);

  /// \brief Remember that a Path is configured and currently in use.
  ///
  /// \param  path_num  The path number.
  /// \param  if_num    The interface number.
  void SetInUse(uint8_t path_num, uint8_t if_num);

  /// \brief Convert the provided address into a string.
  ///
  /// \param  address  The address to convert to a string.
  ///
  /// \return The address as a string.
  std::string AddressToString(in_addr_t address) const;

  /// \brief Get a string representation of the LinkEm state.
  ///
  /// \return String representation of the LinkEm state.
  std::string ToString() const;

  /// \brief Process a cli message from a LinkEm control client.
  ///
  /// \param  server_socket  The server socket listening for connections from
  ///                        the control client.
  ///
  /// \return 0 if successful, -1 if an error occurs.
  int ProcessCliMsg(int server_socket);

  /// \brief Sets the provided interface's promiscuous mode (turns it on or
  /// off).
  ///
  /// \param  s          Socket descriptor.
  /// \param  interface  The name of the interface, e.g., "eth0", to be
  ///                    modified.
  /// \param  on         True turn on promiscuous mode, false to turn it off.
  ///
  /// \return True if successful, false otherwise.
  bool SetPromiscuous(int s, const char* interface, bool on);

  /// \brief Detect if the IP header contains the magic TOS value.
  ///
  /// \param  frame  The received frame.
  ///
  /// \return True if the received frame TOS value is equal to the magic
  ///         value, false otherwise.
  bool HasBypassBitsSet(Frame* frame);

  /// \brief Get the number of the path that the packet matches.
  ///
  /// \param  packet  The received packet.
  /// \param  len     The length of the received packet.
  /// \param  if_num  The interface the packet was received on.
  ///
  /// \return The number of the path that the packet matches. -1 is returned
  ///         if a match is not found.
  uint8_t GetPathNumber(Frame* frame, int if_num);

  /// \brief Sets the simulation model for the LinkEm.
  ///
  /// \param  model_name  The model name.
  /// \param  path_num    The path number.
  /// \param  if_num      The interface number.
  void SetErrorModel(std::string model_name, int path_num, int if_num);

  /// \brief Passes the parameter to the current model for processing.
  ///
  /// \param  name      The model feature name.
  /// \param  value     The model feature value.
  /// \param  path_num  The path number.
  /// \param  if_num    The interface number.
  void SetErrorModelFeature(std::string name, std::string value, int path_num,
                            int if_num);

  /// \brief Sets the jitter model.
  ///
  /// \param  model_name  The jitter model name.
  /// \param  path_num    The path number.
  /// \param  if_num      The interface number.
  void SetJitterModel(const std::string& model_name, int path_num,
                      int if_num);

  /// \brief Set a jitter model feature.
  ///
  /// \param  name      The jitter model feature name.
  /// \param  value     The jitter model feature value.
  /// \param  path_num  The path number.
  /// \param  if_num    The interface number.
  void SetJitterModelFeature(const std::string& name,
                             const std::string& value, int path_num,
                             int if_num);

  /// \brief Sets the delay.
  ///
  /// \param  delay_msec  The delay, in milliseconds.
  /// \param  path_num    The path number.
  /// \param  if_num      The interface number.
  void SetDelay(int delay_msec, int path_num, int if_num);

  /// \brief Sets the access link throttle.
  ///
  /// \param  throttle_kbps  The throttle limit, in Kbps.
  /// \param  if_num         The interface number.
  void SetAccessLinkThrottle(double throttle_kbps, int if_num);

  /// \brief Sets the throttle.
  ///
  /// \param  throttle_kbps  The throttle limit, in Kbps.
  /// \param  path_num       The path number.
  /// \param  if_num         The interface number.
  void SetThrottle(double throttle_kbps, int path_num, int if_num);

  /// \brief Sets the size of the serialization delay buffer.
  ///
  /// \param  buffer_size    The size of the serialization delay buffer, in
  ///                        bytes.
  /// \param  path_num       The path number.
  /// \param  if_num         The interface number.
  void SetMaxSdBufferDepth(int buffer_size, int path_num, int if_num);

  /// \brief Sets the type of accounting used to determine if the
  /// serialization delay buffer is full.
  ///
  /// Valid values are BYTE (for using bytes in the buffer) or PKT (for using
  /// total packets in the buffer) when determining if the recently received
  /// packet will fit into the serialization delay buffer.
  ///
  /// \param  type      The type of accounting used to determine if the
  ///                   serialization delay buffer is full.
  /// \param  path_num  The path number.
  /// \param  if_num    The interface number.
  void SetSdBufferAccountingType(const std::string& type, int path_num,
                                 int if_num);

  /// \brief Determines if the provided interface is one of the 2 interfaces
  /// that are being bridged.
  ///
  /// \param  interface  The interface to check.
  ///
  /// \return True if the prvoided interface is one of the two being bridged,
  ///         false otherwise.
  bool IsLinkEmGroup(int interface);

  /// \brief Get the array index for the provided interface index.
  ///
  /// \param  if_index  Index of the interface.
  ///
  /// \return Array index corresponding to the provided interface index.
  int IndexIF(int if_index);

  /// \brief Get the array index for the other interface index.
  ///
  /// \param  if_index  Index of the interface.
  ///
  /// \return Array index corresponding to the other interface index.
  int OtherIF(int if_index);

  /// \brief Dump out the collected statistics.
  void DumpStats(unsigned long long cur_time);

  /// \brief Generate a 'message too big' ICMP packet when an oversized packet
  /// is received.
  ///
  /// \param  packet  The received packet.
  /// \param  len     The length of the received packet.
  /// \param  max_mtu  The maximum MTU supported.
  ///
  /// \return Length of the reply message, or -1 if there is an error.
  int SetupPmtuMsg(unsigned char* packet, unsigned int len, int max_mtu);

  /// \brief Calculates checksum.
  ///
  /// \param  ptr        The bytes over which to compute the checksum.
  /// \param  num_bytes  The number of bytes to include in the checksum
  ///                    calculation.
  /// \return The calculated checksum.
  unsigned short in_cksum(unsigned short* ptr, int nbytes);

  /// \brief Retrieve a reference to an path information structure.
  ///
  /// \param  path_num  The Path number.
  /// \param  if_num    The interface number.
  ///
  /// \return Reference to the path information structure corresponding to the
  ///         provide Path and interface numbers.
  PathInfo& GetPathInfo(int path_num, int intf);

  /// \brief Get a MAC address in hex c-string format, ready for
  /// human-readable output.
  ///
  /// \param  mac  The MAC address to convert to a human readable string.
  ///
  /// \return The MAC address in human readable form.
  const std::string MacFormat(const unsigned char mac[6]) const;

  /// Remembers if the main processing loop should continue.
  bool                 done_;

  /// The high resolution clock.
  HighResolutionClock  hrc_;

  /// Raw socket, bound to interface 1.
  int                  if1_raw_socket_;

  /// Raw socket, bound to interface 2.
  int                  if2_raw_socket_;

  /// The Frame object pool.
  FramePool            frame_pool_;

  /// The management listen port.
  int                  mgmt_port_;

  /// The bypass TOS value.
  unsigned char        bypass_tos_value_;

  /// Count of the number of packets received that are not from interface 1 or
  /// interface 2.
  unsigned int         not_in_group_cnt_;

  /// The Paths being modeled by the LinkEm.
  PathInfo             paths_[NUM_IFS][NUM_PATHS];

  /// The access link information.
  AccessLinkInfo       access_links_[NUM_IFS][2];

  /// The next statistics report time, in nanoseconds.
  unsigned long long   stats_report_time_ns_;

  /// The statistics reporting interval, in milliseconds.
  unsigned long long   stats_report_int_ms_;

  /// Remembers if we are logging statistics.
  bool                 log_stats_;

}; // end class LinkEm

#endif // IRON_UTIL_LINKEM_LINKEM_H
