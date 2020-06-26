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
/// Implements the Admission Planner (AMP) in IRON.
///
/// AMP runs on each IRON node and controls admission control in each of the
/// proxies by sending and updating service definitions.
/// AMP also acts as an intermediatary between the proxies and the Red GUI.
/// AMP has a remote control client and a remote control server object.
/// The client object manages connections to the IRON proxies and the
/// server object manages connections to the red GUI.
///
/// AMP performs supervisory control by looking at the state of the flows
/// (as reported by local proxies),  the state of the network (as reported
/// by the BPF) and determining which flows should be on. It signals the
/// proxies with any necessary changes to the FlowState over the remote
/// control interface.
///
/// Configuration file passed to amp_main, or else the default values will be 
/// used. When running automated experiments, set these in system.cfg to 
/// override the defaults."
///
///                               CMD file
///                                  |
/// +-----------+                    |
/// | TCP proxy |           +-----------------+
/// | (rc svr)  |-----------|                 |
/// +-----------+           |      AMP        |
///                         |                 |
/// +-----------+           |                 |       +-----------+
/// | TCP proxy |-----------|rc        rc     |-------| GUI       |
/// | (rc svr)  |           |client    server |       | rc client |
/// +-----------+           |                 |       +-----------+
///                         |                 |
/// +-----------+           |                 |
/// |    BPF    |-----------|                 |
/// | (rc svr)  |           |                 |
/// +-----------+           +-----------------+
///

#ifndef IRON_AMP_H
#define IRON_AMP_H

#include "config_info.h"
#include "four_tuple.h"
#include "hash_table.h"
#include "ipv4_address.h"
#include "iron_constants.h"
#include "remote_control.h"
#include "supervisory_ctl_if.h"
#include "svcr.h"
#include "timer.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <list>
#include <vector>
#include <string>

#include <stdint.h>
#include <sys/select.h>

namespace iron
{
  /// The maximum number of targets supported by AMP.
  const uint8_t   kMaxNumAmpSupportedTargets  = 3;

  /// The maximum number of connection retries on initialization
  const int32_t   kMaxNumRetries  = 15;
  
  /// Create simple mapping of target to location in CachedRCMessages array:
  /// [bpf, udp_proxy, tcp_proxy, undefined]
#define TGT_TO_INDEX(tgt)   ((tgt) == "bpf" ? 0 : (tgt) == "udp_proxy" ? 1 :  \
                             (tgt) == "tcp_proxy" ? 2 : 3)

  /// Check if the index is a valid target location in CachedRCMessages array.
#define IS_VALID_TGT_INDEX(index)   (index >= 0 &&                      \
                                     index < kMaxNumAmpSupportedTargets)

  /// Structure to store config file commands and the time they
  /// should be executed.
  struct CmdEntry
  {
    int           time_;
    ::std::string tgt_;
    ::std::string cmd_;
    ::std::string arg1_;
    ::std::string arg2_;

    /// \brief Default constructor
    CmdEntry()
      : time_(0), tgt_(""), cmd_(""), arg1_(""), arg2_("") {}
  };

  /// Structure used to cache service definitions for the attached proxies.
  struct SvcDefn
  {
    std::string   prot;
    uint32_t      lo_port_hbo;
    uint32_t      hi_port_hbo;
    ::std::string utility_fn;
    ::std::string defn_str;
    // Note: The ttg is only used by the UDP Proxy and it is a required field.
    ::std::string ttg;

    /// \brief  Default constructor.
    SvcDefn()
      : prot(""), lo_port_hbo(0), hi_port_hbo(0), utility_fn(""),
        defn_str(""), ttg("0") {}

    /// \brief  Constructor with a port range and utility function string.
    /// \param prot       The protocol used for the flow (udp or tcp).
    /// \param lo_port    The lower end of the port range for the service
    ///                   definition.
    /// \param hi_port    The upper end of the port range for the service
    ///                   definition.
    /// \param utility_fn A string with the utility function associated with
    ///                   the service.
    /// \param ttg        The deadline for a packet to arrive at the
    ///                   destination.
    /// \param defn_str   A string with the entire service definition.
    SvcDefn(std:: string prot, uint32_t lo_port, uint32_t hi_port,
            ::std::string utility_fn, ::std::string defn_str, ::std::string ttg)
      : prot(prot), lo_port_hbo(lo_port), hi_port_hbo(hi_port),
        utility_fn(utility_fn), defn_str(defn_str), ttg(ttg) {}
  };

  /// Structure used to cache flow definitions for the attached proxies.
  /// Flow definitions are specific to address:port pair for the source
  /// and destination of the flow.
  struct FlowDefn
  {
    ::std::string tuple;
    ::std::string utility_fn;
    ::std::string defn_str;
    // Note: The ttg is only used by the UDP Proxy and it is a required field.
    ::std::string ttg;

    /// \brief  Default constructor.
    FlowDefn()
      : tuple(""), utility_fn(""), defn_str(""), ttg("0") {}

    /// \brief  Constructor with the tuple and utility function.
    /// \param  tuple      A string of the  form sport:dport:saddr:daddr.
    /// \param  utility_fn A string with the utility function associated with
    ///                    the flow.
    /// \param ttg         The deadline for a packet to arrive at the
    ///                    destination.
    /// \param defn_str    A string with the entire flow definition.
    FlowDefn(::std::string tuple, ::std::string utility_fn,
            ::std::string defn_str, ::std::string ttg)
      : tuple(tuple), utility_fn(utility_fn), defn_str(defn_str), ttg(ttg) {}
  };

  class Amp
  {

  public:

    /// \brief  The constructor.
    /// \param  timer The timer instance for AMP.
    /// \param  cmd_file A file with the timed commands for AMP to execute.
    Amp(iron::Timer& timer, const ::std::string& cmd_file="");

    /// \brief The destructor.
    virtual ~Amp();

    /// \brief   Initialize Amp with connections and configurations
    ///          for the specific node it is running on.
    /// \param   ci A config info object for the IRON node for this AMP.
    /// \return  True if successful.
    bool Initialize(const ConfigInfo& ci);

    /// \brief Start the AMP process.
    void Start();

    /// \brief  Start the stats collection for the BPF or proxies to push stats.
    ///
    /// \param  target  The target (bpf, udp_proxy or tcp_proxy).
    void StartStatsCollection(std::string target);

    /// \brief  Start the stats collection for the BPF or proxies to stop
    ///         pushing stats.
    ///
    /// \param  target  The target (bpf, udp_proxy or tcp_proxy).
    void StopStatsCollection(std::string target);

    /// \brief  Send a message through AMP's remote control server to a
    ///         specified endpoint.
    /// \param  ep_id    The ID of the destination endpoint.
    /// \param  str_buf  A reference to the string buffer wrapped by the JSON
    ///                  writer.
    /// \return true if the message was successfully sent.
    virtual bool SendMessageToServer(uint32_t ep_id,
                                     rapidjson::StringBuffer& str_buf)
      { return (rc_server_.SendMessage( ep_id, str_buf)); }

    /// \brief Send a message through AMP's remote control client to a
    ///   specified endpoint.
    /// \param ep_id    The ID of the destination endpoint.
    /// \param str_buf  A reference to the string buffer wrapped by the JSON
    ///   writer.
    /// \return true if the message was successfully sent.
    virtual bool SendMessageToClient(uint32_t ep_id,
                                     rapidjson::StringBuffer& str_buf)
      { return (rc_client_.SendMessage( ep_id, str_buf)); }

    /// \brief Send a set message through AMP's remote control client to
    ///        a specified proxy.
    /// \param target The name of the proxy to which the message is being
    ///        sent.
    /// \param cmd The command in the set message.
    /// \param arg The argment of the command.
    virtual void SendSetMsgToClient(std::string target, std::string cmd,
                                    std::string arg)
      { return rc_client_.SendSetMessage(connection_map_[target],
          target, cmd, arg); }

    /// \brief Get the "set" request message contents.
    ///
    /// \param  target            A reference where the target will be placed.
    /// \param  key_value_object  A reference to a pointer that will be set to
    ///                           the set message's object of key/value pairs.
    ///                           Use the RapidJSON Value methods for
    ///                           accessing the key/value pairs.
    ///
    /// \return  True on success, or false otherwise.
    virtual bool GetSetMessageFromServer(std::string& target,
                       const rapidjson::Value*& key_value_object) const
      { return (rc_server_.GetSetMessage(target, key_value_object)); }

    /// \brief Get the "set" request message contents.
    ///
    /// \param  target            A reference where the target will be placed.
    /// \param  key_value_object  A reference to a pointer that will be set to
    ///                           the set message's object of key/value pairs.
    ///                           Use the RapidJSON Value methods for
    ///                           accessing the key/value pairs.
    /// \param  saddr             The source address of the client that sent
    ///                           the message.
    ///
    /// \return  True on success, or false otherwise.
    virtual bool GetSetMessageFromServer(std::string& target,
                       const rapidjson::Value*& key_value_object,
                       Ipv4Address& saddr) const
      { return (rc_server_.GetSetMessage(target, key_value_object, saddr)); }


    /// \brief Get the "get" request message contents.
    ///
    /// \param  target            A reference where the target will be placed.
    /// \param  key_value_object  A reference to a pointer that will be set to
    ///                           the set message's object of key/value pairs.
    ///                           Use the RapidJSON Value methods for
    ///                           accessing the key/value pairs.
    ///
    /// \return  True on success, or false otherwise.
    virtual bool GetGetMessageFromClient(std::string& target,
                       const rapidjson::Value*& key_value_object) const
      { return (rc_client_.GetGetMessage(target, key_value_object)); }

    /// \brief Get the target of the last message recevied by the remote
    ///   control server.
    /// \return The target of the last message received from the remote control
    ///   server.
    virtual std::string GetServerRcvMsgTgt() const
      { return rc_server_.msg_target(); }

    /// \brief Get the ID of the last message recevied by the remote
    ///   control client.
    /// \return The ID of the last message received from the remote control
    ///   client.
    virtual uint32_t GetClientRcvMsgId() const
      { return rc_client_.msg_id(); }

    /// \brief Get the message type for the last message parsed by the
    ///   the remote control client.
    /// \return The message type enum
    virtual RmtCntlMsgType  GetClientMsgType()
      { return rc_client_.msg_type(); }

    /// \brief Get the message type for the last message parsed by the
    ///   the remote control server.
    /// \return The message type enum
    virtual RmtCntlMsgType  GetServerMsgType()
      { return rc_server_.msg_type(); }

    /// \brief Get the name of the command config file.
    ///
    /// \return A string with the name of the command config file.
    inline std::string cmd_file_name() const { return cmd_file_name_; }

    /// \brief Get the number of commands loaded from the config file.
    ///
    /// \return The number of commands loaded from the command config file.
    inline size_t NumCmds() const { return cmds_.size(); }

    /// \brief Terminates the execution of AMP.
    ///
    /// Currently, the only way to terminate the execution of AMP
    /// Forwarder is to send the process a Ctrl-c signal.
    inline void Stop() { running_ = false; };

    /// \brief Send a message to a proxy to turn a flow off.
    ///
    /// \param flow_info A reference to the FlowInfo of the flow being turned
    ///        off.
    void TurnFlowOff(FlowInfo& flow_info);

    /// \brief Send a message to a proxy to turn a flow on.
    ///
    /// \param flow_info A reference to the FlowInfo being turned off.
    void TurnFlowOn(FlowInfo& flow_info);

    /// \brief Get the  triage interval used for supervisory control.
    ///
    /// \return The triage interval, in milliseconds.
    inline uint32_t triage_interval_ms()
    {
      return triage_interval_ms_;
    }

    /// \brief Check if thrashing-based triage is enabled.
    ///
    /// \return True if thrashing-based triage is enabled.
    inline bool enable_thrash_triage()
    {
      return enable_thrash_triage_;
    }

    /// \brief  Get the average queue depth for a bin to a destination.
    ///
    /// \param  bin The McastId/BinId of destination being queried.
    ///
    /// \return The average bin depth to the destination, as reported
    ///         by the BPF.
    uint32_t  GetAvgQueueDepth(McastId bin);

    /// \brief  Query if the queue to a bin is not increasing.
    ///
    /// \param  bin The McastId/BinId of the destination being queried.
    ///
    /// \return True is the queue the particular queue recently has not 
    ///         had a new maximum value i.e. it is not increasing.
    inline bool IsQueueNonIncreasing(McastId bin) const
    {
      std::map<McastId, uint8_t>::const_iterator it;
      it = max_queue_trajectory_.find(bin);
      if (it != max_queue_trajectory_.end())
      {
        return (it->second == 0);
      }
      return true;
    }

    /// \brief  Get the interval at which AMP is receiving stats.
    ///
    /// \return The interval at which AMP is receiving stats.
    inline double stat_interval_s() { return stat_interval_s_; }

    /// \brief  Send a message to a proxy to update the priority of a flow.
    ///
    /// \param  target The target proxy.
    /// \param  four_tuple The four-tuple of the flow.
    /// \param  priority The new priority of the flow.  
    void UpdateFlowPriority(std::string target, std::string four_tuple,
                            std::string priority);

    /// \brief  Reset the maximum queue depth seen since the last probe
    ///         was enabled.
    /// \param  bin_id The BinId of the queue depth being reset.
    inline void ResetMaxQueueDepth(BinId bin_id)
    {
      max_queue_depths_[bin_id] = GetAvgQueueDepth(bin_id);
    }

  protected:

    /// \brief Parse a file with AMP commands.
    /// \return True if the command file was successfully loaded.
    bool LoadCmdFile();

    /// \brief  Convert 'src_ip:src_port -> dst_ip:dst_port' to
    ///         src_port:dst_port:dst_ip:dst_ip
    /// Note:this will eventaully go away when we make four tuple
    /// representation uniform.
    /// \param tuple_str The 'ip:port -> ip:port' representation of
    /// the four tuple.
    /// \return The 'sport:dport:sip:dip' representation of the four tuple.
    std::string ReformatTuple(std::string tuple_str);

    /// \brief Process a message from a connected proxy.
    /// \return True if the message from the remote client was
    /// successfully processed.
    bool ProcessClientRemoteControlMessage();

    /// \brief Process a Push message from a connected proxy/
    /// \return True if the message from the remote client was
    /// successfully processed.
    bool ProcessPushMessage();

    /// \brief  Cache the push message that AMP received from a target and
    ///         intended to be forwarded to GUI.
    ///
    /// \param  target  The proxy target (bpf, udp_proxy or tcp_proxy).
    bool CachePushMessage(std::string target);

    /// \brief  Relay all the cached messages to the GUI.
    void RelayAllMessagesToGui();

    /// \brief Relay a message from a proxy to the GUI.
    ///
    /// \param  target  The optional proxy target (bpf, udp_proxy or tcp_proxy).
    ///                 (If not provided, will try to find in message.)
    ///
    /// \return True if the message from the remote client was
    /// successfully relayed.
    bool RelayMessageToGui(std::string target = "Undetermined");

    /// \brief Process a SET_REPLY message from a proxy.
    /// This message is relayed to the GUI if the SET
    /// message originated there.
    bool ProcessSetReplyMessage();

    /// \brief Process a GET message from AMP.
    /// This is currently being used to get the a utility
    /// function ftom AMP.
    void ProcessProxyGetMessage();

    /// \brief Process a message from the connected GUI.
    /// \return True if the message from the server was successfully
    /// processed.
    bool ProcessServerRemoteControlMessage();

    /// \brief Procsss a PUSH request from the GUI and send it to
    ///        the target proxy.
    /// \return True if the message was relayed to the target.
    bool ProcessGuiPushReq();

    /// \brief Process a SET message from the GUI and send it to the
    ///        target proxy.
    ///        This is used for updating priorities of utility functions.
    void ProcessSetMessage();

    /// \brief Process a GET message from the GUI and send it to the
    ///        target proxy.
    /// \return True is the message was successfully processed and
    ///        forwarded to the target.
    bool ProcessGetMessage();

    /// \brief Get the service definition for a flow.
    ///
    /// \param five_tuple The five tuple for a flow, as a string.
    /// \param svc_defn A reference to store the service definition.
    ///
    /// \return true if a service definition was found.
    bool GetSvcDefn(const ::std::string& five_tuple, SvcDefn& svc_defn) const;

    /// \brief Get a flow definition string for a five tuple.
    ///
    /// \param proxy A string with the proxy of the flow.
    /// \param five_tuple A string with the five tuple of the flow.
    /// \param flow_defn A refence to a string where the flow definition
    ///        should be stored.
    /// \return true if a flow definition can be constructed.
    bool GetFlowDefn(const ::std::string& proxy,
      const ::std::string& five_tuple, ::std::string& flow_defn) const;

    /// \brief Get the utility function for a flow with a given 5-tuple.
    ///
    /// \param five_tuple A string of the form:
    ///                   proxy:src_port:dst_port:src_ip:dst_ip
    ///
    /// \param utility_fn A reference to store the found utility function.
    void GetUtilityFn(const ::std::string& five_tuple,
      ::std::string& utility_fn) const;

    /// \brief Get the utility function and ttg for a UDP flow with a
    ///        given 5-tuple. TCP flows do not have a time-to-go.
    ///
    /// \param five_tuple A string of the form:
    ///                   proxy:src_port:dst_port:src_ip:dst_ip
    ///
    /// \param utility_fn A reference to store the found utility function.
    /// \param ttg A reference to store the found time-to-go. Flows in the
    ///        TCP proxy does not have a time-to-go.
    void GetUdpFlowParams(const ::std::string& five_tuple,
      ::std::string& utility_fn, ::std::string& ttg) const;

    /// \brief Get the utility function from a service or flow defintion
    ///        string.
    ///
    /// \param defn The service or flow definition to be parsed.
    /// \param utility_fn A reference to store the parsed utility function.
    bool GetUtilityFnFromDefn(const ::std::string& defn,
      ::std::string& utility_fn) const;

    /// \brief Get the time-to-go from a UDP service or flow defintion
    ///        string.
    /// Note: This is only for flows in UDP proxy, as the TCP proxy does
    /// not support ttg.
    ///
    /// \param defn The service or flow definition to be parsed.
    /// \param ttg A reference to store the parsed time-to-go.
    /// \param isSvc True if the definition is a service definition, false if
    ///        it is flow definition.
    /// \return true if a ttg is found.
    bool GetTtgFromUdpDefn(const ::std::string& defn, ::std::string& ttg,
      bool isSvc) const;

    /// \brief Update the Service Cache for a specifed proxy with a
    ///        given service definition string. If the port range exactly
    ///        matches an exisiting service definition that is updated,
    ///        else a new service definition is added to the cache.
    ///
    /// \param proxy The proxy to which the service definition applies.
    /// \param svc_def A string with the service defintion being updated:
    ///                proxy:lo-hi;utility
    void UpdateServiceCache(const ::std::string& proxy,
      const ::std::string& svc_def);

    /// \brief  Update the Flow Cache for a specified proxy with a
    ///         a given flow definition.
    ///
    ///         If the flow tuple does not match an
    ///         existing member of the cache, a new new entry is created.
    ///
    /// \param  five_tuple  proxy:sport;dport;saddr;daddr
    /// \param  svc_defn A string with the service defintion being updated.
    void UpdateFlowCache(const ::std::string& five_tuple,
                         const ::std::string& svc_defn);

    /// \brief  Accessory for supervisory control.
    /// \return A pointer to the supervisory control object.
    inline SupervisoryControl* supervisory_ctl() { return supervisory_ctl_; }

    /// \brief Delete a flow from the Flow cache for a specified proxy.
    /// \param five_tuple A string of the form sport:dport:saddr:daddr to
    ///        identify the flow being deleted.
    bool DeleteFlow(const ::std::string& five_tuple);

    /// \brief Parse the utility function to a config info item.
    ///
    /// \param  five_tuple  The five tuple for the utility:
    ///                     proxy:sport:dport:saddr:daddr.
    ///
    /// \param  utility_fn  The utility function to parse into a config item.
    ///
    /// \param  ci  The config info object in which to place the configuration.
    ///
    /// \return True if successfully parsed, false otherwise.
    bool ParseUtilityFn(const std::string& five_tuple,
                        const std::string& utility_fn, ConfigInfo& ci);

    /// \brief  Sanitize the config info, check for issues.
    /// NOTE:   This function should be replaced by the utility factory.
    ///
    /// \param  ci  The config info object to sanitize.
    ///
    /// \return True if passed, false otherwise.
    bool SanitizeUtilityFn(ConfigInfo& ci);


    /// Consider triaging the flows when the timer expires.
    void ConsiderTriage();

    /// The Endpoint IDs for the connections to the proxies.
    /// The key should match the "target" of messages and commands,
    /// which is currently expected to be "udp_proxy", "tcp_proxy"
    /// or "bpf".
    ::std::map<std::string, uint32_t> connection_map_;

    /// Cache used for storing Flow definitions per proxy.
    /// The key is the five tuple.
    HashTable<FiveTuple, FlowDefn>  flow_def_cache_;

    /// Cache used for storing Service definitions per proxy.
    /// Key is the proxied port range proxy:src_port-dst_port
    ::std::map<std::string, SvcDefn>  svc_def_cache_;

    /// Cache used for a map of request message IDs to endpoints IDs.
    /// This is used to direct messages from a proxy to the
    /// appropriate endpoint.
    /// The "key" is the message ID of the push request.
    ::std::map<uint32_t, uint32_t> msg_endpoint_map_;

    /// Connections which failed at initialization and should be
    /// reattempted. The key is the name e.g. "udp_proxy" and the
    /// value is the address of the remote control server.
    ::std::map<std::string, struct sockaddr_in> reconnect_map_;

    /// Flag to specify if remote control connections should be set up or
    /// not. Used to prevent connection attempts during unit tests.
    bool rc_connect_;

    /// Remote control client to maintain connection state to
    /// one or more remote control servers (running at the proxies).
    RemoteControlClient rc_client_;

    /// Remote control server to maintain connection state to
    /// the red GUI remote control client.
    RemoteControlServer rc_server_;

    /// The total outbound capacity among all CATs.
    double aggregate_outbound_capacity_;

  private:

    /// A cached version of the last RC message sent to the proxies / BPF, used
    /// for tracking push requests.
    struct CachedRCMsg
    {
      /// The type of this cached RC message (pushreq, push, set, etc.).
      std::string type_;

      /// The message id of the cached RC message.
      uint32_t    msg_id_;

      /// The mapped msg id of the cached RC message.
      uint32_t    mapped_msg_id_;

      /// The target of this cached RC message (bpf, udp_proxy, tcp_proxy).
      std::string target_;

      /// The interval of reporting in seconds.
      float       interval_s_;

      /// \brief  Default constructor.
      CachedRCMsg() : type_(""), msg_id_(0), mapped_msg_id_(0), target_(""),
        interval_s_(0.)
      { }

      /// \brief  Set some important fields in the  push request message record.
      ///
      /// \param  target  The destination target.
      /// \param  msg_id  The message id.
      /// \param  interval  The interval in seconds.
      inline void SetPushReqMsg(std::string target, uint32_t msg_id,
                                float interval)
      {
        type_           = "pushreq";
        msg_id_         = msg_id;
        mapped_msg_id_  = msg_id;
        target_         = target;
        interval_s_     = interval;
      }

      /// \brief  Clear the cached push req message as happens when stopping
      ///         push req.
      inline void ResetPushReqMsg()
      {
        type_           = "";
        msg_id_         = 0;
        mapped_msg_id_  = 0;
        target_         = "";
        interval_s_     = 0.;
      }
    };

    /// \brief  Find the cached RC message with a given message id.
    /// NOTE: This is useful when push messages do not include a target.
    ///
    /// \param  msg_id  The message id.
    ///
    /// \param  rc_msg  A reference where to place the cached RC message.
    ///
    /// \return true if found, false otherwise.
    bool FindRCMsgFromMsgId(uint32_t msg_id, CachedRCMsg*& rc_msg);

    /// \brief  Print state of AMP.
    void Dump();

    /// The timer for the AMP component.
    iron::Timer&            timer_;

    /// File with the AMP commands which defines the flow and service
    /// definitions and the time at which they should be applied.
    const ::std::string     cmd_file_name_;

    /// File descriptors used in the select loop.
    fd_set                  read_fds_;

    /// Maximum number of file descriptors.
    int                     max_fds_;

    /// Structure to store the AMP commands to run.
    std::vector<CmdEntry>   cmds_;

    /// Counter for server IDs.
    int                     next_server_id_;

    /// The EndpointInfo object for the connection to the GUI.
    EndpointInfo*           gui_ep_;

    /// The interval at which stats should be reported to supervisory
    /// controller in seconds.
    double                  stat_interval_s_;

    /// The id of the push request for the supervisory controller.
    uint32_t                stat_msg_id_;

    /// The average bandwidth of the smallest flow that is pending.
    double                  smallest_pending_traf_;

    /// The interval at which AMP checks whether to triage flows, in ms.
    uint32_t                triage_interval_ms_;

    /// The interval at which the GUI has requested stat updates, in ms.
    uint32_t                gui_push_interval_ms_;

    /// The triage timer handle.
    Timer::Handle           triage_timer_handle_;

    /// The GUI forward push timer handle.
    Timer::Handle           gui_push_timer_handle_;

    /// The cached push requests sent from AMP to the BPF and Proxy targets.
    CachedRCMsg             cached_push_req_[kMaxNumAmpSupportedTargets];

    /// Flag to specify if supervisory control is enabled.
    bool                    enable_supervisory_ctl_;

    /// Flag to specify if thrashing-based triage is enabled.
    bool                    enable_thrash_triage_;

    /// Flag to specify that AMP is running.
    bool                    running_;

    /// A pointer to a supervisory control module for AMP.
    SupervisoryControl*     supervisory_ctl_;

    /// The queue normalizer used.
    uint64_t                k_val_;

    /// The string buffer caching the UDP proxy message to be sent to the GUI.
    rapidjson::StringBuffer udp_str_buf_;

    /// The cached UDP proxy message id.
    uint32_t                udp_last_msg_id_;

    /// The string buffer caching the TCP proxy message to be sent to the GUI.
    rapidjson::StringBuffer tcp_str_buf_;

    /// The cached TCP proxy message id.
    uint32_t                tcp_last_msg_id_;
    /// The string buffer caching the BPF message to be sent to the GUI.
    rapidjson::StringBuffer bpf_str_buf_;

    /// The cached BPF message id.
    uint32_t                bpf_last_msg_id_;

    /// The average queue depth to each destination, as reported by the BPF.
    /// Note: AMP does not have a bin map and values are indexed by BinId rather
    /// than BinIndex.
    std::map<McastId, uint32_t>  avg_queue_depths_;

    /// The maximum queue depth seen by the proxies since the last probe was
    /// enabled. This is used to check if the queues for a given bin is
    /// increasing, and therefore has not converged.
    std::map<McastId, uint32_t>  max_queue_depths_;

    /// The current direction of queue growth. A number greater than 0 indicates
    /// that the queue is growing.
    std::map<McastId, uint8_t>   max_queue_trajectory_;

    /// The default utility function, per proxy per type.
    std::map<std::string, std::map<std::string, std::string> > default_utility_fns_;

  }; // Amp class
} // Iron namespace
#endif
