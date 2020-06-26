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

#include <cppunit/extensions/HelperMacros.h>

#include "amp.h"
#include "log.h"
#include "supervisory_ctl_if.h"
#include "timer.h"

#include <string>
#include <cstdio>
#include <cstring>

#include <stdlib.h>
#include <unistd.h>

using ::std::string;
using ::rapidjson::Value;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;

namespace iron
{

const char*  kClassName = "AmpTester";

// A child class of Amp for testing Amp.

class AmpTester : public Amp
{
public:
  /// Default constructor for AmpTester.
  /// \param  timer The timer instance to be used for the tests.
  AmpTester(Timer& timer);

  /// Constructor for AmpTester with a given AMP config file.
  /// \param  timer The timer instance to be used for the tests.
  /// \param config_file An AMP config file with timed events
  ///   for adding/removing/modifying service definitions.
  AmpTester(Timer& timer, std::string config_file);

  virtual ~AmpTester();

  /// Overloaded methods to avoid actually reading/writing``
  /// from/to sockets.

  /// \brief Bypass writing message to server socket.
  /// \return Always return true.
  virtual bool SendMessageToServer(uint32_t ep_id,
                   rapidjson::StringBuffer& str_buf)
  {
    return true;
  }

  /// \brief Bypass writing message to client socket.
  /// Set sent_msg_ep_id_ to the endpoint ID of the endpoint
  /// that the message would have been sent to.
  /// \return Always return true.
  virtual bool SendMessageToClient(uint32_t ep_id,
                   rapidjson::StringBuffer& str_buf)
  {
    sent_msg_ep_id_ = ep_id;
    return true;
  }

  /// \brief Bypass writing message to client socket. 
  virtual void SendSetMsgToClient(std::string target, std::string cmd,
                                    std::string arg)
  {
    return;
  }

  /// \brief Bypass reading the message target from the remote 
  /// control server. 
  virtual string GetServerRcvMsgTgt() const
  {
    return target_;
  }

  /// \brief Bypass reading the message target from the remote
  /// control client.
  virtual uint32_t GetClientRcvMsgId() const
  {
    return msg_id_;
  }

  /// \brief Bypass reading the message type from the remote
  /// control client.
  virtual RmtCntlMsgType  GetClientMsgType()
  {
    return msg_type_;
  }

  /// \brief Bypass reading the message type from the remote
  /// control server.
  virtual RmtCntlMsgType  GetServerMsgType()
  {
    return msg_type_;
  }

  /// \brief configure the message type.
  void SetMsgType(RmtCntlMsgType msg_type)
  {
    msg_type_ = msg_type;
  }

  /// \brief Read a stored message rather than from a socket.
  /// \param target The target of the message.
  /// \param key_value_object A rapidjson object with the key:value
  /// pairs in the message.
  /// \return Always return true.
  inline virtual bool GetSetMessageFromServer(string& target,
                       const rapidjson::Value*& key_value_object) const
  {
    target = target_;
    key_value_object = key_vals_;
    return true;
  }

  /// \brief Read a stored message rather than from a socket.
  /// \param target The target of the message.
  /// \param key_value_object A rapidjson object with the key:value
  /// pairs in the message.
  /// \return Always return true.
  inline virtual bool GetSetMessageFromServer(string& target,
                       const rapidjson::Value*& key_value_object,
                       Ipv4Address& saddr) const
  {
    target = target_;
    key_value_object = key_vals_;
    saddr = Ipv4Address("127.0.0.1");
    return true;
  }

  /// Accessors for private and protected members of AMP.

  /// \brief Load the config file at that specified in the constructor.
  bool LoadCfgFile()
  {
    return LoadCmdFile();
  }


  /// \brief Get the number of service definitions in the cache.
  /// \return The number of service definitions in the cache.
  size_t NumSvcDefn()
  {
    return (svc_def_cache_.size());
  }

  /// \brief Get the number of flow definitions.
  /// \return The number of flow definitions in the cache.
  size_t NumFlowDefn()
  {
      return (flow_def_cache_.Size());
  }

  /// \brief A wrapper for AMP's ProcessClientRemoteControlMessage method.
  bool ProcessClientRCMsg()
  {
    return (ProcessClientRemoteControlMessage());
  }

  /// \brief A wrapper for AMP's ProcessPushReq method.
  bool ProcGuiPushReq()
  {
    return (ProcessGuiPushReq());
  }

  /// \brief A wrapper for AMP's ProcessGetMessage method.
  bool ProcGetMessage()
  {
    return (ProcessGetMessage());
  }

  /// \brief A wrapper for AMP's ProcessSetMessage method.
  void ProcSetMessage()
  {
    ProcessSetMessage();
  }

  /// \brief A wrapper for AMP's TurnFlowOn method.
  /// \param flow_info The flow which is being turned on.
  void TurnOnFlow(FlowInfo& flow_info)
  {
    TurnFlowOn(flow_info);
  }

  /// \brief A wrapper for AMP's TurnFlowOff method
  /// \param flow_info The flow which is being turned off.
  void TurnOffFlow(FlowInfo& flow_info)
  {
    TurnFlowOff(flow_info);
  }

  /// \brief Add a message_id:message_src pair to the endpoint cache.
  /// \param msg_id A message ID for the mapping.
  /// \param ep_id The endpoint ID of the connection from which the
  ///   message was received.
  void SetEndpointMap(uint32_t msg_id, uint32_t ep_id)
  {
    msg_endpoint_map_[msg_id] = ep_id;
  }

  /// \brief Add an endpoint id for a specified proxy.
  /// \param ep A string to identify the proxy
  ///   (either "udp_proxy" or tcp_proxy")
  /// \param ep_id The associated endpoint ID for this proxy.
  void SetProxyEndpoint(string ep, uint32_t ep_id)
  {
    connection_map_[ep] = ep_id;
  }

  /// \brief A wrapper for AMP's UpdateServiceCache method.
  /// Update the Service Cache for a specifed proxy with a
  ///   given service definition string. If the port range exactly
  ///   matches an exisiting service definition that is updated,
  /// \param svc_defn A string with the service defintion being updated
  ///   preceeded by "proxy_name:" .
  void UpdateSvcCache(const string& proxy, const string& svc_defn)
  {
    UpdateServiceCache(proxy, svc_defn);
  }

  /// \brief A wrapper for AMP's UpdateFlowCache method.
  /// Update the Flow Cache for a specified proxy with a
  ///   a given flow definition. If the flow tuple does not match an
  ///   existing member of the cache, a new entry is created.
  /// \param proxy      A string indicating the proxy to which the flow
  ///                   definition applies.
  /// \param flow       A string with the 4-tuple of the flow being updated.
  /// \param utility_fn A string with the utility function of the flow.
  void UpdateFlwCache(const ::std::string &proxy,
                      const ::std::string &flow,
                      const ::std::string &utility_fn)
  {
    UpdateFlowCache(proxy + ";" + flow,  utility_fn);
  }

  /// \brief A wrapper for AMP's DeleteFlow method.
  /// Delete a flow from the Flow cache for a specified proxy.
  /// \param proxy The proxy from which the flow is being deleted.
  /// \param flow_tuple A string of the form sport:dport:saddr:daddr to
  ///   identify the flow being deleted.
  void DeleteFlw(const ::std::string &proxy,
                 const ::std::string &flow_tuple)
  {
    DeleteFlow(proxy + ";" + flow_tuple);
  }

  /// \brief A wrapper for AMP's GetUtilityFn method.
  /// Get the utlity function for a given 4-tuple from a specified
  ///   proxy.
  /// \param proxy A string indicating the proxy cache to be queried.
  /// \param flow_tuple A string of the form sport:dport:saddr:daddr
  string GetUtilFn(const string &proxy, const string &flow)
  {
    string ttg;
    string utility_fn;
    GetUdpFlowParams(proxy + ";" + flow, utility_fn, ttg);
    return utility_fn;
  }

  /// \brief Set up AMP to be in the state where it received a message
  ///   on the server side (GUI)
  /// \param msg_id The message ID of the received ID.
  /// \param tgt The target of the message.
  void ConfigureServerRcvMsg(uint32_t msg_id, string tgt="");

  /// \brief Set up AMP to be in the state where it received a message
  ///   on the the client side (from an IRON node).
  /// \param msg_id The message ID of the received message.
  void ConfigureClientRcvMsg(uint32_t msg_id);

  /// \brief  Add a flow to the list of flows in supervisory control.
  ///
  /// \param  flow_four_tuple The four tuple identifying a flow.
  ///
  /// \param  priority  The priority of the flow.
  ///
  /// \param  rate  The rate of the flow in bps.
  ///
  /// \param  utility_type The type of utility function, as a string, 
  ///         that should be used for the flow (LOG, TRAP, STRAP).
  ///
  /// \param  state The state of the flow: on, off or triaged.
  ///
  /// \param  ttg The time-to-go to be used for packets of this flow.
  ///         It is defaulted to zero, which means there is no time limit.
  /// 
  /// \return A pointer to the FlowInfo onject created.
  FlowInfo* AddFlow(const string& flow_four_tuple,  const string& priority,
                    const string& rate, const string& utility_type, 
                    const string& state, const string& ttg="0")
  {
    LogD(kClassName, __func__,
         "Adding flow %s with priority %s and rate %s.\n",
         flow_four_tuple.c_str(), priority.c_str(), rate.c_str());

    string five_tuple = "udp_proxy;" + flow_four_tuple;
    string defn = "1/1;1500;0;0;120;" + ttg + ";type=" + utility_type;
    UpdateFlowCache(five_tuple,  defn);

    ConfigInfo ci;
    ci.Add("priority", priority);
    ci.Add("nominal_rate_bps", rate);
    ci.Add("four_tuple", flow_four_tuple);
    ci.Add("five_tuple", "udp_proxy;" + flow_four_tuple);
    ci.Add("proxy","udp_proxy");
    ci.Add("utility_fn", "my_utility");
    ci.Add("type", utility_type);
    ci.Add("adm_rate", rate);
    ci.Add("utility", "2");
    ci.Add("flow_state", state);
    ci.Add("ttg", ttg);
    ci.Add("bin_id", "1");
    double normalized_utility = 0.;
    if (utility_type == "LOG")
    {
      normalized_utility = atof(priority.c_str());
    }
    else
    {
      normalized_utility = atof(priority.c_str())/atof(rate.c_str());
    }
    std::ostringstream os;
    os << normalized_utility;
    ci.Add("normalized_utility", os.str());

    SupervisoryControl* svc = supervisory_ctl();
    svc->UpdateFlowInfo(ci);
     LogD(kClassName, __func__, "done update\n");
    return svc->FindFlowInfo(five_tuple);
 }

  /// \brief  Toggle flows on and off to maximize utility.
  ///
  /// \param  The aggregate outbound capacity in bps.
  void Triage(double capacity_bps);

  /// The endpoint ID of the endpoint to which a message was supposedly
  /// sent to. This is only used for unit testing where we don't actually
  /// send messages.
  uint32_t sent_msg_ep_id_;

  /// The message ID of a simulated message.
  uint32_t msg_id_;

  /// The target of a received message.
  string target_;

  /// The type of message
  RmtCntlMsgType msg_type_;

  /// The key:value rapidjson object for a message received on the server.
  const rapidjson::Value* key_vals_;

}; // class AmpTester

//============================================================================
AmpTester::AmpTester(Timer& timer)
  : Amp(timer), sent_msg_ep_id_(0), msg_id_(0), target_(),
    msg_type_(iron::RC_INVALID), key_vals_(NULL)
{
  // Do not attempt to set up remote control connections.
  rc_connect_ = false;
}

//============================================================================
AmpTester::AmpTester(Timer& timer, std::string config_file)
  : Amp(timer, config_file), sent_msg_ep_id_(0), msg_id_(0), target_(),
    msg_type_(iron::RC_INVALID), key_vals_(NULL)
{
  // Do not attempt to set up remote control connections.
  rc_connect_ = false;
}

//============================================================================
AmpTester::~AmpTester()
{
}

//============================================================================
void AmpTester::ConfigureServerRcvMsg(uint32_t msg_id, string tgt)
{
  msg_id_ = msg_id;
  target_ = tgt;
}

//============================================================================
void AmpTester::ConfigureClientRcvMsg(uint32_t msg_id)
{
  msg_id_ = msg_id;
}

//============================================================================
void AmpTester::Triage(double capacity_bps)
{
  aggregate_outbound_capacity_  = capacity_bps;
  ConsiderTriage();
}
//============================================================================
class AmpTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(AmpTest);

  CPPUNIT_TEST(testConstructor);
  CPPUNIT_TEST(testLoadCfgFile);
  CPPUNIT_TEST(testProcessClientRCMsg);
  CPPUNIT_TEST(testProcessPushReq);
  CPPUNIT_TEST(testProcessGetMessage);
  CPPUNIT_TEST(testProcSetMessage);
  CPPUNIT_TEST(testCacheOperations);
  CPPUNIT_TEST(testConsiderTriage);

  CPPUNIT_TEST_SUITE_END();

private:
  AmpTester*  amp_;
  Timer*      timer_;
  char filename[32];

public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");

    timer_  = new (std::nothrow) Timer();
    CPPUNIT_ASSERT(timer_);

    // Create a temp config file
    memset(filename,0,sizeof(filename));
    strncpy(filename,"/tmp/ampcfg-XXXXXX",18);
    int fd = mkstemp(filename);
    if (fd == -1)
    {
      LogF(kClassName, __func__, "Unable to create temp file\n", filename);
    }
    if (write(fd,"2 udp_proxy add_service 30777-30778;1/1;1500;0;0;120;0;"
             "type=LOG:a=10:m=10000000:p=2:label=mgen_flow1;\n",102) == -1)
    {
       LogF(kClassName, __func__, "Unable to write to temp file\n");
    }
    if (write(fd,"2 udp_proxy add_service 30779-30779;1/1;1500;0;0;120;0;"
             "type=LOG:a=20:m=10000000:p=1:label=mgen_flow3;\n",102) == -1)
    {
       LogF(kClassName, __func__, "Unable to write to temp file\n");
    }
    if (write(fd,"2 udp_proxy add_service 0-65335;1/1;1500;0;0;120;0"
             ";type=LOG:a=20:m=10000000:p=1:label=default_svc;\n",100) == -1)
    {
       LogF(kClassName, __func__, "Unable to write to temp file\n");
    }
    close(fd);
    amp_ = new (std::nothrow) AmpTester(*timer_, filename);
    ConfigInfo ci;
    amp_->Initialize(ci);
  }

  //==========================================================================
  void tearDown()
  {
    delete amp_;
    unlink(filename);
    amp_    = NULL;
    timer_->CancelAllTimers();
    CallbackNoArg<AmpTest>::EmptyPool();
    delete timer_;
    timer_  = NULL;
    Log::SetDefaultLevel("F");
  }

  //==========================================================================
  void testConstructor()
  {
    // The number of commands will be initialzed to 0 and only change
    // after processing a config file with valid AMP commands.
    CPPUNIT_ASSERT(amp_->NumCmds() == 0);
    // Test that the command file name is properly set.
    CPPUNIT_ASSERT(amp_->cmd_file_name().compare(filename) == 0);
  }

  //==========================================================================
  void testLoadCfgFile()
  {
    CPPUNIT_ASSERT(amp_->LoadCfgFile());
    CPPUNIT_ASSERT(amp_->NumCmds() == 3);
  }
  //==========================================================================
  void testProcessClientRCMsg()
  {
    // We need to map message ID to origin in order for this to work.
    amp_->ConfigureClientRcvMsg(5);
    amp_->SetMsgType(iron::RC_INVALID);
    CPPUNIT_ASSERT(!amp_->ProcessClientRCMsg());
    amp_->SetMsgType(iron::RC_SETREPLY);
    CPPUNIT_ASSERT(!amp_->ProcessClientRCMsg());
    amp_->SetEndpointMap(5, 1);
    CPPUNIT_ASSERT(amp_->ProcessClientRCMsg());
  }

  //==========================================================================
  void testProcessPushReq()
  {
    // If we haven't set up endpoint maps, this should fail.
    CPPUNIT_ASSERT(amp_->sent_msg_ep_id_ == 0);
    amp_->ConfigureServerRcvMsg(5, "udp_proxy");
    CPPUNIT_ASSERT(!amp_->ProcGuiPushReq());
    CPPUNIT_ASSERT(amp_->sent_msg_ep_id_ == 0);

    // TODO: Test the method further.
  }

  //==========================================================================
  void testProcessGetMessage()
  {
    // If we haven't set up endpoint maps, this should fail.
    CPPUNIT_ASSERT(amp_->sent_msg_ep_id_ == 0);
    amp_->ConfigureServerRcvMsg(5, "udp_proxy");
    CPPUNIT_ASSERT(!amp_->ProcGetMessage());
    CPPUNIT_ASSERT(amp_->sent_msg_ep_id_ == 0);

    // Once the mapping is in place we should be able to call
    // the remote control's send message.
    amp_->SetProxyEndpoint("udp_proxy", 2);
    CPPUNIT_ASSERT(amp_->ProcGetMessage());
    CPPUNIT_ASSERT(amp_->sent_msg_ep_id_ == 2);
  }

  //==========================================================================
  void testProcSetMessage()
  {
    amp_->SetProxyEndpoint("udp_proxy", 2);
    // Populate the service defn cache
    amp_->UpdateSvcCache("udp_proxy", "30777-30778;1/1;1500;0;0;120;0;"
      "type=LOG:a=10:m=10000000:p=2:label=mgen_flow1");
    amp_->UpdateSvcCache("udp_proxy", "30779-30779;1/1;1500;0;0;120;0;"
      "type=LOG:a=10:m=10000000:p=2:label=mgen_flow2");

    // Create a set message and set it up so that it would be read as a
    // message from the GUI.
    string msg = "{ \"msg\":\"set\", \"keyvals\": {\"parameter\":\"priority\", "
      "\"priority\":\"2\",\"flow_tuple\":\"172.24.2.1:30777 "
      "-> 172.24.1.1:30777\"}}";

    rapidjson::Document document;
    document.Parse(msg.c_str());
    const Value& a  = document["keyvals"];
    amp_->key_vals_ = &a;
    amp_->target_   = "udp_proxy";
    CPPUNIT_ASSERT(amp_->key_vals_->IsObject());

    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 0);
    amp_->ProcSetMessage();

    // If it works we would have updated the flow_defn_cache last.
    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 1);

    // Verify that the flow defn is what we expect.
    string util_fn = amp_->GetUtilFn("udp_proxy",
      "30777;30777;172.24.2.1;172.24.1.1");
    CPPUNIT_ASSERT(util_fn.compare(
      "type=LOG:a=10:m=10000000:p=2:label=mgen_flow1") == 0);
  }

  //==========================================================================
  void testCacheOperations()
  {
    // svc_defn_cache_ and flow_defn_cache_ should be initially empty.
    CPPUNIT_ASSERT(amp_->NumSvcDefn() == 0);
    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 0);

    // Add to the service defn cache.
    amp_->UpdateSvcCache("udp_proxy", "30777-30778;1/1;1500;0;0;120;0;"
      "type=LOG:a=10:m=10000000:p=2:label=mgen_flow1");
    amp_->UpdateSvcCache("udp_proxy", "30779-30779;1/1;1500;0;0;120;0;"
      "type=LOG:a=10:m=10000000:p=2:label=mgen_flow2");
    CPPUNIT_ASSERT(amp_->NumSvcDefn() == 2);
    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 0);

    // Add to the tcp_proxy service defn.
    amp_->UpdateSvcCache("tcp_proxy:", "20777-20778;1/1;1500;0;0;120;0;"
      "type=LOG:a=10:m=10000000:p=2:label=tcp_flow1");
    CPPUNIT_ASSERT(amp_->NumSvcDefn() == 3);
    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 0);

    // Add a udp_proxy flow defn.
    amp_->UpdateFlwCache("udp_proxy","30777;30777;172.24.1.1;172.24.2.1",
      "1/1;1500;0;0;120;0;type=LOG:a=10:m=10000000:p=6:label=udp_flow5");
    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 1);

    amp_->UpdateFlwCache("udp_proxy","30778;30778;172.24.1.1;172.24.2.1",
      "1/1;1500;0;0;120;0;type=LOG:a=10:b=11500:m=10000000:p=6:label=udp_flow6");
    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 2);

    // Test GetUtilFn with an existing flow defn.
    string util_fn = amp_->GetUtilFn("udp_proxy",
      "30777;30777;172.24.1.1;172.24.2.1");
    CPPUNIT_ASSERT(util_fn.compare(
      "type=LOG:a=10:m=10000000:p=6:label=udp_flow5") == 0);

    // If we query the reverse direction, then it should return the svc defn.
    util_fn = amp_->GetUtilFn("udp_proxy",
      "30777;30777;172.24.2.1;172.24.1.1");
    CPPUNIT_ASSERT(util_fn.compare(
      "type=LOG:a=10:m=10000000:p=2:label=mgen_flow1") == 0);

    // Delete a flow defn
    amp_->DeleteFlw("udp_proxy", "30777;30777;172.24.1.1;172.24.2.1");
    CPPUNIT_ASSERT(amp_->NumFlowDefn() == 1);
    util_fn = amp_->GetUtilFn("udp_proxy",
      "30777;30777;172.24.1.1;172.24.2.1");
    // This should now match the svc defn since we deleted the flow defn.
        CPPUNIT_ASSERT(util_fn.compare(
      "type=LOG:a=10:m=10000000:p=2:label=mgen_flow1") == 0);
  }

  //==========================================================================
  void testConsiderTriage()
  { 
    FlowInfo* flow1 = amp_->AddFlow("1;1;1;1", "10.", "900000.", "STRAP", "1");
    FlowInfo* flow2 = amp_->AddFlow("2;2;2;2", "1.", "949000.", "STRAP", "2");
    FlowInfo* flow3 = amp_->AddFlow("3;3;3;3", "10.", "1100000.", "STRAP", "1");
    FlowInfo* flow4 = amp_->AddFlow("4;4;4;4", "10.", "1000000.", "STRAP", "1");
    FlowInfo* flow5 = amp_->AddFlow("5;5;5;5", "11.", "1000000.", "STRAP", "2");
    FlowInfo* flow6 = amp_->AddFlow("6;6;6;6", "11.", "10000.", "STRAP", "1");
    FlowInfo* flow7 = amp_->AddFlow("7;7;7;7", "1.", "50000.", "STRAP", "2");
    FlowInfo* flow8 = amp_->AddFlow("8;8;8;8", "1.", "8000.", "STRAP", "1");
    FlowInfo* flow9 = amp_->AddFlow("9;9;9;9", "1.", "10000.", "STRAP", "1");
    FlowInfo* flow10 = amp_->AddFlow("10;10;10;10", "1.", "10000.", "STRAP", "1");
    FlowInfo* flow11 = amp_->AddFlow("11;11;11;11", "1.", "10000.", "STRAP", "1");
    FlowInfo* flow12 = amp_->AddFlow("12;12;12;12", "1.", "10000.", "STRAP", "1");
    FlowInfo* flow13 = amp_->AddFlow("13;13;13;13", "1.", "0.", "LOG", "1");
    FlowInfo* flow14 = amp_->AddFlow("14;14;14;14", "1.", "0.", "LOG", "1");

    LogD(kClassName, __func__," *************\n");
    amp_->Triage(1999000.);
    // The following is the state of the flows after turning on/off.
    CPPUNIT_ASSERT(flow1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow2->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow3->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(flow4->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(flow5->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(flow6->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow7->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow8->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow9->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow10->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow11->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow12->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow13->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow14->flow_state_ == FLOW_ON);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(AmpTest);

}
