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

#ifndef IRON_UDP_PROXY_ADMISSION_CONTROLLER_H
#define IRON_UDP_PROXY_ADMISSION_CONTROLLER_H

#include "iron_constants.h"
#include "itime.h"
#include "packet.h"
#include "queue_depths.h"
#include "rng.h"
#include "utility_fn_if.h"

#include <string>

#include <inttypes.h>

class EncodingState;
class UdpProxy;

/// The allowed startup time for a flow.
const iron::Time   kStartupTime = iron::Time(0.02);

/// \brief A base class for admission control in the UDP proxy.
///
/// The admission controller is responsible for determining the rate at which
/// packets are released into the BPF from local applications, based on the
/// utility function associated with the flow. Packets are admitted in bursts
/// and the admission controller manages the time of the next burst.
class AdmissionController
{
  public:

  /// \brief Constructor.
  ///
  /// \param  encoding_state  Reference to the flow's encoding state.
  AdmissionController(EncodingState& encoding_state);

  /// \brief Destructor.
  virtual ~AdmissionController();

  /// \brief Create the admission controller's utility function.
  ///
  /// The utility functions are initialized and configured from the information
  /// contained in the string of colon-separated key:value pairs.
  ///
  /// \param  utility_def   String of colon-separated key:value pairs of
  ///                       parameters for the utility function.
  /// \param  flow_id       Unique tag identifying the flow to which the
  ///                       admission controller belongs.
  /// \param  queue_depths  Reference to the QueueDepths object.
  ///
  /// \return True if the utility function is successfully created, false
  ///         otherwise.
  virtual bool CreateUtilityFn(std::string& utility_def, uint32_t flow_id,
                               iron::QueueDepths& queue_depths) = 0;

  /// \brief Service the admission control events.
  ///
  /// \param  now  The current time.
  virtual void SvcEvents(iron::Time& now) = 0;

  /// \brief Get the flow's instantaneous utility.
  ///
  /// \param  rate  The flow's send rate.
  ///
  /// \return The flow's instantaneous utility.
  virtual double ComputeUtility(double rate) = 0;

  /// \brief  Set the flow's state.
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
  virtual void set_flow_state(iron::FlowState flow_state) = 0;

  /// \brief Get the flow's state.
  ///
  /// \return The flow's state.
  virtual iron::FlowState flow_state() = 0;

  /// \brief Get the flow's priority.
  ///
  /// \return The flow's priority.
  virtual double priority() = 0;

  /// \brief Get the tolerable loss threshold for the flow.
  ///
  /// This should be a value between 0 and 100.
  ///
  /// return The tolerable loss threshold for the flow, as a percentage.
  virtual uint8_t loss_thresh_pct() = 0;

  /// \brief  Set the total number of times this flow has already gone from
  ///         a non-zero send rate to a zero send rate or vice versa.
  /// \param  count The total number of times this flow has already gone from
  ///         a non-zero send rate to a zero send rate or vice versa.
  inline void set_toggle_count(uint32_t count)
  {
    toggle_count_ = count;
  } 

  /// \brief  Get the total number of times this flow has gone from a non-zero
  //          to a zero send rate or vice versa.
  /// \return The total number of times this flow has gone from a non-zero
  ///         to a zero send rate or vice versa.
  inline uint32_t toggle_count() const
  {
    return toggle_count_;
  }

  /// \brief Update a parameter of the utility function for this state.
  ///
  /// \param key_val A key:value pair of the parameter to be updated and it's
  ///        new value.
  virtual void UpdateUtilityFn(std::string key_val) = 0;

  /// \brief  Check if there is an event that requires stats to be pushed
  ///         to AMP immediately.
  /// \return True if stats should be pushed to AMP immediately.
  bool push_stats() const
  {
    return push_stats_;
  }

  protected:

  /// \brief Get the type from a utility function definition string.
  ///
  /// \param  utility_def  String of colon-separated key:value pairs of
  ///                      parameters for the utility function.
  /// \param  flow_id       Unique tag identifying the flow to which the
  ///                       admission controller belongs.
  ///
  /// \return The type of utility function, as a string.
  std::string GetUtilityFnType(std::string& utility_def,
                               uint32_t flow_id) const;

  /// \brief Configure the admission controller's utility function.
  ///
  /// The utility functions is initialized and configured from the information
  /// contained in the string of colon-separated key:value pairs.
  ///
  /// \param  utility_fn   The utility function to be configure.
  /// \param  utility_def  String of colon-separated key:value pairs of
  ///                      parameters for the utility function.
  ///
  /// \return True if the utility function configuration is successful, false
  ///         otherwise.
  bool ConfigureUtilityFn(iron::UtilityFn* utility_fn,
                          std::string& utility_def);

  /// \brief Service the admission event timeout.
  ///
  /// \param  now         The current time.
  /// \param  utility_fn  The utility function.
  void SvcAdmissionEvent(iron::Time& now, iron::UtilityFn* utility_fn);

  /// \brief Admit a packet to the BPF.
  ///
  /// \return The number of bytes admitted to the BPF.
  size_t AdmitPkt();

  /// \brief Admit packets to the BPF.
  ///
  /// \param  now         The current time.
  virtual void AdmitPkts(iron::Time& now);

  /// \brief Cancel a scheduled event.
  ///
  /// \param  time  A reference to the time for the scheduled event.
  void inline CancelScheduledEvent(iron::Time& time)
  {
    time.SetInfinite();
  }


  /// \brief Update the scheduled admission event.
  ///
  /// \param  now  The current time.
  /// \param  utility_fn  The utility function.
  virtual void UpdateScheduledAdmissionEvent(iron::Time& now,
                                     iron::UtilityFn* utility_fn);

  /// Reference to the encoding state of the flow.
  EncodingState&  encoding_state_;

  /// The next time that a packet can be admitted to the BPF.
  iron::Time      next_admission_time_;

  /// The last time the admission controller was turned on.
  iron::Time      start_time_;

  /// The burst interval for sending packet to the BPF.
  iron::Time      bpf_min_burst_;

  /// The last send rate computed.
  double          last_send_rate_;

  /// The total number of times this flow has gone from a non-zero send rate
  /// to a zero send ratei or vice versa.
  uint32_t        toggle_count_;

  /// A flag to indicate is stats should be pushed to AMP immediately.
  bool            push_stats_;

  private:

  /// \brief No-arg constructor.
  AdmissionController();

  /// \brief Copy constructor.
  AdmissionController(const AdmissionController& ac);

  /// \brief Assignment operator.
  AdmissionController& operator=(const AdmissionController& ac);

  /// Flag that remembers if the flow is idle or not.
  bool            flow_is_idle_;

  /// A random number generator object for the admission controller.
  iron::RNG       rng_;

};  // end class AdmissionController

#endif  // IRON_UDP_PROXY_ADMISSION_CONTROLLER_H
