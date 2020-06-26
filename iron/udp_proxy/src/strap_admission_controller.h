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

#ifndef IRON_UDP_PROXY_STRAP_ADMISSION_CONTROLLER_H
#define IRON_UDP_PROXY_STRAP_ADMISSION_CONTROLLER_H

#include "admission_controller.h"
#include "src_info.h"
#include "src_rate_estimator.h"
#include "strap_utility.h"

/// \brief An admission controller for flows with trapezoidal utility.
///
/// This is a child class of AdmissionController. Packets are admitted at
/// discrete rates (steps). The rate increases, or decreases based the
/// available packets and the queues in the BPF. This admission controller
/// manages a STRAP utility funtion and maintains the times for which various
/// events associated with the utility function be processed.
class StrapAdmissionController : public AdmissionController
{
  public:

  /// \brief Constructor.
  ///
  /// \param  encoding_state      Reference to the flow's encoding state.
  /// \param  src_rate_estimator  Reference to the flow's source rate
  ///                             estimator.
  /// \param  src_info            Flow information.
  StrapAdmissionController(EncodingState& encoding_state,
                           SrcRateEstimator& src_rate_estimator,
                           SrcInfo& src_info);

  /// \brief Destructor.
  virtual ~StrapAdmissionController();

  /// \brief Create the admission controller's strap utility function.
  ///
  /// The strap utility function is initialized and configured from the
  /// information contained in the string of colon-separated key:value pairs.
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
                               iron::QueueDepths& queue_depths);

  /// \brief Service the admission control events.
  ///
  /// \param  now  The current time.
  virtual void SvcEvents(iron::Time& now);

  /// \brief Get the flow's instantaneous utility.
  ///
  /// \param  rate  The flow's send rate.
  ///
  /// \return The flow's instantaneous utility.
  virtual double ComputeUtility(double rate);

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
  virtual void set_flow_state(iron::FlowState flow_state);

  /// \brief Get the flow's state.
  ///
  /// \return The flow's state.
  virtual iron::FlowState flow_state();

  /// \brief Get the flow's priority.
  ///
  /// \return The flow's priority.
  virtual double priority();

  /// \brief Update a parameter of the utility function for this state.
  ///
  /// \param key_val A key:value pair of the parameter to be updated and it's
  ///        new value.
  virtual void UpdateUtilityFn(std::string key_val);

  /// \brief Get the tolerable loss threshold for the flow.
  ///
  /// return The tolerable loss threshold for the flow, as a percentage.
  virtual inline uint8_t loss_thresh_pct()
  {
    return (100 - strap_utility_->delta()*100);
  }

  /// \brief Update the scheduled admission event.
  ///
  /// \param  now  The current time.
  /// \param  utility_fn  The utility function.
  virtual void UpdateScheduledAdmissionEvent(iron::Time& now,
                                     iron::UtilityFn* utility_fn);

  /// \brief Admit packets to the BPF.
  ///
  /// \param  now         The current time.
  virtual void AdmitPkts(iron::Time& now);

  private:

  /// \brief No-arg constructor.
  StrapAdmissionController();

  /// \brief Copy constructor.
  StrapAdmissionController(const StrapAdmissionController& sac);

  /// \brief Assignment operator.
  StrapAdmissionController& operator=(const StrapAdmissionController& sac);

  /// \brief The strap admission controller restart event timeout.
  ///
  /// \param  now  The current time.
  void RestartTimeout(iron::Time& now);

  /// \brief The strap admission controller step event timeout.
  ///
  /// \param  now  The current time.
  void StepTimeout(iron::Time& now);

  /// \brief Schedule the next step time.
  ///
  /// This is always set to now + trap utility's step interval.
  void ScheduleStepTime();

  /// \brief Schedule the next restart time.
  ///
  /// This is always set to now + trap utility's restart interval.
  void ScheduleRestartTime();

  /// Reference to the flow's source rate estimator.
  SrcRateEstimator&    src_rate_estimator_;

  /// Reference to the flow's source information.
  SrcInfo&             src_info_;

  /// The strap utility.
  iron::StrapUtility*  strap_utility_;

  /// The restart time.
  iron::Time           restart_time_;

  /// The step time.
  iron::Time           step_time_;

};  // end class StrapAdmissionController

#endif  // IRON_UDP_PROXY_STRAP_ADMISSION_CONTROLLER_H
