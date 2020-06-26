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

#ifndef IRON_UDP_PROXY_FEC_CONTEXT_H
#define IRON_UDP_PROXY_FEC_CONTEXT_H

#include "itime.h"
#include "iron_types.h"

#include <string>

#include <inttypes.h>
#include <sys/types.h>

/// Class for managing FEC encoding information
class FECContext
{
  public:

  /// \brief Default Constructor.
  FECContext();

  /// Constructor that explicitly sets all instance variables.
  ///
  /// \param  loPort        Lower end of the UDP port capture range.
  /// \param  hiPort        Upper end of the UDP port capture range.
  /// \param  baseRate      Base encoding rate (no. of original packets).
  /// \param  totalRate     Total encoding rate (no. of original + repair
  ///                       packets).
  /// \param  maxChunkSz    Maximum payload size in a chunk.
  /// \param  maxHoldTime   Maximum time before forcing FEC repair packet
  ///                       generation.
  /// \param  inOrder       Flag indicating whether service requires in-order
  ///                       delivery.
  /// \param  timeOut       Maximum inactivity time before context is garbage
  ///                       collected (seconds).
  /// \param  time_to_go    The Time-to-go value, in milliseconds.
  /// \param  ttg_valid     True if the time to go was set to something other
  ///                       than 0.
  /// \param  util_fn_defn  The utility function definition.
  /// \param  dscp          The DSCP value.
  /// \param  reorder_time  The maximum time the packet should be held for
  ///                       reordering at the decoder.
  /// \param  dst_vec       Bit vector specifying multicast destination bin IDs
  ///                       for when this is a context for a multicast flow.
  FECContext(int loPort, int hiPort, int baseRate, int totalRate,
             int maxChunkSz, struct timeval maxHoldTime, bool inOrder,
             time_t timeOut, const iron::Time& time_to_go, bool ttg_valid,
             std::string util_fn_defn, int8_t dscp,
             const iron::Time& reorder_time, const iron::DstVec& dst_vec);


  /// \brief  Destructor.
  virtual ~FECContext();

  /// \brief Set the lower bound of the port range for this context.
  ///
  /// \param lo_port The lower bound of the port range for this context.
  inline void set_lo_port(int lo_port)
  {
    lo_port_ = lo_port;
  }

  /// \brief Get the lower bound of the port range for this context.
  ///
  /// \return The lower bound of the port range for this context.
  inline int lo_port() const
  {
    return lo_port_;
  }

  /// \brief Set the upper bound of the port range for this context.
  ///
  /// \param hi_port The upper end of the port range for this context.
  inline void set_hi_port(int hi_port)
  {
    hi_port_ = hi_port;
  }

  /// \brief Get the upper bound of the port range for this context.
  ///
  /// \return The upper bound of the port range for this context.
  inline int hi_port() const
  {
    return hi_port_;
  }

  /// \brief Set the base encoding rate for this context.
  ///
  /// param base_rate The base encoding rate for this context.
  inline void set_base_rate(int base_rate)
  {
    base_rate_ = base_rate;
  }

  /// \brief Get the base encoding rate for this context.
  ///
  /// \return The base encoding rate for this context.
  inline int base_rate() const
  {
    return base_rate_;
  }

  /// \brief Set the total encoding rate for this context.
  ///
  /// \param total_rate The total encoding rate for this context.
  inline void set_total_rate(int total_rate)
  {
    total_rate_ = total_rate;
  }

  /// \brief Get the total encoding rate for this context.
  ///
  /// \return The total encoding rate for this context.
  inline int total_rate() const
  {
    return total_rate_;
  }

  /// Set the maximum payload size of each chunk for this context.
  ///
  /// \param max_chunk_sz The maximum payload size of each chunk for this
  ///                     context.
  inline void set_max_chunk_sz(int max_chunk_sz)
  {
    max_chunk_sz_ = max_chunk_sz;
  }

  /// \brief Get the maximum chunk size for this context.
  ///
  /// \return The maximum payload size of each chunk for this context.
  inline int max_chunk_sz() const
  {
    return max_chunk_sz_;
  }

  /// \brief Set the maximum hold time before forcing FEC repair packet
  ///        generation.
  ///
  /// \param max_hold_time The maximum hold time before forcing FEC
  ///                      repair packet generation.
  inline void set_max_hold_time(struct timeval max_hold_time)
  {
    max_hold_time_ = max_hold_time;
  }

  /// \brief Get the maximum hold time before forcing FEC repair
  ///        packet generation for this context.
  ///
  /// \return The maximum hold time before forcing FEC repair packet generation.
  inline struct timeval max_hold_time() const
  {
    return max_hold_time_;
  }

  /// \brief Set the flag indicating whether in order delivery is required.
  ///
  /// \param in_order A flag indicating whether in order delivery is required.
  inline void set_in_order(bool in_order)
  {
    in_order_ = in_order;
  }

  /// \brief Get the inOrder flag for this context.
  ///
  /// \return A flag indicating whether in order delivery is required.
  inline bool in_order() const
  {
    return in_order_;
  }

  /// \brief Set the garbage collection timeout value for old state.
  ///
  /// \param timeout The garbage collection timeout value for old state.
  inline void set_timeout(time_t timeout)
  {
    timeout_ = timeout;
  }

  /// \brief Get the garbage collection timeout value for this context.
  ///
  /// \return The garbage collection timeout value for old state.
  inline time_t timeout() const
  {
    return timeout_;
  }

  /// \brief Get the differentiated service value for this context.
  ///
  /// \return The differentiated service value for this context.
  inline uint8_t dscp() const
  {
    return dscp_;
  }

  /// \brief Set the differentiated service value for this state.
  ///
  /// \param  dscp_val  The differentiated service value for this state.
  inline void SetDSCP(uint8_t dscp_val)
  {
    dscp_ = dscp_val;
  }

  /// \brief Set the time-to-go time.
  ///
  /// \param  ttg  The time-to-go time.
  inline void set_time_to_go(const iron::Time& ttg)
  {
    time_to_go_ = ttg;
  }

  /// \brief Set the destination bit vector.
  ///
  /// \param  dst_vec  Bit vector specifying multicast destination bin IDs.
  inline void set_dst_vec(const iron::DstVec& dst_vec)
  {
    dst_vec_ = dst_vec;
  }

  /// \brief Get the time-to-go time.
  ///
  /// \return The time-to-go time.
  inline iron::Time time_to_go() const
  {
    return time_to_go_;
  }

  /// \brief Set whether or not the time to go is valid.
  ///
  /// \param  ttg_valid  The time-to-go validity.
  inline void set_time_to_go_valid(bool ttg_valid)
  {
    time_to_go_valid_ = ttg_valid;
  }

  /// \brief Get the time-to-go validity (was it explicitly set for this flow).
  ///
  /// \return The time-to-go validity.
  inline bool time_to_go_valid() const
  {
    return time_to_go_valid_;
  }

  /// \brief Set the utility function definition string.
  ///
  /// \param defn The service definition string.
  inline void set_util_fn_defn(const std::string defn)
  {
    util_fn_defn_ = defn;
  }

  /// \brief Get the utility function definition as a string.
  ///
  /// \return The service definition string.
  inline const std::string &util_fn_defn() const
  {
    return util_fn_defn_;
  }

  /// \brief Set the maximum reorder time.
  ///
  /// \param reorder_time The maximum reorder time for this context.
  inline void set_reorder_time(iron::Time& reorder_time)
  {
    reorder_time_ = reorder_time;
  }

  /// \brief Get the maximum reorder time.
  ///
  /// \return The maximum reorder time.
  inline iron::Time reorder_time() const
  {
    return reorder_time_;
  }

  /// \brief Get the destination bit vector.
  ///
  /// \return  Bit vector specifying multicast destination bin IDs.
  inline iron::DstVec dst_vec() const
  {
    return dst_vec_;
  }

  protected:

  /// Lower end of the covered port range.
  int             lo_port_;

  /// Upper end of the covered port range.
  int             hi_port_;

  /// Base rate for the FEC encoder.
  int             base_rate_;

  /// Total rate for the FEC encoder.
  int             total_rate_;

  /// Maximum number of *PAYLOAD* bytes in a chunk.
  int             max_chunk_sz_;

 /// Max time before releasing a partial FEC.
  struct timeval  max_hold_time_;

  /// Only send in order flag
  bool            in_order_;

  /// How long to keep old state (sec) - 0 is forever.
  time_t          timeout_;

  /// The time-to-go time.
  iron::Time      time_to_go_;

  /// True if the time to go was set to something other than 0 (no time to
  /// go).
  bool            time_to_go_valid_;

  /// DSCP value.
  int8_t          dscp_;

  /// Utility function definition string.
  std::string     util_fn_defn_;

  /// The maximum hold time for reordering in the decoding state.
  iron::Time      reorder_time_;

  /// Bit vector specifying multicast destination bin IDs for when this is a
  /// context for a multicast flow.
  iron::DstVec    dst_vec_;
};

#endif // IRON_UDP_PROXY_FEC_CONTEXT_H
