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

/// \brief Gradient structure
///
/// This structure defines a gradient, which is used in both
/// the forwarding algorithm and starvation computation in
/// bin queue mgr.  This gradient consists of a value, bin,
/// patch controller, and indication about whether or not the
/// destination is the next hop.

#ifndef IRON_BPF_GRADIENT_H
#define IRON_BPF_GRADIENT_H

#include "bin_map.h"

namespace iron
{

  /// Define the gradient structure used in algorithms.
  struct Gradient
  {
    int64_t        value;            // Value of gradient (negative possible).
    iron::BinIndex bin_idx;          // Destination (or mcast group) bin index
    size_t         path_ctrl_index;  // Path controller index.
    bool           is_dst;           // Whether path ctrl goes to bin's dst.
    DstVec         dst_vec;          // The positive gradient dst vector.
    bool           is_zombie;        // Flag to indicate if zombies dominate
                                     // the gradient.
    // Constructor.
    Gradient()
    : value(0), bin_idx(0), path_ctrl_index(0),
      is_dst(false), dst_vec(0), is_zombie(false)
    { }

    // Destructor.
    ~Gradient()
    {
      value = 0;
    }

    bool operator<(const Gradient& other) const
    {
      return value < other.value;
    }

    // Assignment operator.
    Gradient& operator= (const Gradient& other)
    {
      value           = other.value;
      bin_idx         = other.bin_idx;
      path_ctrl_index = other.path_ctrl_index;
      is_dst          = other.is_dst;
      dst_vec         = other.dst_vec;
      is_zombie       = other.is_zombie;
      return *this;
    }
  };  // End Gradient.

}
#endif  // IRON_BPF_GRADIENT_H
