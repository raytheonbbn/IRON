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

/// \brief Provides definitions for IRON system-wide simple types.

#ifndef IRON_COMMON_IRON_TYPES_H
#define IRON_COMMON_IRON_TYPES_H

#include <stdint.h>
#include <inttypes.h>

/// Print formatter for printing type BinId.
#define PRIBinId PRIu8

/// Print formatter for printing type McastId.
#define PRIMcastId PRIu32

/// Print formatter for printing type BinIndex.
#define PRIBinIndex PRIu16

/// Print formatter for printing type DstVec.
#define PRIDstVec PRIu32

namespace iron
{
  /// N.B.: BinId is 0-based, McastId is 1-based, BinIndex (internal only) is
  /// 0-based.

  /// The type for Bin Identifiers (really IRON node identifiers). There is
  /// exactly one BinId for each IRON node. These are used for labeling
  /// traffic, tracking and directing packets, etc.
  ///
  /// Valid values are from 0 to kMaxUcastBinId for IRON edge nodes, and from
  /// 0 to kMaxBinId for IRON interior nodes. The invalid value kInvalidBinId
  /// is the maximum value of the type.
  ///
  /// Note: BinIds are carried on the wire. Changing this type requires
  /// changing packet formats.
  typedef uint8_t BinId;

  /// The type for Multicast Group Identifiers. There is one identifier for
  /// each multicast group, identified via a hash of the multicast group IPv4
  /// address to avoid contention. These are used for labeling groups in QLAMs
  /// and other data on-the-wire.
  ///
  /// Valid values are 1 to kMaxMcastId. The invalid value kInvalidMcastId is
  /// the minimum value of the type.
  ///
  /// Note: McastIds are carried on the wire. Changing this type requires
  /// changing packet formats.
  ///
  /// See also kMaxNumMcastGroups in iron_constants.h.
  typedef uint32_t McastId;

  /// The type for IRON node-specific Bin Indices that are used for arrays of
  /// local information. The arrays must utilize the BinIndexableArray
  /// template classes in order to work correctly.
  ///
  /// Valid values are 0 to kInvalidBinIndex-1. The invalid value
  /// kInvalidBinIndex is the maximum value of the type.
  ///
  /// This type is internal to each IRON node instance and is not exposed in
  /// any messages.
  ///
  /// There is a one-to-one mapping between in-use BinId and McastId values and
  /// in-use BinIndex values. However, these are distinct types in
  /// order to allow BinIds and McastIds that aren't adjacent. Within each
  /// block of BinIndex values (one for unicast destination BinIds, one for
  /// IRON interior node BinIds, and one for multicast destination McastIds),
  /// the BinIndex values must be contiguous. The BinIndexableArray template
  /// classes handle these three blocks of BinIndex values automatically.
  typedef uint16_t BinIndex;

  /// The type used to store a bit vector of BinId values indicating the
  /// unicast destinations (IRON edge nodes) to which a multicast packet must
  /// be sent.
  ///
  /// Note: If this type is changed, then path_controller.[h,cc] will also
  /// need to change to read/write the correct number of bits onto the
  /// wire. Anything that examines CAT headers on the wire (wireshark
  /// dissectors, for instance) would also have to be updated.
  typedef uint32_t DstVec;

} // namespace iron

#endif // IRON_COMMON_IRON_TYPES_H
