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
//
// This code is derived in part from the stablebits libquic code available at:
// https://github.com/stablebits/libquic.
//
// The stablebits code was forked from the devsisters libquic code available
// at:  https://github.com/devsisters/libquic
//
// The devsisters code was extracted from Google Chromium's QUIC
// implementation available at:
// https://chromium.googlesource.com/chromium/src.git/+/master/net/quic/
//
// The original source code file markings are preserved below.

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//============================================================================

#ifndef IRON_SLIQ_PRIVATE_TYPES_H
#define IRON_SLIQ_PRIVATE_TYPES_H

#include <stdint.h>
#include <inttypes.h>
#include <sys/uio.h>


namespace sliq
{

  typedef uint8_t   CcId;
  typedef uint32_t  ClientId;
  typedef uint32_t  EndOffset;
  typedef uint8_t   FecBlock;
  typedef uint16_t  FecEncPktLen;
  typedef uint32_t  FecGroupBitVec;
  typedef uint16_t  FecGroupId;
  typedef uint8_t   FecRound;
  typedef uint16_t  MsgTag;
  typedef uint32_t  PktCount;
  typedef uint32_t  PktSeqNumber;
  typedef uint8_t   RetransCount;
  typedef int       SocketId;
  typedef uint8_t   TtgCount;
  typedef uint16_t  TtgTime;
  typedef uint32_t  WindowSize;

  // Macros for printing format specifiers.
#define PRICcId              PRIu8
#define PRIClientId          PRIu32
#define PRIEndOffset         PRIu32
#define PRIFecBlock          PRIu8
#define PRIFecEncPktLen      PRIu16
#define PRIFecGroupBitVec    PRIu32
#define PRIFecGroupId        PRIu16
#define PRIFecRound          PRIu8
#define PRIMsgTag            PRIu16
#define PRIPktCount          PRIu32
#define PRIPktSeqNumber      PRIu32
#define PRIRetransCount      PRIu8
#define PRISocketId          "d"
#define PRITtgCount          PRIu8
#define PRITtgTime           PRIu16
#define PRIWindowSize        PRIu32

} // namespace sliq

#endif // IRON_SLIQ_PRIVATE_TYPES_H
