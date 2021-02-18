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
  typedef uint16_t  FecEncPktLen;
  typedef uint32_t  FecGroupBitVec;
  typedef uint16_t  FecGroupId;
  typedef uint8_t   FecRound;
  typedef uint8_t   FecSize;
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
#define PRIFecEncPktLen      PRIu16
#define PRIFecGroupBitVec    PRIu32
#define PRIFecGroupId        PRIu16
#define PRIFecRound          PRIu8
#define PRIFecSize           PRIu8
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
