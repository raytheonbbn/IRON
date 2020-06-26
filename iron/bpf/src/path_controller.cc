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

/// \file path_controller.cc
///
/// The Path Controller source file.
///

#include "path_controller.h"

#include "log.h"

#include <inttypes.h>


using ::iron::Log;
using ::iron::Packet;
using ::iron::PathController;


//
// Constants.
//
namespace
{
  /// The class name string for logging.
  const char  kClassName[] = "PathController";
}


//============================================================================
bool PathController::NeedsMetadataHeaders(Packet* pkt)
{
  if (pkt == NULL)
  {
    return false;
  }

  // Note: The latency header is needed only if there is an origin timestamp
  // to send.  This is because the SLIQ data header captures the TTG
  // information from the Packet object.
  return ((pkt->origin_ts_ms() != kUnsetOriginTs) ||
          pkt->send_packet_history() || pkt->send_packet_id() ||
          pkt->send_packet_dst_vec());
}

//============================================================================
bool PathController::AddMetadataHeaders(Packet* pkt)
{
  if (pkt == NULL)
  {
    return false;
  }

  // Clear any existing metadata headers in the packet.
  size_t  mdh_len = 0;

  if (!pkt->SetMetadataHeaderLengthInBytes(mdh_len))
  {
    return false;
  }

  // Add a latency header only if there is an origin timestamp to send.
  if (pkt->origin_ts_ms() != kUnsetOriginTs)
  {
    PktLatencyHeader  lat_hdr;

    // Only store the origin timestamp.
    lat_hdr.type       = CAT_PKT_LATENCY_HEADER;
    lat_hdr.flags      = 0;
    lat_hdr.origin_ts  = htons(pkt->origin_ts_ms());
    lat_hdr.time_to_go = 0;

    mdh_len += kPktLatHdrSize;

    if (!pkt->SetMetadataHeaderLengthInBytes(mdh_len))
    {
      return false;
    }

    ::memcpy(reinterpret_cast<void*>(pkt->GetMetadataHeaderBuffer()),
             &lat_hdr, kPktLatHdrSize);

    LogD(kClassName, __func__, "Path controller %" PRIu32 " added latency "
         "header: origin_ts %" PRIu16 "\n", path_controller_number_,
         pkt->origin_ts_ms());
  }

  // Add the CAT packet history header if needed.
  if (pkt->send_packet_history())
  {
    PktHistoryHeader  hst_hdr;

    hst_hdr.type = CAT_PKT_HISTORY_HEADER;
    ::memcpy(reinterpret_cast<void*>(hst_hdr.history), pkt->history(),
             sizeof(hst_hdr.history));

    mdh_len += kPktHistHdrSize;

    if (!pkt->SetMetadataHeaderLengthInBytes(mdh_len))
    {
      return false;
    }

    ::memcpy(reinterpret_cast<void*>(pkt->GetMetadataHeaderBuffer()),
             &hst_hdr, kPktHistHdrSize);

    LogD(kClassName, __func__, "Path controller %" PRIu32 " added history "
         "header: %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %"
         PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 "\n",
         path_controller_number_, hst_hdr.history[0], hst_hdr.history[1],
         hst_hdr.history[2], hst_hdr.history[3], hst_hdr.history[4],
         hst_hdr.history[5], hst_hdr.history[6], hst_hdr.history[7],
         hst_hdr.history[8], hst_hdr.history[9], hst_hdr.history[10]);
  }

  // Add the CAT packet ID header if needed.
  if (pkt->send_packet_id())
  {
    PktIdHeader  id_hdr;

    id_hdr.type_bin_id_pkt_id = htonl(
      (static_cast<uint32_t>(CAT_PKT_ID_HEADER) << 24) |
      ((static_cast<uint32_t>(pkt->bin_id()) & 0x0f) << 20) |
      (pkt->packet_id() & 0x000fffff));

    mdh_len += kPktIdHdrSize;

    if (!pkt->SetMetadataHeaderLengthInBytes(mdh_len))
    {
      return false;
    }

    ::memcpy(reinterpret_cast<void*>(pkt->GetMetadataHeaderBuffer()), &id_hdr,
             kPktIdHdrSize);

    LogD(kClassName, __func__, "Path controller %" PRIu32 " added packet ID "
         "header: bin_id %" PRIBinId " pkt_id %" PRIu32 "\n",
         path_controller_number_, pkt->bin_id(), pkt->packet_id());
  }

  // Add the CAT packet destination vector header if needed.
  if (pkt->send_packet_dst_vec())
  {
    PktDstVecHeader  dst_hdr;

    dst_hdr.type_dst_vec = htonl(
      (static_cast<uint32_t>(CAT_PKT_DST_VEC_HEADER) << 24) |
      (pkt->dst_vec() & 0x00ffffff));

    mdh_len += kPktDstVecHdrSize;

    if (!pkt->SetMetadataHeaderLengthInBytes(mdh_len))
    {
      return false;
    }

    ::memcpy(reinterpret_cast<void*>(pkt->GetMetadataHeaderBuffer()),
             &dst_hdr, kPktDstVecHdrSize);

    LogD(kClassName, __func__, "Path controller %" PRIu32 " added "
         "destination vector header: dst vec %" PRIu32 "\n",
         path_controller_number_, pkt->dst_vec());
  }

  return true;
}

//============================================================================
bool PathController::ProcessMetadataHeaders(Packet* pkt)
{
  if (pkt == NULL)
  {
    return false;
  }

  // Loop over the packet headers, processing and removing each of the Packet
  // object metadata headers that are understood by the path controller.
  bool  stop = false;

  while ((!stop) && (pkt->GetLengthInBytes() > 0))
  {
    // Get the next packet header's type.
    int  hdr_type = pkt->GetRawType();

    // Process the Packet object metadata headers.
    switch (hdr_type)
    {
      case CAT_PKT_DST_VEC_HEADER:
      {
        if (pkt->GetLengthInBytes() < kPktDstVecHdrSize)
        {
          return false;
        }

        PktDstVecHeader  dst_hdr;

        ::memcpy(&dst_hdr, reinterpret_cast<void*>(pkt->GetBuffer()),
                 kPktDstVecHdrSize);

        if (!pkt->RemoveBytesFromBeginning(kPktDstVecHdrSize))
        {
          return false;
        }

        uint32_t  dst_mask = (ntohl(dst_hdr.type_dst_vec) & 0x00ffffff);

        pkt->set_dst_vec(dst_mask);
        pkt->set_send_packet_dst_vec(true);

        LogD(kClassName, __func__, "Path controller %" PRIu32 " processed "
             "destination vector header: dst vec %" PRIu32 "\n",
             path_controller_number_, pkt->dst_vec());

        break;
      }

      case CAT_PKT_ID_HEADER:
      {
        if (pkt->GetLengthInBytes() < kPktIdHdrSize)
        {
          return false;
        }

        PktIdHeader  id_hdr;

        ::memcpy(&id_hdr, reinterpret_cast<void*>(pkt->GetBuffer()),
                 kPktIdHdrSize);

        if (!pkt->RemoveBytesFromBeginning(kPktIdHdrSize))
        {
          return false;
        }

        uint32_t  hdr_hbo = ntohl(id_hdr.type_bin_id_pkt_id);
        uint8_t   bin_id  = ((hdr_hbo >> 20) & 0x0f);
        uint32_t  pkt_id  = (hdr_hbo & 0x000fffff);

        pkt->set_bin_id(bin_id);
        pkt->set_packet_id(pkt_id);
        pkt->set_send_packet_id(true);

        LogD(kClassName, __func__, "Path controller %" PRIu32 " processed "
             "packet ID header: bin_id %" PRIBinId " pkt_id %" PRIu32 "\n",
             path_controller_number_, pkt->bin_id(), pkt->packet_id());

        break;
      }

      case CAT_PKT_HISTORY_HEADER:
      {
        if (pkt->GetLengthInBytes() < kPktHistHdrSize)
        {
          return false;
        }

        PktHistoryHeader  hst_hdr;

        ::memcpy(&hst_hdr, reinterpret_cast<void*>(pkt->GetBuffer()),
                 kPktHistHdrSize);

        if (!pkt->RemoveBytesFromBeginning(kPktHistHdrSize))
        {
          return false;
        }

        pkt->set_history(hst_hdr.history);
        pkt->set_send_packet_history(true);

        LogD(kClassName, __func__, "Path controller %" PRIu32 " processed "
             "history header: %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %"
             PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " %"
             PRIu8 "\n", path_controller_number_, hst_hdr.history[0],
             hst_hdr.history[1], hst_hdr.history[2], hst_hdr.history[3],
             hst_hdr.history[4], hst_hdr.history[5], hst_hdr.history[6],
             hst_hdr.history[7], hst_hdr.history[8], hst_hdr.history[9],
             hst_hdr.history[10]);

        break;
      }

      case CAT_PKT_LATENCY_HEADER:
      {
        if (pkt->GetLengthInBytes() < kPktLatHdrSize)
        {
          return false;
        }

        PktLatencyHeader  lat_hdr;

        ::memcpy(&lat_hdr, reinterpret_cast<void*>(pkt->GetBuffer()),
                 kPktLatHdrSize);

        if (!pkt->RemoveBytesFromBeginning(kPktLatHdrSize))
        {
          return false;
        }

        // Only extract the origin timestamp.
        uint16_t  origin_ts = ntohs(lat_hdr.origin_ts);

        pkt->set_origin_ts_ms(origin_ts);

        LogD(kClassName, __func__, "Path controller %" PRIu32 " processed "
             "latency header: origin_ts %" PRIu16 "\n",
             path_controller_number_, pkt->origin_ts_ms());

        break;
      }

      default:
        stop = true;
    }
  }

  return true;
}
