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

#include "fec_state.h"
#include "decoding_state.h"
#include "log.h"
#include "packet_pool.h"
#include "unused.h"
#include "vdmfec.h"

#include <ctime>
#include <limits>

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

using ::iron::BinId;
using ::iron::FlowState;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Time;

namespace
{
  /// Class name for logging.
  const char  kClassName[] = "FecState";
}

//============================================================================
FecState::FecState(iron::PacketPool& packet_pool)
    : packet_pool_(packet_pool),
      bytes_sourced_(0),
      bytes_released_(0),
      max_pkt_sn_(0),
      min_pkt_sn_(0),
      bin_id_(0)
{
  int i;

  group_id_         =  0;
  base_rate_        =  0;
  fec_rate_         =  0;
  orig_count_       =  0;
  fec_count_        =  0;
  max_pkt_id_        = -1;
  expiration_time_ = Time(0);
  fec_used_        =  true;
  decoding_state_  = NULL;

  for (i = 0; i < MAX_FEC_RATE; i++)
  {
    orig_cache_[i]  = NULL;
    orig_valid_[i]  = false;
    pkt_sent_[i]    = false;
    pkt_lookup_[i]  = -1;
  }

  for (i = 0; i < MAX_FEC_RATE; i++)
  {
    fec_cache_[i]   = NULL;
    fec_valid_[i]   = false;
  }
}

//============================================================================
FecState::~FecState()
{
  // Recycle any Packets in the cache.
  FlushCache();
}

//============================================================================
void FecState::Initialize()
{
  int i;
  for (i = 0; i < orig_count_; i++)
  {
    orig_cache_[i] = NULL;
    orig_valid_[i] = false;
    pkt_sent_[i]   = false;
    pkt_lookup_[i] = -1;
  }

  for (i = 0; i < fec_count_; i++)
  {
    fec_cache_[i] = NULL;
    fec_valid_[i] = false;
  }

  group_id_         =  0;
  base_rate_        =  0;
  fec_rate_         =  0;
  orig_count_       =  0;
  fec_count_        =  0;
  max_pkt_id_        = -1;
  expiration_time_ = Time(0);
  fec_used_        =  true;
  decoding_state_  = NULL;

  bytes_sourced_  = 0;
  bytes_released_ = 0;
  min_pkt_sn_     = 0;
  max_pkt_sn_     = 0;
  bin_id_         = 0;
}

//============================================================================
int FecState::AddToCache(unsigned long type, Packet* qpkt, int index,
                         bool fec_used, uint64_t bytes_sourced,
                         uint32_t pkts_sourced)
{
  if (bytes_sourced > bytes_sourced_)
  {
    bytes_sourced_ = bytes_sourced;
    max_pkt_sn_    = pkts_sourced;
  }

  if (min_pkt_sn_ == 0)
  {
    min_pkt_sn_ = pkts_sourced - index;
    bin_id_     = qpkt->bin_id();
  }

  if (type == FEC_ORIGINAL)
  {
    if ((index < 0) || (index >=  MAX_FEC_RATE) ||
        (orig_valid_[index] == true))
    {
      return FECSTATE_OUTOFBOUNDS;
    }

    orig_cache_[index] = qpkt;
    orig_valid_[index] = true;
    orig_count_++;
    fec_used_ = fec_used;

    // Do some bookeeping to help reassembly functions
    UpdateLookupInfo(index);
  }

  else // if (type == FEC_REPAIR)
  {
    if ((index < 0) || (index >=  MAX_FEC_RATE) || (fec_valid_[index] == true))
    {
      return FECSTATE_OUTOFBOUNDS;
    }

    fec_cache_[index] = qpkt;
    fec_valid_[index] = true;
    fec_count_++;
  }

  return FECSTATE_OKAY;
}

//============================================================================
Packet* FecState::ReassembleFromCache(int pktID)
{
  FECChunkTrailer*  chunkTrlr;
  Packet*           cpkt = NULL;
  Packet*           qpkt = NULL;

  unsigned char*  bffr;
  int             start;
  int             len;
  int             initPktID;
  int             nChunks;
  int             index;
  int             i;
  bool            failed = false;

  // Sanity check for a call against a pktID for which we have no data
  if ((pktID < 0) || (pktID > max_pkt_id_))
  {
    LogW(kClassName, __func__, "   pktID %d out of range\n", pktID);
    return NULL;
  }

  // Retrieve the index into the cache for this packet ID and do another
  // sanity check.
  index = pkt_lookup_[pktID];

  if ((index < 0) || (index >= MAX_FEC_RATE) || (!orig_valid_[index]))
  {
    LogD(kClassName,__func__, "   Packet index %d out of range or not "
         "valid\n", index);
    return NULL;
  }

  // If we have already sent this packet, we just return.
  if ( pkt_sent_[pktID])
  {
    LogD(kClassName,__func__, "   Packet %d (index %d) already sent.\n",
         pktID, index);
    return NULL;
  }

  // We have a valid ID and some supporting data for a packet that has not yet
  // been sent. Looks like we might actually have something to do. See
  // if we have all the chunks

  cpkt = orig_cache_[index];
  len  = cpkt->GetLengthInBytes() - sizeof(FECChunkTrailer);

  chunkTrlr = (FECChunkTrailer *)(cpkt->GetBuffer() + len);
  initPktID = chunkTrlr->pkt_id;
  nChunks   = chunkTrlr->n_chunks;

  // Please note that although we could check the chunk trailers for
  // consistency (i.e., they are in sequence and all from the same packet) we
  // assume that the FEC control trailer causes us to correctly place the
  // chunks into the right slots -- so all we really need to test for is
  // whether the packet is in the slot.
  if (chunkTrlr->is_blob)
  {
    if ((pktID <  initPktID) || (pktID >= initPktID + nChunks))
    {
      LogW(kClassName, __func__, "   pktID out of range.\n");
      return NULL;
    }
  }
  else
  {
    for (i = 0; i < nChunks; i++)
    {
      if (!orig_valid_[index+i])
      {
        // Looks like we are still missing chunks.
        return NULL;
      }
    }
  }

  // Looks like we have them all. Set up a new packet object to hold the
  // rebuilt packet.
  qpkt = packet_pool_.CloneHeaderOnly(cpkt, iron::PACKET_NO_TIMESTAMP);
  qpkt->set_bin_id(cpkt->bin_id());
  qpkt->set_origin_ts_ms(cpkt->origin_ts_ms());
  if (!qpkt)
  {
    LogF(kClassName, __func__, "Failed to clone packet\n");
  }

  // Now reassemble the original packet from its chunks
  if (chunkTrlr->is_blob)
  {
    unsigned char *payld;
    unsigned short plen;
    unsigned int   chkLen;

    // Grab key values, pointers
    bffr  = cpkt->GetBuffer();
    start = cpkt->GetIpPayloadOffset();
    payld = &bffr[start];

    memcpy(&plen,payld,sizeof(plen));
    payld += sizeof(plen);
    chkLen = sizeof(plen) + plen;

    while ((initPktID < pktID) && !failed)
    {
      if ((chkLen + sizeof(plen)) > (unsigned)len)
      {
        // We are about to read past the end of the packet
        LogW(kClassName, __func__, "   Reconstruction failure: request to "
             "read past the end of muliple packet chunk.\n");
        failed = true;
      }
      else
      {
        payld  += plen;
        memcpy(&plen,payld,sizeof(plen));
        payld  += sizeof(plen);;
        chkLen += plen + sizeof(plen);

        initPktID ++;
      }
    }

    // Append this chunk to the end of our reassembly packet.
    if (!failed)
    {
      qpkt->AppendBlockToEnd((uint8_t*)payld,plen);
    }
  }
  else
  {
    failed = false;
    for (i = 0; i < nChunks; i++)
    {
      // Get a pointer to the next chunk
      cpkt  = orig_cache_[index+i];

      // Grab key values, pointers
      bffr  = cpkt->GetBuffer();
      start = cpkt->GetIpPayloadOffset();
      len   = cpkt->GetLengthInBytes() - (start + sizeof(FECChunkTrailer));

      chunkTrlr = (FECChunkTrailer *)&bffr[cpkt->GetLengthInBytes() -
                                           sizeof(FECChunkTrailer)];
      if ((chunkTrlr->chunk_id != i) || (chunkTrlr->pkt_id != pktID))
      {
        LogW(kClassName, __func__, "Mismatch in reconstruction parameters: "
             "expected chunkID %u got %u; expected pktID %u got %u\n", i,
             chunkTrlr->chunk_id, pktID, chunkTrlr->pkt_id);
        failed = true;
      }

      // Append this chunk to the end of our reassembly packet
      if (!failed)
      {
        qpkt->AppendBlockToEnd((uint8_t*)&bffr[start],len);
      }
    }
  }

  // Throw the packet away if reconstruction fails
  if (failed)
  {
    LogW(kClassName, __func__, "   failed reassembly\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(qpkt);
    return NULL;
  }

  // Recompute the checksums, and we're good to go
  qpkt->UpdateChecksums();

  // Mark that we have sent this packet
  pkt_sent_[pktID] = true;
  bytes_released_ += qpkt->GetLengthInBytes();

  return qpkt;
}

//============================================================================
bool FecState::UpdateFEC()
{
  Packet *qpkt    = (Packet *)NULL;
  Packet *rpkt    = (Packet *)NULL;
  Packet *lastPkt = (Packet *)NULL;

  FECRepairTrailer repTrlr;
  ::memset(&repTrlr, 0, sizeof(repTrlr));

  unsigned char *qptr;
  unsigned char *qdata;
  int            qlen;

  unsigned char *rptr;
  unsigned char *rdata;
  int            rlen;

  unsigned short fecLen;

  int rprID = 0;
  int hole;
  int i;
  int j;
  int rc;

  // Check for benign condition (we have all the orig packets)

  if (orig_count_ == base_rate_)
    return true;


  // Return false if we don't have enough combined original
  // and repair packets to do anything

  if ((orig_count_ + fec_count_) < base_rate_)
    return false;


  // If here we have enough packets to do a repair.


  // We support two special modes: rate 1/N, and rate N/(N+1)
  // in addition to the more general N/(N+K) Vandermond matrix
  // based FEC encoder

  if (base_rate_ == 1) // rate 1/N mode
  {
    // If we are here, we haven't sent the original packet
    // but we have at least one repair packet in the cache.
    // which is good enough for this coding rate

    for (i=0; i<(int)fec_rate_; i++)
    {
      if (fec_valid_[i])
      {
        rpkt  = fec_cache_[i];
        rprID = i;
        break;
      }
    }

    if (!rpkt)
    {
      return(false);
    }

    // Note that we store repair packets with the additional
    // trailer so we can conveniently retain the FECed length
    // Hence we need to remove it before sending it

    if (!rpkt->RemoveBlockFromEnd((uint8_t*)&repTrlr,(int)sizeof(repTrlr)))
    {
      LogW(kClassName, __func__, "Failed to remove block from end\n");
    }

    // We used the repair packet to form the original
    // packet. So we need to fixup the various caches

    orig_cache_[0]    = rpkt;
    orig_valid_[0]    = true;
    pkt_sent_[0]      = false;
    orig_count_++;

    UpdateLookupInfo(0);

    fec_cache_[rprID] = NULL;
    fec_valid_[rprID] = false;
    fec_count_--;
  }

  else if (fec_rate_ == 1) // rate N/(N+1) mode
  {
    // If we are here, we have exactly one repair packet in
    // the cache, so we don't need to search

    rpkt = fec_cache_[0];

    // Again we store repair packets with the additional
    // trailer, so we need to remove it

    if (!rpkt->RemoveBlockFromEnd((uint8_t*)&repTrlr,(int)sizeof(repTrlr)))
    {
      LogW(kClassName, __func__, "Failed to remove block from end\n");
    }

    // Now perform the FEC processing

    rptr  = rpkt->GetBuffer();
    rdata = rptr + rpkt->GetIpPayloadOffset();

    fecLen = repTrlr.fec_len;

    // Pull remaining packets in sequence from the cache
    // and use them to compute the single FEC block

    hole = -1;

    for (i=0; i<base_rate_; i++)
    {
      if (orig_valid_[i])
      {
        qpkt = orig_cache_[i];
        qptr  = qpkt->GetBuffer();
        qdata = qptr + qpkt->GetIpPayloadOffset();
        qlen  = qpkt->GetLengthInBytes() - (qdata - qptr);

        for (j=0; j<qlen; j++)
        {
          rdata[j] ^= qdata[j];
        }

        // Also reconstruct the length of the missing
        // packet

        fecLen ^= (unsigned short)qlen;
      }

      else // Found the hole
      {
        hole = i;
      }
    }

    if (hole == -1)
    {
      LogF(kClassName, __func__, "Could not find a hole\n");
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(qpkt);
      packet_pool_.Recycle(rpkt);
      return(false);
    }

    rpkt->UpdateIpLen(fecLen + (rdata-rptr));

    // We used the repair packet to form the missing original
    // packet. So we need to fixup the various caches

    orig_cache_[hole] = rpkt;
    orig_valid_[hole] = true;
    pkt_sent_[hole]   = false;

    UpdateLookupInfo(hole);

    orig_count_++;

    fec_cache_[0] = NULL;
    fec_valid_[0] = false;
    fec_count_--;
  }

  else // Must be we used the VDM FEC code
  {
    unsigned char *psrc   [MAX_FEC_RATE];
    unsigned char *pdst   [MAX_FEC_RATE];
    int            index  [MAX_FEC_RATE];
    unsigned short szArray[MAX_FEC_RATE];
    unsigned short fecSz  [MAX_FEC_RATE];
    unsigned short recSz  [MAX_FEC_RATE];

    memset(psrc,    0, sizeof(psrc));
    memset(pdst,    0, sizeof(pdst));
    memset(index,   0, sizeof(index));
    memset(szArray, 0, sizeof(szArray));
    memset(fecSz,   0, sizeof(fecSz));
    memset(recSz,   0, sizeof(recSz));

    for (i=0,j=0; i<base_rate_; i++)
    {
      if (orig_valid_[i])
      {
        qpkt = orig_cache_[i];
        qptr  = qpkt->GetBuffer();
        qdata = qptr + qpkt->GetIpPayloadOffset();
        qlen  = qpkt->GetLengthInBytes() - (qdata - qptr);

        psrc[j]    = qdata;
        szArray[j] = qlen;
        fecSz[j]   = qlen;
        index[j++] = i;

        pdst[i]    = qdata;
        lastPkt    = qpkt;
      }
    }

    for (i=0; i<fec_rate_; i++)
    {
      if (fec_valid_[i])
      {
        rpkt = fec_cache_[i];

        if (!rpkt->RemoveBlockFromEnd((uint8_t*)&repTrlr,(int)sizeof(repTrlr)))
        {
          LogW(kClassName, __func__, "Failed to remove block from end\n");
        }

        rptr  = rpkt->GetBuffer();
        rdata = rptr + rpkt->GetIpPayloadOffset();
        rlen  = rpkt->GetLengthInBytes() - (rdata - rptr);

        psrc[j]    = rdata;
        szArray[j] = rlen;
        fecSz[j]   = repTrlr.fec_len;
        index[j++] = i + base_rate_;
        lastPkt    = rpkt;
      }
    }

    if (j != base_rate_)
    {
      LogW(kClassName, __func__, "Corrupted state in FEC decoder\n");
      return false;
    }

    // We finish setting up the call by creating empty packets
    // with the correct IP headers as targets for the reconstruction
    // process
    qpkt = lastPkt;
    for (i=0; i<base_rate_; i++)
    {
      if (!orig_valid_[i])
      {
        rpkt    = packet_pool_.Clone(qpkt, false, iron::PACKET_NO_TIMESTAMP);
        rptr    = rpkt->GetBuffer();
        rdata   = rptr + rpkt->GetIpPayloadOffset();

        pdst[i] = rdata;

        orig_cache_[i] = rpkt;
      }
    }

    if ((rc = decode_vdmfec (psrc, pdst, index, base_rate_, szArray, fecSz, recSz)) != 0)
    {
      LogW(kClassName, __func__, "FEC decoding error: decoder returned %d)\n", rc);

      // If we hit a decoding error, we need to back out the newly allocated
      // packets intended to hold the repairs
      for (i=0; i<base_rate_; i++)
      {
        if (!orig_valid_[i])
        {
          TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
          packet_pool_.Recycle(orig_cache_[i]);
        }
      }

      // and abort
      return false;
    }

    LogD(kClassName, __func__, "Decode vdm success\n");

    // If we are here, we successfully performed a reconstruction
    // Now we just need to assign the packet lengths and mark them as valid
    for (i=0; i<base_rate_; i++)
    {
      if (!orig_valid_[i])
      {
        rpkt = orig_cache_[i];
        rptr  = rpkt->GetBuffer();
        rdata = rptr + rpkt->GetIpPayloadOffset();

        rpkt->UpdateIpLen(recSz[i] + (rdata-rptr));

        // Can now declare the repaired packet as valid

        orig_valid_[i] = true;
        orig_count_++;

        UpdateLookupInfo(i);
      }
    }
  }

  return true;
}

//============================================================================
int FecState::FlushCache()
{
  int i;

  for (i=0; i<MAX_FEC_RATE; i++)
  {
    if (orig_valid_[i])
    {
      packet_pool_.Recycle(orig_cache_[i]);
      orig_valid_[i] = false;
    }
    pkt_sent_[i]   = false;
    pkt_lookup_[i] = -1;
  }

  orig_count_ =  0;
  max_pkt_id_  = -1;

  for (i=0; i<MAX_FEC_RATE; i++)
  {
    if (fec_valid_[i])
    {
      packet_pool_.Recycle(fec_cache_[i]);
      fec_valid_[i] = false;
    }
  }

  fec_count_ = 0;

  // Also reset the rates.
  base_rate_ = 0;
  fec_rate_  = 0;

  return FECSTATE_OKAY;
}

//============================================================================
int FecState::getFirstUnsentPktID() const
{
  int  i;
  for (i = 0; i <= max_pkt_id_; i++)
  {
    if (!pkt_sent_[i])
    {
      return (i);
    }
  }
  return (max_pkt_id_ + 1);
}

//============================================================================
Time FecState::next_pkt_exp(int index) const
{
  Time  zero_time(0);

  for (int i = index + 1; i <= max_pkt_id_; i++)
  {
    if ((pkt_expiration_time_[i] != zero_time) && !pkt_sent_[i])
    {
      return pkt_expiration_time_[i];
    }
  }
  return Time::Infinite();
}

//============================================================================
Packet* FecState::FetchFromCache(unsigned long type, int index)
{
  if (type == FEC_ORIGINAL)
  {
    if ((index < 0) || (index >=  MAX_FEC_RATE) || (!orig_valid_[index]))
    {
      return NULL;
    }
    return orig_cache_[index];
  }
  else // if (type == FEC_REPAIR)
  {
    if ((index < 0) || (index >=  MAX_FEC_RATE) || (!fec_valid_[index]))
    {
      return NULL;
    }
    return fec_cache_[index];
  }
}

//============================================================================
void FecState::UpdateLookupInfo(int index)
{
  Packet*          cpkt;
  FECChunkTrailer* chunkTrlr;
  unsigned int     pktID;
  unsigned int     chunkID;
  unsigned int     nChunks;
  unsigned int     i;
  unsigned int     len;

  // Get the chunk trailer
  cpkt = orig_cache_[index];
  len  = cpkt->GetLengthInBytes() - sizeof(FECChunkTrailer);

  chunkTrlr = (FECChunkTrailer *)(cpkt->GetBuffer() + len);
  chunkID   =  chunkTrlr->chunk_id;
  pktID     =  chunkTrlr->pkt_id;
  nChunks   =  chunkTrlr->n_chunks;

  // Updates depend on whether or not this is a blob
  if (chunkTrlr->is_blob)
  {
    // If this is a blob, record that it contains multiple packets
    for (i=0; i<nChunks; i++)
    {
      pkt_lookup_[pktID + i] = index;
      unsigned short dport = 0;
      cpkt->GetDstPort(dport);

      dport = ntohs(dport);
      LogD(kClassName, __func__, "   setting lookup for blob pktID %d to %d "
           "(port %u)\n", pktID + i, index, dport);

    }

    // Remember the maximum packet index seen so far
    if (max_pkt_id_ < (int)(pktID + nChunks - 1))
    {
      max_pkt_id_ = (int)(pktID + nChunks - 1);
    }
  }
  else
  {
    // If not a blob, only record the lookup if its the first chunk
    if (chunkID == 0)
    {
      pkt_lookup_[pktID] = index;
      unsigned short dport = 0;
      cpkt->GetDstPort(dport);
      dport = ntohs(dport);
      LogD(kClassName, __func__, "   setting lookup for fragment pktID %d to "
           "%d (port %u)\n", pktID, index, dport);
    }

    // Remember the maximum packet index seen so far
    if (max_pkt_id_ < (int)pktID)
    {
      max_pkt_id_ = (int)pktID;
    }
  }
}
