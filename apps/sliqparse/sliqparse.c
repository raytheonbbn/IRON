/* IRON: iron_headers */
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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <pcap.h>
#include <pcap/sll.h>
#include <math.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ppp_defs.h>
#include <stdint.h>
#include <inttypes.h>

#include "sliq.h"

/* Options. */
static int  opt_min_eth_warn = 0;
static int  opt_inner_pkts   = 1;
static int  opt_ack_blocks   = 1;
static int  opt_log[OPT_LOG_SIZE];

/* Output. */
static int  lines_logged = 0;


/* ======================================================================== */
void print_conn_hndshk(double pkt_time, const char *saddr, const char *daddr,
                       uint8_t *sliq, size_t pkt_len)
{
  uint8_t  i   = 0;
  size_t   len = 0;

  printf("%.6f ConHsk %s -> %s", pkt_time, saddr, daddr);

  if (pkt_len >= kConnHndshkHdrBaseSize)
  {
    struct ConnHndshkHdrBase   *chb_hdr = (struct ConnHndshkHdrBase *)sliq;
    struct ConnHndshkHdrCcAlg  *cha_hdr =
      (struct ConnHndshkHdrCcAlg *)(sliq + kConnHndshkHdrBaseSize);

    printf(" numcc %d tag %c%c ts %" PRIu32 " echo_ts %" PRIu32 ,
           (int)(chb_hdr->num_cc),
           (int)((chb_hdr->tag >> 8) & 0x00ff),
           (int)(chb_hdr->tag & 0x00ff),
           (uint32_t)ntohl(chb_hdr->ts),
           (uint32_t)ntohl(chb_hdr->echo_ts));

    for (i = 0, len = (kConnHndshkHdrBaseSize + kConnHndshkHdrCcAlgSize);
         ((i < chb_hdr->num_cc) && (len <= pkt_len));
         ++i, len += kConnHndshkHdrCcAlgSize)
    {
      printf(" | cc[%d] type %d det %d pace %d param %" PRIu32 ,
             (int)i,
             (int)cha_hdr[i].cc_type,
             (int)((cha_hdr[i].cc_flags >> 1) & 0x01),
             (int)(cha_hdr[i].cc_flags & 0x01),
             (uint32_t)ntohl(cha_hdr[i].cc_params));
    }
  }
  else
  {
    printf(" ERROR: too short");
  }

  printf("\n");
}

/* ======================================================================== */
void print_reset_conn(double pkt_time, const char *saddr, const char *daddr,
                      uint8_t *sliq, size_t pkt_len)
{
  printf("%.6f RstCon %s -> %s", pkt_time, saddr, daddr);

  if (pkt_len >= kResetConnHdrSize)
  {
    struct ResetConnHdr  *hdr = (struct ResetConnHdr *)sliq;

    printf(" error %d",
           (int)ntohs(hdr->error));
  }
  else
  {
    printf(" ERROR: too short");
  }

  printf("\n");
}

/* ======================================================================== */
void print_close_conn(double pkt_time, const char *saddr, const char *daddr,
                      uint8_t *sliq, size_t pkt_len)
{
  printf("%.6f ClsCon %s -> %s", pkt_time, saddr, daddr);

  if (pkt_len >= kCloseConnHdrSize)
  {
    struct CloseConnHdr  *hdr = (struct CloseConnHdr *)sliq;

    printf(" ack %d reason %d",
           (int)(hdr->flags & 0x01),
           (int)ntohs(hdr->reason));
  }
  else
  {
    printf(" ERROR: too short");
  }

  printf("\n");
}

/* ======================================================================== */
void print_create_stream(double pkt_time, const char *saddr,
                         const char *daddr, uint8_t *sliq, size_t pkt_len)
{
  int  del_time = 0;

  printf("%.6f CrtStm %s -> %s", pkt_time, saddr, daddr);

  if (pkt_len >= kCreateStreamHdrSize)
  {
    struct CreateStreamHdr  *hdr = (struct CreateStreamHdr *)sliq;

    del_time = ((hdr->flags >> 1) & 0x01);

    printf(" deltime %d ack %d stream %d prio %d initwinsz %" PRIu32
           " initseq %" PRIu32 " del %d rel %d rxlim %d",
           del_time,
           (int)(hdr->flags & 0x01),
           (int)(hdr->stream),
           (int)(hdr->priority),
           (uint32_t)ntohl(hdr->init_win_size),
           (uint32_t)ntohl(hdr->init_seq),
           (int)(((hdr->del_rel) >> 4) & 0x0f),
           (int)((hdr->del_rel) & 0x0f),
           (int)(hdr->rexmit_limit));

    if (del_time)
    {
      printf(" tgttime %f",
             ((double)ntohs(hdr->tgt_del) * 0.001));
    }
    else
    {
      printf(" tgtrnds %d",
             (int)ntohs(hdr->tgt_del));
    }

    printf(" tgtrcvprob %f",
           ((double)ntohs(hdr->tgt_rcv) * 0.0001));
  }
  else
  {
    printf(" ERROR: too short");
  }

  printf("\n");
}

/* ======================================================================== */
void print_reset_stream(double pkt_time, const char *saddr, const char *daddr,
                        uint8_t *sliq, size_t pkt_len)
{
  printf("%.6f RstStm %s -> %s", pkt_time, saddr, daddr);

  if (pkt_len >= kResetStreamHdrSize)
  {
    struct ResetStreamHdr  *hdr = (struct ResetStreamHdr *)sliq;

    printf(" stream %d error %d finseq %" PRIu32 ,
           (int)(hdr->stream),
           (int)(hdr->error),
           (uint32_t)ntohl(hdr->final_seq));
  }
  else
  {
    printf(" ERROR: too short");
  }

  printf("\n");
}

/* ======================================================================== */
void print_data(double pkt_time, const char *saddr, const char *daddr,
                size_t missing_len, uint8_t **sliq, size_t *pkt_len,
                int *enc_pkt)
{
  size_t  i           = 0;
  size_t  payload_len = 0;
  size_t  num_ttg     = 0;
  int     mv_fwd      = 0;
  int     fec         = 0;
  int     epl         = 0;

  *enc_pkt = 0;

  if (opt_log[DATA_HEADER])
  {
    printf("%.6f Data   %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kDataHdrBaseSize)
  {
    struct DataHdrBase  *b_hdr = (struct DataHdrBase *)(*sliq);

    mv_fwd  = (int)((b_hdr->flags >> 4) & 0x01);
    fec     = (int)((b_hdr->flags >> 5) & 0x01);
    epl     = (int)((b_hdr->flags >> 6) & 0x01);
    num_ttg = (size_t)(b_hdr->num_ttg);

    if (opt_log[DATA_HEADER])
    {
      printf(" epl %d fec %d mfw %d pst %d fin %d stream %d numttg %d cc %d "
             "rexmit %d plen %d seq %" PRIu32 " ts %" PRIu32 " ts_delta %"
             PRIu32 ,
             epl,
             fec,
             mv_fwd,
             (int)((b_hdr->flags >> 1) & 0x01),
             (int)(b_hdr->flags & 0x01),
             (int)(b_hdr->stream),
             (int)(b_hdr->num_ttg),
             (int)(b_hdr->cc_id),
             (int)(b_hdr->rexmit),
             (int)ntohs(b_hdr->pld_len),
             (uint32_t)ntohl(b_hdr->seq),
             (uint32_t)ntohl(b_hdr->ts),
             (uint32_t)ntohl(b_hdr->ts_delta));
    }

    *sliq    += kDataHdrBaseSize;
    *pkt_len -= kDataHdrBaseSize;

    payload_len = (*pkt_len + missing_len);

    if (mv_fwd != 0)
    {
      if (*pkt_len >= kDataHdrMvFwdSize)
      {
        if (opt_log[DATA_HEADER])
        {
          struct DataHdrMvFwd  *mf_hdr = (struct DataHdrMvFwd *)(*sliq);

          printf(" mfseq %" PRIu32 ,
                 (uint32_t)ntohl(mf_hdr->seq));
        }

        *sliq    += kDataHdrMvFwdSize;
        *pkt_len -= kDataHdrMvFwdSize;
      }
      else
      {
        *sliq    += kDataHdrMvFwdSize;
        *pkt_len  = 0;
      }

      payload_len -= kDataHdrMvFwdSize;
    }

    if (fec != 0)
    {
      if (*pkt_len >= kDataHdrFecSize)
      {
        struct DataHdrFec  *fec_hdr = (struct DataHdrFec *)(*sliq);

        if (opt_log[DATA_HEADER])
        {
          printf(" fectype %d idx %d numsrc %d rnd %d grp %d",
                 (int)((fec_hdr->type_idx >> 7) & 0x01),
                 (int)(fec_hdr->type_idx & 0x3f),
                 (int)((fec_hdr->src_rnd >> 4) & 0x0f),
                 (int)(fec_hdr->src_rnd & 0x0f),
                 (int)ntohs(fec_hdr->grp));
        }

        if (((fec_hdr->type_idx >> 7) & 0x01) == 1)
        {
          *enc_pkt = 1;
        }

        *sliq    += kDataHdrFecSize;
        *pkt_len -= kDataHdrFecSize;
      }
      else
      {
        *sliq    += kDataHdrFecSize;
        *pkt_len  = 0;
      }

      payload_len -= kDataHdrFecSize;
    }

    if (epl != 0)
    {
      if (*pkt_len >= kDataHdrEPLenSize)
      {
        if (opt_log[DATA_HEADER])
        {
          struct DataHdrEPLen  *epl_hdr = (struct DataHdrEPLen *)(*sliq);

          printf(" eplen 0x%04x",
                 (unsigned int)ntohs(epl_hdr->epl));
        }

        *sliq    += kDataHdrEPLenSize;
        *pkt_len -= kDataHdrEPLenSize;
      }
      else
      {
        *sliq    += kDataHdrEPLenSize;
        *pkt_len  = 0;
      }

      payload_len -= kDataHdrEPLenSize;
    }

    if (num_ttg > 0)
    {
      for (i = 0; ((i < num_ttg) && (*pkt_len >= kDataHdrTTGSize)); ++i)
      {
        if (opt_log[DATA_HEADER])
        {
          struct DataHdrTTG  *ttg_hdr = (struct DataHdrTTG *)(*sliq);

          uint16_t  ttg_val = (uint32_t)ntohs(ttg_hdr->ttg);
          double    ttg_sec = 0.0;

          if ((ttg_val & 0x8000) != 0)
          {
            ttg_sec = (1.0 + ((double)(ttg_val & 0x7fff) / 1000.0));
          }
          else
          {
            ttg_sec = ((double)(ttg_val & 0x7fff) / 32767.0);
          }

          printf(" ttg[%d] 0x%04x (%0.6f)",
                 (int)i,
                 (unsigned int)ttg_val,
                 ttg_sec);
        }

        *sliq    += kDataHdrTTGSize;
        *pkt_len -= kDataHdrTTGSize;
      }

      payload_len -= (num_ttg * kDataHdrTTGSize);
    }

    if (opt_log[DATA_HEADER])
    {
      printf(" len %zu",
             payload_len);
    }
  }
  else
  {
    printf(" ERROR: too short");

    payload_len = (*pkt_len + missing_len - kDataHdrBaseSize);

    if (opt_log[DATA_HEADER])
    {
      printf(" len %zu",
             payload_len);
    }

    *sliq    += kDataHdrBaseSize;
    *pkt_len  = 0;
  }

  if (opt_log[DATA_HEADER])
  {
    printf("\n");
  }
}

/* ======================================================================== */
void print_ack(double pkt_time, const char *saddr, const char *daddr,
               uint8_t **sliq, size_t *pkt_len)
{
  bool      in_multi_block = false;
  size_t    i              = 0;
  size_t    num_times      = 0;
  size_t    num_blocks     = 0;
  size_t    b_pkt_len      = 0;
  uint16_t  blk_type       = 0;
  uint16_t  blk_offset     = 0;
  uint32_t  ne_seq         = 0;
  uint32_t  start_seq      = 0;
  uint8_t   *b_sliq        = NULL;

  if (opt_log[ACK_HEADER])
  {
    printf("%.6f ACK    %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kAckHdrBaseSize)
  {
    struct AckHdrBase  *b_hdr = (struct AckHdrBase *)(*sliq);

    num_times  = (size_t)((b_hdr->num_opt_abo >> 5) & 0x07);
    num_blocks = (size_t)(b_hdr->num_opt_abo & 0x1f);

    ne_seq = (uint32_t)ntohl(b_hdr->ne_seq);

    if (opt_log[ACK_HEADER])
    {
      printf(" stream %d times %d blocks %d neseq %" PRIu32 " ts %" PRIu32
             " ts_delta %" PRIu32 ,
             (int)(b_hdr->stream),
             (int)num_times,
             (int)num_blocks,
             ne_seq,
             (uint32_t)ntohl(b_hdr->ts),
             (uint32_t)ntohl(b_hdr->ts_delta));
    }

    *sliq    += kAckHdrBaseSize;
    *pkt_len -= kAckHdrBaseSize;

    for (i = 0; ((i < num_times) && (*pkt_len >= kAckHdrTimeSize)); ++i)
    {
      if (opt_log[ACK_HEADER])
      {
        struct AckHdrTime  *t_hdr = (struct AckHdrTime *)(*sliq);

        printf(" | obs[%d] seq %" PRIu32 " ts %" PRIu32 ,
               (int)i,
               (uint32_t)ntohl(t_hdr->tm_seq),
               (uint32_t)ntohl(t_hdr->tm_ts));
      }

      *sliq    += kAckHdrTimeSize;
      *pkt_len -= kAckHdrTimeSize;
    }

    if (i == num_times)
    {
      b_sliq    = *sliq;
      b_pkt_len = *pkt_len;

      for (i = 0; ((i < num_blocks) && (*pkt_len >= kAckHdrBlockSize)); ++i)
      {
        if (opt_log[ACK_HEADER])
        {
          struct AckHdrBlock  *blk_hdr = (struct AckHdrBlock *)(*sliq);

          blk_type   = (uint16_t)((ntohs(blk_hdr->type_offset) >> 15) &
                                  0x0001);
          blk_offset = (uint16_t)(ntohs(blk_hdr->type_offset) & 0x7fff);

          printf(" | blk[%d] type %d off %d",
                 (int)i,
                 (int)blk_type,
                 (int)blk_offset);
        }

        *sliq    += kAckHdrBlockSize;
        *pkt_len -= kAckHdrBlockSize;
      }

      if (i == num_blocks)
      {
        if ((num_blocks > 0) && (opt_ack_blocks))
        {
          *sliq    = b_sliq;
          *pkt_len = b_pkt_len;

          if (opt_log[ACK_HEADER])
          {
            printf(" | Ack");
          }

          for (i = 0; ((i < num_blocks) && (*pkt_len >= kAckHdrBlockSize));
               ++i)
          {
            struct AckHdrBlock  *blk_hdr2 = (struct AckHdrBlock *)(*sliq);

            blk_type   = (uint16_t)((ntohs(blk_hdr2->type_offset) >> 15) &
                                    0x0001);
            blk_offset = (uint16_t)(ntohs(blk_hdr2->type_offset) & 0x7fff);

            if (blk_type == 0)
            {
              if (opt_log[ACK_HEADER])
              {
                printf(" %" PRIu32 ,
                       (ne_seq + (uint32_t)blk_offset));
              }
              in_multi_block = false;
            }
            else if (blk_type == 1)
            {
              if (!in_multi_block)
              {
                start_seq      = (ne_seq + (uint32_t)blk_offset);
                in_multi_block = true;
              }
              else
              {
                if (opt_log[ACK_HEADER])
                {
                  printf(" %" PRIu32 "-%" PRIu32 ,
                         start_seq,
                         (ne_seq + (uint32_t)blk_offset));
                }
                in_multi_block = false;
              }
            }

            *sliq    += kAckHdrBlockSize;
            *pkt_len -= kAckHdrBlockSize;
          }

          if (i != num_blocks)
          {
            *sliq    += kAckHdrBlockSize;
            *pkt_len  = 0;
          }
        }
      }
      else
      {
        *sliq    += kAckHdrBlockSize;
        *pkt_len  = 0;
      }
    }
    else
    {
      *sliq    += kAckHdrTimeSize;
      *pkt_len  = 0;
    }
  }
  else
  {
    printf(" ERROR: too short");

    *sliq    += kAckHdrBaseSize;
    *pkt_len  = 0;
  }

  if (opt_log[ACK_HEADER])
  {
    printf("\n");
  }
}

/* ======================================================================== */
void print_cc_sync(double pkt_time, const char *saddr, const char *daddr,
                   uint8_t **sliq, size_t *pkt_len)
{
  if (opt_log[CC_SYNC_HEADER])
  {
    printf("%.6f CcSync %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kCcSyncHdrSize)
  {
    struct CcSyncHdr  *hdr = (struct CcSyncHdr *)(*sliq);

    if (opt_log[CC_SYNC_HEADER])
    {
      printf(" cc %d seq %d param %d",
             (int)(hdr->cc_id),
             (int)ntohs(hdr->seq_num),
             (int)ntohl(hdr->params));
    }

    *sliq    += kCcSyncHdrSize;
    *pkt_len -= kCcSyncHdrSize;
  }
  else
  {
    printf(" ERROR: too short");

    *sliq    += kCcSyncHdrSize;
    *pkt_len  = 0;
  }

  if (opt_log[CC_SYNC_HEADER])
  {
    printf("\n");
  }
}

/* ======================================================================== */
void print_rcvd_pkt_cnt(double pkt_time, const char *saddr, const char *daddr,
                        uint8_t **sliq, size_t *pkt_len)
{
  if (opt_log[RCVD_PKT_CNT_HEADER])
  {
    printf("%.6f RxPkCt %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kRcvdPktCntHdrSize)
  {
    struct RcvdPktCntHdr  *hdr = (struct RcvdPktCntHdr *)(*sliq);

    if (opt_log[RCVD_PKT_CNT_HEADER])
    {
      printf(" stream %d rexmit %d seq %" PRIu32 " cnt %" PRIu32 ,
             (int)(hdr->stream),
             (int)(hdr->rexmit),
             (uint32_t)ntohl(hdr->seq),
             (uint32_t)ntohl(hdr->cnt));
    }

    *sliq    += kRcvdPktCntHdrSize;
    *pkt_len -= kRcvdPktCntHdrSize;
  }
  else
  {
    printf(" ERROR: too short");

    *sliq    += kRcvdPktCntHdrSize;
    *pkt_len  = 0;
  }

  if (opt_log[RCVD_PKT_CNT_HEADER])
  {
    printf("\n");
  }
}

/* ======================================================================== */
void print_cc_pkt_train(double pkt_time, const char *saddr, const char *daddr,
                        size_t missing_len, uint8_t *sliq, size_t pkt_len)
{
  printf("%.6f CcPkTr %s -> %s", pkt_time, saddr, daddr);

  if (pkt_len >= kCcPktTrainHdrSize)
  {
    struct CcPktTrainHdr  *hdr = (struct CcPktTrainHdr *)sliq;

    printf(" cc %d type %d seq %d irt %" PRIu32 " ts %" PRIu32 " ts_delta %"
           PRIu32 " len %zu",
           (int)(hdr->cc_id),
           (int)(hdr->pt_type),
           (int)(hdr->pt_seq),
           (uint32_t)ntohl(hdr->pt_irt),
           (uint32_t)ntohl(hdr->pt_ts),
           (uint32_t)ntohl(hdr->pt_ts_delta),
           (size_t)(pkt_len + missing_len - kCcPktTrainHdrSize));
  }
  else
  {
    printf(" ERROR: too short");
  }

  printf("\n");
}

/* ======================================================================== */
void print_cat_cap_est(double pkt_time, const char *saddr, const char *daddr,
                       uint8_t *pkt, size_t pkt_len)
{
  printf("%.6f CapEst %s -> %s", pkt_time, saddr, daddr);

  if (pkt_len >= kCatCapEstHdrSize)
  {
    struct CatCapEstHdr  *hdr = (struct CatCapEstHdr *)pkt;

    printf(" capest %" PRIu32 " kbps",
           (((uint32_t)hdr->est_ho << 16) | ((uint32_t)ntohs(hdr->est_lo))));
  }
  else
  {
    printf(" ERROR: too short");
  }

  printf("\n");
}

/* ======================================================================== */
void print_pkt_dest_list(double pkt_time, const char *saddr,
                         const char *daddr, uint8_t **pkt, size_t *pkt_len)
{
  if ((opt_log[CAT_PKT_DEST_LIST_HEADER]) && (opt_inner_pkts))
  {
    printf("%.6f PktDst %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kPktDestListHdrSize)
  {
    struct PktDestListHdr  *hdr = (struct PktDestListHdr *)(*pkt);

    if ((opt_log[CAT_PKT_DEST_LIST_HEADER]) && (opt_inner_pkts))
    {
      printf(" dests 0x%06x",
             (unsigned int)(((uint32_t)hdr->dest_ho << 16) |
                            ((uint32_t)ntohs(hdr->dest_lo))));
    }

    *pkt     += kPktDestListHdrSize;
    *pkt_len -= kPktDestListHdrSize;
  }
  else
  {
    printf(" ERROR: too short");

    *pkt     += kPktDestListHdrSize;
    *pkt_len  = 0;
  }

  if ((opt_log[CAT_PKT_DEST_LIST_HEADER]) && (opt_inner_pkts))
  {
    printf("\n");
  }
}

/* ======================================================================== */
void print_pkt_id(double pkt_time, const char *saddr, const char *daddr,
                  uint8_t **pkt, size_t *pkt_len)
{
  if ((opt_log[CAT_PKT_ID_HEADER]) && (opt_inner_pkts))
  {
    printf("%.6f PktId  %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kPktIdHdrSize)
  {
    struct PktIdHdr  *hdr = (struct PktIdHdr *)(*pkt);

    if ((opt_log[CAT_PKT_ID_HEADER]) && (opt_inner_pkts))
    {
      printf(" bin %d pkt %" PRIu32 ,
             (int)((hdr->bin_pkt_ho >> 4) & 0x0f),
             ((((uint32_t)hdr->bin_pkt_ho & 0x0f) << 16) |
              (uint32_t)ntohs(hdr->pkt_lo)));
    }

    *pkt     += kPktIdHdrSize;
    *pkt_len -= kPktIdHdrSize;
  }
  else
  {
    printf(" ERROR: too short");

    *pkt     += kPktIdHdrSize;
    *pkt_len  = 0;
  }

  if ((opt_log[CAT_PKT_ID_HEADER]) && (opt_inner_pkts))
  {
    printf("\n");
  }
}

/* ======================================================================== */
void print_pkt_history(double pkt_time, const char *saddr, const char *daddr,
                       uint8_t **pkt, size_t *pkt_len)
{
  size_t  i = 0;

  if ((opt_log[CAT_PKT_HISTORY_HEADER]) && (opt_inner_pkts))
  {
    printf("%.6f PktHst %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kPktHistoryHdrSize)
  {
    struct PktHistoryHdr  *hdr = (struct PktHistoryHdr *)(*pkt);

    for (i = 0; i < kPktHistoryNumBinIds; ++i)
    {
      if ((opt_log[CAT_PKT_HISTORY_HEADER]) && (opt_inner_pkts))
      {
        printf(" bin[%d] %" PRIu8 ,
               (int)i,
               hdr->bin_id[i]);
      }
    }

    *pkt     += kPktHistoryHdrSize;
    *pkt_len -= kPktHistoryHdrSize;
  }
  else
  {
    printf(" ERROR: too short");

    *pkt     += kPktHistoryHdrSize;
    *pkt_len  = 0;
  }

  if ((opt_log[CAT_PKT_HISTORY_HEADER]) && (opt_inner_pkts))
  {
    printf("\n");
  }
}

/* ======================================================================== */
void print_pkt_latency(double pkt_time, const char *saddr, const char *daddr,
                       uint8_t **pkt, size_t *pkt_len)
{
  if ((opt_log[CAT_PKT_LATENCY_HEADER]) && (opt_inner_pkts))
  {
    printf("%.6f PktLat %s -> %s", pkt_time, saddr, daddr);
    ++lines_logged;
  }

  if (*pkt_len >= kPktLatencyHdrSize)
  {
    struct PktLatencyHdr  *hdr = (struct PktLatencyHdr *)(*pkt);

    if ((opt_log[CAT_PKT_LATENCY_HEADER]) && (opt_inner_pkts))
    {
      printf(" valid %d ts %" PRIu16 " ttg %" PRIu32 ,
             (int)(hdr->flags & 0x01),
             (uint16_t)ntohs(hdr->origin_ts),
             (uint32_t)ntohl(hdr->ttg));
    }

    *pkt     += kPktLatencyHdrSize;
    *pkt_len -= kPktLatencyHdrSize;
  }
  else
  {
    printf(" ERROR: too short");

    *pkt     += kPktLatencyHdrSize;
    *pkt_len  = 0;
  }

  if ((opt_log[CAT_PKT_LATENCY_HEADER]) && (opt_inner_pkts))
  {
    printf("\n");
  }
}

/* ======================================================================== */
void parse_sliq_payload(double pkt_time, const char *saddr, const char *daddr,
                        size_t missing_data, uint8_t **pkt, uint8_t *pkt_end,
                        size_t *pkt_len)
{
  size_t   payload_len = 0;
  uint8_t  pkt_type    = 0;

  /* Parse the SLIQ payload, which follows the SLIQ data header. */
  while ((*pkt) < pkt_end)
  {
    /* The first byte always contains the header or packet type. */
    pkt_type = *(*pkt);

    if (pkt_type == CAT_CAP_EST_HEADER)
    {
      if ((opt_log[pkt_type]) && (opt_inner_pkts))
      {
        print_cat_cap_est(pkt_time, saddr, daddr, *pkt, *pkt_len);
        ++lines_logged;
      }

      /* No other packets can follow. */
      *pkt = pkt_end;
    }
    else if (pkt_type == CAT_PKT_DEST_LIST_HEADER)
    {
      print_pkt_dest_list(pkt_time, saddr, daddr, pkt, pkt_len);
    }
    else if (pkt_type == CAT_PKT_ID_HEADER)
    {
      print_pkt_id(pkt_time, saddr, daddr, pkt, pkt_len);
    }
    else if (pkt_type == CAT_PKT_HISTORY_HEADER)
    {
      print_pkt_history(pkt_time, saddr, daddr, pkt, pkt_len);
    }
    else if (pkt_type == CAT_PKT_LATENCY_HEADER)
    {
      print_pkt_latency(pkt_time, saddr, daddr, pkt, pkt_len);
    }
    else
    {
      if (opt_inner_pkts)
      {
        payload_len = (*pkt_len + missing_data);

        if (pkt_type == QLAM_PACKET)
        {
          if (opt_log[pkt_type])
          {
            printf("%.6f QLAM   %s -> %s len %zu\n", pkt_time, saddr, daddr,
                   payload_len);
            ++lines_logged;
          }
        }
        else if (pkt_type == LSA_PACKET)
        {
          if (opt_log[pkt_type])
          {
            printf("%.6f LSA    %s -> %s len %zu\n", pkt_time, saddr, daddr,
                   payload_len);
            ++lines_logged;
          }
        }
        else if (pkt_type == ZOMBIE_PACKET)
        {
          if (opt_log[pkt_type])
          {
            printf("%.6f Zombie %s -> %s len %zu\n", pkt_time, saddr, daddr,
                   payload_len);
            ++lines_logged;
          }
        }
        else if ((pkt_type >> 4) == 4)
        {
          if (opt_log[IPV4_PACKET])
          {
            printf("%.6f IPv4   %s -> %s len %zu\n", pkt_time, saddr, daddr,
                   payload_len);
            ++lines_logged;
          }
        }
        else
        {
          /* This is an unknown packet. */
          printf("%.6f 0x%02x   %s -> %s len %zu\n", pkt_time,
                 (unsigned int)pkt_type, saddr, daddr, payload_len);
          ++lines_logged;
        }
      }

      /* No other packets can follow. */
      *pkt = pkt_end;
    }
  }
}

/* ======================================================================== */
void parse_pcap(const char *pcap_file)
{
  pcap_t               *p          = (pcap_t *)NULL;
  struct sll_header    *sll        = (struct sll_header *)NULL;;
  uint8_t              *pkt_in     = (uint8_t *)NULL;
  struct ether_header  *eth        = (struct ether_header *)NULL;
  struct iphdr         *ip         = (struct iphdr *)NULL;
  struct udphdr        *udp        = (struct udphdr *)NULL;
  uint8_t              *sliq       = (uint8_t *)NULL;
  uint8_t              *sliq_end   = (uint8_t *)NULL;
  uint8_t               sliq_type  = 0;
  uint16_t              net_proto  = 0;
  size_t                pkt_len    = 0;
  size_t                pld_len    = 0;
  int32_t               ip_hlen    = 0;
  int32_t               fr_hlen    = 0;
  int32_t               num_pkts   = 0;
  int32_t               short_pkts = 0;
  int                   p_type     = 0;
  int                   enc_pkt    = 0;
  double                pkt_time   = 0.0;
  double                start_time = 0.0;
  char                  saddr[32];
  char                  daddr[32];
  char                  err_buf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr    pkt_hdr;
  struct in_addr        ip_addr;

  /* Open the capture file. */
  if ((p = pcap_open_offline(pcap_file, &err_buf[0])) == NULL)
  {
    printf("Open failed, explanation is: %s\n", &err_buf[0]);
    return;
  }

  /* Can only process the file if we have ethernet, cooked, or PPP packets. */
  p_type = pcap_datalink(p);

  if ((p_type != DLT_EN10MB) && (p_type != DLT_LINUX_SLL) &&
      (p_type != DLT_PPP))
  {
    printf("This application only understands dumps from ethernet, cooked, "
           "or PPP captures.\n");
    pcap_close(p);
    return;
  }

  /* Process the packets in the capture file. */
  while ((pkt_in = (uint8_t *)pcap_next(p, &pkt_hdr)) != NULL)
  {
    /* Retrieve the IP header if this is an IP packet. */
    ip = NULL;

    if (p_type == DLT_EN10MB)
    {
      /* Get the ethernet payload. */
      eth       = (struct ether_header *)pkt_in;
      net_proto = ntohs(eth->ether_type);
      fr_hlen   = sizeof(struct ether_header);

      if (net_proto == ETHERTYPE_IP)
      {
        ip = (struct iphdr *)&pkt_in[sizeof(struct ether_header)];
      }
    }
    else if (p_type == DLT_LINUX_SLL)
    {
      /* From the ethereal/tcpdump source code, cooked packets contain a
       * MAC-like pseudo header that is 16 bytes long. */
      sll       = (struct sll_header *)pkt_in;
      net_proto = ntohs(sll->sll_protocol);
      fr_hlen   = sizeof(struct sll_header);

      if (net_proto == ETHERTYPE_IP)
      {
        ip = (struct iphdr *)&pkt_in[sizeof(struct sll_header)];
      }
    }
    else /* if (p_type == DLT_PPP) */
    {
      /* PPP packets contain either PPP without framing, or PPP in HDLC-like
       * framing.  Only support PPP without framing, encapsulating IP packets,
       * as generated by ns-3. */
      fr_hlen = 2;

      if ((pkt_in[0] == 0x00) && (pkt_in[1] == PPP_IP))
      {
        ip = (struct iphdr *)&pkt_in[fr_hlen];
      }
    }

    /* Only process if this is an IP packet. */
    if (ip != NULL)
    {
      /* Handle the case where IP may have options. */
      ip_hlen = (ip->ihl << 2);

      /* Only process if this is a UDP packet. */
      if (ip->protocol == IPPROTO_UDP)
      {
        pkt_len = (pkt_hdr.caplen - (fr_hlen + ip_hlen + sizeof(udphdr)));

        if (pkt_len < 4)
        {
          short_pkts++;
          continue;
        }

        /* Limit the parsing to the UDP payload size. */
        udp     = (udphdr *)((uint8_t *)ip  + ip_hlen);
        pld_len = ((size_t)ntohs(udp->len) - sizeof(struct udphdr));

        /* Note that the minimum Ethernet frame size is 64 bytes on a packet
         * receive (not on a packet transmission).  When this happens, the
         * minimum PCAP capture payload length (UDP payload plus padding) is:
         *
         *   64 - (6 + 6 + 2 + 4) - 20 - 8 = 18 bytes
         *
         * If the UDP payload length is less than the PCAP capture payload
         * length, and the UDP payload length is less than the 18 bytes
         * computed above, then adjust the PCAP capture payload length down to
         * the UDP payload length to remove the Ethernet frame padding
         * bytes. */
        if ((pld_len < pkt_len) && (pld_len < 18))
        {
          if (opt_min_eth_warn)
          {
            printf("WARNING: capture payload length %zu, UDP payload length "
                   "%zu.\n", pkt_len, pld_len);
          }

          pkt_len = pld_len;
        }

        /* Prepare for parsing the SLIQ headers. */
        sliq     = (uint8_t *)((uint8_t *)udp + sizeof(struct udphdr));
        sliq_end = (sliq + pkt_len);
        pkt_time = (((double)pkt_hdr.ts.tv_sec) +
                    ((double)pkt_hdr.ts.tv_usec / 1.0e6));

        /* Update the time. */
        if (num_pkts == 0)
        {
          start_time = pkt_time;
          pkt_time   = 0.0;
        }
        else
        {
          pkt_time -= start_time;
        }

        /* Parse the IP addresses. */
        ip_addr.s_addr = ip->saddr;
        strncpy(saddr, inet_ntoa(ip_addr), sizeof(saddr));

        ip_addr.s_addr = ip->daddr;
        strncpy(daddr, inet_ntoa(ip_addr), sizeof(daddr));

        ++num_pkts;

        lines_logged = 0;

        /* ---------- FILTERS ---------- */
        /* if ((pkt_time < 296.0) || (pkt_time > 310.0) || */
        /*     (strcmp(daddr, "172.24.6.1") != 0)) */
        /* { */
        /*   continue; */
        /* } */
        /* ---------- FILTERS ---------- */

        while (sliq < sliq_end)
        {
          /* The first byte always contains the SLIQ header type. */
          sliq_type = *sliq;

          if (sliq_type == CONNECTION_HANDSHAKE_HEADER)
          {
            if (opt_log[sliq_type])
            {
              print_conn_hndshk(pkt_time, saddr, daddr, sliq, pkt_len);
              ++lines_logged;
            }

            /* No other SLIQ headers can follow. */
            sliq = sliq_end;
          }
          else if (sliq_type == RESET_CONNECTION_HEADER)
          {
            if (opt_log[sliq_type])
            {
              print_reset_conn(pkt_time, saddr, daddr, sliq, pkt_len);
              ++lines_logged;
            }

            /* No other SLIQ headers can follow. */
            sliq = sliq_end;
          }
          else if (sliq_type == CLOSE_CONNECTION_HEADER)
          {
            if (opt_log[sliq_type])
            {
              print_close_conn(pkt_time, saddr, daddr, sliq, pkt_len);
              ++lines_logged;
            }

            /* No other SLIQ headers can follow. */
            sliq = sliq_end;
          }
          else if (sliq_type == CREATE_STREAM_HEADER)
          {
            if (opt_log[sliq_type])
            {
              print_create_stream(pkt_time, saddr, daddr, sliq, pkt_len);
              ++lines_logged;
            }

            /* No other SLIQ headers can follow. */
            sliq = sliq_end;
          }
          else if (sliq_type == RESET_STREAM_HEADER)
          {
            if (opt_log[sliq_type])
            {
              print_reset_stream(pkt_time, saddr, daddr, sliq, pkt_len);
              ++lines_logged;
            }

            /* No other SLIQ headers can follow. */
            sliq = sliq_end;
          }
          else if (sliq_type == DATA_HEADER)
          {
            print_data(pkt_time, saddr, daddr, (pkt_hdr.len - pkt_hdr.caplen),
                       &sliq, &pkt_len, &enc_pkt);

            if (enc_pkt)
            {
              /* This is encoded data for FEC. */
              printf("%.6f FEC    %s -> %s len %zu\n", pkt_time, saddr, daddr,
                     (pkt_len + (pkt_hdr.len - pkt_hdr.caplen)));
              ++lines_logged;
            }
            else
            {
              /* Parse the SLIQ payload. */
              parse_sliq_payload(pkt_time, saddr, daddr,
                                 (pkt_hdr.len - pkt_hdr.caplen), &sliq,
                                 sliq_end, &pkt_len);
            }

            /* No other SLIQ headers can follow. */
            sliq = sliq_end;
          }
          else if (sliq_type == ACK_HEADER)
          {
            print_ack(pkt_time, saddr, daddr, &sliq, &pkt_len);
          }
          else if (sliq_type == CC_SYNC_HEADER)
          {
            print_cc_sync(pkt_time, saddr, daddr, &sliq, &pkt_len);
          }
          else if (sliq_type == RCVD_PKT_CNT_HEADER)
          {
            print_rcvd_pkt_cnt(pkt_time, saddr, daddr, &sliq, &pkt_len);
          }
          else if (sliq_type == CC_PKT_TRAIN_HEADER)
          {
            if (opt_log[sliq_type])
            {
              print_cc_pkt_train(pkt_time, saddr, daddr,
                                 (pkt_hdr.len - pkt_hdr.caplen), sliq,
                                 pkt_len);
              ++lines_logged;
            }

            /* No other SLIQ headers can follow. */
            sliq = sliq_end;
          }
          else
          {
            /* This is a non-SLIQ header.  Stop parsing the packet. */
            sliq = sliq_end;
          }
        }

        /* Add an empty line between parsed packets. */
        if (lines_logged > 0)
        {
          printf("\n");
        }
      }
    }
  }

  pcap_close(p);

  if (short_pkts > 0)
  {
    printf("\n**** Total of %d packets too short to decapsulate ****\n",
           short_pkts);
  }

  printf("\nParsed %d SLIQ packets.\n", num_pkts);

  return;
}

/* ======================================================================== */
int main(int argc, char **argv)
{
  int  i = 0;

  for (i = 0; i < OPT_LOG_SIZE; ++i)
  {
    opt_log[i] = 0;
  }

  /* ---------- OPTIONS ---------- */
  opt_min_eth_warn = 0;

  opt_inner_pkts = 1;

  opt_ack_blocks = 1;

  opt_log[CONNECTION_HANDSHAKE_HEADER] = 1;
  opt_log[RESET_CONNECTION_HEADER]     = 1;
  opt_log[CLOSE_CONNECTION_HEADER]     = 1;

  opt_log[CREATE_STREAM_HEADER]        = 1;
  opt_log[RESET_STREAM_HEADER]         = 1;

  opt_log[QLAM_PACKET]                 = 1;
  opt_log[LSA_PACKET]                  = 1;
  opt_log[ZOMBIE_PACKET]               = 1;

  opt_log[DATA_HEADER]                 = 1;
  opt_log[ACK_HEADER]                  = 1;
  opt_log[CC_SYNC_HEADER]              = 1;
  opt_log[RCVD_PKT_CNT_HEADER]         = 1;

  opt_log[CC_PKT_TRAIN_HEADER]         = 1;

  opt_log[CAT_CAP_EST_HEADER]          = 1;
  opt_log[CAT_PKT_DEST_LIST_HEADER]    = 1;
  opt_log[CAT_PKT_ID_HEADER]           = 1;
  opt_log[CAT_PKT_HISTORY_HEADER]      = 1;
  opt_log[CAT_PKT_LATENCY_HEADER]      = 1;

  opt_log[IPV4_PACKET]                 = 1;
  /* ---------- OPTIONS ---------- */

  if (argc < 2)
  {
    printf("First, update the FILTERS and OPTIONS sections in the source "
           "code.\n");
    printf("Next, recompile the program: make\n\n");
    printf("Usage: sliqparse <pcap_file>\n");
    exit(-1);
  }

  parse_pcap(argv[1]);

  return 0;
}
