/* packet-sliq.c
 * Routines for SLIQ packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 *
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-sliq.c 35224 2015-11-29 05:35:29Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "config.h"
#include <stdio.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/decode_as.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>


#define SLIQ_PORT_DEFAULTS  "30300"

static range_t  *global_sliq_udp_range = NULL;
static range_t  *sliq_udp_range        = NULL;

static int   proto_sliq = -1;
static gint  ett_sliq   = -1;

static dissector_handle_t  ip_handle;
static dissector_handle_t  qlam_handle;
static dissector_handle_t  cce_handle;
static dissector_handle_t  kupd_handle;
static dissector_handle_t  ironlsa_handle;
static dissector_handle_t  rrm_handle;
static dissector_handle_t  cat_handle;

gboolean  qlam_handle_found    = FALSE;
gboolean  cce_handle_found     = FALSE;
gboolean  kupd_handle_found    = FALSE;
gboolean  ironlsa_handle_found = FALSE;
gboolean  rrm_handle_found     = FALSE;
gboolean  cat_handle_found     = FALSE;

static tvbuff_t  *ip_tvb;

void proto_reg_handoff_sliq(void);
void proto_register_sliq(void);


/* Definitions for sliq headers. */
#define CONN_HANDSHK_HDR  0
#define CONN_RESET_HDR    1
#define CONN_CLOSE_HDR    2

#define STRM_CREATE_HDR   3
#define STRM_RESET_HDR    4

#define DATA_HDR          32
#define ACK_HDR           33
#define CC_SYNC_HDR       34
#define RCVD_PKT_CNT_HDR  35

#define CC_PKT_TRAIN_HDR  40

static const value_string  headertypenames[] = {
  {CONN_HANDSHK_HDR, "Connection Handshake"},
  {CONN_RESET_HDR,   "Connection Reset"},
  {CONN_CLOSE_HDR,   "Connection Close"},
  {STRM_CREATE_HDR,  "Stream Create"},
  {STRM_RESET_HDR,   "Stream Reset"},
  {DATA_HDR,         "Data"},
  {ACK_HDR,          "ACK"},
  {CC_SYNC_HDR,      "CC Synchronization"},
  {RCVD_PKT_CNT_HDR, "Received Packet Count"},
  {CC_PKT_TRAIN_HDR, "CC Packet Train"},
  {41, NULL}
};


/* Header Formats */

/* Common header field variables. */
static int  hf_sliq_type      = -1;
static int  hf_sliq_stream_id = -1;


/* Connection Handshake */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |  # of CC Alg  |          Message Tag          | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                       Packet Timestamp                        | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                        Echo Timestamp                         | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | CC Alg Type #1|   Unused  |D|P|             Unused            | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                     CC Alg Parameters #1                      | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* ~                                                               ~ */
/* ~                                                               ~ */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | CC Alg Type #N|   Unused  |D|P|             Unused            | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                     CC Alg Parameters #N                      | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags:  D = Deterministic */
/*         P = Pacing        */

#define CH_BASE_HDR_LEN    12
#define CH_CC_ALG_HDR_LEN  8

static int  hf_sliq_ch_num_cc_alg      = -1;
static int  hf_sliq_ch_msg_tag         = -1;
static int  hf_sliq_ch_ts              = -1;
static int  hf_sliq_ch_echo_ts         = -1;
static int  hf_sliq_ch_cc_type         = -1;
static int  hf_sliq_ch_cc_flags        = -1;
static int  hf_sliq_ch_cc_flags_determ = -1;
static int  hf_sliq_ch_cc_flags_pacing = -1;
static int  hf_sliq_ch_cc_params       = -1;

#define CH_DETERM_FLAG  0x02
#define CH_PACING_FLAG  0x01

/* Congestion Control Types */
static const value_string  cctypenames[] = {
  {0,  "No CC"},
  {1,  "Google TCP Cubic Bytes"},
  {2,  "Google TCP Reno Bytes"},
  {3,  "TCP Cubic"},
  {4,  "Copa Constant Delta"},
  {5,  "CopaM"},
  {6,  "Copa2"},
  {7,  "Copa3"},
  {8,  "Undefined 8"},
  {9,  "Undefined 9"},
  {10, "Undefined 10"},
  {11, "Undefined 11"},
  {12, "Undefined 12"},
  {13, "Undefined 13"},
  {14, "Undefined 14"},
  {15, "Fixed Rate"},
  {16, NULL}
};

/* Message Tags */
#define CLIENT_HELLO_TAG    0x4843
#define SERVER_HELLO_TAG    0x4853
#define CLIENT_CONFIRM_TAG  0x4343
#define REJECT_TAG          0x4A52

static const value_string messagetagnames[] = {
  {CLIENT_HELLO_TAG,   "Client Hello"},
  {SERVER_HELLO_TAG,   "Server Hello"},
  {CLIENT_CONFIRM_TAG, "Client Confirm"},
  {REJECT_TAG,         "Reject"},
  {0, NULL}
};


/* Connection Reset */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |Flags (Unused) |          Error Code           | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define CR_HDR_LEN  4

static int  hf_sliq_cr_error_code = -1;

static const value_string crerrorcodenames[] = {
  {0, "No Error"},
  {1, "Receive Close Error"},
  {2, "Socket Write Error"},
  {3, "Internal Error"},
  {4, NULL}
};


/* Connection Close */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |   Unused    |A|          Reason Code          | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags:  A = ACK */

#define CC_HDR_LEN  4

static int  hf_sliq_cc_flags     = -1;
static int  hf_sliq_cc_flags_ack = -1;
static int  hf_sliq_cc_reason    = -1;

#define CC_ACK_FLAG  0x01

static const value_string ccreasonnames[] = {
  {0, "Normal"},
  {1, "Flow Control Sent Too Much Data"},
  {2, NULL}
};


/* Stream Create */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |  Unused   |T|A|   Stream ID   |   Priority    | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                      Initial Window Size                      | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                Initial Packet Sequence Number                 | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |  Del  |  Rel  | Rexmit Limit  | FEC Target Delivery Rnds/Time | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |FEC Target Pkt Recv Probability|            Unused             | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags:  T = Delivery Time */
/*         A = ACK           */

#define SC_HDR_LEN  20

static int  hf_sliq_sc_flags          = -1;
static int  hf_sliq_sc_flags_del_time = -1;
static int  hf_sliq_sc_flags_ack      = -1;
static int  hf_sliq_sc_priority       = -1;
static int  hf_sliq_sc_init_win_size  = -1;
static int  hf_sliq_sc_init_pkt_seq   = -1;
static int  hf_sliq_sc_del_mode       = -1;
static int  hf_sliq_sc_rel_mode       = -1;
static int  hf_sliq_sc_rexmit_limit   = -1;
static int  hf_sliq_sc_tgt_del_rnds   = -1;
static int  hf_sliq_sc_tgt_del_time   = -1;
static int  hf_sliq_sc_tgt_rcv_prob   = -1;

#define SC_DEL_TIME_FLAG  0x02
#define SC_ACK_FLAG       0x01
#define SC_DEL_MODE       0xf0
#define SC_REL_MODE       0x0f

static const value_string scdeliverymodenames[] = {
  {0, "Unordered Delivery"},
  {1, "Ordered Delivery"},
  {2, NULL}
};

static const value_string screliabilitymodenames[] = {
  {0, "Best Effort"},
  {1, "Semi-Reliable ARQ"},
  {2, "Semi-Reliable ARQ+FEC"},
  {3, "Undefined 3"},
  {4, "Reliable ARQ"},
  {5, "Undefined 5"},
  {6, "Undefined 6"},
  {7, "Undefined 7"},
  {8, NULL}
};


/* Stream Reset */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |Flags (Unused) |   Stream ID   |  Error Code   | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                 Final Packet Sequence Number                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define SR_HDR_LEN  8

static int  hf_sliq_sr_error_code  = -1;
static int  hf_sliq_sr_fin_pkt_seq = -1;

static const value_string srerrorcodenames[] = {
  {0, "Normal"},
  {1, "Socket Partial Write Error"},
  {2, "Socket Write Error"},
  {3, "Flow Control Error"},
  {4, "Transmit Queue Error"},
  {5, NULL}
};


/* Data */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |U|L|E|M| U |P|F|   Stream ID   | Number of TTG | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     CC ID     | Rexmit Count  |    Payload Length in Bytes    | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                    Packet Sequence Number                     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                       Packet Timestamp                        | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                    Packet Timestamp Delta                     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |             Move Forward Packet Sequence Number*              | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |T|U|  Index*   |NumSrc*|Round* |           Group ID*           | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Encoded Packet Length*     |        Time-To-Go #1*         | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |        Time-To-Go #2*         |        Time-To-Go #3*         | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* ~                                                               ~ */
/* ~                                                               ~ */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |        Time-To-Go #N*         |            Payload            | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               + */
/* |                                                               | */
/* ~                                                               ~ */
/* ~                                                               ~ */
/* |                                                               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags:  L = Encoded Packet Length Present */
/*         E = FEC Fields Present            */
/*         M = Move Forward Present          */
/*         P = Persist                       */
/*         F = FIN                           */

#define D_BASE_HDR_LEN         20
#define D_MOVE_FWD_HDR_LEN     4
#define D_FEC_HDR_LEN          4
#define D_ENC_PKT_LEN_HDR_LEN  2
#define D_TIME_TO_GO_HDR_LEN   2

static int  hf_sliq_d_flags             = -1;
static int  hf_sliq_d_flags_enc_pkt_len = -1;
static int  hf_sliq_d_flags_fec         = -1;
static int  hf_sliq_d_flags_mv_fwd      = -1;
static int  hf_sliq_d_flags_persist     = -1;
static int  hf_sliq_d_flags_fin         = -1;
static int  hf_sliq_d_num_ttgs          = -1;
static int  hf_sliq_d_cc_id             = -1;
static int  hf_sliq_d_rtx               = -1;
static int  hf_sliq_d_payload_len       = -1;
static int  hf_sliq_d_pkt_seq           = -1;
static int  hf_sliq_d_ts                = -1;
static int  hf_sliq_d_ts_delta          = -1;
static int  hf_sliq_d_mv_fwd_seq        = -1;
static int  hf_sliq_d_fec_type          = -1;
static int  hf_sliq_d_fec_idx           = -1;
static int  hf_sliq_d_fec_num_src       = -1;
static int  hf_sliq_d_fec_rnd           = -1;
static int  hf_sliq_d_fec_grp           = -1;
static int  hf_sliq_d_enc_pkt_len       = -1;
static int  hf_sliq_d_ttg               = -1;

#define D_ENC_PKT_LEN_FLAG  0x40
#define D_FEC_FLAG          0x20
#define D_MOVE_FWD_FLAG     0x10
#define D_PERSIST_FLAG      0x02
#define D_FIN_FLAG          0x01

#define D_FEC_TYPE     0x8000
#define D_FEC_IDX      0x3f00
#define D_FEC_NUM_SRC  0x00f0
#define D_FEC_RND      0x000f

static const value_string dfectypenames[] = {
  {0, "FEC Source Data Packet"},
  {1, "FEC Encoded Data Packet"},
  {2, NULL}
};


/* ACK */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |Flags (Unused) |   Stream ID   | #OPT|   #ABO  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |             Next Expected Packet Sequence Number              | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                       Packet Timestamp                        | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                    Packet Timestamp Delta                     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |              Observed Packet Sequence Number #1               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                 Observed Packet Timestamp #1                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |              Observed Packet Sequence Number #2               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                 Observed Packet Timestamp #2                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* ~                                                               ~ */
/* ~                                                               ~ */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |              Observed Packet Sequence Number #N               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                 Observed Packet Timestamp #N                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |T|     ACK Block Offset #1     |T|     ACK Block Offset #2     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* ~                                                               ~ */
/* ~                                                               ~ */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |T|     ACK Block Offset #N     |                                 */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                 */

/* Fields:  #OPT = Number of Observed Packet Times */
/*          #ABO =  Number of ACK Block Offsets    */

#define A_BASE_HDR_LEN          16
#define A_OBS_PKT_TIME_HDR_LEN  8
#define A_ACK_BLOCK_HDR_LEN     2

static int  hf_sliq_a_nopt       = -1;
static int  hf_sliq_a_nabo       = -1;
static int  hf_sliq_a_next_seq   = -1;
static int  hf_sliq_a_ts         = -1;
static int  hf_sliq_a_ts_delta   = -1;
static int  hf_sliq_a_obs_seq    = -1;
static int  hf_sliq_a_obs_ts     = -1;
static int  hf_sliq_a_blk_type   = -1;
static int  hf_sliq_a_blk_offset = -1;

#define A_NOPT  0xe0
#define A_NABO  0x1f

#define A_BLK_TYPE    0x8000
#define A_BLK_OFFSET  0x7fff


/* Congestion Control Synchronization */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |     CC ID     |        Sequence Number        | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                        CC Parameter(s)                        | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define SY_HDR_LEN  8

static int  hf_sliq_sy_cc_id     = -1;
static int  hf_sliq_sy_seq_num   = -1;
static int  hf_sliq_sy_cc_params = -1;


/* Received Packet Count */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |Flags (Unused) |   Stream ID   | Rexmit Count  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                    Packet Sequence Number                     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |             Connection Received Data Packet Count             | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define RC_HDR_LEN  12

static int  hf_sliq_rc_rtx         = -1;
static int  hf_sliq_rc_pkt_seq     = -1;
static int  hf_sliq_rc_rcv_pkt_cnt = -1;


/* Congestion Control Packet Train */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |     CC ID     |  PT Pkt Type  |   PT Seq Num  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                Packet Pair Inter-Receive Time                 | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                       Packet Timestamp                        | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                    Packet Timestamp Delta                     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                            Payload                            | */
/* ~                                                               ~ */
/* ~                                                               ~ */
/* |                                                               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define PT_HDR_LEN  16

static int  hf_sliq_pt_cc_id    = -1;
static int  hf_sliq_pt_type     = -1;
static int  hf_sliq_pt_seq      = -1;
static int  hf_sliq_pt_irt      = -1;
static int  hf_sliq_pt_ts       = -1;
static int  hf_sliq_pt_ts_delta = -1;


static int dissect_sliq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        void* data _U_)
{
  gboolean     done        = FALSE;
  guint        offset      = 0;
  guint8       packet_type = 0;
  guint8       del_time    = 0;
  int          nopt        = 0;
  int          nabo        = 0;
  int          nocca       = 0;
  proto_item  *ti          = NULL;
  proto_item  *sliq_tree   = NULL;

  if (!tree)
  {
    return tvb_captured_length(tvb);
  }

  while ((!done) && (tvb_reported_length_remaining(tvb, offset) > 0))
  {
    /* Grab the packet type, print it out and use it to determine subsequent
     * processing. */
    packet_type = tvb_get_guint8(tvb, offset);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SLIQ Header");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
                 val_to_str(packet_type, headertypenames,
                            "Unknown (0x%02x)"));

    ti = proto_tree_add_item(tree, proto_sliq, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type %s",
                           val_to_str(packet_type, headertypenames,
                                      "Unkown (0x%02x)"));

    sliq_tree = proto_item_add_subtree(ti, ett_sliq);

    switch (packet_type)
    {
      case CONN_HANDSHK_HDR: /* Connection Handshake */
        if (tvb_reported_length_remaining(tvb, offset) >= CH_BASE_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          nocca = (int)tvb_get_guint8(tvb, offset);
          proto_tree_add_item(sliq_tree, hf_sliq_ch_num_cc_alg,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_ch_msg_tag,
                              tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          proto_tree_add_item(sliq_tree, hf_sliq_ch_ts,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_ch_echo_ts,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          while ((tvb_reported_length_remaining(tvb, offset) >=
                  CH_CC_ALG_HDR_LEN) && (nocca-- > 0))
          {
            proto_tree_add_item(sliq_tree, hf_sliq_ch_cc_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(sliq_tree, hf_sliq_ch_cc_flags,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sliq_tree, hf_sliq_ch_cc_flags_determ,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sliq_tree, hf_sliq_ch_cc_flags_pacing,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            offset += 2;

            proto_tree_add_item(sliq_tree, hf_sliq_ch_cc_params,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
          }
        }
        done = TRUE;
        break;

      case CONN_RESET_HDR: /* Connection Reset */
        if (tvb_reported_length_remaining(tvb, offset) >= CR_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_cr_error_code,
                              tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
        }
        done = TRUE;
        break;

      case CONN_CLOSE_HDR: /* Connection Close */
        if (tvb_reported_length_remaining(tvb, offset) >= CC_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_cc_flags,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_cc_flags_ack,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_cc_reason,
                              tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
        }
        done = TRUE;
        break;

      case STRM_CREATE_HDR: /* Stream Create */
        if (tvb_reported_length_remaining(tvb, offset) >= SC_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          del_time = (tvb_get_guint8(tvb, offset) & SC_DEL_TIME_FLAG);
          proto_tree_add_item(sliq_tree, hf_sliq_sc_flags,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_sc_flags_del_time,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_sc_flags_ack,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_stream_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_sc_priority,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_sc_init_win_size,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_sc_init_pkt_seq,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_sc_del_mode,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_sc_rel_mode,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_sc_rexmit_limit,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          if (del_time == 0)
          {
            proto_tree_add_item(sliq_tree, hf_sliq_sc_tgt_del_rnds,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
          }
          else
          {
            proto_tree_add_item(sliq_tree, hf_sliq_sc_tgt_del_time,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
          }
          offset += 2;

          proto_tree_add_item(sliq_tree, hf_sliq_sc_tgt_rcv_prob,
                              tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          offset += 2;
        }
        done = TRUE;
        break;

      case STRM_RESET_HDR: /* Stream Reset */
        if (tvb_reported_length_remaining(tvb, offset) >= SR_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_stream_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_sr_error_code,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_sr_fin_pkt_seq,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
        done = TRUE;
        break;

      case DATA_HDR: /* Data */
        if (tvb_reported_length_remaining(tvb, offset) >= D_BASE_HDR_LEN)
        {
          gboolean  has_payload = TRUE;
          guint8    enc_pkt_len = 0;
          guint8    fec_fields  = 0;
          guint8    move_fwd    = 0;
          guint8    ntimes      = 0;
          guint8    inner_type  = 0;

          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          enc_pkt_len = (tvb_get_guint8(tvb, offset) & D_ENC_PKT_LEN_FLAG);
          fec_fields  = (tvb_get_guint8(tvb, offset) & D_FEC_FLAG);
          move_fwd    = (tvb_get_guint8(tvb, offset) & D_MOVE_FWD_FLAG);
          proto_tree_add_item(sliq_tree, hf_sliq_d_flags,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_d_flags_enc_pkt_len,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_d_flags_fec,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_d_flags_mv_fwd,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_d_flags_persist,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_d_flags_fin,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_stream_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          ntimes = tvb_get_guint8(tvb, offset);
          proto_tree_add_item(sliq_tree, hf_sliq_d_num_ttgs,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_d_cc_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_d_rtx,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_d_payload_len,
                              tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          proto_tree_add_item(sliq_tree, hf_sliq_d_pkt_seq,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_d_ts,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_d_ts_delta,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          if (move_fwd)
          {
            if (tvb_reported_length_remaining(tvb, offset) >=
                D_MOVE_FWD_HDR_LEN)
            {
              proto_tree_add_item(sliq_tree, hf_sliq_d_mv_fwd_seq,
                                  tvb, offset, 4, ENC_BIG_ENDIAN);
              offset += 4;
            }
            else
            {
              has_payload = FALSE;
            }
          }

          if (fec_fields)
          {
            if (tvb_reported_length_remaining(tvb, offset) >= D_FEC_HDR_LEN)
            {
              proto_tree_add_item(sliq_tree, hf_sliq_d_fec_type,
                                  tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(sliq_tree, hf_sliq_d_fec_idx,
                                  tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(sliq_tree, hf_sliq_d_fec_num_src,
                                  tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(sliq_tree, hf_sliq_d_fec_rnd,
                                  tvb, offset, 2, ENC_BIG_ENDIAN);
              offset += 2;

              proto_tree_add_item(sliq_tree, hf_sliq_d_fec_grp,
                                  tvb, offset, 2, ENC_BIG_ENDIAN);
              offset += 2;
            }
            else
            {
              has_payload = FALSE;
            }
          }

          if (enc_pkt_len)
          {
            if (tvb_reported_length_remaining(tvb, offset) >=
                D_ENC_PKT_LEN_HDR_LEN)
            {
              proto_tree_add_item(sliq_tree, hf_sliq_d_enc_pkt_len,
                                  tvb, offset, 2, ENC_BIG_ENDIAN);
              offset += 2;
            }
            else
            {
              has_payload = FALSE;
            }
          }

          if (ntimes)
          {
            if (tvb_reported_length_remaining(tvb, offset) <
                (ntimes * D_TIME_TO_GO_HDR_LEN))
            {
              has_payload = FALSE;
            }
            while ((tvb_reported_length_remaining(tvb, offset) >=
                    D_TIME_TO_GO_HDR_LEN) && (ntimes-- > 0))
            {
              proto_tree_add_item(sliq_tree, hf_sliq_d_ttg,
                                  tvb, offset, 2, ENC_BIG_ENDIAN);
              offset += 2;
            }
          }

          if ((has_payload) &&
              (tvb_reported_length_remaining(tvb, offset) >= 1))
          {
            ip_tvb     = tvb_new_subset_remaining(tvb, offset);
            inner_type = tvb_get_guint8(tvb, offset);

            if ((inner_type & 0xf0) == 0x40)
            {
              gboolean  is_rrm = FALSE;

              if (tvb_reported_length_remaining(tvb, offset) >= 24)
              {
                guint8   protocol = tvb_get_guint8(tvb, (offset + 9));
                guint16  dst_port = tvb_get_ntohs(tvb, (offset + 22));

                if ((protocol == IPPROTO_UDP) &&
                    (dst_port == 48900)) /* RRM */
                {
                  if (!rrm_handle_found)
                  {
                    rrm_handle = find_dissector("rrm");
                    if (rrm_handle)
                    {
                      rrm_handle_found = TRUE;
                    }
                  }
                  if (rrm_handle_found)
                  {
                    is_rrm  = TRUE;
                    offset += 20;
                    ip_tvb  = tvb_new_subset_remaining(tvb, offset);
                    call_dissector(rrm_handle, ip_tvb, pinfo, tree);
                  }
                }
              }

              if (!is_rrm) /* IPv4 */
              {
                call_dissector(ip_handle, ip_tvb, pinfo, tree);
              }
            }
            else if ((inner_type & 0xf0) == 0x30) /* CAT */
            {
              if (!cat_handle_found)
              {
                cat_handle = find_dissector("cat");
                if (cat_handle)
                {
                  cat_handle_found = TRUE;
                }
              }
              if (cat_handle_found)
              {
                call_dissector(cat_handle, ip_tvb, pinfo, tree);
              }
            }
            else
            {
              switch (inner_type)
              {
                case 0x10: /* QLAM */
                  if (!qlam_handle_found)
                  {
                    qlam_handle = find_dissector("qlam");
                    if (qlam_handle)
                    {
                      qlam_handle_found = TRUE;
                    }
                  }
                  if (qlam_handle_found)
                  {
                    call_dissector(qlam_handle, ip_tvb, pinfo, tree);
                  }
                  break;

                case 0x11: /* CCE */
                  /* Required for IRON code, legacy for GNAT code. */
                  if (!cce_handle_found)
                  {
                    cce_handle = find_dissector("cce");
                    if (cce_handle)
                    {
                      cce_handle_found = TRUE;
                    }
                  }
                  if (cce_handle_found)
                  {
                    call_dissector(cce_handle, ip_tvb, pinfo, tree);
                  }
                  break;

                case 0x13: /* LSA */
                  if (!ironlsa_handle_found)
                  {
                    ironlsa_handle = find_dissector("ironlsa");
                    if (ironlsa_handle)
                    {
                      ironlsa_handle_found = TRUE;
                    }
                  }
                  if (ironlsa_handle_found)
                  {
                    call_dissector(ironlsa_handle, ip_tvb, pinfo, tree);
                  }
                  break;

                case 0x14: /* KUPD */
                  /* Required for IRON code, legacy for GNAT code. */
                  if (!kupd_handle_found)
                  {
                    kupd_handle = find_dissector("kupd");
                    if (kupd_handle)
                    {
                      kupd_handle_found = TRUE;
                    }
                  }
                  if (kupd_handle_found)
                  {
                    call_dissector(kupd_handle, ip_tvb, pinfo, tree);
                  }
                  break;
              }
            }
          }
        }
        done = TRUE;
        break;

      case ACK_HDR: /* ACK */
        if (tvb_reported_length_remaining(tvb, offset) >= A_BASE_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_stream_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          nopt = (int)((tvb_get_guint8(tvb, offset) & A_NOPT) >> 5);
          nabo = (int)(tvb_get_guint8(tvb, offset) & A_NABO);
          proto_tree_add_item(sliq_tree, hf_sliq_a_nopt,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(sliq_tree, hf_sliq_a_nabo,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_a_next_seq,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_a_ts,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_a_ts_delta,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          if (tvb_reported_length_remaining(tvb, offset) <
              (nopt * A_OBS_PKT_TIME_HDR_LEN))
          {
            done = TRUE;
          }

          while ((tvb_reported_length_remaining(tvb, offset) >=
                  A_OBS_PKT_TIME_HDR_LEN) && (nopt-- > 0))
          {
            proto_tree_add_item(sliq_tree, hf_sliq_a_obs_seq,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(sliq_tree, hf_sliq_a_obs_ts,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
          }

          if (tvb_reported_length_remaining(tvb, offset) <
              (nabo * A_ACK_BLOCK_HDR_LEN))
          {
            done = TRUE;
          }

          while ((tvb_reported_length_remaining(tvb, offset) >=
                  A_ACK_BLOCK_HDR_LEN) && (nabo-- > 0))
          {
            proto_tree_add_item(sliq_tree, hf_sliq_a_blk_type,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(sliq_tree, hf_sliq_a_blk_offset,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
          }
        }
        else
        {
          done = TRUE;
        }
        break;

      case CC_SYNC_HDR: /* Congestion Control Synchronization */
        if (tvb_reported_length_remaining(tvb, offset) >= SY_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_sy_cc_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_sy_seq_num,
                              tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          proto_tree_add_item(sliq_tree, hf_sliq_sy_cc_params,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
        else
        {
          done = TRUE;
        }
        break;

      case RCVD_PKT_CNT_HDR: /*  Received Packet Count */
        if (tvb_reported_length_remaining(tvb, offset) >= RC_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_stream_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_rc_rtx,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_rc_pkt_seq,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_rc_rcv_pkt_cnt,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
        else
        {
          done = TRUE;
        }
        break;

      case CC_PKT_TRAIN_HDR: /* Congestion Control Packet Train */
        if (tvb_reported_length_remaining(tvb, offset) >= PT_HDR_LEN)
        {
          proto_tree_add_item(sliq_tree, hf_sliq_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_pt_cc_id,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_pt_type,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_pt_seq,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          proto_tree_add_item(sliq_tree, hf_sliq_pt_irt,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_pt_ts,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          proto_tree_add_item(sliq_tree, hf_sliq_pt_ts_delta,
                              tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
        done = TRUE;
        break;

      default:
        done = TRUE;
    }
  }

  return tvb_captured_length(tvb);
}

void proto_register_sliq(void)
{
  module_t  *sliq_module;

  static hf_register_info hf_sliq[] = {
    /* Common */
    { &hf_sliq_type,
      { "Type", "sliq.type",
        FT_UINT8, BASE_DEC,
        VALS(headertypenames), 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_stream_id,
      { "Stream ID", "sliq.stream_id",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* Connection Handshake */
    { &hf_sliq_ch_num_cc_alg,
      { "Number Congestion Control Algorithms", "sliq.ch_num_cc_alg",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_ch_msg_tag,
      { "Message Tag", "sliq.ch_msg_tag",
        FT_UINT16, BASE_DEC,
        VALS(messagetagnames), 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_ch_ts,
      { "Timestamp", "sliq.ch_ts",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_ch_echo_ts,
      { "Echo Timestamp", "sliq.ch_echo_ts",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_ch_cc_type,
      { "Congestion Control Type", "sliq.ch_cc_type",
        FT_UINT8, BASE_DEC,
        VALS(cctypenames), 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_ch_cc_flags,
      { "Flags", "sliq.ch_cc_flags",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_ch_cc_flags_determ,
      { "Deterministic", "sliq.ch_cc_flags_deterministic",
        FT_BOOLEAN, 8,
        NULL, CH_DETERM_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_ch_cc_flags_pacing,
      { "Pacing", "sliq.ch_cc_flags_pacing",
        FT_BOOLEAN, 8,
        NULL, CH_PACING_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_ch_cc_params,
      { "Congestion Control Parameters", "sliq.ch_cc_params",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* Connection Reset */
    { &hf_sliq_cr_error_code,
      { "Error Code", "sliq.cr_error_code",
        FT_UINT16, BASE_DEC,
        VALS(crerrorcodenames), 0x0,
        NULL, HFILL }
    },
    /* Connection Close */
    { &hf_sliq_cc_flags,
      { "Flags", "sliq.cc_flags",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_cc_flags_ack,
      { "ACK", "sliq.cc_flags_ack",
        FT_BOOLEAN, 8,
        NULL, CC_ACK_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_cc_reason,
      { "Reason", "sliq.cc_reason",
        FT_UINT16, BASE_DEC,
        VALS(ccreasonnames), 0x0,
        NULL, HFILL }
    },
    /* Stream Create */
    { &hf_sliq_sc_flags,
      { "Flags", "sliq.sc_flags",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sc_flags_del_time,
      { "Delivery Time", "sliq.sc_flags_delivery_time",
        FT_UINT8, BASE_DEC,
        NULL, SC_DEL_TIME_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_sc_flags_ack,
      { "ACK", "sliq.sc_flags_ack",
        FT_BOOLEAN, 8,
        NULL, SC_ACK_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_sc_priority,
      { "Priority", "sliq.sc_priority",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sc_init_win_size,
      { "Initial Window Size Packets", "sliq.sc_init_win_size",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sc_init_pkt_seq,
      { "Initial Packet Sequence Number", "sliq.sc_init_pkt_seq",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sc_del_mode,
      { "Delivery Mode", "sliq.sc_delivery_mode",
        FT_UINT8, BASE_DEC,
        VALS(scdeliverymodenames), SC_DEL_MODE,
        NULL, HFILL }
    },
    { &hf_sliq_sc_rel_mode,
      { "Reliability Mode", "sliq.sc_reliability_mode",
        FT_UINT8, BASE_DEC,
        VALS(screliabilitymodenames), SC_REL_MODE,
        NULL, HFILL }
    },
    { &hf_sliq_sc_rexmit_limit,
      { "Semi-Reliable Packet Delivery Retransmission Limit",
        "sliq.sc_rexmit_limit",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sc_tgt_del_rnds,
      { "FEC Target Delivery Rounds", "sliq.sc_tgt_del_rounds",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sc_tgt_del_time,
      { "FEC Target Delivery Time", "sliq.sc_tgt_del_time",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sc_tgt_rcv_prob,
      { "FEC Target Packet Receive Probability", "sliq.sc_tgt_rcv_prob",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* Stream Reset */
    { &hf_sliq_sr_error_code,
      { "Error Code", "sliq.sr_error_code",
        FT_UINT8, BASE_DEC,
        VALS(srerrorcodenames), 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sr_fin_pkt_seq,
      { "Final Packet Sequence Number", "sliq.sr_fin_pkt_seq",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* Data */
    { &hf_sliq_d_flags,
      { "Flags", "sliq.d_flags",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_flags_enc_pkt_len,
      { "Encoded Packet Length Present", "sliq.d_flags_enc_pkt_len",
        FT_BOOLEAN, 8,
        NULL, D_ENC_PKT_LEN_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_d_flags_fec,
      { "FEC Fields Present", "sliq.d_flags_fec",
        FT_BOOLEAN, 8,
        NULL, D_FEC_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_d_flags_mv_fwd,
      { "Move Forward Present", "sliq.d_flags_move_fwd",
        FT_BOOLEAN, 8,
        NULL, D_MOVE_FWD_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_d_flags_persist,
      { "Persist", "sliq.d_flags_persist",
        FT_BOOLEAN, 8,
        NULL, D_PERSIST_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_d_flags_fin,
      { "FIN", "sliq.d_flags_fin",
        FT_BOOLEAN, 8,
        NULL, D_FIN_FLAG,
        NULL, HFILL }
    },
    { &hf_sliq_d_num_ttgs,
      { "Number of Time-To-Gos", "sliq.d_num_ttgs",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_cc_id,
      { "Congestion Control ID", "sliq.d_cc_id",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_rtx,
      { "Retransmission Count", "sliq.d_rtx",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_payload_len,
      { "Payload Length", "sliq.d_payload_len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_pkt_seq,
      { "Packet Sequence Number", "sliq.d_pkt_seq",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_ts,
      { "Timestamp", "sliq.d_ts",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_ts_delta,
      { "Timestamp Delta", "sliq.d_ts_delta",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_mv_fwd_seq,
      { "Move Forward Packet Sequence Number", "sliq.d_move_fwd_seq",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_fec_type,
      { "FEC Type", "sliq.d_fec_type",
        FT_UINT16, BASE_DEC,
        VALS(dfectypenames), D_FEC_TYPE,
        NULL, HFILL }
    },
    { &hf_sliq_d_fec_idx,
      { "FEC Block Index", "sliq.d_fec_idx",
        FT_UINT16, BASE_DEC,
        NULL, D_FEC_IDX,
        NULL, HFILL }
    },
    { &hf_sliq_d_fec_num_src,
      { "FEC Block Source Packets", "sliq.d_fec_num_src",
        FT_UINT16, BASE_DEC,
        NULL, D_FEC_NUM_SRC,
        NULL, HFILL }
    },
    { &hf_sliq_d_fec_rnd,
      { "FEC Block Round", "sliq.d_fec_rnd",
        FT_UINT16, BASE_DEC,
        NULL, D_FEC_RND,
        NULL, HFILL }
    },
    { &hf_sliq_d_fec_grp,
      { "FEC Group ID", "sliq.d_fec_grp",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_enc_pkt_len,
      { "Encoded Packet Length", "sliq.d_enc_pkt_len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_d_ttg,
      { "Time-To-Go", "sliq.d_pkt_ttg",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* ACK */
    { &hf_sliq_a_nopt,
      { "Number Observed Packet Times", "sliq.a_num_obs_pkt_times",
        FT_UINT8, BASE_DEC,
        NULL, A_NOPT,
        NULL, HFILL }
    },
    { &hf_sliq_a_nabo,
      { "Number ACK Block Offsets", "sliq.a_num_ack_blk_offsets",
        FT_UINT8, BASE_DEC,
        NULL, A_NABO,
        NULL, HFILL }
    },
    { &hf_sliq_a_next_seq,
      { "Next Expected Packet Sequence Number", "sliq.a_next_seq",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_a_ts,
      { "Timestamp", "sliq.a_ts",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_a_ts_delta,
      { "Timestamp Delta", "sliq.a_ts_delta",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_a_obs_seq,
      { "Observed Packet Sequence Number", "sliq.a_obs_seq",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_a_obs_ts,
      { "Observed Packet Timestamp", "sliq.a_obs_ts",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_a_blk_type,
      { "ACK Block Type", "sliq.a_blk_type",
        FT_UINT16, BASE_DEC,
        NULL, A_BLK_TYPE,
        NULL, HFILL }
    },
    { &hf_sliq_a_blk_offset,
      { "ACK Block Offset", "sliq.a_blk_offset",
        FT_UINT16, BASE_DEC,
        NULL, A_BLK_OFFSET,
        NULL, HFILL }
    },
    /* Congestion Control Synchronization */
    { &hf_sliq_sy_cc_id,
      { "Congestion Control ID", "sliq.sy_cc_id",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sy_seq_num,
      { "Sequence Number", "sliq.sy_seq_num",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_sy_cc_params,
      { "Congestion Control Parameters", "sliq.sy_cc_params",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* Received Packet Count */
    { &hf_sliq_rc_rtx,
      { "Retransmission Count", "sliq.rc_rtx",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_rc_pkt_seq,
      { "Packet Sequence Number", "sliq.rc_pkt_seq",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_rc_rcv_pkt_cnt,
      { "Connection Received Data Packet Count", "sliq.rc_rcv_pkt_cnt",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* Congestion Control Packet Train */
    { &hf_sliq_pt_cc_id,
      { "Congestion Control ID", "sliq.pt_cc_id",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_pt_type,
      { "Type", "sliq.pt_type",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_pt_seq,
      { "Sequence Number", "sliq.pt_seq",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_pt_irt,
      { "Packet Pair Inter-Receive Time", "sliq.pt_irt",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_pt_ts,
      { "Timestamp", "sliq.pt_ts",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sliq_pt_ts_delta,
      { "Timestamp Delta", "sliq.pt_ts_delta",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
  };


  /* Protocol subtree array. */
  static gint *ett_sliq_arr[] = {
    &ett_sliq
  };


  /* Register protocol. */
  proto_sliq = proto_register_protocol("SLIQ Protocol", "SLIQ", "sliq");
  proto_register_field_array(proto_sliq, hf_sliq, array_length(hf_sliq));
  proto_register_subtree_array(ett_sliq_arr, array_length(ett_sliq_arr));

  /* Preferences handling. */
  sliq_module = prefs_register_protocol(proto_sliq, proto_reg_handoff_sliq);

  range_convert_str(wmem_epan_scope(), &global_sliq_udp_range,
                    SLIQ_PORT_DEFAULTS, 65535);
  sliq_udp_range = range_empty(NULL);
  prefs_register_range_preference(sliq_module, "udp.port", "UDP Ports",
                                  "UDP Ports range", &global_sliq_udp_range,
                                  65535);
}

void proto_reg_handoff_sliq(void)
{
  static gboolean            sliq_prefs_initialized = FALSE;
  static dissector_handle_t  sliq_handle;

  if (!sliq_prefs_initialized)
  {
    ip_handle   = find_dissector("ip");
    sliq_handle = create_dissector_handle(dissect_sliq, proto_sliq);

    sliq_prefs_initialized = TRUE;
  }
  else
  {
    dissector_delete_uint_range("udp.port", sliq_udp_range, sliq_handle);
    g_free(sliq_udp_range);
  }

  sliq_udp_range = range_copy(NULL, global_sliq_udp_range);
  dissector_add_uint_range("udp.port", sliq_udp_range, sliq_handle);
}
