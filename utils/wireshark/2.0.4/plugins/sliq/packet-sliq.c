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
#include <time.h>

#define SLIQ_PORT_DEFAULTS "30300"

static range_t *global_sliq_udp_range = NULL;
static range_t *sliq_udp_range = NULL;

static int proto_sliq = -1;
static gint ett_sliq = -1;
static dissector_handle_t ip_handle;
static dissector_handle_t qlam_handle;
static dissector_handle_t lrm_handle;
gboolean qlam_handle_found = FALSE;
gboolean lrm_handle_found = FALSE;
static tvbuff_t *ip_tvb;

void proto_reg_handoff_sliq(void);
void proto_register_sliq(void);

/* Variables for sliq packets */
static int hf_sliq_type = -1;
#define Conn_H 0
#define Conn_R 1
#define Conn_C 2
#define Str_C 3
#define Str_R 4
#define Data 5
#define ACK 6
#define MvFwd 7
#define Metadata 8
#define LatInfo 9

static const value_string packettypenames[] = {
  {Conn_H, "Connection Handshake"},
  {Conn_R, "Connection Reset"},
  {Conn_C, "Connection Close"},
  {Str_C, "Stream Connection Create"},
  {Str_R, "Stream Reset"},
  {Data, "Data"},
  {ACK, "ACK"},
  {MvFwd, "Move Forward"},
  {Metadata, "IRON Metadata"},
  {LatInfo, "Latency Info"},
  {10, NULL}
};


/* Packet Formats */

/* Connection Handshake */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Type (0)   |U|U|U|P| CCType|      Message Tag              | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags                            */
/*                                  */
/* P      = Pacing                  */
/* CCType = Congestion Control Type */
/*                                  */

static int hf_sliq_h_flags = -1;
#define H_PACING_FLAG 0x10
static int hf_sliq_h_flags_pacing = -1;
#define H_CC_TYPE 0x0F
static int hf_sliq_h_flags_cc_type = -1;
static int hf_sliq_h_msg_tag = -1;

/* Message Tag                      */
/*                                  */
#define Client_Hello     0x4843
#define Server_Hello     0x4853
#define Client_Confirm   0x4343
#define Reject           0x4A52

static const value_string messagetagnames[] = {
  {Client_Hello, "Client Hello"},
  {Server_Hello, "Server Hello"},
  {Client_Confirm, "Client Confirm"},
  {Reject, "Reject"},
  {0, NULL}
};

/* Connection Reset */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Type (1)   |    unused     |      Error Code               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Connection Error Code            */
/*                                  */
/* No Error           0             */
/* Recv Close Error   1             */
/* Internal Error     2             */
/* Last Error         3             */
/*                                  */

static int hf_sliq_cr_error_code = -1;

static const value_string crerrorcodenames[] = {
  {0, "No Error"},
  {1, "Receive Close Error"},
  {2, "Internal Error"},
  {3, "Last Error"},
  {4, NULL}
};

/* Connection Close */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Type (2)   |    unused   |A|      Reason                   | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags                            */
/*                                  */
/* A      = ACK                     */
/*                                  */
static int hf_sliq_cc_flags = -1;
static int hf_sliq_cc_flags_ack = -1;
#define CC_ACK_TYPE 0x01

/* Reason                           */
/*                                  */
/* NORMAL             0             */
/* TOO MUCH DATA      1             */
/* LAST CLOSE         2             */
/*                                  */

static int hf_sliq_cc_reason = -1;
static const value_string crreasonnames[] = {
  {0, "Normal"},
  {1, "Too Much Data"},
  {2, "Last Close"},
  {3, NULL}
};

/* Stream Connection Create            */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Type (3)   |U|U|A|W|D| RM  |   Stream ID   |   Priority    | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                  Initial Window Size (packets)                | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                 Initial Packet Sequence Number                | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |      Semi-Reliable Packet Delivery Time Limit                 | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags                               */
/*                                     */
/* A   = ACK                           */
/* W   = Auto-Tune Flow Control Window */
/* D   = Delivery Mode                 */
/* RM  = Reliability Mode              */
/*                                     */
/* Semi-Reliable Time Limit is in milliseconds */

static int hf_sliq_stream_id = -1;
static int hf_sliq_sc_flags = -1;
static int hf_sliq_sc_flags_ack = -1;
#define CS_ACK_TYPE 0x20
static int hf_sliq_sc_flags_w = -1;
#define CS_W_TYPE 0x10
static int hf_sliq_sc_flags_d = -1;
#define CS_D_TYPE 0x08
static int hf_sliq_sc_flags_rm = -1;
#define CS_RM_TYPE 0x07
static int hf_sliq_sc_priority = -1;
static int hf_sliq_iws = -1;
static int hf_sliq_ipsn = -1;
static int hf_sliq_srtl = -1;

/* Stream Reset */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Type (4)   |      unused   |   Stream ID   |   Error Code  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                 Final Packet Sequence Number                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Stream Error Code                     */
/*                                       */
/* NORMAL                  0             */
/* PARTIAL WRITE ERROR     1             */
/* WRITE ERROR             2             */
/* FLOW CONTROL ERROR      3             */
/* TRANSMIT QUEUE ERROR    4             */
/* LAST ERROR              5             */
/*                                       */

static const value_string srerrorcodenames[] = {
  {0, "Normal"},
  {1, "Partial Write Error"},
  {2, "Write Error"},
  {3, "Flow Control Error"},
  {4, "Transmit Queue Error"},
  {5, "Last Error"},
  {6, NULL}
};

/* static int hf_sliq_stream_id = -1; defined earlier */
static int hf_sliq_sr_error_code = -1;
static int hf_sliq_fpsn = -1;


/* Data              */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Type (5)   | unused  |P|B|F|   Stream ID   |    Rtx Count  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                     Packet Sequence Number                    | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                              Payload                          | */
/* |                          (variable length)                    | */
/* |                                                               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags                               */
/*                                     */
/* P   = Persist                       */
/* B   = Flow Control Blocked          */
/* F   = FIN                           */
/*                                     */

/* static int hf_sliq_stream_id = -1; defined earlier */
static int hf_sliq_d_flags = -1;
static int hf_sliq_d_flags_p = -1;
#define D_P_TYPE 0x04
static int hf_sliq_d_flags_b = -1;
#define D_B_TYPE 0x02
static int hf_sliq_d_flags_f = -1;
#define D_F_TYPE 0x01
static int hf_sliq_d_rtx = -1;
static int hf_sliq_psn = -1;


/* ACK */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |    Type (6)   |      unused   |   Stream ID   |     NOPDTs    | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |              NNR              |          WSIP,S               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |             Next Expected Packet Sequence Number              | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |            Largest Observed Packet Sequence Number            | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   Observed Packet Sequence Number                             | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   Observed Packet Delta Time in Microseconds                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   repeat above pair for total of NOPDT times                  | */
/*                                                                   */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Offset    |  Range Length |     Offset    |  Range Length | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   repeat above pair for total of NNR times                    | */
/*                                                                   */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */


/* Fields                                        */
/*                                               */
/* NOPDTs  Number of Observed Packet Delta Times */
/* NNR     Number of NACK Ranges                 */
/* WSIP,S  Window Size in Packets, Scaled        */
/*                                       */

/* static int hf_sliq_stream_id = -1; defined earlier */
static int hf_sliq_a_nopdt = -1;
guint8 nopdt = 0; // Used to iterate through list of Observed Packet Delta times
static int hf_sliq_a_nnr = -1;
guint16 nnr = 0; // Used to interate through list of NACK Ranges
static int hf_sliq_a_wsips = -1;
static int hf_sliq_nepsn = -1;
static int hf_sliq_lopsn = -1;
static int hf_sliq_a_opsn = -1;
static int hf_sliq_a_opdt = -1;
static int hf_sliq_a_offset = -1;
static int hf_sliq_a_range_len = -1;

/* The SLIQ move forward packet.                                       */
/*                                                                     */
/*  0                   1                   2                   3      */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1    */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   */
/* |     Type      |Flags (Unused) |   Stream ID   |    Unused     |   */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   */
/* |             Next Expected Packet Sequence Number              |   */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   */
/*                                                                     */
/*   Packet Type (1 byte) (0x07)                                       */
/*   Flags (1 byte) (uuuuuuuu)                                         */
/*     uuuuuuuu - Unused (8 bits)                                      */
/*   Stream ID (1 byte)                                                */
/*   Unused (1 byte)                                                   */
/*   Next Expected Packet Sequence Number (4 bytes)                    */

/* static int hf_sliq_stream_id = -1; defined earlier */
/* static int hf_sliq_nepsn = -1;     defined earlier */

/* IRON Metadata */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   Type (8)    |               BinId + PacketId                | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* BinId (4 bits) + PacketId (20 bits) is assembled in host byte */
/* order, sent in network bytes order.                           */

static int hf_sliq_bid = -1;
#define M_BID_FLAG 0xf0
static int hf_sliq_pid = -1;
#define M_PID_FLAG 0x0fffff

/* IRON latency information */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   Type (9)    | Epoch + TTG Valid + Latency info buf location | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                Time to go in microseconds                     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Epoch(3 bits) + time to go valid (1 bit) + PacketId (20 bits) is  */
/* assembled in host byte order, sent in network bytes order.        */

static int hf_sliq_epoch = -1;
#define LI_EP_FLAG 0xe0
static int hf_sliq_ttg_valid = -1;
#define LI_TTGV_FLAG 0x10
static int hf_sliq_buf_loc = -1;
#define LI_BLOC_FLAG 0x0fffff
static int hf_sliq_ttg = -1;

static int
dissect_sliq (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint offset = 0;
  gboolean done = FALSE;
  guint8 packet_type;
  proto_item *ti;
  proto_item *sliq_tree;

  if (!tree)
    {
      return tvb_captured_length(tvb);
    }

  while (!done && (offset < tvb_reported_length(tvb)))
    {
      // Grab the packet type, print it out and use it to determine subsequent processing
      packet_type = tvb_get_guint8(tvb, offset);
  
      col_set_str (pinfo-> cinfo, COL_PROTOCOL, "SLIQ Header");
      col_clear (pinfo->cinfo, COL_INFO);
      col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
		   val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

      ti = proto_tree_add_item (tree, proto_sliq, tvb, 0, -1, ENC_NA);
      proto_item_append_text(ti, ", Type %s",
			     val_to_str(packet_type, packettypenames, "Unkown (0x%02xx)"));

      sliq_tree = proto_item_add_subtree (ti, ett_sliq);
	  
      if (offset + 1 <= tvb_reported_length(tvb))
	{
	  // Packet type
	  proto_tree_add_item (sliq_tree, hf_sliq_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	  offset += 1;
	}

      switch (packet_type) {
      case Conn_H: // Handshake
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_h_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_h_flags_pacing, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_h_flags_cc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 2 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_h_msg_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
	    offset += 2;
	  }
	done = TRUE;
	break;
      case Conn_R: // Connection Reset
	offset += 1;
	if (offset + 2 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_cr_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	    offset += 2;
	  }
	done = TRUE;
	break;
      case Conn_C: // Connection Close
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_cc_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_cc_flags_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 2 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_cc_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
	    offset += 2;
	  }
	done = TRUE;
	break;
      case Str_C: // Stream Connection Create
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_sc_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_sc_flags_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_sc_flags_w, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_sc_flags_d, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_sc_flags_rm, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_sc_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 4 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_iws, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	if (offset + 4 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_ipsn, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	if (offset + 4 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_srtl, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	done = TRUE;
	break;
      case Str_R: // Stream Reset
	offset += 1;
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_sr_error_code, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	done = TRUE;
	break;
      case Data: // Data
	{ // Need block since cannot otherwise have variable declaration as first line after switch
	  static gboolean has_payload = TRUE;
	  static guint8 stream_id;
	  if (offset + 1 <= tvb_reported_length(tvb))
	    {
	      proto_tree_add_item(sliq_tree, hf_sliq_d_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	      proto_tree_add_item(sliq_tree, hf_sliq_d_flags_p, tvb, offset, 1, ENC_BIG_ENDIAN);
	      proto_tree_add_item(sliq_tree, hf_sliq_d_flags_b, tvb, offset, 1, ENC_BIG_ENDIAN);
	      proto_tree_add_item(sliq_tree, hf_sliq_d_flags_f, tvb, offset, 1, ENC_BIG_ENDIAN);
	      offset += 1;
	    }
	  else {has_payload = FALSE;}
	  if (offset + 1 <= tvb_reported_length(tvb))
	    {
	      proto_tree_add_item(sliq_tree, hf_sliq_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	      stream_id = tvb_get_guint8(tvb, offset);
	      offset += 1;
	    }
	  else {has_payload = FALSE;}
	  if (offset + 1 <= tvb_reported_length(tvb))
	    {
	      proto_tree_add_item(sliq_tree, hf_sliq_d_rtx, tvb, offset, 1, ENC_BIG_ENDIAN);
	      offset += 1;
	    }
	  else {has_payload = FALSE;}
	  if (offset + 4 <= tvb_reported_length(tvb))
	    {
	      proto_tree_add_item (sliq_tree, hf_sliq_psn, tvb, offset, 4, ENC_BIG_ENDIAN);
	      offset += 4;
	    }
	  else {has_payload = FALSE;}
	  if (has_payload)
	    {
	      ip_tvb = tvb_new_subset_remaining (tvb, offset);
	      if (stream_id == 1) // QLAM
		{
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
		      call_dissector (qlam_handle, ip_tvb, pinfo, tree);
		    }
		}
	      else if (stream_id == 3) // LRM
		{
		  if (!lrm_handle_found)
		    {
		      lrm_handle = find_dissector("lrm");
		      if (lrm_handle)
			{
			  lrm_handle_found = TRUE;
			}
		    }
		  if (lrm_handle_found)
		    {
		      call_dissector (lrm_handle, ip_tvb, pinfo, tree);
		    }
		}
	      else
		{
		  call_dissector (ip_handle, ip_tvb, pinfo, tree);
		}
	    }
	  done = TRUE;
	  break;
	}
      case ACK: // ACK
	offset += 1;
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    nopdt = tvb_get_guint8(tvb, offset);	    
	    proto_tree_add_item (sliq_tree, hf_sliq_a_nopdt, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	if (offset + 2 <= tvb_reported_length(tvb))
	  {
	    nnr = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_item (sliq_tree, hf_sliq_a_nnr, tvb, offset, 2, ENC_BIG_ENDIAN);
	    offset += 2;
	  }
	if (offset + 2 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_a_wsips, tvb, offset, 2, ENC_BIG_ENDIAN);
	    offset += 2;
	  }
	if (offset + 4 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_nepsn, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	if (offset + 4 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_lopsn, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	while ((offset + 8 <= tvb_reported_length(tvb)) && (nopdt-- > 0))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_a_opsn, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	    proto_tree_add_item (sliq_tree, hf_sliq_a_opdt, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	while ((offset + 2 <= tvb_reported_length(tvb)) && (nnr-- > 0))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_a_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	    proto_tree_add_item (sliq_tree, hf_sliq_a_range_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
	break;
      case MvFwd: // Move Forward
        offset += 1;
	if (offset + 1 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	    offset += 1;
	  }
        offset += 1;
	if (offset + 4 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_nepsn, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	break;
      case Metadata: // IRON Metadata
	if (offset + 3 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_bid, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_pid, tvb, offset, 3, ENC_BIG_ENDIAN);
	    offset += 3;
	  }
	break;
      case LatInfo: // IRON Latency Info
	if (offset + 3 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_epoch, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_ttg_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item (sliq_tree, hf_sliq_buf_loc, tvb, offset, 3, ENC_BIG_ENDIAN);
	    offset += 3;
	  }
	if (offset + 4 <= tvb_reported_length(tvb))
	  {
	    proto_tree_add_item (sliq_tree, hf_sliq_ttg, tvb, offset, 4, ENC_BIG_ENDIAN);
	    offset += 4;
	  }
	break;
      }
    }
  return offset;
}

void
proto_register_sliq(void)
{
  module_t        *sliq_module;

  static hf_register_info hf_sliq[] = {
    { &hf_sliq_type,
      { "Type", "sliq.type",
	FT_UINT8, BASE_DEC,
	VALS(packettypenames), 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_h_flags,
      { "Flags", "sliq.h_flags",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_h_flags_pacing,
      { "Pacing Flag", "sliq.h_flags_pacing",
	FT_BOOLEAN, 8,
	NULL, H_PACING_FLAG,
	NULL, HFILL }
    },
    { &hf_sliq_h_flags_cc_type,
      { "Congestion Control Type", "sliq.h_flags_cc_type",
	FT_UINT8, BASE_DEC,
	NULL, H_CC_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_h_msg_tag,
      { "Msg Tag", "sliq.h_msg_tag",
	FT_UINT16, BASE_DEC,
	VALS(messagetagnames), 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_cr_error_code,
      { "Conn Reset Error Code", "sliq.cr_error_code",
	FT_UINT16, BASE_DEC,
	VALS(crerrorcodenames), 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_cc_flags,
      { "Flags", "sliq.cc_flags",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_cc_flags_ack,
      { "ACK", "sliq.cc_flags_ack",
	FT_BOOLEAN, 8,
	NULL, CC_ACK_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_cc_reason,
      { "Conn Close Reason", "sliq.cr_reason",
	FT_UINT16, BASE_DEC,
	VALS(crreasonnames), 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_sc_flags,
      { "Flags", "sliq.cc_flags",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_sc_flags_ack,
      { "ACK Flag", "sliq.cc_flags_ack",
	FT_BOOLEAN, 8,
	NULL, CS_ACK_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_sc_flags_w,
      { "Auto-Tune Flag", "sliq.cc_flags_w",
	FT_BOOLEAN, 8,
	NULL, CS_W_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_sc_flags_d,
      { "Delivery Mode Flag", "sliq.cc_flags_d",
	FT_BOOLEAN, 8,
	NULL, CS_D_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_sc_flags_rm,
      { "Reliability Mode", "sliq.cc_flags_d",
	FT_UINT8, BASE_DEC,
	NULL, CS_RM_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_stream_id,
      { "Stream ID", "sliq.stream_id",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_sc_priority,
      { "Conn Close Priority", "sliq.cc_priority",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_iws,
      { "Initial Window Size", "sliq.iws",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_ipsn,
      { "Initial Packet Sequence Number", "sliq.ipsn",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_srtl,
      { "Semi-Reliable Packet Delivery Time Limit", "sliq.srtl",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_sr_error_code,
      { "Stream Reset Error Code", "sliq.sr_error_code",
	FT_UINT8, BASE_DEC,
	VALS(srerrorcodenames), 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_fpsn,
      { "Final Packet Sequence Number", "sliq.fpsn",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_d_flags,
      { "Data Flags", "sliq.d_flags",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_d_flags_p,
      { "Persist Flag", "sliq.d_flags_p",
	FT_BOOLEAN, 8,
	NULL, D_P_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_d_flags_b,
      { "Flow Control Blocked Flag", "sliq.d_flags",
	FT_BOOLEAN, 8,
	NULL, D_B_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_d_flags_f,
      { "FIN Flag", "sliq.d_flag_f",
	FT_BOOLEAN, 8,
	NULL, D_F_TYPE,
	NULL, HFILL }
    },
    { &hf_sliq_d_rtx,
      { "Data Rtx Count", "sliq.d_rtx",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_psn,
      { "Packet Sequence Number", "sliq.psn",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_a_nopdt,
      { "Num Obs Pkt Delta Times", "sliq.a_nopdt",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_a_nnr,
      { "Num NACK Ranges", "sliq.a_nnr",
	FT_UINT16, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_nepsn,
      { "Next Expected Packet Sequence Number", "sliq.nepsn",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_lopsn,
      { "Largest Observed Packet Sequence Number", "sliq.lopsn",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_a_wsips,
      { "Window Size", "sliq.a_wsips",
	FT_UINT16, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_a_opsn,
      { "Observed Packet Seq Num", "sliq.a_opsn",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_a_opdt,
      { "Observed Packet Delta Time", "sliq.a_opdt",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_a_offset,
      { "Offset", "sliq.a_offset",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_a_range_len,
      { "Range Length", "sliq.a_range_len",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_sliq_bid,
      { "Source Bin Id", "sliq.bid",
	FT_UINT8, BASE_DEC,
	NULL, M_BID_FLAG,
	NULL, HFILL }
    },
    { &hf_sliq_pid,
      { "Packet Id", "sliq.pid",
	FT_UINT32, BASE_DEC,
	NULL, M_PID_FLAG,
	NULL, HFILL }
    },
    { &hf_sliq_epoch,
      { "Latency Info Epoch", "sliq.epoch",
	FT_UINT8, BASE_DEC,
	NULL, LI_EP_FLAG,
	NULL, HFILL }
    },
    { &hf_sliq_ttg_valid,
      { "Time to go valid", "sliq.ttg_valid",
	FT_BOOLEAN, 8,
	NULL, LI_TTGV_FLAG,
	NULL, HFILL }
    },
    { &hf_sliq_buf_loc,
      { "Latency Info Buffer Location", "sliq.buf_loc",
	FT_UINT32, BASE_DEC,
	NULL, LI_BLOC_FLAG,
	NULL, HFILL }
    },
    { &hf_sliq_ttg,
      { "Time to go", "sliq.ttg",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    }
  };


  static gint *ett_sliq_arr[] = { /* protocol subtree array */
    &ett_sliq
  };

  
  /* Register protocol */
  proto_sliq = proto_register_protocol("SLIQ traffic", "SLIQ", "sliq");
  proto_register_field_array (proto_sliq, hf_sliq, array_length (hf_sliq));
  proto_register_subtree_array (ett_sliq_arr, array_length (ett_sliq_arr));

  /* Preferences handling */
  sliq_module = prefs_register_protocol(proto_sliq, proto_reg_handoff_sliq);

  range_convert_str(&global_sliq_udp_range, SLIQ_PORT_DEFAULTS, 65535);
  sliq_udp_range = range_empty();
  prefs_register_range_preference(sliq_module, "udp.port", "UDP Ports", "UDP Ports range",
				  &global_sliq_udp_range, 65535);

}

void
proto_reg_handoff_sliq(void)
{
  static gboolean sliq_prefs_initialized = FALSE;
  static dissector_handle_t sliq_handle;

  if (!sliq_prefs_initialized) {
    ip_handle = find_dissector("ip");
    sliq_handle = new_create_dissector_handle (dissect_sliq, proto_sliq);
    sliq_prefs_initialized = TRUE;
  } else {
    dissector_delete_uint_range("udp.port", sliq_udp_range, sliq_handle);
    g_free(sliq_udp_range);
  }

  sliq_udp_range = range_copy(global_sliq_udp_range);
  dissector_add_uint_range("udp.port", sliq_udp_range, sliq_handle);
  
}

