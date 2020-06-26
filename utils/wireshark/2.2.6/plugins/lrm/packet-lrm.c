/* packet-lrm.c
 * Routines for LRM packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-lrm.c 35224 2015-11-29 05:35:29Z guy $
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

#define LRM_PORT_DEFAULTS "5555,5556"

static range_t *global_lrm_udp_range = NULL;
static range_t *lrm_udp_range = NULL;

static int proto_lrm = -1;
static gint ett_lrm = -1;

void proto_reg_handoff_lrm(void);
void proto_register_lrm(void);

/* Variables for lrm packets */
static int hf_ctrl_msg_type   = -1;
static int hf_src_bin_id   = -1;
static int hf_dst_bin_id   = -1;
static int hf_lrm_pkt_id   = -1;
static int hf_lrm_epoch    = -1;
static int hf_lrm_buff_loc = -1;
static int hf_lrm_ttg      = -1;

#define H_SBI_MASK 0xF0
#define H_DBI_MASK 0x0F
#define H_PKT_MASK 0xFFFFFF
#define H_EPO_MASK 0xC0000000
#define H_PBL_MASK 0x3FFFFFFC

/* Packet Format */
/* 0                   1                   2                   3     */
/* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1   */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Msg Type (x12)|scBinId|dsBinId|      packet ID                  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*  pktId  | pad   | E |    prev buff location             |  pad  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     pad       |                   TTG at destination            */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*   TTG           |                 pad                             */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

static int
dissect_lrm (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint   offset = 0;
  nstime_t t;

  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "LRM packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti = NULL;
    proto_item *lrm_tree = NULL;

    ti = proto_tree_add_item (tree, proto_lrm, tvb, 0, -1, ENC_NA);
    lrm_tree = proto_item_add_subtree (ti, ett_lrm);

    if (offset + 1 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (lrm_tree, hf_ctrl_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
      }
    if (offset + 1 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (lrm_tree, hf_src_bin_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item (lrm_tree, hf_dst_bin_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
      }
    if (offset + 3 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (lrm_tree, hf_lrm_pkt_id, tvb, offset, 3, ENC_LITTLE_ENDIAN);
	offset += 3;
      }
    if (offset + 4 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (lrm_tree, hf_lrm_epoch, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item (lrm_tree, hf_lrm_buff_loc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
      }
    if (offset + 4 <= tvb_reported_length(tvb))
      {
    	t.secs = tvb_get_letohl(tvb, offset)/1000000;
    	t.nsecs = (tvb_get_letohl(tvb, offset)-t.secs*1000000)*1000;
    	proto_tree_add_time(lrm_tree, hf_lrm_ttg, tvb, offset, 8, &t);
    	offset += 4;
      }
    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_lrm(void)
{
  module_t        *lrm_module;

  static hf_register_info hf_lrm[] = {
    { &hf_ctrl_msg_type,
      { "Message type", "ctrl.type",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_src_bin_id,
      { "Source Bin ID", "lrm.src_bin_id",
	FT_UINT8, BASE_DEC,
	NULL, H_SBI_MASK,
	NULL, HFILL }
    },
    { &hf_dst_bin_id,
      { "Destination Bin ID", "lrm.dst_bin_id",
	FT_UINT8, BASE_DEC,
	NULL, H_DBI_MASK,
	NULL, HFILL }
    },
    { &hf_lrm_pkt_id,
      { "Packet ID", "lrm.pkt_id",
	FT_UINT24, BASE_DEC,
	NULL, H_PKT_MASK,
	NULL, HFILL }
    },
    { &hf_lrm_epoch,
      { "Epoch", "lrm.epoch",
	FT_UINT32, BASE_DEC,
	NULL, H_EPO_MASK,
	NULL, HFILL }
    },
    { &hf_lrm_buff_loc,
      { "Buffer Location", "lrm.buff_loc",
	FT_UINT32, BASE_DEC,
	NULL, H_PBL_MASK,
	NULL, HFILL }
    },
    { &hf_lrm_ttg,
      { "Time To Go", "lrm.ttg",
	FT_RELATIVE_TIME, FT_NONE,
	NULL, 0x0,
	"LRM Latency", HFILL }
    }
  };
  static gint *ett_lrm_arr[] = { /* protocol subtree array */
    &ett_lrm
  };

  
  /* Register protocol */
  proto_lrm = proto_register_protocol("LRM traffic", "LRM", "lrm");
  proto_register_field_array (proto_lrm, hf_lrm, array_length (hf_lrm));
  proto_register_subtree_array (ett_lrm_arr, array_length (ett_lrm_arr));

  /* Preferences handling */
  lrm_module = prefs_register_protocol(proto_lrm, proto_reg_handoff_lrm);

  range_convert_str(&global_lrm_udp_range, LRM_PORT_DEFAULTS, 65535);
  lrm_udp_range = range_empty();
  prefs_register_range_preference(lrm_module, "udp.port", "UDP Ports", "UDP Ports range",
				  &global_lrm_udp_range, 65535);

}

void
proto_reg_handoff_lrm(void)
{
  static gboolean lrm_prefs_initialized = FALSE;
  static dissector_handle_t lrm_handle;

  if (!lrm_prefs_initialized) {
    lrm_handle = create_dissector_handle (dissect_lrm, proto_lrm);
    lrm_prefs_initialized = TRUE;

    /* Register dissector */
    register_dissector("lrm", dissect_lrm, proto_lrm); 

  } else {
    dissector_delete_uint_range("udp.port", lrm_udp_range, lrm_handle);
    g_free(lrm_udp_range);
  }

  lrm_udp_range = range_copy(global_lrm_udp_range);
  dissector_add_uint_range("udp.port", lrm_udp_range, lrm_handle);
  
}

