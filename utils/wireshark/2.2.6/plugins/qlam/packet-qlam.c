/* packet-qlam.c
 * Routines for QLAM packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-qlam.c 35224 2015-11-29 05:35:29Z guy $
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

#define QLAM_PORT_DEFAULTS "5555,5556"

static range_t *global_qlam_udp_range = NULL;
static range_t *qlam_udp_range = NULL;

static int proto_qlam = -1;
static gint ett_qlam = -1;

void proto_reg_handoff_qlam(void);
void proto_register_qlam(void);

/* Variables for qlam packets */
static int hf_ctrl_msg_type  = -1;
static int hf_src_address    = -1;
static int hf_qlam_msg_type  = -1;
static int hf_qlam_num_bins  = -1;
static int hf_qlam_seq_no    = -1;
static int hf_qlam_bin_id    = -1;
static int hf_qlam_bin_depth = -1;

/* Packet Format */
/* 0                   1                   2                   3 */
/* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Msg Type (x10)|                   Src Address                   */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*                 | QLAM Msg Type | N QUEUE LENS  | SEQUENCE        */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*           NUMBER                                |   qlamBinId     */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*                  qlamBinId (cont)               |   bin depth     */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                bin depth (cont)               |   qlamBinId     */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

static int
dissect_qlam (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint   offset = 0;
  guint   n = 0;
  guint8  num_bins = 0;
  guint32 addr;

  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "QLAM packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti = NULL;
    proto_item *qlam_tree = NULL;

    ti = proto_tree_add_item (tree, proto_qlam, tvb, 0, -1, ENC_NA);
    qlam_tree = proto_item_add_subtree (ti, ett_qlam);

    if (offset + 1 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (qlam_tree, hf_ctrl_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
      }
    if (offset + 4 <= tvb_reported_length(tvb))
      {
	addr = tvb_get_ipv4(tvb, offset);
	proto_tree_add_ipv4 (qlam_tree, hf_src_address, tvb, offset, 4, addr);
	offset += 4;
      }
    if (offset + 1 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (qlam_tree, hf_qlam_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
      }
    if (offset + 1 <= tvb_reported_length(tvb))
      {
	num_bins = tvb_get_guint8(tvb, offset);
	proto_tree_add_item (qlam_tree, hf_qlam_num_bins, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
      }
    if (offset + 4 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (qlam_tree, hf_qlam_seq_no, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
      }
    while ((offset + 8 <= tvb_reported_length(tvb)) && (++n <= num_bins))
      {
	proto_tree_add_item (qlam_tree, hf_qlam_bin_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item (qlam_tree, hf_qlam_bin_depth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
      }
    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_qlam(void)
{
  module_t        *qlam_module;

  static hf_register_info hf_qlam[] = {
    { &hf_ctrl_msg_type,
      { "Message type", "ctrl.type",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_src_address,
      { "Source Address", "qlam.src_addr",
	FT_IPv4, BASE_NONE,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_qlam_msg_type,
      { "QLAM Message type", "qlam.type",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_qlam_num_bins,
      { "Number bins", "qlam.num_bins",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_qlam_seq_no,
      { "Seq. No.", "qlam.seq_no",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_qlam_bin_id,
      { "Bin ID", "qlam.bin_id",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_qlam_bin_depth,
      { "Bin Depth", "qlam.bin_depth",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    }
  };
  static gint *ett_qlam_arr[] = { /* protocol subtree array */
    &ett_qlam
  };

  /* Decode as handling */
  /* static build_valid_func qlam_da_build_value[1] = {qlam_value}; */
  /* static decode_as_value_t qlam_da_values = {qlam_prompt, 1, qlam_da_build_value}; */
  /* static decode_as_t qlam_da = {"qlam", "QLAM packet", "qlam.packet", 1, 0, &qlam_da_values, NULL, NULL, */
  /* 				decode_as_default_populate_list, decode_as_default_reset, */
  /* 				decode_as_default_change, NULL}; */
  /* register_decode_as(&qlam_da); */
  
  /* Register protocol */
  proto_qlam = proto_register_protocol("QLAM traffic", "QLAM", "qlam");
  proto_register_field_array (proto_qlam, hf_qlam, array_length (hf_qlam));
  proto_register_subtree_array (ett_qlam_arr, array_length (ett_qlam_arr));

  /* Preferences handling */
  qlam_module = prefs_register_protocol(proto_qlam, proto_reg_handoff_qlam);

  range_convert_str(&global_qlam_udp_range, QLAM_PORT_DEFAULTS, 65535);
  qlam_udp_range = range_empty();
  prefs_register_range_preference(qlam_module, "udp.port", "UDP Ports", "UDP Ports range",
				  &global_qlam_udp_range, 65535);

}

void
proto_reg_handoff_qlam(void)
{
  static gboolean qlam_prefs_initialized = FALSE;
  static dissector_handle_t qlam_handle;

  if (!qlam_prefs_initialized) {
    qlam_handle = create_dissector_handle (dissect_qlam, proto_qlam);
    qlam_prefs_initialized = TRUE;

    /* Register dissector */
    register_dissector("qlam", dissect_qlam, proto_qlam); 

  } else {
    dissector_delete_uint_range("udp.port", qlam_udp_range, qlam_handle);
    g_free(qlam_udp_range);
  }

  qlam_udp_range = range_copy(global_qlam_udp_range);
  dissector_add_uint_range("udp.port", qlam_udp_range, qlam_handle);
  
}

