/* packet-ironlsa.c
 * Routines for IRON LSA packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-ironlsa.c 35224 2015-11-29 05:35:29Z guy $
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

#define IRONLSA_PORT_DEFAULTS "1111,1111"

static range_t *global_ironlsa_udp_range = NULL;
static range_t *ironlsa_udp_range = NULL;

static int proto_ironlsa = -1;
static gint ett_ironlsa = -1;

void proto_reg_handoff_ironlsa(void);
void proto_register_ironlsa(void);

/* Variables for iron lsa packets */
static int hf_ctrl_msg_type         = -1;
static int hf_ironlsa_src_bin_id    = -1;
static int hf_ironlsa_seq_num       = -1;
static int hf_ironlsa_num_nbrs      = -1;
static int hf_ironlsa_num_dst_bins  = -1;
static int hf_ironlsa_bin_id        = -1;
static int hf_ironlsa_latency       = -1;
static int hf_ironlsa_dest_bin_id   = -1;
static int hf_ironlsa_queue_delay   = -1;

/* Packet Format */
/* 0                   1                   2                   3 */
/* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Msg Type (x13)|   Src Bin ID  |   Sequence Number             | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Num neighbors | Num dst bins  |      Padding                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Latency BinId |  Padding      |      Latency                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Latency BinId |  Padding      |      Latency                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*               . . .                                               */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Latency BinId |  Padding      |      Latency                  | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   Bin Id      |  Queue delay (for microseconds, use <<8)      | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   Bin Id      |  Queue delay (for microseconds, use <<8)      | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*               . . .                                               */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |   Bin Id      |  Queue delay  (for microseconds, use <<8)     | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

static int
dissect_ironlsa (tvbuff_t *tvb, packet_info *pinfo,
                  proto_tree *tree, void* data _U_)
{
  guint   offset = 0;

  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "LSA packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree)
  {
    static guint8 num_nbrs  = 0;
    proto_item *ti = NULL;
    proto_item *ironlsa_tree = NULL;

    num_nbrs  = 0;
    ti = proto_tree_add_item (tree, proto_ironlsa, tvb, 0, -1, ENC_NA);
    ironlsa_tree = proto_item_add_subtree (ti, ett_ironlsa);

    if (offset + 1 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (ironlsa_tree, hf_ctrl_msg_type,
                           tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
    }
    if (offset + 1 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (ironlsa_tree, hf_ironlsa_src_bin_id,
                           tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
    }
    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (ironlsa_tree, hf_ironlsa_seq_num,
                           tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    if (offset + 1 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (ironlsa_tree, hf_ironlsa_num_nbrs,
                           tvb, offset, 1, ENC_BIG_ENDIAN);
      num_nbrs  = (tvb_get_guint8(tvb, offset));
      offset += 1;
    }
    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (ironlsa_tree, hf_ironlsa_num_dst_bins,
                           tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 3; // Skip 3 bytes padding
    }
    for (int binid = 0; binid < num_nbrs; ++binid)
    {
      if (offset + 4 <= tvb_reported_length(tvb))
      {
        proto_tree_add_item (ironlsa_tree, hf_ironlsa_bin_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2; // one for bin id, one for padding
        proto_tree_add_item (ironlsa_tree, hf_ironlsa_latency, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
      }
    }
    while (offset + 4 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (ironlsa_tree, hf_ironlsa_dest_bin_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item (ironlsa_tree, hf_ironlsa_queue_delay, tvb, offset, 3, ENC_BIG_ENDIAN);
      offset += 3;
    }
    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_ironlsa(void)
{
  module_t        *ironlsa_module;

  static hf_register_info hf_ironlsa[] = {
    { &hf_ctrl_msg_type,
      { "Message type", "ctrl.type",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { & hf_ironlsa_src_bin_id,
      { "Source Bin Id", "ironlsa.src_bin",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_ironlsa_seq_num,
      { "Sequence Num", "ironlsa.seq_num",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_ironlsa_num_nbrs,
      { "Num Neighbors", "ironlsa.num_nbrs",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_ironlsa_num_dst_bins,
      { "Num Dst Bin Ids", "ironlsa.num_dst_bins",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_ironlsa_bin_id,
      { "Bin Id", "ironlsa.binid",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_ironlsa_latency,
      { "Latency", "ironlsa.latency",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_ironlsa_dest_bin_id,
      { "Dest Bin Id", "ironlsa.dest_binid",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_ironlsa_queue_delay,
      { "Queue Delay", "ironlsa.queue_delay",
        FT_UINT24, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
  };
  static gint *ett_ironlsa_arr[] = { /* protocol subtree array */
    &ett_ironlsa
  };

  /* Decode as handling */
  /* static build_valid_func ironlsa_da_build_value[1] = {ironlsa_value}; */
  /* static decode_as_value_t ironlsa_da_values = {ironlsa_prompt, 1, ironlsa_da_build_value}; */
  /* static decode_as_t ironlsa_da = {"ironlsa", "IRON LSA packet", "ironlsa.packet", 1, 0, &ironlsa_da_values, NULL, NULL, */
  /* 				decode_as_default_populate_list, decode_as_default_reset, */
  /* 				decode_as_default_change, NULL}; */
  /* register_decode_as(&ironlsa_da); */
  
  /* Register protocol */
  proto_ironlsa = proto_register_protocol("IRON LSA traffic", "IRON LSA", "ironlsa");
  proto_register_field_array (proto_ironlsa, hf_ironlsa, array_length (hf_ironlsa));
  proto_register_subtree_array (ett_ironlsa_arr, array_length (ett_ironlsa_arr));

  /* Preferences handling */
  ironlsa_module = prefs_register_protocol(proto_ironlsa, proto_reg_handoff_ironlsa);

  range_convert_str(wmem_epan_scope(),&global_ironlsa_udp_range, IRONLSA_PORT_DEFAULTS, 65535);
  ironlsa_udp_range = range_empty(NULL);
  prefs_register_range_preference(ironlsa_module, "udp.port", "UDP Ports", "UDP Ports range",
				  &global_ironlsa_udp_range, 65535);

}

void
proto_reg_handoff_ironlsa(void)
{
  static gboolean ironlsa_prefs_initialized = FALSE;
  static dissector_handle_t ironlsa_handle;

  if (!ironlsa_prefs_initialized) {
    ironlsa_handle = create_dissector_handle (dissect_ironlsa, proto_ironlsa);
    ironlsa_prefs_initialized = TRUE;

    /* Register dissector */
    register_dissector("ironlsa", dissect_ironlsa, proto_ironlsa); 

  } else {
    dissector_delete_uint_range("udp.port", ironlsa_udp_range, ironlsa_handle);
    g_free(ironlsa_udp_range);
  }

  ironlsa_udp_range = range_copy(NULL,global_ironlsa_udp_range);
  dissector_add_uint_range("udp.port", ironlsa_udp_range, ironlsa_handle);
  
}

