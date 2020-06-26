/* packet-kupd.c
 * Routines for K Update packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-kupd.c 35224 2015-11-29 05:35:29Z guy $
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

#define KUPD_PORT_DEFAULTS "1111,1111"

static range_t *global_kupd_udp_range = NULL;
static range_t *kupd_udp_range = NULL;

static int proto_kupd = -1;
static gint ett_kupd = -1;

void proto_reg_handoff_kupd(void);
void proto_register_kupd(void);

/* Variables for kupd packets */
static int hf_ctrl_msg_type      = -1;
static int hf_kupd_src_bin_id    = -1;
static int hf_kupd_seq_num       = -1;
static int hf_kupd_k             = -1;

/* Packet Format */
/* 0                   1                   2                   3 */
/* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* | Msg Type (x14)|   Src Bin ID  |   Sequence Number             | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |               New K Value (uint64, NBO)                         */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*                  New K Value (cont)                             | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

static int
dissect_kupd (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint   offset = 0;

  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "KUPD packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree)
  {
    proto_item *ti = NULL;
    proto_item *kupd_tree = NULL;

    ti = proto_tree_add_item (tree, proto_kupd, tvb, 0, -1, ENC_NA);
    kupd_tree = proto_item_add_subtree (ti, ett_kupd);

    if (offset + 1 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (kupd_tree, hf_ctrl_msg_type, tvb, offset, 1,
                           ENC_BIG_ENDIAN);
      offset += 1;
    }
    if (offset + 1 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (kupd_tree, hf_kupd_src_bin_id, tvb, offset, 1,
                           ENC_BIG_ENDIAN);
      offset += 1;
    }
    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (kupd_tree, hf_kupd_seq_num, tvb, offset, 2,
                           ENC_BIG_ENDIAN);
      offset += 2;
    }
    if (offset + 8 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (kupd_tree, hf_kupd_k, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 4;
    }
    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_kupd(void)
{
  module_t        *kupd_module;

  static hf_register_info hf_kupd[] = {
    { &hf_ctrl_msg_type,
      { "Message type", "ctrl.type",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { & hf_kupd_src_bin_id,
      { "Source Bin Id", "kupd.src_bin",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_kupd_seq_num,
      { "Sequence Num", "kupd.seq_num",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_kupd_k,
      { "K Value", "kupd.k",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
  };
  static gint *ett_kupd_arr[] = { /* protocol subtree array */
    &ett_kupd
  };

  /* Decode as handling */
  /* static build_valid_func kupd_da_build_value[1] = {kupd_value}; */
  /* static decode_as_value_t kupd_da_values = {kupd_prompt, 1, kupd_da_build_value}; */
  /* static decode_as_t kupd_da = {"kupd", "KUPD packet", "kupd.packet", 1, 0, &kupd_da_values, NULL, NULL, */
  /* 				decode_as_default_populate_list, decode_as_default_reset, */
  /* 				decode_as_default_change, NULL}; */
  /* register_decode_as(&kupd_da); */
  
  /* Register protocol */
  proto_kupd = proto_register_protocol("KUPD traffic", "KUPD", "kupd");
  proto_register_field_array (proto_kupd, hf_kupd, array_length (hf_kupd));
  proto_register_subtree_array (ett_kupd_arr, array_length (ett_kupd_arr));

  /* Preferences handling */
  kupd_module = prefs_register_protocol(proto_kupd, proto_reg_handoff_kupd);

  range_convert_str(&global_kupd_udp_range, KUPD_PORT_DEFAULTS, 65535);
  kupd_udp_range = range_empty();
  prefs_register_range_preference(kupd_module, "udp.port", "UDP Ports", "UDP Ports range",
				  &global_kupd_udp_range, 65535);

}

void
proto_reg_handoff_kupd(void)
{
  static gboolean kupd_prefs_initialized = FALSE;
  static dissector_handle_t kupd_handle;

  if (!kupd_prefs_initialized) {
    kupd_handle = create_dissector_handle (dissect_kupd, proto_kupd);
    kupd_prefs_initialized = TRUE;

    /* Register dissector */
    register_dissector("kupd", dissect_kupd, proto_kupd); 

  } else {
    dissector_delete_uint_range("udp.port", kupd_udp_range, kupd_handle);
    g_free(kupd_udp_range);
  }

  kupd_udp_range = range_copy(global_kupd_udp_range);
  dissector_add_uint_range("udp.port", kupd_udp_range, kupd_handle);
  
}

