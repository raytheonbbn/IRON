/* packet-cce.c
 * Routines for IRON CCE packet disassembly
 * Copyright (c) 2018 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 *
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-cce.c 35224 2015-11-29 05:35:29Z guy $
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

#define CCE_PORT_DEFAULTS "1111,1111"

static range_t *global_cce_udp_range = NULL;
static range_t *cce_udp_range = NULL;

static int proto_cce = -1;
static gint ett_cce = -1;

void proto_reg_handoff_cce(void);
void proto_register_cce(void);

/* Variables for IRON CCE packets. */
static int hf_ctrl_msg_type = -1;
static int hf_cce_cap_est   = -1;

/* Packet Format */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |               Capacity Estimate               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/*                                                                   */
/* Note that the Capacity Estimate field is an unsigned integer      */
/* field stored in network byte order, and records the capacity      */
/* estimate in units of 1000 bits per second.  The capacity estimate */
/* is always rounded up to the next 1000 bits per second value       */
/* before scaling it.                                                */

static int
dissect_cce (tvbuff_t *tvb, packet_info *pinfo,
             proto_tree *tree, void* data _U_)
{
  guint   offset = 0;

  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "CCE packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree)
  {
    proto_item *ti = NULL;
    proto_item *cce_tree = NULL;

    ti = proto_tree_add_item (tree, proto_cce, tvb, 0, -1, ENC_NA);
    cce_tree = proto_item_add_subtree (ti, ett_cce);

    if (offset + 1 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (cce_tree, hf_ctrl_msg_type,
                           tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
    }
    if (offset + 3 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item (cce_tree, hf_cce_cap_est,
                           tvb, offset, 3, ENC_BIG_ENDIAN);
      offset += 3;
    }
    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_cce(void)
{
  module_t        *cce_module;

  static hf_register_info hf_cce[] = {
    { &hf_ctrl_msg_type,
      { "Message type", "ctrl.type",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_cce_cap_est,
      { "CAT Capacity Estimate", "cce.cap_est",
        FT_UINT24, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
  };
  static gint *ett_cce_arr[] = { /* protocol subtree array */
    &ett_cce
  };

  /* Decode as handling */
  /* static build_valid_func cce_da_build_value[1] = {cce_value}; */
  /* static decode_as_value_t cce_da_values = {cce_prompt, 1, cce_da_build_value}; */
  /* static decode_as_t cce_da = {"cce", "IRON CCE packet", "cce.packet", 1, 0, &cce_da_values, NULL, NULL, */
  /*                              decode_as_default_populate_list, decode_as_default_reset, */
  /*                              decode_as_default_change, NULL}; */
  /* register_decode_as(&cce_da); */

  /* Register protocol */
  proto_cce = proto_register_protocol("IRON CCE traffic", "IRON CCE", "cce");
  proto_register_field_array (proto_cce, hf_cce, array_length (hf_cce));
  proto_register_subtree_array (ett_cce_arr, array_length (ett_cce_arr));

  /* Preferences handling */
  cce_module = prefs_register_protocol(proto_cce, proto_reg_handoff_cce);

  range_convert_str(wmem_epan_scope(), &global_cce_udp_range, CCE_PORT_DEFAULTS, 65535);
  cce_udp_range = range_empty(NULL);
  prefs_register_range_preference(cce_module, "udp.port", "UDP Ports", "UDP Ports range",
                                  &global_cce_udp_range, 65535);

}

void
proto_reg_handoff_cce(void)
{
  static gboolean cce_prefs_initialized = FALSE;
  static dissector_handle_t cce_handle;

  if (!cce_prefs_initialized) {
    cce_handle = create_dissector_handle (dissect_cce, proto_cce);
    cce_prefs_initialized = TRUE;

    /* Register dissector */
    register_dissector("cce", dissect_cce, proto_cce);

  } else {
    dissector_delete_uint_range("udp.port", cce_udp_range, cce_handle);
    g_free(cce_udp_range);
  }

  cce_udp_range = range_copy(NULL, global_cce_udp_range);
  dissector_add_uint_range("udp.port", cce_udp_range, cce_handle);

}
