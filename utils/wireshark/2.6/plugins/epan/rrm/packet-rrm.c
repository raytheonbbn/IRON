/* packet-rrm.c
 * Routines for RRM packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-rrm.c 35224 2015-11-29 05:35:29Z guy $
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

#define IRONRRM_PORT_DEFAULTS "48900"

static range_t *global_rrm_udp_range = NULL;
static range_t *rrm_udp_range = NULL;

static int proto_rrm = -1;
static gint ett_rrm = -1;

void proto_reg_handoff_rrm(void);
void proto_register_rrm(void);

/* Variables for RRM packets */
static int  hf_rrm_flow_src_port   = -1;
static int  hf_rrm_special_port    = -1;
static int  hf_rrm_length          = -1;
static int  hf_rrm_checksum        = -1;
static int  hf_rrm_flow_dst_port   = -1;
static int  hf_rrm_bytes_sourced   = -1;
static int  hf_rrm_bytes_released  = -1;
static int  hf_rrm_pkts_sourced    = -1;
static int  hf_rrm_pkts_released   = -1;
static int  hf_rrm_avg_loss_rate   = -1;

/* Packet Format   */
/* IP header (20B) */
/* UDP header (8B) */
/*  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Flow destination port (2B)   |          Padding (2B)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Bytes Sourced (8B)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Bytes Released (8B)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Packets Sourced (4B)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Packets Released (4B)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Average Loss Rate (4B)                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

static int
dissect_rrm (tvbuff_t *tvb, packet_info *pinfo,
                  proto_tree *tree, void* data _U_)
{
  guint   offset = 0;
  g_log(NULL, G_LOG_LEVEL_DEBUG, "In RRM dissector.");

  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "RRM packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree)
  {
    proto_item *ti = NULL;
    proto_item *rrm_tree = NULL;

    ti = proto_tree_add_item (tree, proto_rrm, tvb, 0, -1, ENC_NA);
    rrm_tree = proto_item_add_subtree (ti, ett_rrm);

    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_flow_src_port,
        tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_special_port,
        tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_length,
        tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_checksum,
        tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    if (offset + 2 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_flow_dst_port,
        tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 4;  // Skip 2byte padding.
    }
    if (offset + 8 <= tvb_reported_length(tvb))
    {
      guint64 bytes_srcd  = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint64(rrm_tree, hf_rrm_bytes_sourced,
        tvb, offset, 8, bytes_srcd);
      offset += 8;
    }
    if (offset + 8 <= tvb_reported_length(tvb))
    {
      guint64 bytes_rlsd  = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint64(rrm_tree, hf_rrm_bytes_released,
        tvb, offset, 8, bytes_rlsd);
      offset += 8;
    }
    if (offset + 4 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_pkts_sourced,
        tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    if (offset + 4 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_pkts_released,
        tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    if (offset + 4 <= tvb_reported_length(tvb))
    {
      proto_tree_add_item(rrm_tree, hf_rrm_avg_loss_rate,
        tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_rrm(void)
{
  module_t        *rrm_module;

  static hf_register_info hf_rrm[] = {
    { &hf_rrm_flow_src_port,
      { "Source port", "rrm.flow_src_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_special_port,
      { "RRM special port", "rrm.special_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_length,
      { "Length", "rrm.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_checksum,
      { "Checksum", "rrm.checksum",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_flow_dst_port,
      { "Destination port", "rrm.dst_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_bytes_sourced,
      { "Bytes sourced", "rrm.bytes_srcd",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_bytes_released,
      { "Bytes released", "rrm.bytes_rlsd",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_pkts_sourced,
      { "Packets sourced", "rrm.pkts_srcd",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_pkts_released,
      { "Packets released", "rrm.pkts_rlsd",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rrm_avg_loss_rate,
      { "Average loss rate", "rrm.avg_loss_rate",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
  };
  static gint *ett_rrm_arr[] = { /* protocol subtree array */
    &ett_rrm
  };
  /* Register protocol */
  proto_rrm = proto_register_protocol("RRM traffic", "RRM", "rrm");
  proto_register_field_array (proto_rrm, hf_rrm, array_length (hf_rrm));
  proto_register_subtree_array (ett_rrm_arr, array_length (ett_rrm_arr));

  /* Preferences handling */
  rrm_module = prefs_register_protocol(proto_rrm, proto_reg_handoff_rrm);

  range_convert_str(wmem_epan_scope(), &global_rrm_udp_range, IRONRRM_PORT_DEFAULTS, 65535);
  rrm_udp_range = range_empty(NULL);
  prefs_register_range_preference(rrm_module, "udp.port", "UDP Ports", "UDP Ports range",
       &global_rrm_udp_range, 65535);

}

void
proto_reg_handoff_rrm(void)
{
  static gboolean rrm_prefs_initialized = FALSE;
  static dissector_handle_t rrm_handle;

  if (!rrm_prefs_initialized) {
    rrm_handle = create_dissector_handle (dissect_rrm, proto_rrm);
    rrm_prefs_initialized = TRUE;

    /* Register dissector */
    register_dissector("rrm", dissect_rrm, proto_rrm); 

  } else {
    dissector_delete_uint_range("udp.port", rrm_udp_range, rrm_handle);
    g_free(rrm_udp_range);
  }

  rrm_udp_range = range_copy(NULL,global_rrm_udp_range);
  dissector_add_uint_range("udp.port", rrm_udp_range, rrm_handle);
  
}

