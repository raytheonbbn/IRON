/* packet-cat.c
 * Routines for CAT packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 *
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-cat.c 35224 2015-11-29 05:35:29Z guy $
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


#define CAT_PORT_DEFAULTS  "1001,1001"

static range_t  *global_cat_udp_range = NULL;
static range_t  *cat_udp_range        = NULL;

static int   proto_cat = -1;
static gint  ett_cat   = -1;

static dissector_handle_t  ip_handle;
static dissector_handle_t  qlam_handle;
static dissector_handle_t  ironlsa_handle;
static dissector_handle_t  rrm_handle;

gboolean  qlam_handle_found    = FALSE;
gboolean  ironlsa_handle_found = FALSE;
gboolean  rrm_handle_found     = FALSE;

static tvbuff_t  *ip_tvb;

void proto_reg_handoff_cat(void);
void proto_register_cat(void);


/* Definitions for CAT headers. */
#define CAT_CAP_EST_HDR        48

#define CAT_PKT_DEST_LIST_HDR  52
#define CAT_PKT_ID_HDR         53
#define CAT_PKT_HISTORY_HDR    54
#define CAT_PKT_LATENCY_HDR    55

static const value_string  headertypenames[] = {
  {CAT_CAP_EST_HDR,       "CAT Capacity Estimate"},
  {CAT_PKT_DEST_LIST_HDR, "CAT Packet Destination List"},
  {CAT_PKT_ID_HDR,        "CAT Packet Identification"},
  {CAT_PKT_HISTORY_HDR,   "CAT Packet History"},
  {CAT_PKT_LATENCY_HDR,   "CAT Packet Latency"},
  {56, NULL}
};


/* Header Formats */

/* Common header field variables. */
static int  hf_cat_type = -1;


/* CAT Capacity Estimate (CCE) */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |               Capacity Estimate               | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define CCE_HDR_LEN  4

static int  hf_cat_cce_cap_est = -1;

#define CCE_CAP_EST_BITMASK  0xffffff


/* CAT Packet Destination List */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |          Destination List Bitmap              | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define PDL_HDR_LEN  4

static int  hf_cat_pdl_dest_bitmap = -1;

#define PDL_DEST_LIST_BITMASK  0xffffff


/* CAT Packet Identifier */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      | BinId |               PacketId                | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define PID_HDR_LEN  4

static int  hf_cat_pid_bin_id = -1;
static int  hf_cat_pid_pkt_id = -1;

#define PID_BIN_ID  0xf0
#define PID_PKT_ID  0x0fffff


/* CAT Packet History */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |Node Bin ID #0 |Node Bin ID #1 |Node Bin ID #2 | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |Node Bin ID #3 |Node Bin ID #4 |Node Bin ID #5 |Node Bin ID #6 | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |Node Bin ID #7 |Node Bin ID #8 |Node Bin ID #9 |Node Bin ID #10| */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

#define PHI_HDR_LEN  12

static int  hf_cat_phi_bin_id = -1;

#define PHI_BIN_ID_SIZE  11


/* CAT Packet Latency */
/*  0                   1                   2                   3    */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |     Type      |   Unused    |V|       Origin Timestamp        | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                          Time-To-Go                           | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* Flags:  V = Time-To-Go Valid */

#define PLI_HDR_LEN  8

static int  hf_cat_pli_flags           = -1;
static int  hf_cat_pli_flags_ttg_valid = -1;
static int  hf_cat_pli_origin_ts       = -1;
static int  hf_cat_pli_ttg             = -1;

#define PLI_TTG_VALID_FLAG  0x01


static int dissect_cat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       void* data _U_)
{
  gboolean     done        = FALSE;
  guint        offset      = 0;
  guint8       packet_type = 0;
  guint8       inner_type  = 0;
  int          binid       = 0;
  proto_item  *ti          = NULL;
  proto_item  *cat_tree    = NULL;

  if (!tree)
  {
    return tvb_captured_length(tvb);
  }

  while ((!done) && (tvb_reported_length_remaining(tvb, offset) > 0))
  {
    /* Grab the packet type and use it to determine subsequent processing. */
    packet_type = tvb_get_guint8(tvb, offset);

    if ((packet_type & 0xf0) == 0x30)
    {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAT Header");
      col_clear(pinfo->cinfo, COL_INFO);
      col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
                   val_to_str(packet_type, headertypenames,
                              "Unknown (0x%02x)"));

      ti = proto_tree_add_item(tree, proto_cat, tvb, 0, -1, ENC_NA);
      proto_item_append_text(ti, ", Type %s",
                             val_to_str(packet_type, headertypenames,
                                        "Unkown (0x%02x)"));

      cat_tree = proto_item_add_subtree(ti, ett_cat);

      switch (packet_type)
      {
        case CAT_CAP_EST_HDR: /* CAT Capacity Estimate (CCE) */
          if (tvb_reported_length_remaining(tvb, offset) >= CCE_HDR_LEN)
          {
            proto_tree_add_item(cat_tree, hf_cat_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(cat_tree, hf_cat_cce_cap_est,
                                tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
          }
          done = TRUE;
          break;

        case CAT_PKT_DEST_LIST_HDR: /* CAT Packet Destination List */
          if (tvb_reported_length_remaining(tvb, offset) >= PDL_HDR_LEN)
          {
            proto_tree_add_item(cat_tree, hf_cat_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(cat_tree, hf_cat_pdl_dest_bitmap,
                                tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
          }
          else
          {
            done = TRUE;
          }
          break;

        case CAT_PKT_ID_HDR: /* CAT Packet Identifier */
          if (tvb_reported_length_remaining(tvb, offset) >= PID_HDR_LEN)
          {
            proto_tree_add_item(cat_tree, hf_cat_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(cat_tree, hf_cat_pid_bin_id,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cat_tree, hf_cat_pid_pkt_id,
                                tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
          }
          else
          {
            done = TRUE;
          }
          break;

        case CAT_PKT_HISTORY_HDR: /* CAT Packet History */
          if (tvb_reported_length_remaining(tvb, offset) >= PHI_HDR_LEN)
          {
            proto_tree_add_item(cat_tree, hf_cat_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            for (binid = 0; binid < PHI_BIN_ID_SIZE; ++binid)
            {
              proto_tree_add_item(cat_tree, hf_cat_phi_bin_id,
                                  tvb, offset, 1, ENC_BIG_ENDIAN);
              offset += 1;
            }
          }
          else
          {
            done = TRUE;
          }
          break;

        case CAT_PKT_LATENCY_HDR: /* CAT Packet Latency */
          if (tvb_reported_length_remaining(tvb, offset) >= PLI_HDR_LEN)
          {
            proto_tree_add_item(cat_tree, hf_cat_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(cat_tree, hf_cat_pli_flags,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cat_tree, hf_cat_pli_flags_ttg_valid,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(cat_tree, hf_cat_pli_origin_ts,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(cat_tree, hf_cat_pli_ttg,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
          }
          else
          {
            done = TRUE;
          }
          break;

        default:
          done = TRUE;
      }
    }
    else
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

          if ((protocol == IPPROTO_UDP) && (dst_port == 48900)) /* RRM */
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
        }
      }

      done = TRUE;
    }
  }

  return tvb_captured_length(tvb);
}

void proto_register_cat(void)
{
  module_t  *cat_module;

  static hf_register_info hf_cat[] = {
    /* Common */
    { &hf_cat_type,
      { "Type", "cat.type",
        FT_UINT8, BASE_DEC,
        VALS(headertypenames), 0x0,
        NULL, HFILL }
    },
    /* CAT Capacity Estimate (CCE) */
    { &hf_cat_cce_cap_est,
      { "Capacity Estimate", "cat.cce_cap_est",
        FT_UINT32, BASE_OCT,
        NULL, CCE_CAP_EST_BITMASK,
        NULL, HFILL }
    },
    /* CAT Packet Destination List */
    { &hf_cat_pdl_dest_bitmap,
      { "Destination Bitmap", "cat.pdl_dest_bitmap",
        FT_UINT32, BASE_OCT,
        NULL, PDL_DEST_LIST_BITMASK,
        NULL, HFILL }
    },
    /* CAT Packet Identifier */
    { &hf_cat_pid_bin_id,
      { "Source Bin ID", "cat.pid_bin_id",
        FT_UINT8, BASE_DEC,
        NULL, PID_BIN_ID,
        NULL, HFILL }
    },
    { &hf_cat_pid_pkt_id,
      { "Packet ID", "cat.pid_pkt_id",
        FT_UINT32, BASE_DEC,
        NULL, PID_PKT_ID,
        NULL, HFILL }
    },
    /* CAT Packet History */
    { &hf_cat_phi_bin_id,
      { "Bin ID", "cat.phi_bin_id",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    /* CAT Packet Latency */
    { &hf_cat_pli_flags,
      { "Flags", "cat.pli_flags",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_cat_pli_flags_ttg_valid,
      { "Time To Go Valid", "cat.pli_flags_ttg_valid",
        FT_BOOLEAN, 8,
        NULL, PLI_TTG_VALID_FLAG,
        NULL, HFILL }
    },
    { &hf_cat_pli_origin_ts,
      { "Origin Timestamp", "cat.pli_origin_ts",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_cat_pli_ttg,
      { "Time To Go", "cat.pli_ttg",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
  };


  /* Protocol subtree array. */
  static gint *ett_cat_arr[] = {
    &ett_cat
  };


  /* Register protocol. */
  proto_cat = proto_register_protocol("CAT Protocol", "CAT", "cat");
  proto_register_field_array(proto_cat, hf_cat, array_length(hf_cat));
  proto_register_subtree_array(ett_cat_arr, array_length(ett_cat_arr));

  /* Preferences handling. */
  cat_module = prefs_register_protocol(proto_cat, proto_reg_handoff_cat);

  range_convert_str(&global_cat_udp_range,
                    CAT_PORT_DEFAULTS, 65535);
  cat_udp_range = range_empty();
  prefs_register_range_preference(cat_module, "udp.port", "UDP Ports",
                                  "UDP Ports range", &global_cat_udp_range,
                                  65535);
}

void proto_reg_handoff_cat(void)
{
  static gboolean            cat_prefs_initialized = FALSE;
  static dissector_handle_t  cat_handle;

  if (!cat_prefs_initialized)
  {
    ip_handle   = find_dissector("ip");
    cat_handle = create_dissector_handle(dissect_cat, proto_cat);

    cat_prefs_initialized = TRUE;

    register_dissector("cat", dissect_cat, proto_cat);
  }
  else
  {
    dissector_delete_uint_range("udp.port", cat_udp_range, cat_handle);
    g_free(cat_udp_range);
  }

  cat_udp_range = range_copy(global_cat_udp_range);
  dissector_add_uint_range("udp.port", cat_udp_range, cat_handle);
}
