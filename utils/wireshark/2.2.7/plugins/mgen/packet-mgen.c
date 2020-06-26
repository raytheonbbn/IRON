/* packet-mgen.c
 * Routines for MGEN packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-mgen.c 35224 2015-11-29 05:35:29Z guy $
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

#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/decode_as.h>
#include <time.h>

#define MGEN_PORT_DEFAULTS "30700,30701"

static range_t *global_mgen_udp_range = NULL;
static range_t *mgen_udp_range = NULL;

static int proto_mgen = -1;
static gint ett_mgen = -1;

void proto_reg_handoff_mgen(void);
void proto_register_mgen(void);

static dissector_handle_t data_handle;
static tvbuff_t *data_tvb;

/* Variables for mgen packets */
static int hf_mgen_msg_size = -1;
static int hf_mgen_version = -1;
static int hf_mgen_flags = -1;
static int hf_mgen_flow_id = -1;
static int hf_mgen_seq_no = -1;
static int hf_mgen_timestamp = -1;
static int hf_mgen_latency = -1;

/* Packet Format */
/*  0                   1                   2                   3 */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |          messageSize          |    version    |    flags      | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                          mgenFlowId                           | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                        sequenceNumber                         | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                         txTimeSeconds                         | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |                       txTimeMicroseconds                      | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

/* static void */
/* mgen_prompt(packet_info *pinfo _U_, gchar* result) */
/* { */
/*   g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Interpret MGEN messages as"); */
/* } */

/* static gpointer */
/* mgen_value(packet_info *pinfo _U_) */
/* { */
/*   return 0; */
/* } */

static int
dissect_mgen (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint offset = 0;
  nstime_t t;
  nstime_t frame_t;
  nstime_t delta;

  /* TODO: Some sanity checking to determine whether the packet is really */
  /*       an mgen traffic packet */
  if (/* not an mgen packet */FALSE)
    return 0;
  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "MGEN packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti = NULL;
    proto_item *mgen_tree = NULL;

    ti = proto_tree_add_item (tree, proto_mgen, tvb, 0, -1, ENC_NA);
    mgen_tree = proto_item_add_subtree (ti, ett_mgen);

    if (offset + 2 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (mgen_tree, hf_mgen_msg_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
      }
    if (offset + 1 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (mgen_tree, hf_mgen_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
      }
    if (offset + 1 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (mgen_tree, hf_mgen_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
      }
    if (offset + 4 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (mgen_tree, hf_mgen_flow_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
      }
    if (offset + 4 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (mgen_tree, hf_mgen_seq_no, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
      }
    if (offset + 8 <= tvb_reported_length(tvb))
      {
	t.secs = tvb_get_ntohl(tvb, offset);
	t.nsecs = tvb_get_ntohl(tvb, offset+4)*1000;
	proto_tree_add_time(mgen_tree, hf_mgen_timestamp, tvb, offset, 8, &t);
	offset += 8;
      }
    frame_t.secs  = pinfo->fd->abs_ts.secs;
    frame_t.nsecs = pinfo->fd->abs_ts.nsecs;
    nstime_delta(&delta, &frame_t, &t);
    proto_tree_add_time(mgen_tree, hf_mgen_latency, tvb, offset, 8, &delta);

    if (offset + 8 <= tvb_reported_length(tvb))
      {
	data_tvb = tvb_new_subset_remaining (tvb, offset);
	call_dissector (data_handle, data_tvb, pinfo, tree);
      }

    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_mgen(void)
{
  module_t        *mgen_module;

  static hf_register_info hf_mgen[] = {
    { &hf_mgen_msg_size,
      { "Message size", "mgen.msg_size",
	FT_UINT16, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_mgen_version,
      { "Version", "mgen.version",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    /* Flags but none are used, so just treat as a byte */
    { &hf_mgen_flags,
      { "Flags", "mgen.flags",
	FT_UINT8, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_mgen_flow_id,
      { "Flow ID", "mgen.flow_id",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_mgen_seq_no,
      { "Sequence number", "mgen.seq_no",
	FT_UINT32, BASE_DEC,
	NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_mgen_timestamp,
      { "Timestamp", "mgen.timestamp",
	FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	NULL, 0x0,
	"MGEN timestamp", HFILL }
    },
    { &hf_mgen_latency,
      { "Latency", "mgen.latency",
	FT_RELATIVE_TIME, FT_NONE,
	NULL, 0x0,
	"MGEN Latency", HFILL }
    }
  };
  static gint *ett_mgen_arr[] = { /* protocol subtree array */
    &ett_mgen
  };

  /* Decode as handling */
  /* static build_valid_func mgen_da_build_value[1] = {mgen_value}; */
  /* static decode_as_value_t mgen_da_values = {mgen_prompt, 1, mgen_da_build_value}; */
  /* static decode_as_t mgen_da = {"mgen", "MGEN packet", "mgen.packet", 1, 0, &mgen_da_values, NULL, NULL, */
  /* 				decode_as_default_populate_list, decode_as_default_reset, */
  /* 				decode_as_default_change, NULL}; */
  /* register_decode_as(&mgen_da); */
  
  /* Register protocol */
  proto_mgen = proto_register_protocol("MGEN traffic", "MGEN", "mgen");
  proto_register_field_array (proto_mgen, hf_mgen, array_length (hf_mgen));
  proto_register_subtree_array (ett_mgen_arr, array_length (ett_mgen_arr));

  /* Preferences handling */
  mgen_module = prefs_register_protocol(proto_mgen, proto_reg_handoff_mgen);

  range_convert_str(&global_mgen_udp_range, MGEN_PORT_DEFAULTS, 65535);
  mgen_udp_range = range_empty();
  prefs_register_range_preference(mgen_module, "udp.port", "UDP Ports", "UDP Ports range",
				  &global_mgen_udp_range, 65535);

}

void
proto_reg_handoff_mgen(void)
{
  static gboolean mgen_prefs_initialized = FALSE;
  static dissector_handle_t mgen_handle;

  if (!mgen_prefs_initialized) {
    data_handle = find_dissector("data");
    mgen_handle = create_dissector_handle (dissect_mgen, proto_mgen);
    mgen_prefs_initialized = TRUE;
  } else {
    dissector_delete_uint_range("udp.port", mgen_udp_range, mgen_handle);
    g_free(mgen_udp_range);
  }
  mgen_udp_range = range_copy(global_mgen_udp_range);
  dissector_add_uint_range("udp.port", mgen_udp_range, mgen_handle);
  
}

