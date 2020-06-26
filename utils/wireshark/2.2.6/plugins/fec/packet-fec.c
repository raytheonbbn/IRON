/* packet-fec.c
 * Routines for FEC packet disassembly
 * Copyright (c) 2015 BBN Technologies
 * Based on packet-foo.c
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-fec.c 35224 2015-11-29 05:35:29Z guy $
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

static int proto_fec = -1;
static gint ett_fec = -1;

void proto_reg_handoff_fec(void);
void proto_register_fec(void);

/* Variables for fec packets */
static int hf_fec_group_id = -1;

#define H_GROUP_ID  0xFFFFFF00

/* Packet Format */
/* NOTE: This is a trailer and is ONLY on UDP packets */

/*  0                   1                   2                   3 */
/*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
/* |               groupId                         | padding       | */
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

static int
dissect_fec (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint offset = tvb_reported_length(tvb)-12;
  nstime_t t;

  /* Sanity checking to determine whether the packet is long */
  /*   enough to contain an fec trailer */
  if (tvb_reported_length(tvb)!=tvb_captured_length(tvb))
    return 0;
  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "FEC trailer");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti = NULL;
    proto_item *fec_tree = NULL;

    ti = proto_tree_add_item (tree, proto_fec, tvb, 0, -1, ENC_NA);
    fec_tree = proto_item_add_subtree (ti, ett_fec);

    if (offset + 4 <= tvb_reported_length(tvb))
      {
	proto_tree_add_item (fec_tree, hf_fec_group_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
      }

    return offset;
  }
  return tvb_reported_length(tvb);
}

void
proto_register_fec(void)
{
  //  module_t        *fec_module;

  static hf_register_info hf_fec[] = {
    { &hf_fec_group_id,
      { "Group ID", "fec.group_id",
	FT_UINT32, BASE_DEC,
	NULL, H_GROUP_ID,
	NULL, HFILL }
    },
  };
  static gint *ett_fec_arr[] = { /* protocol subtree array */
    &ett_fec
  };

  /* Register protocol */
  proto_fec = proto_register_protocol("FEC trailer", "FEC", "fec");
  proto_register_field_array (proto_fec, hf_fec, array_length (hf_fec));
  proto_register_subtree_array (ett_fec_arr, array_length (ett_fec_arr));

}

void
proto_reg_handoff_fec(void)
{
  static gboolean fec_prefs_initialized = FALSE;
  static dissector_handle_t fec_handle;

  if (!fec_prefs_initialized) {
    fec_handle = create_dissector_handle (dissect_fec, proto_fec);
    register_postdissector(fec_handle);
    fec_prefs_initialized = TRUE;
  }
}

