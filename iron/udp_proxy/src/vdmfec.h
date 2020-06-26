// IRON: iron_headers 
/*
 * Distribution A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
 * DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
 * Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contracts No. HR0011-15-C-0097 and
 * HR0011-17-C-0050. Any opinions, findings and conclusions or
 * recommendations expressed in this material are those of the author(s)
 * and do not necessarily reflect the views of the Defense Advanced
 * Research Project Agency.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* IRON: end */

#ifndef __VDMFEC_H__
#define __VDMFEC_H__

/// Maximum number of original packets,and
/// maximum number of repair packets, individually
#define MAX_TOTAL_FEC_SZ 32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function to initialize the FEC encoder/decoder library
 *
 */
void
init_vdmfec
	(void);

/**
 * Function to generate FEC repair packets from a set of original packets
 *
 * @param  pdata    Array of original packet arrays used to generate FEC packets
 * @param  szArray  Length of each packet array in pdata in bytes
 * @param  n        Number of entries in pdata, szArray (i.e., number of packets)
 * @param  pfec     Preallocated arrays to hold FEC repair packets (must be >= max(szArray) in length
 * @param  fecSz    Preallocated array to hold FEC repair packet (these are FECs 
 *                  computed from the packet lengths, not the lengths of pfec packets)
 * @param  k        Number of repair FEC packets requested
 */
void
encode_vdmfec
	(unsigned char  **pdata, 
	 unsigned short  *szArray, 
	 int              n, 
	 unsigned char  **pfec,
	 unsigned short  *fecSz,
	 int              k);

/**
 * Function to reconstruct original packets from a mix of original and repair packets
 *
 * @param  psrc     Array of original packets, followed by FEC packets
 * @param  pdst     Array of original packets, in order, post recovery
 * @param  index    Array holding the index of each packet in psrc; 
 * @param  n        Number of entries in psrc, pdst, index
 *                  By convention, if an index value in array "index" is greater
 *                  than n, it is a repair packet. Note we are recovering n original packets
 *		    from a total of n original and repair packets
 * @param  szArray  Array of original and FEC repair packet sizes
 * @param  fecSz    Array of FEC repair info regarding packet sizes
 *                  This is needed to handle situations when not all original
 *                  packets are the same length, and hence we need to know how long
 *	            a missing packet is post-recovery (in addition to its contents)
 * @param  recSz    Lengths of the reovered packets
 */
int
decode_vdmfec
	(unsigned char **psrc, 
	 unsigned char **pdst, 
	 int            *index, 
	 int             n, 
	 unsigned short *szArray,
	 unsigned short *fecSz,
	 unsigned short *recSz);

#ifdef __cplusplus
}
#endif

#endif // __VDMFEC_H__
