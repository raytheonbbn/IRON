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

//============================================================================
//
// This code is derived in part from the vdm98 code available at:
// http://info.iet.unipi.it/~luigi/fec.html
//
// The original source code file markings are preserved below.

// (C) 1996, 1997 Luigi Rizzo (luigi@iet.unipi.it)
//
// Portions derived from code by Phil Karn (karn@ka9q.ampr.org), Robert
// Morelos-Zaragoza (robert@spectra.eng.hawaii.edu) and Hari Thirumoorthy
// (harit@spectra.eng.hawaii.edu), Aug 1995
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//      This product includes software developed by Luigi Rizzo,
//      and other contributors.
// 4. Neither the name of the Author nor the names of other contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//============================================================================

#ifndef IRON_SLIQ_VDM_FEC_H_
#define IRON_SLIQ_VDM_FEC_H_


#include <stdint.h>


// Maximum number of original packets, and maximum number of repair packets,
// individually.
#define MAX_FEC_RATE  32


namespace sliq
{
  /// Class to encode and decode forward error correction (FEC) packets using
  /// a Vandermonde-based erasure code.
  ///
  /// Note that this is a systematic code, which means that it sends K
  /// original source data packets without change, then sends (N-K) encoded
  /// data packets containing the repair information.
  class VdmFec
  {
   public:

    /// Constructor.
    VdmFec() {};

    /// Destructor.
    virtual ~VdmFec() {};

    /// \brief Initialize the encoder/decoder state.
    ///
    /// \return  True on success, or false on error.
    static void Initialize();

    /// \brief Generate FEC repair packets (encoded data packets) from a set
    /// of original packets (soure data packets).
    ///
    /// \param  num_src_pkt   The number of source data packets.
    /// \param  src_pkt_data  The array of source data packets.  Must be an
    ///                       array of num_src_pkt elements.
    /// \param  src_pkt_size  The array of source data packet sizes in bytes.
    ///                       Must be an array of num_src_pkt elements.
    /// \param  num_enc_pkt   The number of encoded data packets.
    /// \param  enc_pkt_data  The array of encoded data packets that will be
    ///                       populated with repair information.  Must be an
    ///                       array of num_enc_pkt elements.  Encoded data
    ///                       packets to be generated must be non-NULL in this
    ///                       array.  Encoded data packets that are NULL are
    ///                       skipped.
    /// \param  enc_pkt_size  The array of encoded data packet sizes that will
    ///                       be populated with encoded packet length
    ///                       information.  Must be an array of num_enc_pkt
    ///                       elements.
    static void EncodePackets(int       num_src_pkt,
                              uint8_t** src_pkt_data,
                              uint16_t* src_pkt_size,
                              int       num_enc_pkt,
                              uint8_t** enc_pkt_data,
                              uint16_t* enc_pkt_size);

    /// \brief Decode original packets (source data packets) from a mix of
    /// original packets (source data packets) and repair packets (encoded
    /// data packets).
    ///
    /// \param  num_src_pkt      The number of received source and encoded
    ///                          data packets to be decoded into the same
    ///                          number of source data packets.  This must be
    ///                          the K value in an (N,K) code.
    /// \param  in_pkt_data      The array of received source data packets,
    ///                          followed by received encoded data packets.
    ///                          There must be num_src_pkt elements populated
    ///                          with no gaps.  The array size must be
    ///                          MAX_FEC_RATE.
    /// \param  in_pkt_size      The array of packet sizes for the received
    ///                          source and encoded data packets.  There must
    ///                          be num_src_pkt elements populated with no
    ///                          gaps.  The array size must be MAX_FEC_RATE.
    /// \param  in_enc_pkt_size  The array of encoded packet sizes for the
    ///                          received data packets.  There must be
    ///                          num_src_pkt elements populated with no gaps.
    ///                          The array size must be MAX_FEC_RATE.  Use the
    ///                          actual packet sizes, in bytes, for each
    ///                          source data packet, and the encoded packet
    ///                          sizes for each encoded data packet.
    /// \param  in_pkt_index     The array holding the original zero-based
    ///                          index of each packet in the in_pkt_data,
    ///                          in_pkt_size, and in_enc_pkt_size arrays.
    ///                          There must be num_src_pkt elements populated
    ///                          with no gaps.  The array size must be
    ///                          MAX_FEC_RATE.
    /// \param  out_pkt_data     The array of output source data packets.
    ///                          There must be num_src_pkt elements populated
    ///                          with no gaps.  The array size must be
    ///                          MAX_FEC_RATE.  The source data packets
    ///                          present in in_pkt_data must also be set in
    ///                          this array in the correct index used during
    ///                          encoding.  Missing source data packets to be
    ///                          decoded must have a buffer of an appropriate
    ///                          size set in this array in the correct index
    ///                          used during encoding.
    /// \param  out_pkt_size     The array of output source data packet
    ///                          lengths.  The array size must be
    ///                          MAX_FEC_RATE, and the elements must be zeroed
    ///                          before this method is called.  Upon success,
    ///                          the decoded source data packet lengths will
    ///                          be present in the correct index in this
    ///                          array.
    ///
    /// \return  Returns zero on success, or non-zero on error.
    static int DecodePackets(int       num_src_pkt,
                             uint8_t** in_pkt_data,
                             uint16_t* in_pkt_size,
                             uint16_t* in_enc_pkt_size,
                             int*      in_pkt_index,
                             uint8_t** out_pkt_data,
                             uint16_t* out_pkt_size);

  }; // end class VdmFec

} // namespace sliq

#endif // IRON_SLIQ_VDM_FEC_H_
