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

/*
 * fec.c -- forward error correction based on Vandermonde matrices
 *
 * (C) 1996, 1997 Luigi Rizzo (luigi@iet.unipi.it)
 *
 * Portions derived from code by Phil Karn (karn@ka9q.ampr.org), Robert
 * Morelos-Zaragoza (robert@spectra.eng.hawaii.edu) and Hari Thirumoorthy
 * (harit@spectra.eng.hawaii.edu), Aug 1995
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Luigi Rizzo,
 *      and other contributors.
 * 4. Neither the name of the Author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>

#include "vdmfec.h"

#define P_KMAX MAX_TOTAL_FEC_SZ

#define MM  16	                // code over GF(2**MM)
#define	NN ((1 << MM) - 1)	// powers of @

// This defines the type used to store an element of the Galois Field
// used by the code.

typedef unsigned short gf; // Galois Field 65536

// To speed up computations, we have tables for logarithm, exponent
// and inverse of a number.
// There is also a macro for multiplications.

#define A0	(NN)	        // log(0) is not defined, use a special value

static gf  gf_exp [NN + 1];	// index->polynomial form conversion table
static int gf_log [NN + 1];	// Polynomial->index form conversion table
static gf  inverse[NN + 1];	// inverse of a number inv[@^i] = @^[NN-i-1]

// Compute x % NN, where NN is 2**MM - 1, without a slow divide.
// Many calls (about 1/8) are done with a small x < 2 NN

// Note: modnn does the following, only much faster
// #define modnn(x) ((x) % 0xffff)

static inline gf
modnn(int x)
{
  while (x >= NN) 
    {
      x -= NN;
      x = (x >> MM) + (x & NN);
    }
  return x;
}

// gf_mul(x,y) multiplies two numbers.

static inline gf
gf_mul (gf x, gf y)
{
  if ((x)==0 || (y)==0) return 0;

  return gf_exp[modnn(gf_log[x] + gf_log[y])] ;
}

//  Generate GF(2**m) from the irreducible polynomial p(X) in p[0]..p[m]
//  Lookup tables:
//     index->polynomial form		gf_exp[] contains j=alpha**i;
//     polynomial form -> index form	gf_log[j=alpha**i] = i
//     alpha=2 is the primitive element of GF(2**m)

void
init_vdmfec(void)
{
  // Primitive polynomials - see Lin & Costello, Appendix A,
  // and  Lee & Messerschmitt, p. 453.

  char primPoly[] = 
    {
      "11010000000010001"	// MM=16: 1+x+x^3+x^12+x^16
    };

  int i;
  int mask;

  mask = 1;

  gf_exp[MM] = 0; // will be updated at the end of the 1st loop

  for (i = 0; i < MM; i++) 
    {
      gf_exp[i]         = mask;
      gf_log[gf_exp[i]] = i;

      // If primPoly[i] == 1 then, term @^i occurs in poly-repr of @^MM

      if (primPoly[i] =='1') // primPoly[i] != 0
	{
	  gf_exp[MM] ^= mask;	// Bit-wise XOR operation
	}

      mask <<= 1;	// single left-shift
    }

  gf_log[gf_exp[MM]] = MM;

  // Have obtained poly-repr of @^MM. Poly-repr of @^(i+1) is given by
  // poly-repr of @^i shifted left one-bit and accounting for any @^MM
  // term that may occur when poly-repr of @^i is shifted.
  
  mask >>= 1;
  
  for (i = MM + 1; i < NN; i++) 
    {
      if (gf_exp[i - 1] >= mask)
	{
	  gf_exp[i] = gf_exp[MM] ^ ((gf_exp[i - 1] ^ mask) << 1);
	}
      else
	{
	  gf_exp[i] = gf_exp[i - 1] << 1;
	}
      gf_log[gf_exp[i]] = i;
    }
  
  gf_log[0]  = A0;
  gf_exp[NN] = 0;
  
  inverse[0] = NN; // invalid!
  inverse[1] = 1;
  
  for (i=2; i<=NN; i++)
    {
      inverse[i] = gf_exp[NN-gf_log[i]];
    }
}

// encode_vdmfec accepts as input pointers to n data packets of size sz,
// and produces as output k packets pointed to by fec, computed
// with index 0 through k-1
//
// Be very careful in nesting loops, invert them and you lose half speed.
// Unrolling the inner loop does not seem to save much time, at
// least using -O9

void
encode_vdmfec
	(unsigned char  **pdata, 
	 unsigned short  *szArray, 
	 int              n, 
	 unsigned char  **pfec,
	 unsigned short  *fecSz,
	 int              k)
{
  int  i;
  int  j;
  int  maxSz;
  int  item;

  gf **data = (gf **)pdata;
  gf **fec  = (gf **)pfec;

  maxSz = 0;
  for (i=0; i<n; i++)
    {
      if (szArray[i] > maxSz)
	{
	  maxSz = szArray[i];
	}
    }

  // Need to make sure we clear enough of the repair buffer
  // by ensuring the length is an even number of bytes

  if (maxSz & 0x1)
    {
      maxSz++;
    }

  for (j=0; j<k; j++)
    {
      gf *fp = fec[j];

      bzero(fp, maxSz * sizeof(unsigned char));
      fecSz[j] = 0;

      for (i=0; i<n; i++) 
	{
	  int  ix = gf_exp[modnn(i*j)]; // this is the encoding matrix
	  gf  *g  = data[i];
	  int  sz = szArray[i] >> 1;

	  for (item = 0; item < sz; item++)
	    {
	      fp[item] ^= gf_mul(ix, *g++);
	    }

	  if (szArray[i] & 0x1)
	    {
	      unsigned short tmp;

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
	      tmp = (unsigned short)(*(unsigned char *)g);
#else // (__BYTE_ORDER == __BIG_ENDIAN)
	      tmp = (unsigned short)((*(unsigned char *)g) << 8);
#endif 

	      fp[item] ^= gf_mul(ix,tmp); 
	    }

	  fecSz[j] ^= gf_mul(ix,szArray[i]);
	}
    }
}

// decode_vdmfec receives as input a vector of data, the indexes of
// data themselves, and produces the correct vector as output.
// B*src = A1*dst Initially B=I, A1 is the submatrix of A made of
// the rows corresponding to the received data.
//
// Note: Below, sz is the length of the packets
// and index is the array of received packet indices
// When an index value in ix is greater than n, it 
// is by convention an FEC repair packet (rather 
// than an original packet)

// src is the array of pointers to received packets (both orig and FEC),
// dst is the array of reconstructed packets

int
decode_vdmfec
	(unsigned char **psrc, 
	 unsigned char **pdst, 
	 int            *index, 
	 int             n, 
	 unsigned short *szArray,
	 unsigned short *fecSz,
	 unsigned short *recSz)
{
  gf b [P_KMAX][P_KMAX];
  gf a1[P_KMAX][P_KMAX];

  gf **src = (gf **)psrc;
  gf **dst = (gf **)pdst;

  int missing = 0;
  int maxSz   = 0;

  int i;

  for (i=0; i<n; i++)
    {
      if (szArray[i] > maxSz)
	{
	  maxSz = szArray[i];
	}
    }

  // Need to make sure we clear enough of the repair buffer
  // by ensuring the length is an even number of bytes

  if (maxSz & 0x1)
    {
      maxSz++;
    }

#define SWAP(a,b,t) {t tmp; tmp=a; a=b; b=tmp;}
  {
    int i;
    int v;

  again:

    // A word about the following swapping business
    // If it finds a packet index that is less
    // than n, it is an original packet --
    // so the orginal packet is moved to its
    // "correct" position within the pointer array
    // When we are done, the pointer array
    // will consist either of packets in the correct
    // position *or* repair packets. No original
    // packets will be out of place
    
    // This is done so that the later in the processing,
    // if the index value is equal to the loop index,
    // it just copies the original packet into the 
    // destination array
    
    for (i=0; i<n; i++) 
      {
	v = index[i];
	if (v<n && v != i ) 
	  {
	    SWAP(src[i],     src[v],     gf *);
	    SWAP(index[i],   index[v],   int);
	    SWAP(szArray[i], szArray[v], unsigned short);
	    SWAP(fecSz[i],   fecSz[v],   unsigned short);
	    goto again;
	  }
      }
  }

  // build matrix b
  {   
    int i;
    bzero(b, sizeof(b));
    bzero(a1, sizeof(a1));
    for (i=0; i<n; i++) 
      {
	b[i][i] = 1; // init
	if (index[i]< n) 
	  {
	    if (index[i] != i) 
	      {
		// fprintf(stderr,"ouch, %d should not be at %d\n",
		//	index[i], i);
		return -1;
	      } 
	    else 
	      {
		a1[i][i]=1;
	      }
	  } 
	else 
	  {
	    int pow = index[i] - n;
	    int j;
	    for (j=0;j<n;j++)
	      a1[i][j] = gf_exp[modnn(j*pow)];
	  }
      }
  }

  // invert matrix, using a crude method
  {   
    int row;
    
    for (row=0; row<n; row++) 
      {
	int mul;
	int r;
	int col;
	
	if (a1[row][row] == 0)   // pivot...
	  {
	    int t;
	    for (t=row+1; t<n; t++) 
	      {
		if (a1[row][t] != 0) // found a good one
		  {
		    int i;

		    SWAP(src[row],     src[t],     gf *);
		    SWAP(index[row],   index[t],   int );
		    SWAP(szArray[row], szArray[t], unsigned short);
		    SWAP(fecSz[row],   fecSz[t],   unsigned short);

		    for (i=0; i<n; i++) 
		      {
			SWAP(a1[i][row], a1[i][t], int);
			SWAP(b [i][row], b [i][t], int);
		      }
		    break;
		  }
	      }
	    
	    if (t == n) 
	      {
		// fprintf(stderr,"ouch, diagonal element %d = 0\n", row);
		return -2;
	      }
	  }
	
	if ((mul = inverse[a1[row][row]]) != 1)
	  {
	    for (col=0; col<n; col++) 
	      {
		b [row][col] = gf_mul(mul,b[row][col]);
		a1[row][col] = gf_mul(mul,a1[row][col]);
	      }
	  }
	
	for (r=0; r<n; r++) 
	  {
	    if (r == row || (mul=a1[r][row]) == 0)
	      {
		continue;
	      }
	    
	    if (index[row]==row) // source, only a1[row][row] != 0
	      {
		b [r][row] ^= gf_mul(mul,b[row][row]);
		a1[r][row] ^= gf_mul(mul,a1[row][row]);
	      } 
	    else
	      {
		for (col=0; col<n; col++) 
		  {
		    b [r][col] ^= gf_mul(mul,b[row][col]);
		    a1[r][col] ^= gf_mul(mul,a1[row][col]);
		  }
	      }
	  }
      }
  }
  
  // do the actual decoding
  {
    int item;
    int row;
    int col;

    for (row=0; row<n; row++) 
      {
	// Per above discussion, if index[row] == row then
	// this is an original packet. Just copy it to the 
	// destination array
	
	if (index[row]==row)
	  {
	    // We have set this up so it does the repair in place
	    // hence the following is commented out
	    // bcopy(src[row], dst[row], szArray[row]*sizeof(unsigned char));

	    recSz[row] = szArray[row];
	  }
	
	// Othwerwise, we do a reconstruction for this position
	
	else 
	  {
	    // Set up a pointer to the reconstruction buffer
	    
	    gf *d = dst[row];
	    
	    // Increment our "number of missing packets" counter
	    
	    missing++;
	    
	    // Clear the reconstruction buffer
	    
	    bzero(d, maxSz*sizeof(unsigned char));
	    recSz[row] = 0;
	    
	    // Loop over the available packets to reconstruct
	    // the missing packet
	    
	    for (col=0; col<n; col++) 
	      {
		gf  x  = b[row][col];
		gf *s  = src[col];
		int sz = szArray[col] >> 1;

		for (item=0; item < sz; item++)
		  {
		    d[item] ^= gf_mul(x, *s++);
		  }

		if (szArray[col] & 0x1)
		  {
		    unsigned short tmp;

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
		    tmp = (unsigned short)(*(unsigned char *)s);
#else // (__BYTE_ORDER == __BIG_ENDIAN)
		    tmp = (unsigned short)((*(unsigned char *)s) << 8);
#endif
		    
		    d[item] ^= gf_mul(x,tmp); 
		  }
		
		recSz[row] ^= gf_mul(x, fecSz[col]);
	      }
	  }
      }
  }
  
  return 0;
}
