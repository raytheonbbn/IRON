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

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
 *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
 *=*
 *=* FILE   : CallocND.h
 *=*
 *=* PURPOSE: Header file defining constants and function prototypes
 *=*          for multi-dimensional array allocators
 *=*
 *=* AUTHOR : Steve Zabele
 *=*
 *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
 *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
 */

#ifndef __CALLOCND_H_
#define __CALLOCND_H_

#ifdef __cplusplus
extern "C" {
#endif 

char    *Calloc1D 
		(size_t nelems, 
		 size_t elemsize);

char   **Calloc2D 
		(size_t melems, 
		 size_t nelems, 
		 size_t elemsize);

char  ***Calloc3D 
		(size_t lelems, 
		 size_t melems, 
		 size_t nelems, 
		 size_t elemsize);

char ****Calloc4D 
		(size_t kelems, 
		 size_t lelems, 
		 size_t melems, 
		 size_t nelems, 
		 size_t elemsize);

char    *Malloc1D 
		(size_t nelems, 
		 size_t elemsize);

char   **Malloc2D 
		(size_t melems, 
		 size_t nelems, 
		 size_t elemsize);

char  ***Malloc3D 
		(size_t lelems, 
		 size_t melems, 
		 size_t nelems, 
		 size_t elemsize);

char ****Malloc4D 
		(size_t kelems, 
		 size_t lelems, 
		 size_t melems, 
		 size_t nelems, 
		 size_t elemsize);

void FreeND 
		(void * memptr);

#ifdef __cplusplus
}
#endif 

#endif /* __CALLOCND_H_ */
