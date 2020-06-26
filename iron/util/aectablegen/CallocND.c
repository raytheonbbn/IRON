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
 *=* PROGRAM: CallocND.c
 *=*
 *=* PURPOSE: Multi-dimensional array memory allocation functions.
 *=*	      General allocation routines - allocating multiple 
 *=*	      dimensional arrays with a single allocation call so 
 *=*	      that memory is contiguous (can be accessed as single
 *=*          or multipledimensional arrays) and can be deallocated
 *=*          with a single call
 *=*
 *=* AUTHOR : Steve Zabele
 *=*
 *=* FUNCTIONS INCLUDE:     
 *=*                        Calloc1D
 *=*                        Calloc2D
 *=*                        Calloc3D
 *=*                        Calloc4D
 *=*                        Malloc1D
 *=*                        Malloc2D
 *=*                        Malloc3D
 *=*                        Malloc4D
 *=*                        FreeND
 *=*
 *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
 *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
 */

#include <stdlib.h>
#include <malloc.h>
#include <memory.h>

#include "CallocND.h"

/*
 *************************************************************************
 *
 * NAME:
 *    Calloc1D
 *
 * DESCRIPTION:
 *    Allocate and clear dynamic memory for a one dimensional 
 *    array[nelems].
 *
 * ARGUMENTS:
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char *Calloc1D (size_t nelems, 
		size_t elemsize)
{
  size_t  dsize;
  char   *ptr;

  if (!(ptr = Malloc1D (nelems, elemsize)))
    return(NULL);

  dsize = nelems * elemsize;

  memset(&ptr[0],0,dsize);

  return(ptr);
}

/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    Calloc2D
 *
 * DESCRIPTION:
 *    Allocate and clear dynamic memory for a two dimensional 
 *    array[melems][nelems].
 *
 * ARGUMENTS:
 *    melems  - number of column elements
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char **Calloc2D (size_t melems, 
		 size_t nelems, 
		 size_t elemsize)
{
  size_t   dsize;
  char   **pptr;

  if (!(pptr = Malloc2D (melems, nelems, elemsize)))
    return (pptr);

  dsize = melems * nelems * elemsize;

  memset(&pptr[0][0],0,dsize);

  return(pptr);
}

/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    Calloc3D
 *
 * DESCRIPTION:
 *    Allocate and clear dynamic memory for a three dimensional 
 *    array[lelems][melems][nelems].
 *
 * ARGUMENTS:
 *    lelems  - number of plane elements 
 *    melems  - number of column elements
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char ***Calloc3D (size_t lelems, 
		  size_t melems, 
		  size_t nelems, 
		  size_t elemsize)
{
  size_t    dsize;
  char   ***ppptr;
  
  if (!(ppptr = Malloc3D(lelems, melems, nelems, elemsize)))
    return (ppptr);

  dsize = lelems * melems * nelems * elemsize;

  memset(&ppptr[0][0][0],0,dsize);

  return(ppptr);
}

/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    Calloc4D
 *
 * DESCRIPTION:
 *    Allocate and clear dynamic memory for a four dimensional 
 *    array[kelems][lelems][melems][nelems].
 *
 * ARGUMENTS:
 *    kelems  - number of hyperplane elements 
 *    lelems  - number of plane elements 
 *    melems  - number of column elements
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char ****Calloc4D (size_t kelems, 
		   size_t lelems, 
		   size_t melems, 
		   size_t nelems, 
		   size_t elemsize)
{
  char ****pppptr;
  size_t   dsize;
  
  if (!(pppptr = Malloc4D(kelems, lelems, melems, nelems, elemsize)))
    return (pppptr);

  dsize = kelems * lelems * melems * nelems * elemsize;
  
  memset(&pppptr[0][0][0][0],0,dsize);

  return (pppptr);
}

/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    Malloc1D
 *
 * DESCRIPTION:
 *    Allocate dynamic memory for a one dimensional 
 *    array[nelems].
 *
 * ARGUMENTS:
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char *Malloc1D (size_t nelems, 
		size_t elemsize)
{
  char *ptr;

  if (!(ptr = (char *)malloc((unsigned)nelems*(unsigned)elemsize)))
    return (NULL);

  return(ptr);
}

/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    Malloc2D
 *
 * DESCRIPTION:
 *    Allocate dynamic memory for a two dimensional 
 *    array[melems][nelems].
 *
 * ARGUMENTS:
 *    melems  - number of column elements
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char **Malloc2D (size_t melems, 
		 size_t nelems, 
		 size_t elemsize)
{
  char   **pptr, *dptr;
  size_t   i, ppsize, dsize, dstart, dinc;

  ppsize = melems * sizeof(char *);
  dsize  = melems * nelems * elemsize;

  /* Make sure data is aligned on the proper boundaries */

  dstart = ((ppsize + elemsize - 1) / elemsize) * elemsize;

  if (!(pptr = (char **)malloc((unsigned)(dstart+dsize)*sizeof(char))))
    return (NULL);
  
  dptr = (char *)pptr + dstart;   /* Beginning of the data areas   */
  dinc = nelems * elemsize;       /* Increments between data areas */

  for (i=0; i!=melems; i++,dptr+=dinc)
  {
    pptr[i] = dptr;
  }

  return(pptr);
}

/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    Malloc3D
 *
 * DESCRIPTION:
 *    Allocate dynamic memory for a three dimensional 
 *    array[lelems][melems][nelems].
 *
 * ARGUMENTS:
 *    lelems  - number of plane elements 
 *    melems  - number of column elements
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char ***Malloc3D (size_t lelems, 
		  size_t melems, 
		  size_t nelems, 
		  size_t elemsize)
{
  char   ***ppptr, *pptr, *dptr;
  size_t    i, j, pppsize, ppsize, dsize, ppinc, dstart, dinc;
  
  pppsize = lelems * sizeof(char **);
  ppsize  = lelems * melems * sizeof(char *);
  dsize   = lelems * melems * nelems * elemsize;

  /* Make sure data is aligned on the proper boundaries */

  dstart = ((pppsize + ppsize + elemsize - 1) / elemsize) * elemsize;

  if (!(ppptr = (char ***)malloc((unsigned)(dstart+dsize)*sizeof(char))))
    return(NULL);
  
  pptr  = (char *)ppptr + pppsize;   /* Beginning of the ** areas   */
  ppinc = melems * sizeof(char **);  /* Increments between ** areas */

  dptr = (char *)ppptr + dstart;    /* Beginning of the data areas   */
  dinc = nelems * elemsize;         /* Increments between data areas */

  for (i=0; i!=lelems; i++,pptr+=ppinc)
  {
    ppptr[i] = (char **)pptr;
    for (j=0; j!=melems; j++,dptr+=dinc)
    {
      ppptr[i][j] = dptr;
    }
  }

  return(ppptr);
}


/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    Malloc4D
 *
 * DESCRIPTION:
 *    Allocate dynamic memory for a four dimensional 
 *    array[kelems][lelems][melems][nelems].
 *
 * ARGUMENTS:
 *    kelems  - number of hyperplane elements 
 *    lelems  - number of plane elements 
 *    melems  - number of column elements
 *    nelems  - number of row elements
 *    elmsize - size of each array element in bytes
 *
 * RETURN ( none ):
 *    STACK   - address of the allocated memory array
 *
 *************************************************************************
 */

char ****Malloc4D (size_t kelems, 
		   size_t lelems, 
		   size_t melems, 
		   size_t nelems,
		   size_t elemsize)
{
  char   ****pppptr, *ppptr, *pptr, *dptr;
  size_t i, j, k, ppppsize, pppsize, ppsize, dsize, pppinc, ppinc, dstart, dinc;
  
  ppppsize = kelems * sizeof(char ***);
  pppsize  = kelems * lelems * sizeof(char **);
  ppsize   = kelems * lelems * melems * sizeof(char *);
  dsize    = kelems * lelems * melems * nelems * elemsize;

  /* Make sure data is aligned on the proper boundaries */

  dstart = ((ppppsize + pppsize + ppsize + elemsize - 1) / elemsize)
                                                         * elemsize;

  if (!(pppptr = (char ****)malloc((unsigned)(dstart+dsize)*sizeof(char))))
    return(NULL);
  
  ppptr  = (char *)pppptr + ppppsize; /* Beginning of the *** areas   */
  pppinc = lelems * sizeof(char ***); /* Increments between *** areas */

  pptr   = (char *)ppptr  + pppsize;  /* Beginning of the ** areas   */
  ppinc  = melems * sizeof(char **);  /* Increments between ** areas */

  dptr   = (char *)pppptr   + dstart; /* Beginning of the data areas   */
  dinc   = nelems * elemsize;         /* Increments between data areas */

  for (i=0; i!=kelems; i++,ppptr+=pppinc)
  {
    pppptr[i] = (char ***)ppptr;
    for (j=0; j!=lelems; j++,pptr+=ppinc)
    {
      pppptr[i][j] = (char **)pptr;
      for (k=0; k!=melems; k++,dptr+=dinc)
      {
	pppptr[i][j][k] = dptr;
      }
    }
  }

  return(pppptr);
}

/*************************************************************************
 ****************************** FUNCTION *********************************
 *************************************************************************
 *
 * NAME:
 *    FreeND
 *
 * DESCRIPTION:
 *    Frees memory allocated by any of the CallocND functions
 *
 * ARGUMENTS:
 *    void *memptr = pointer to memory allocated by CallocND functions
 *
 * RETURN ( Void ):
 *    Nothing
 *
 *************************************************************************
 */

void FreeND (void * memptr)
{
  free (memptr);
}

