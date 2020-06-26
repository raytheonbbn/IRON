/* IRON: iron_headers */
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

#ifndef IPPacket_h
#define IPPacket_h

#include <iostream>
#include <string.h>
#include <pthread.h>

typedef unsigned char byte;
typedef unsigned char* byte_ptr;

#define MAXTOTSIZE 66000
#define MAXPKTSIZE 65535
#define MAXHDRSIZE (MAXTOTSIZE - MAXPKTSIZE)

#define QREF_NETWORK   0
#define QREF_TRANSPORT 1
#define QREF_PAYLOAD   2
#define QREF_END       3

/**
 *
 * \class IPPacketPool 
 *
 * This class maintains a pool of IPPacket-sized buffers so that we do not
 * need to continuously allocate and deallocate memory.
 *
 * @author rgray
 */

class IPPacket;

class IPPacketPool
{
public:

  /**
   * Deafault constructor
   */
  IPPacketPool (void):
    _pool ((IPPacket *) NULL)
  {
    //
    pthread_mutex_init(&_poolMutex, NULL);
  }
  
  /**
   * Destructor
   */
  
  ~IPPacketPool () 
  {
    Purge();
    
    pthread_mutex_destroy(&_poolMutex);
  }
      
  /**
   * delete all of the IPPacket buffers
   */
  void Purge (void);
      
  /**
   * get a buffer for a new IPPacket object
   *
   * @return a pointer to the buffer
   */
  void *NewIPPacket (void);
  
  /**
   * return a IPPacket buffer to the pool
   *
   * @param buffer a pointer to a buffer previously returned by
   *               the NewIPPacket method
   */
  void Recycle (void *buffer);
  
private:

  /// list of IPPacket buffers
  IPPacket *_pool;

  /// MUTEXes for accessing the various shared objects
  static pthread_mutex_t _poolMutex;
};

/**
 *
 * \class IPPacket
 *
 * This class provides a container for buffering packets in a fifo
 * 
 * @author Multiple
 */
class IPPacket 
{
  friend class IPPacketPool;

public:
  /**
   * Default constructor.  
   */
  inline IPPacket() 
  {
    _pktlen   =  0;
  }
  
  /**
   * Constructor that builds 
   */
  IPPacket(unsigned long  saddr,
            unsigned long  daddr,
            unsigned short sport,
            unsigned short dport,
            unsigned long  protocol);
    
  /**
   * Default destructor.  This is not virtual due to our IPPacketPool class.
   */
  
  ~IPPacket () { /* do nothing */ }
  
  
  /**
   *  IPPacket allocator
   *
   * @param size the size of the IPPacket object
   *
   * @return     a pointer to a memory buffer large enough to hold an
   *             IPPacket object
   */
  void *operator new (size_t size) 
  {
    if (_packetPool == (IPPacketPool *) NULL) 
      {
	_packetPool = new IPPacketPool();
      }
    
    return _packetPool->NewIPPacket();
  }
  
  /**
   *  IPPacket deallocator
   *
   * @param mem  a pointer to the memory buffer allocated for an 
   *             IPPacket object
   */
  void operator delete (void *mem) 
  {
    if (mem != (void *) NULL) 
      {
	_packetPool->Recycle (mem);
      }
  }
  
  /**
   *  IPPacket equals overloaded function definition
   *
   * @param i    Pointer to the IPPacket object used for comparison with this object
   *
   * @return     true if this object and the supplied object have the same content
   *             false otherwise
   */
  inline bool operator==(const IPPacket& i) 
  { 
    return ((_pktlen == i._pktlen) && 
	    (memcmp(&_pktdata[0],&i._pktdata[0],_pktlen) == 0));
  }

  /// Accessor returning the maximum size of the IPPacket internal buffer (upper bounds totlen value).
  inline int getMaxSize() const { return MAXTOTSIZE; }

  /// Accessor returning the maximum size of a packet that may be stored in the internal buffer
  inline int getMaxPktSize() const { return MAXPKTSIZE; }

  /**
   *  Methodr to pull the usual five tuple from an IP header
   *  NOTE: Unlike the rest of these functions, this function
   *  returns info in HOST BYTE ORDER
   *
   * @param saddr Returned source address
   * @param daddr Returned destination address
   * @param sport Returned source port
   * @param dport Returned destination port
   * @param proto Returned protocol type (generally TCP or UDP)
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool getFiveTuple 
	(unsigned long  &saddr,
	 unsigned long  &daddr,
	 unsigned short &sport,
	 unsigned short &dport,
	 unsigned int   &proto) const;

  /**
   * Accessor to pull the source address out of an IP header
   *
   * @param saddr Returned source address
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool getSrcAddr (unsigned long &saddr) const; 

  /**
   * Accessor to pull the destination address out of an IP header
   *
   * @param daddr Returned destination address
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool getDstAddr (unsigned long &daddr) const; 

  /**
   * Accessor to pull the protocol out of an IP header
   *
   * @param protocol Returned protocol
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool getProtocol (unsigned long &protocol) const; 

  /**
   * Accessor to pull the source port out of a TCP or UDP packet
   *
   * @param sport Returned source port
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool getSrcPort (unsigned short &sport) const;

  /**
   * Accessor to pull the destination port out of a TCP or UDP packet
   *
   * @param sport Returned destination port
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool getDstPort (unsigned short &dport) const;

  /**
   * Accessor to pull the DSCP value out of an IP header
   *
   * @param dscp Returned DSCP value
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool getDSCP (unsigned char &dscp) const;
  
  /**
   * Accessor to set the protocol type for a given packet
   *
   * @param protocol Protocol number
   *
   * @return true if the retrieval was successful, false otherwise
   */
  bool setProtocol (unsigned long protocol) const; 

  /**
   * Accessor to set the source port in a TCP or UDP packet
   *
   * @param sport source port
   *
   * @return true if the operation was successful, false otherwise
   */
  bool setSrcPort (unsigned short sport) const;


  /**
   * Accessor to set the destination port in a TCP or UDP packet
   *
   * @param dport destination port
   *
   * @return true if the operation was successful, false otherwise
   */
  bool setDstPort (unsigned short dport) const;


  /**
   * Accessor to set the DSCP value in an IP header
   *
   * @param dscp DSCP value
   *
   * @return true if the operation was successful, false otherwise
   */
  bool setDSCP (unsigned char dscp) const;


  /**
   * Support routine to update network and transport layer checksums
   *
   * @return true if the operation was successful, false otherwise
   */
  bool updateChecksums () const;

  /**
   * Support routine to update network layer checksum
   *
   * @return true if the operation was successful, false otherwise
   */
  bool updateIPChecksum () const;

  /**
   * Support routine to update transport layer checksum
   *
   * @return true if the operation was successful, false otherwise
   */
  bool updateTransportChecksum () const;

  /**
   * Support routine to get retrieve various packet lengths
   *
   *
   * @return true if the operation was successful, false otherwise
   */
  bool getVariousLens (unsigned short &ipLen,
                       unsigned short &ipHdrLen,
                       unsigned short &xportLen) const;

  /**
   * Support routine to update length fields in IP and transport headers
   *
   * @return true if the operation was successful, false otherwise
   */
  bool updateIPLen () const;

  /**
   * Support routine to update the length field in the IP header
   *
   * @return true if the operation was successful, false otherwise
   */
  bool updateIPLen (const int len);

  /**
   * Support routine to trim a packet by "len" bytes
   * @param len number of bytes to remove from the end of a packet
   *
   * @return true if the operation was successful, false otherwise
   */
  bool trimIPLen (const int len);

  /**
   * Support routine to insert a block of data into a IPPacket
   *
   * @param data   buffer containing data to insert into the packet
   * @param len    length of data block
   * @param offset position within the packet to insert the block
   *
   * @return true if the operation was successful, false otherwise
   */
  bool insertBlockInPayload
  	(void         *data,
	 unsigned int  len,
	 unsigned int  offset);

  /**
   * Support routine to remove a block of data from a IPPacket
   *
   * @param data   buffer to hold the data to remove from the packet
   * @param len    length of data block to removentohs
   * @param offset position within the packet to remove the block from
   *
   * @return true if the operation was successful, false otherwise
   */
  bool deleteBlockFromPayload
	(void         *data,
	 unsigned int  len,
	 unsigned int  offset);

  /**
   * Support routine to append a block of data onto the end of an IPPacket
   *
   * @param data   buffer holding the data to append to the end of the packet
   * @param len    length of data block to append
   *
   * @return true if the operation was successful, false otherwise
   */
  bool appendBlockToEnd
  	(void         *data,
	 unsigned int  len);

  /**
   * Support routine to copy a block of data from the end of an IPPacket
   *
   * @param data   buffer to hold the to be copied from the end of the packet
   * @param len    length of data block to be copied
   *
   * @return true if the operation was successful, false otherwise
   */
  bool copyBlockFromEnd
	(void         *data,
	 unsigned int  len);

  /**
   * Support routine to copy and remove a block of data from the end of an IPPacket
   *
   * @param data   buffer to hold the to be copied from the end of the packet
   * @param len    length of data block to be copied
   *
   * @return true if the operation was successful, false otherwise
   */
  bool removeBlockFromEnd
	(void         *data,
	 unsigned int  len);

  // Test the Don't Fragment Flag
  bool isDFSet();

  // Test the More Fragments Flag
  bool isMFSet();

  // Set/Unset the Don't fragment Flag
  bool setDF(bool val);
  
  // Set/Unset the More Fragments Flag
  bool setMF(bool val);

  // Get the length of the packet from the header
  bool getIHLen(unsigned int &len) const;


  // Set the fragmentation offset in the header
  bool setFragmentOffset(int offset);

  // Set the fragmentation offset in the header
  bool getFragmentOffset(int &offset) const;

  
  /// Support routines to clone a packet, just the header, etc
  IPPacket *clone();

  /// Support routines to clone a packet header
  IPPacket *cloneHeaderOnly();

  /// Support routines to clone only the IP header
  IPPacket *cloneIPHeaderOnly();

  /// Accessor for getting the position of the payload within the packet
  unsigned long getPayloadOffset () const;

  /// Accessor for getting the length of the payload within the packet
  unsigned long getPayloadLen () const;

  /// Base buffer accessor methods
  /// Get a pointer to the start of the memory block.  
  /// Must be used with care.
  inline byte* ptr() { return &_pktdata[0]; }
  inline const byte* ptr() const { return &_pktdata[0]; }

  /// Convenience method to cast the buffer into a pointer of type byte_ptr
  inline operator byte_ptr() { return &_pktdata[0]; }

  /// Packet accessor section
  /// Get a pointer to the start of the packet data.  
  /// Must be used with care.
  inline byte* getPktData() { return &_pktdata[0]; }
  inline const byte* getPktData() const { return &_pktdata[0]; }

  /// Accessor to get the length of a packet
  inline int  getPktLen() const { return _pktlen; }

  /// Method to set the length of a packet
  inline bool setPktLen(int c)  
  { if (_pktlen <= MAXTOTSIZE)
    { _pktlen=c; return true; } return false; }

  /**
   * Prints the buffer pointer (along with total length and max size
   * information).
   */
  friend std::ostream& operator<<(std::ostream&, const IPPacket& qpkt);

protected:
  /// Length of the packet within the buffer
  int _pktlen;

  /// Buffer holding the packet
  byte _pktdata[MAXTOTSIZE];

  /// Pointer to the next packet in the linked list (used by the packet pool)
  IPPacket *_next;

  /// Pointer to the shared packet pool management object
  static IPPacketPool *_packetPool;
};

#endif /* IPPacket_h */
