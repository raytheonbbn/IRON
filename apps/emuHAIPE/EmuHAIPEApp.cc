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
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <linux/types.h>
#include <linux/filter.h>

#include "EmuHAIPEApp.hh"
#include "IPPacket.hh"
#include "esp.h"
#include "ZLog.h"

static const char  cn[] = "EmuHAIPEApp";

// bogus eincryption block
char trailerBlock[1500];
char trailerBitBucket[1500];

//============================================================================
EmuHAIPEApp::EmuHAIPEApp()
  : qThread(this), decapThread(this), encapThread(this), halt(true)
{
};

//============================================================================
EmuHAIPEApp::~EmuHAIPEApp()
{
  // Quit looking for packets
  disableCapture();
 
  // Shutdown the threads
  decapThread.stop();
  encapThread.stop();
  qThread.stop();

  // Undo the plumbing
  if ( !unplumb() ) 
  {
    zlogW(cn,"~EmuHAIPE",("Failed to unplumb...!\n"));
  }
  
  // Close the various sockets
  virtualIF.close();
  rawIF.close();

}

//============================================================================
bool EmuHAIPEApp::initSockets()
{
  // open the virtual IF

  if (virtualIF.open (&_VIFDevName[0]) == false)
    {
      return false;
    }

  // open the raw IF

  if (rawIF.open () == false)
    {
      return false;
    }

  return true;
}

//============================================================================
bool EmuHAIPEApp::plumb()
{
  char cmdline[512];

  // Bring up the VIF

  snprintf(&cmdline[0],sizeof(cmdline)-1,
	   "%s %s %s netmask %s broadcast %s up",
	   _IFCmd,_VIFDevName,_VIFAddress,_VIFNetmask,_VIFBroadcast);

  if (system(cmdline) != 0)
    {
      zlogE(cn, "plumb", 
	    ("failed system command:\n    '%s'\n",cmdline));
      return (false);
    }

  // Turn off reverse path filtering on the VIF

  snprintf(&cmdline[0],sizeof(cmdline)-1,
	   "echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter",_VIFDevName);

  if (system(cmdline) != 0)
    {
      zlogE(cn, "plumb", 
	    ("failed system command:\n    '%s'\n",cmdline));
      return (false);
    }

  if (_externalPlumbing == 0)
    {
      // Add a route to the VIF in the specified alternate routing table
      
      snprintf(&cmdline[0],sizeof(cmdline)-1,
	       "%s route add default dev %s table %d",
	       _IPCmd,_VIFDevName,_VIFAltTable);
      
      if (system(cmdline) != 0)
	{
	  zlogE(cn, "plumb", 
		("failed system command:\n    '%s'\n",cmdline));
	  return (false);
	}
      
      // Add a rule to make packets with the assigned firewall mark use the specified
      // alternate routing table
      
      snprintf(&cmdline[0],sizeof(cmdline)-1,
	       "%s rule add fwmark %d table %d",
	       _IPCmd,_FirewallMark,_VIFAltTable);
      
      if (system(cmdline) != 0)
	{
	  zlogE(cn, "plumb", 
		("failed system command:\n    '%s'\n",cmdline));
	  return (false);
	}
    }
  
  return true;
}

//============================================================================
bool EmuHAIPEApp::unplumb()
{
  char cmdline[512];
  
  if (_externalPlumbing == 0)
    {
      // Remove the rule to make packets with the assigned firewall 
      // mark use the specified alternate routing table
      
      snprintf(&cmdline[0],sizeof(cmdline)-1,
	       "%s rule del fwmark %d table %d",
	       _IPCmd,_FirewallMark,_VIFAltTable);
      
      if (system(cmdline) != 0)
	{
	  zlogE(cn, "unplumb", 
		("failed system command:\n    '%s'\n",cmdline));
	  return (false);
	}
    }


 // Bring down the VIF

  snprintf(&cmdline[0],sizeof(cmdline)-1,
	   "%s %s down",
	   _IFCmd,_VIFDevName);

  if (system(cmdline) != 0)
    {
      zlogE(cn, "unplumb", 
	    ("failed system command:\n    '%s'\n",cmdline));
      return (false);
    }
  return true;
}

//============================================================================
bool EmuHAIPEApp::configure(PropertyTable& pt, const char* prefix)
{
  // Set up the name of the IF facing the Subnet

  strncpy(&_RedDevName[0],pt.get("RedSide_PhyDevName", USEALLIFS),
	  sizeof(_RedDevName) - 1);
  
  // Set up the name of the IF facing the Internet
  strncpy(&_BlackDevName[0],pt.get("BlackSide_PhyDevName",USEALLIFS),
	  sizeof(_BlackDevName)-1);

  // Set up the name of the virtual IF
  strncpy(&_VIFDevName[0],pt.get("VIFDevName","haipe0"),
	  sizeof(_VIFDevName)-1);


  // Set up the address assigned to the virtual IF
  strncpy(&_VIFAddress[0],pt.get("VIFAddress","10.129.129.129"),
	  sizeof(_VIFAddress)-1);


  // Set up the netmask assigned to the virtual IF
  strncpy(&_VIFNetmask[0],pt.get("VIFNetmask","255.255.255.252"),
	  sizeof(_VIFNetmask)-1);


  // Set up the broadcast address assigned to the virtual IF
  strncpy(&_VIFBroadcast[0],pt.get("VIFBroadcast","10.129.129.131"),
	  sizeof(_VIFBroadcast)-1);


  // Set up the name of the iptables command

  strncpy(&_IPTablesCmd[0],pt.get("IPTablesCmd","/sbin/iptables"),
	  sizeof(_IPTablesCmd)-1);
  
  // Set up the name of the ip command
  strncpy(&_IPCmd[0],pt.get("IPCmd","/sbin/ip"),
	  sizeof(_IPCmd)-1);
  
  // Set up the name of the ifconfig command
  strncpy(&_IFCmd[0],pt.get("IFCmd","/sbin/ifconfig"),
	  sizeof(_IFCmd)-1);
  
  // Set up the target firewall mark
  _FirewallMark = pt.getInt("FirewallMark",4);

  // Set up the target alternate routing table
  _VIFAltTable = pt.getInt("VIFAltTable",4);

  // Set up the overhead for haipe emulation
  if ((_overhead = pt.getInt("HAIPE_Overhead",60)) < 30)
  {
    zlogE(cn, "configure", 
	("HAIPE overhead must be at least 30 bytes"));
    return false;
  }

  // Set up the external plumbing flag
  _externalPlumbing = pt.getInt("ExternalPlumbing",0);

  // Now we can enable the capture of packets from other FEC gateways
  if (enableCapture() == false) 
    {
      return false;
    }

  return true;
}


//=============================================================================
bool EmuHAIPEApp::enableCapture()
{
  char cmdline[512];
  char useRedIF[128];
  char useBlackIF[128];

  if (_externalPlumbing == 0)
    {
      if (strcmp(_RedDevName, USEALLIFS))
	{
	  snprintf(&useRedIF[0], sizeof(useRedIF) - 1, "-i %s ", _RedDevName);
	}
      else
	{
	  useRedIF[0] = 0;
	}
      
      if (strcmp(_BlackDevName, USEALLIFS))
	{
	  snprintf(&useBlackIF[0], sizeof(useBlackIF) - 1,"-i %s ", _BlackDevName);
	}
      else
	{
	  useBlackIF[0] = 0;
	}

      //
      //  Add in the iptables rules for catching ESP packets (Black side, facing
      //  WAN)
      //
      
      snprintf(&cmdline[0], sizeof(cmdline) - 1,
	       "%s -I PREROUTING -t mangle %s -p 50 -j MARK --set-mark %d",
	       _IPTablesCmd, useBlackIF, _FirewallMark);
      
      if (system(cmdline) != 0)
	{
	  zlogW(cn, "enableCapture",
		("failed system command:\n    '%s'\n",cmdline));
	  return false;
	}
      
      //
      //  Add in the iptables rules (Red side, facing apps)
      //
      
      snprintf(&cmdline[0], sizeof(cmdline) - 1,
	       "%s -I PREROUTING -t mangle %s -j MARK --set-mark %d",
	       _IPTablesCmd, useRedIF, _FirewallMark);
      
      if (system(cmdline) != 0) 
	{
	  zlogE(cn, "enableCapture", 
		("failed system command:\n    '%s'\n",cmdline));
	  return false;
	}  
    }
  else
    {
      zlogI(cn, "enableCapture",
	    ("Using external plumbing\n"));
    }

  return true;
}

//=============================================================================
bool EmuHAIPEApp::disableCapture()
{
  char cmdline[512];
  char useRedIF[128];
  char useBlackIF[128];

  if (_externalPlumbing == 0)
    {
      if (strcmp(_RedDevName, USEALLIFS))
	{
	  snprintf(&useRedIF[0], sizeof(useRedIF) - 1, "-i %s ", _RedDevName);
	}
      else
	{
	  useRedIF[0] = 0;
	}
      
      if (strcmp(_BlackDevName, USEALLIFS))
	{
	  snprintf(&useBlackIF[0], sizeof(useBlackIF) - 1,"-i %s ", _BlackDevName);
	}
      else
	{
	  useBlackIF[0] = 0;
	}
      
      //
      // Delete the iptables rules
      //
      
      snprintf(&cmdline[0],sizeof(cmdline)-1,
	       "%s -D PREROUTING -t mangle %s -p 50  -j MARK --set-mark %d",
	       _IPTablesCmd, useBlackIF, _FirewallMark);
      
      if (system(cmdline) != 0) 
	{
	  zlogW(cn, "disableCapture", 
		("failed system command:\n    '%s'\n",cmdline));
	  return false;
	}
      
      snprintf(&cmdline[0],sizeof(cmdline)-1,
	       "%s -D PREROUTING -t mangle %s -j MARK --set-mark %d",
	       _IPTablesCmd, useRedIF, _FirewallMark);
  
      if (system(cmdline) != 0) 
	{
	  zlogE(cn, "disableCapture", 
		("failed system command:\n    '%s'\n",cmdline));
	  return false;
	}
    }

  return true;
}


//============================================================================
void EmuHAIPEApp::start()
{
  halt = false;

  decapThread.start();
  encapThread.start();
  qThread.start();
}

//============================================================================
void EmuHAIPEApp::stop()
{
  halt = true; 
}

//============================================================================
void EmuHAIPEApp::runQ()
{
  struct timeval tv;
  fd_set         fdset;
  int            maxfd;
  int            hfd;
  int            rfd;
  int            nfds;

  zlogI(cn, "runQ", 
	("Starting packet queuing thread\n"));

  hfd = virtualIF.viffd();
  rfd = rawIF.rawfd();

  maxfd = hfd;
  if (rfd > maxfd)
    {
      maxfd = rfd;
    }

  while(true) // Run until the thread is killed
    {
      tv.tv_sec  = 1;
      tv.tv_usec = 0;
      
      FD_ZERO(&fdset);
      FD_SET (hfd, &fdset);
      FD_SET (rfd, &fdset);

      nfds = select(maxfd+1, &fdset, NULL, NULL, &tv);

      //
      // Test to see if the thread has been cancelled.
      //

      pthread_testcancel();
     
      if (nfds > 0)
	{
	  if (FD_ISSET(hfd, &fdset))
	    {
	      IPPacket *qPkt = new IPPacket();

	      virtualIF.recv(*qPkt);
	      
	      if (qPkt->getPktLen() <= 0)
		{
		  zlogW(cn, "runQ", 
			("VirtualIF read Failed\n"));
		  delete qPkt;
		}
	      else
		{
		  unsigned long protocol;
		  qPkt->getProtocol(protocol);

		  if (protocol == IPPROTO_ESP)
		    {
		      if (!decapQueue.enqueue(qPkt))
			{
			  // If the enqueue fails it's because we are getting behind.
			  // This really doesn't cause a problem from a correctness
			  // perspective, but we do need to delete the qPkt to 
			  // prevent memory leaks -- otherwise the gateway will 
			  // eventually fail due to the host running out of memory

			  zlogW(cn, "runQ", 
				("Decap enqueue failed:\n"));
			  
			  delete qPkt;
			}
		    }
		  else
		    {
		      if (!encapQueue.enqueue(qPkt))
			{
			  // See comment above on why we delete the packet on an
			  // enqueuing failure

			  delete qPkt;
			}
		    }
		}
	    }

	  if (FD_ISSET(rfd, &fdset))
	    {
	      IPPacket *qPkt = new IPPacket();

	      rawIF.recv(*qPkt);

	      if (qPkt->getPktLen() <= 0)
		{
		  zlogW(cn, "runQ", 
			("RawIF read Failed\n"));
		  delete qPkt;
		}
	      else
		{
                  zlogD(cn, "runQ", 
			("RawIF read succeeded\n"));

		  if (!decapQueue.enqueue(qPkt))
		    {
		      // See comment above on why we delete the packet on an
		      // enqueuing failure
		      
		      zlogW(cn, "runQ", 
			    ("Decap enqueue failed:\n"));
		      delete qPkt;		    
		    }
		}
	    }
	}
    }
  
  // We can not really get here

  zlogI(cn, "runQ", 
	("Stopping packet enqueuing thread\n"));
}

//============================================================================
void EmuHAIPEApp::runDecap()
{
  IPPacket* qpkt   = (IPPacket *)NULL;
  IPPacket* outPkt = (IPPacket *)NULL;
  int orgPktLen;
 
  zlogI(cn, "runDecap", 
	("Starting decap thread\n"));

  while(true) // Run until the thread is killed
    {
      /// Test to see if the thread has been cancelled.
      pthread_testcancel();
      
      /// Wait until a buffer is queued for decapsulation

      if ((qpkt = (IPPacket *)decapQueue.delayedDequeue()) == NULL) 
	{
	  /// This will happen when we call the queue object's signalTermination method
	  /// zlogW(cn, "runDecap",("Extracted null pointer -- ignoring\n"));
	  continue;
	}

      /// Tell the user what we have
      dumpPacket((char *)"runDecap pre-processed",qpkt);
    
      /// Remove what we added on the far side
      removeTrailer(qpkt);

      /// What was the original packet size
      orgPktLen = qpkt->getPktLen()-(sizeof(iphdr)+sizeof(esphdr));

      /// create an output packet
      outPkt    = new IPPacket();

      /// Fill in the output packet with payload of the decap packet
      if ( !qpkt->copyBlockFromEnd(outPkt->getPktData(),orgPktLen)) {
        zlogW(cn,"runDecap",
              ("failed to copy data from transport packet\n"));
        delete qpkt;
        delete outPkt;
        return;
      }

      /// Set the packet length in the IP header
      outPkt->setPktLen(orgPktLen);

      /// Tell the user what we have now 
      dumpPacket((char *)"runDecap post-processed",outPkt);
      
      //      rawIF.send(outPkt);
      virtualIF.send(outPkt);
      delete qpkt;
      delete outPkt;
    }
  
  // We can never really get here
  zlogI(cn, "runDecap", 
	("Stopping Haipe decap thread\n"));
}

//============================================================================
void EmuHAIPEApp::runEncap()
{
  IPPacket* qpkt   = (IPPacket *)NULL;
  IPPacket* cpkt   = (IPPacket *)NULL;

  unsigned short pktsz;
  unsigned short encsz;

  zlogI(cn, "runEncap", 
	("Starting Haipe encap thread\n"));

  // Clean data to insert.
  memset((void*)&trailerBlock,0,1500);

  while(true) // Run until the thread is killed
    {
      // Test to see if the thread has been cancelled.
      pthread_testcancel();

      // Wait until a buffer is queued for encaping

      if ((qpkt = (IPPacket *)encapQueue.delayedDequeue()) == NULL)
	{
	  // This will happen when we call the queue object's signalTermination method
	  // zlogW(cn, "runEncap",("Extracted null pointer -- ignoring\n"));
	  continue;
	}      

      // Calculate the padded HAIPE packet size needed to perform 
      // the encryption. Packet sizes are always 32 + N * 48, up to 
      // a limit of 1424 bytes (including 56 or 60 bytes for encryption 
      // which implies the true limit is 1482 or 1484 depending on whether 
      // we emulate IPSEC or HAIPE IS headers) before fragmentation occurs.
      
      pktsz = qpkt->getPktLen();
      encsz = (((pktsz + 15) / 48) * 48) + 32;
      
      zlogI(cn, "runEncap",("Got packet of size %d\n",pktsz));

      // If packet is over the critical size, fragment it into two pieces

      if ( encsz > 1424 ) 
	{
	  // Fragmentation may fail if the "don't fragment" flag is set
	  // in which case we just drop the packet
	  
	  if ( !fragmentIt(qpkt,cpkt,1424) ) {
	    delete qpkt;
	    continue;
	  }

	  // Fragmentation appears to have completed successfully, so we send
	  // along the two fragments

	  else
	    {
	      // First packet fragment
	      if ( sendAsHaipePkt(qpkt) ) 
		{
		  zlogI(cn, "runEncap",("failed to send first fragment\n"));
		}
	      
	      // Second packet fragment
	      if ( sendAsHaipePkt(cpkt) ) 
		{
		  zlogI(cn, "runEncap",("failed to send second fragment\n"));
		}
	    }
	}
      
      // Fragmentation isn't necessary -- just send it along
  
    else
	{
	  // Standalone packet
	  if ( sendAsHaipePkt(qpkt) ) {
	    zlogI(cn, "runEncap",("failed to send packet\n"));
	  }
	}    
    }
  
  zlogI(cn, "runEncap", 
	("Stopping encap thread\n"));
}


//=============================================================================
bool  EmuHAIPEApp::sendAsHaipePkt(IPPacket *qpkt)
{
  IPPacket* outPkt = (IPPacket *)NULL;

  unsigned short pktsz;
  unsigned short encsz;
  unsigned short delta;
  
  unsigned long  saddr;
  unsigned long  daddr;
  unsigned char  dscp;

  static unsigned int seqno = 0;

  if (!qpkt->getSrcAddr(saddr))
  {
    zlogI(cn, "sendAsHaipePkt",("getSrcAddr retrieval failed \n"));
    delete qpkt;
    return false;
  }
  
  if (!qpkt->getDstAddr(daddr))
  {
    zlogI(cn, "sendAsHaipePkt",("getDstAddr retrieval failed \n"));
    delete qpkt;
    return false;
  }

  if (!qpkt->getDSCP(dscp))
  {
    zlogI(cn, "sendAsHaipePkt",("getDSCP retrieval failed \n"));
    delete qpkt;
    return false;
  }

  saddr = ntohl(saddr);
  daddr = ntohl(daddr);

  // Tell the user what we have to send
  dumpPacket((char *)"sendAsHaipePkt pre-processed ",qpkt);
  
  // Create a new packet for transporting fragment;
  outPkt = new IPPacket(saddr,daddr,0,0,IPPROTO_ESP);

  // Make sure to preserve the DSCP byte
  if (!outPkt->setDSCP(dscp))
  {
    zlogI(cn, "sendAsHaipePkt",("setDSCP insertion failed \n"));
    delete qpkt;
    delete outPkt;
    return false;
  }
          
  // Add the ESP header
  addHeader(outPkt,seqno++);

  // First packet fragment
  pktsz = qpkt->getPktLen();
  encsz = (((pktsz + 15) / 48) * 48) + 32;
  delta = (encsz - pktsz) + _overhead - outPkt->getPktLen();
  
  // Append all of our packet data to the end of our transport packet
  if ( ! outPkt->appendBlockToEnd( qpkt->getPktData() , qpkt->getPktLen()) ) {
    zlogW(cn,"sendAsHaipePkt",("failed to append data to \n"));
    delete qpkt;
    delete outPkt;
  }
  /// Add HAIPE "encryption" to the end of the IP packet
  addTrailer(outPkt,delta);

  /// Fix the IP checksum
  outPkt->updateIPChecksum();

  /// Tell the user what we are sending
  dumpPacket((char *)"sendAsHaipePkt post-processed",outPkt);
  
  rawIF.send(outPkt);
  delete qpkt;
  delete outPkt;

  return true;
}

//=============================================================================
void EmuHAIPEApp::removeHeader(IPPacket *qpkt)
{
  esphdr ehdr;

  // Strip off the size of the "header"      
  qpkt->removeBlockFromEnd(&ehdr,sizeof(ehdr));
}

//=============================================================================
void EmuHAIPEApp::addHeader(IPPacket *qpkt, unsigned int seqno)
{
  esphdr ehdr;

  ehdr.spi   = htonl(0x4146524c); // "AFRL"
  ehdr.seqno = htonl(seqno);
 
  // Append the "header" block
  qpkt->appendBlockToEnd(&ehdr,sizeof(ehdr));
}

//=============================================================================
void EmuHAIPEApp::removeTrailer(IPPacket *qpkt)
{
  unsigned short delta;
  // Strip off the size of the "trailer"      
  qpkt->removeBlockFromEnd(&delta,sizeof(delta));

  // Strip off the rest of the "trailer"
  qpkt->removeBlockFromEnd(&trailerBitBucket,ntohs(delta) - sizeof(delta));
}

//=============================================================================
void EmuHAIPEApp::addTrailer(IPPacket *qpkt, int delta)
{
  unsigned short overlen;
 
  overlen = ntohs((unsigned short)(delta));
        
  // Append the "trailer" block, minus the room for the original port
  // and the size of the size of the delta
  qpkt->appendBlockToEnd(&trailerBlock,delta-sizeof(overlen));
  
  // Append the total number of bytes added
  qpkt->appendBlockToEnd( &overlen,sizeof(overlen) );  
}

//=============================================================================
bool EmuHAIPEApp::fragmentIt(IPPacket *qpkt, IPPacket *(&cpkt), int mtu)
{
  int          numFragBlocks        = 0;
  int          numByteForSecondFrag = 0;
  int          fragmentOffset       = 0;
  unsigned int ihLen                = 0;
  char         data[1500]           = { 0 };
  
  //
  // If the original packet is larger than the MTU or the Don't
  // Fragment Flag is set there is nothing to do
  //
  if  ( !(qpkt->getPktLen() <= mtu) ) {

    //
    if ( qpkt->isDFSet() )
    {
      qpkt->setDF(false);
      qpkt->updateChecksums();
    }
    
    if ( !qpkt->isDFSet() )
    {

      // Remove & save data from the first block for appending to the second
      if (  !qpkt->getIHLen( ihLen ) ) {
        zlogI(cn,"fragmentIt",
              ("failed to get the original packet IP header length\n"));
        return false;
      }
      // require 8 byte blocks for fragmenting
      numFragBlocks        = (mtu - ihLen*4)/8;
      numByteForSecondFrag = qpkt->getPktLen() - ihLen*4  -  numFragBlocks*8;
      
      if ( !qpkt->removeBlockFromEnd(&data,numByteForSecondFrag) ) {
        zlogW(cn,"fragmentIt",
              ("failed to remove data from original packet\n"));
        return false;
      }

      // Cloning the header gives us the beginning of a new packet
      // TODO: Deal with options in the header
      cpkt = qpkt->cloneIPHeaderOnly();

      // Add in the data for this packet
      // With will update the total pkt len (without dealing witho options)
      if ( ! cpkt->appendBlockToEnd(&data, numByteForSecondFrag) ) {
        zlogW(cn,"fragmentIt",("failed to append data to the new packet\n"));
        delete cpkt;
        return false;
      }

      // TODO Deal with options in the header
      // cpkt IHL = ( (orgIHL*4 - (lenght of options not copied)) +3 )/4
      if (  !qpkt->getFragmentOffset( fragmentOffset ) ) {
        zlogI(cn,"fragmentIt",
              ("failed to get the fragment offset\n"));
        return false;
      }
      cpkt->setFragmentOffset( fragmentOffset + numFragBlocks );

      // If we are fragmenting an already fragmented packet, the
      // cloning of the orginal packet will have set, as needed,
      // the MF second packet.  If this is a new fragmentation,
      // set the MF flag only on the first packet.
      if ( ! qpkt->isMFSet() ) {
        if ( !qpkt->setMF(true) ) {
        zlogI(cn,"fragmentIt",
              ("failed to set the MF flag\n"));
        delete cpkt;
        return false;
        }
      }
      
      // Update the checksum on IP header only
      qpkt->updateIPChecksum();
      cpkt->updateIPChecksum();

      return true;  
        
    }else {
      zlogI(cn,"fragmentIt",
            ("Don't fragment flag set, nothing to do.\n"));
      return false;
    }
  }else{
    zlogW(cn,"fragmentIt",("packet does not need to be fragmented\n"));
    return false;
  }
}


//=============================================================================
BasicString EmuHAIPEApp::intToIP(int i)
{
  BasicString s;
  
  s.bsnprintf(32,"%lu.%lu.%lu.%lu",
              ((i >> 24) & 0xff), ((i >> 16) & 0xff),
              ((i >> 8) & 0xff), (i & 0xff));
  return s;
}


//=============================================================================
void EmuHAIPEApp::dumpPacket(char *name, IPPacket *qpkt )
{
  unsigned long  saddr;
  unsigned long  daddr;
  unsigned long  proto; 


  if (!qpkt->getSrcAddr(saddr)) {
    zlogI(cn, "dumpPacket",("getSrcAddr retrieve failed \n"));
  }
  
  if (!qpkt->getDstAddr(daddr)) {
    zlogI(cn, "dumpPacket",("getDstAddr retrieve failed \n"));
  }

  if (!qpkt->getProtocol(proto)) {
    zlogI(cn, "dumpPacket",("getProtocol retrieve failed \n"));
  }
  
  zlogI(cn, name,
        ("saddr %s daddr %s proto %d\n",
         intToIP(ntohl(saddr)).str(),intToIP(ntohl(daddr)).str(),proto));
}

//=============================================================================
//=============================================================================
