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

#ifndef IRON_COMMON_BIN_MAP_H
#define IRON_COMMON_BIN_MAP_H

/// Provides the IRON software with various identifer-related mappings.

#include "config_info.h"
#include "ipv4_address.h"
#include "iron_constants.h"
#include "iron_types.h"

#include <string>

namespace iron
{
  /// \brief Mapping of identifiers to IRON nodes and multicast groups.
  ///
  /// There are two major types of identifiers used in the mappings: Bin IDs
  /// and Multicast IDs.
  ///
  /// Bin IDs are used to identify IRON nodes.  Each Bin ID may identify
  /// either an Edge Node, which can have application traffic destined to it,
  /// or an Interior Node, which cannot have application traffic destined to
  /// it.  Thus, Edge Node Bin IDs are also called Unicast Destination Bin
  /// IDs.
  ///
  /// Each Unicast Destination Bin ID (aka Edge Node Bin ID) contains the
  /// following information:
  /// - A list of Host Masks for all unicast application traffic destined to
  ///   the node.  Each Host Mask consists of an IPv4 address and a prefix
  ///   length.
  ///
  /// Each Interior Node Bin ID does not contain any other information, since
  /// application traffic can never be destined to it.
  ///
  /// Multicast IDs are used to identify the multicast groups for multicast
  /// application traffic.  Each Multicast ID contains the following
  /// information:
  /// - The IPv4 multicast address that is specified as the destination
  ///   address in the traffic packets.
  /// - A bit vector of all of the destination Unicast Destination Bin IDs
  ///   (aka Edge Node Bin IDs) for the multicast traffic packets.
  ///
  /// Multicast groups that are specified in the BinMap configuration file are
  /// static multicast groups.  The bit vector of destination Bin IDs cannot
  /// be modified once set with static multicast groups.  Multicast groups
  /// that are added at run-time are dynamic multicast groups, and can have
  /// their destination Bin IDs modified at any time.
  ///
  /// Finally, in order to simplify storage to related information within each
  /// IRON node, every Bin ID and Multicast ID is also mapped to a
  /// node-specific Bin Index.  Given a topology-wide Bin ID or Multicast ID,
  /// this class maps that ID to local-node-specific Bin Index.  This class
  /// also allows looking up the topology-wide Bin ID or Multicast ID for a
  /// given Bin Index on the local node.
  ///
  /// This class is designed to be stored in shared memory, which allows the
  /// entire IRON application to have consistent notion of the available bins.
  /// Make sure that the creator of the BinMap memory area sets the memory to
  /// zero before calling Initialize() in order to initialize the initialized_
  /// member properly.
  class BinMap
  {

   public:

    // ---------- Initialization ----------

    /// \brief Initialize the object using the provided configuration
    ///        information object.
    ///
    /// \param  config_info  A reference to the configuration information.
    ///
    /// \return  Returns true if the initialization is successful, or false
    ///          otherwise.
    bool Initialize(const ConfigInfo& config_info);

    /// \brief Check of the object has been initialized.
    ///
    /// \return  Returns true if the object has been initialized.
    inline bool initialized() const
    {
      return initialized_;
    }

    // ---------- Counts ----------

    /// \brief Get the number of active Unicast Destination Bin IDs.
    ///
    /// Note that Unicast Destinations are Edge Nodes.
    ///
    /// \return  The number of active Unicast Destination Bin IDs.
    inline uint32_t GetNumUcastBinIds() const
    {
      return dst_info_.num_;
    }

    /// \brief Get the number of active Interior Node Bin IDs.
    ///
    /// \return  The number of active Interior Node Bin IDs.
    inline uint32_t GetNumIntNodeBinIds() const
    {
      return int_info_.num_;
    }

    /// \brief Get the number of active Multicast IDs.
    ///
    /// \return  The number of active Multicast IDs.
    inline uint32_t GetNumMcastIds() const
    {
      return mcast_info_.num_;
    }

    // ---------- Iterators ----------

    /// \brief Get the first Unicast Destination Bin Index.
    ///
    /// Note that Unicast Destinations are Edge Nodes.
    ///
    /// \param  bin_idx  A reference to where the first Unicast Destination
    ///                  Bin Index is returned, if there is one.
    ///
    /// \return  Returns true if there was a valid first Unicast Destination
    ///          Bin Index to return, or false otherwise.
    bool GetFirstUcastBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the next Unicast Destination Bin Index.
    ///
    /// Note that Unicast Destinations are Edge Nodes.
    ///
    /// \param  bin_idx  A reference to where the current Unicast Destination
    ///                  Bin Index is located, and where the next is returned
    ///                  if there is one.
    ///
    /// \return  Returns true if there was a valid next Unicast Destination
    ///          Bin Index to return, or false otherwise.
    bool GetNextUcastBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the first Interior Node Bin Index.
    ///
    /// \param  bin_idx  A reference to where the first Interior Node Bin
    ///                  Index is returned, if there is one.
    ///
    /// \return  Returns true if there was a valid first Interior Node Bin
    ///          Index to return, or false otherwise.
    bool GetFirstIntNodeBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the next Interior Node Bin Index.
    ///
    /// \param  bin_idx  A reference to where the current Interior Node Bin
    ///                  Index is located, and where the next is returned if
    ///                  there is one.
    ///
    /// \return  Returns true if there was a valid next Interior Node Bin
    ///          Index to return, or false otherwise.
    bool GetNextIntNodeBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the first Multicast Bin Index.
    ///
    /// \param  bin_idx  A reference to where the first Multicast Bin Index is
    ///                  returned, if there is one.
    ///
    /// \return  Returns true if there was a valid first Multicast Bin Index
    ///          to return, or false otherwise.
    bool GetFirstMcastBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the next Multicast Bin Index.
    ///
    /// \param  bin_idx  A reference to where the current Multicast Bin Index
    ///                  is located, and where the next is returned if there
    ///                  is one.
    ///
    /// \return  Returns true if there was a valid next Multicast Bin Index to
    ///          return, or false otherwise.
    bool GetNextMcastBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the first Destination Bin Index.
    ///
    /// A Destination Bin Index is a Unicast or Multicast Bin Index.
    ///
    /// \param  bin_idx  A reference to where the first Destination Bin Index
    ///                  is returned, if there is one.
    ///
    /// \return  Returns true if there was a valid first Destination Bin Index
    ///          to return, or false otherwise.
    bool GetFirstDstBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the next Destination Bin Index.
    ///
    /// A Destination Bin Index is a Unicast or Multicast Bin Index.
    ///
    /// \param  bin_idx  A reference to where the current Destination Bin
    ///                  Index is located, and where the next is returned if
    ///                  there is one.
    ///
    /// \return  Returns true if there was a valid next Destination Bin Index
    ///          to return, or false otherwise.
    bool GetNextDstBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the first Physical Bin Index.
    ///
    /// A Physical Bin Index is a Unicast or Interior Node Bin Index.
    ///
    /// \param  bin_idx  A reference to where the first Physical Bin Index is
    ///                  returned, if there is one.
    ///
    /// \return  Returns true if there was a valid first Physical Bin Index to
    ///          return, or false otherwise.
    bool GetFirstPhyBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the next Physical Bin Index.
    ///
    /// A Physical Bin Index is a Unicast or Interior Node Bin Index.
    ///
    /// \param  bin_idx  A reference to where the current Physical Bin Index
    ///                  is located, and where the next is returned if there
    ///                  is one.
    ///
    /// \return  Returns true if there was a valid next Physical Bin Index to
    ///          return, or false otherwise.
    bool GetNextPhyBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the first Bin Index.
    ///
    /// A Bin Index is a Unicast, Interior Node, or Multicast Bin Index.
    ///
    /// \param  bin_idx  A reference to where the first Bin Index is returned,
    ///                  if there is one.
    ///
    /// \return  Returns true if there was a valid first Bin Index to return,
    ///          or false otherwise.
    bool GetFirstBinIndex(BinIndex& bin_idx) const;

    /// \brief Get the next Bin Index.
    ///
    /// A Bin Index is a Unicast, Interior Node, or Multicast Bin Index.
    ///
    /// \param  bin_idx  A reference to where the current Bin Index is
    ///                  located, and where the next is returned if there is
    ///                  one.
    ///
    /// \return  Returns true if there was a valid next Bin Index to return,
    ///          or false otherwise.
    bool GetNextBinIndex(BinIndex& bin_idx) const;

    // ---------- BinIndexableArray Information ----------

    /// \brief Get the BinIndex offset for Unicast Destination Bin IDs.
    ///
    /// Note that Unicast Destinations are Edge Nodes.
    ///
    /// \return  The BinIndex offset for Unicast Destination Bin IDs.
    inline BinIndex ucast_bin_idx_offset() const
    {
      return dst_info_.offset_;
    }

    /// \brief Get the maximum number of supported Unicast Destination Bin
    ///        Indices.
    ///
    /// Note that Unicast Destinations are Edge Nodes.
    ///
    /// \return  The maximum number of supported Unicast Destination Bin
    ///          Indices.
    inline size_t max_num_ucast_bin_idxs() const
    {
      return kMaxNumDsts;
    }

    /// \brief Get the BinIndex offset for Interior Node Bin IDs.
    ///
    /// \return  The BinIndex offset for Interior Node Bin IDs.
    inline BinIndex int_bin_idx_offset() const
    {
      return int_info_.offset_;
    }

    /// \brief Get the maximum number of supported Interior Node Bin Indices.
    ///
    /// \return  The maximum number of supported Interior Node Bin Indices.
    inline size_t max_num_int_bin_idxs() const
    {
      return kMaxNumIntNodes;
    }

    /// \brief Get the BinIndex offset for Multicast IDs.
    ///
    /// \return  The BinIndex offset for Multicast IDs.
    inline BinIndex mcast_bin_idx_offset() const
    {
      return mcast_info_.offset_;
    }

    /// \brief Get the maximum number of supported Multicast Bin Indices.
    ///
    /// \return  Maximum number of supported Multicast Bin Indices.
    inline size_t max_num_mcast_bin_idxs() const
    {
      return kMaxNumMcastGroups;
    }

    // ---------- Mappings ----------

    /// \brief Get the Destination Bin Index associated with the provided IP
    ///        address.
    ///
    /// Note that this can be used for both unicast and multicast IP
    /// addresses.  A unicast IP address can only return a Unicast Destination
    /// Bin Index, and a multicast IP address can only return a Multicast Bin
    /// Index.  A Unicast Destination is an Edge Node.
    ///
    ///
    /// \param  ip_addr  The IPv4 address to use in looking up the Bin Index.
    ///
    /// \return  The Bin Index associated with the IP address on success, or
    ///          kInvalidBinIndex otherwise.
    BinIndex GetDstBinIndexFromAddress(const iron::Ipv4Address& ip_addr)
      const;

    /// \brief Get the Multicast ID of a multicast group IP address.
    ///
    /// \param  group_addr  The IPv4 address of the multicast group.
    ///
    /// \return  The Multicast ID of the multicast group.  Currently, this is
    ///          simply the IPv4 address as a uint32_t in network byte order.
    inline McastId GetMcastIdFromAddress(const iron::Ipv4Address& group_addr)
      const
    {
      return group_addr.address();
    }

    /// \brief Get the Bin Index associated with a Physical Bin ID.
    ///
    /// A Physical Bin ID is a Unicast or Interior Node Bin ID.
    ///
    /// \param  bin_id  The Physical Bin ID to use in looking up the Bin
    ///                 Index.
    ///
    /// \return  The Bin Index associated with the Physical Bin ID on success,
    ///          or kInvalidBinIndex otherwise.
    BinIndex GetPhyBinIndex(BinId bin_id) const;

    /// \brief Get the Bin Index associated with a Multicast ID.
    ///
    /// \param  mcast_id  The Multicast ID to use in looking up the Bin Index.
    ///
    /// \return  The Bin Index associated with the Multicast ID on success, or
    ///          kInvalidBinIndex otherwise.
    BinIndex GetMcastBinIndex(McastId mcast_id) const;

    /// \brief Get the Bin ID associated with a Physical Bin Index.
    ///
    /// A Physical Bin Index is a Unicast or Interior Node Bin Index.
    ///
    /// \param  bin_idx  The Physical Bin Index to use in looking up the Bin
    ///                  ID.
    ///
    /// \return  The Bin ID associated with the Physical Bin Index on success,
    ///          or kInvalidBinId otherwise.
    BinId GetPhyBinId(BinIndex bin_idx) const;

    /// \brief Get the Multicast ID associated with a Multicast Bin Index.
    ///
    /// \param  bin_idx  The Multicast Bin Index to use in looking up the
    ///                  Multicast ID.
    ///
    /// \return  The Multicast ID associated with the Multicast Bin Index on
    ///          success, or kInvalidMcastId otherwise.
    McastId GetMcastId(BinIndex bin_idx) const;

    // ---------- Multicast Group Management ----------

    /// \brief Add a dynamic multicast group.
    ///
    /// \param  mcast_addr  The multicast IPv4 address of the group.
    ///
    /// \return The Bin Index associated with the Multicast ID on success, or
    ///         kInvalidBinIndex otherwise.
    BinIndex AddMcastGroup(const iron::Ipv4Address& mcast_addr);

    /// \brief Add the Destination Bin ID of a Destination Bin Index to the
    ///        destination vector (DstVec) of a dynamic multicast group.
    ///
    /// If the multicast group does not already exist, it will be created
    /// automatically.
    ///
    /// \param  mcast_addr   The multicast IPv4 address of the group.
    /// \param  dst_bin_idx  The Destination Bin Index of the Destination Bin
    ///                      ID to be added.
    void AddDstToMcastGroup(const iron::Ipv4Address& mcast_addr,
                            BinIndex dst_bin_idx);

    /// \brief Remove the Destination Bin ID of a Destination Bin Index from
    ///        the destination vector (DstVec) of a dynamic multicast group.
    ///
    /// \param  mcast_addr   The multicast IPv4 address of the group.
    /// \param  dst_bin_idx  The Destination Bin Index of the Destination Bin
    ///                      ID to be removed.
    void RemoveDstFromMcastGroup(const iron::Ipv4Address& mcast_addr,
                                 BinIndex dst_bin_idx);

    /// \brief Remove the Destination Bin ID of a Destination Bin Index from
    ///        all dynamic multicast groups.
    ///
    /// This is done when processing GRAMs and allows a node to implicitly
    /// advertise leaving a group.
    ///
    /// \param  dst_bin_idx  The Destination Bin Index of the Destination Bin
    ///                      ID to be removed.
    void PurgeDstFromMcastGroups(BinIndex dst_bin_idx);

    /// \brief Get the current destination bit vector for a multicast group.
    ///
    /// \param  bin_idx  The Multicast Bin Index associated with the multicast
    ///                  group.
    ///
    /// \return  The destination bit vector representing destinations for the
    ///          multicast group if found, or an empty destination bit vector
    ///          otherwise.
    DstVec GetMcastDst(BinIndex bin_idx) const;

    // ---------- BinId Operations ----------

    /// \brief Check if a Unicast Destination Bin ID is within the valid
    ///        range.
    ///
    /// Note that this does not check if the Unicast Destination Bin ID has
    /// been assigned or not.
    ///
    /// \param  bin_id  The Unicast Destination Bin ID to check.
    ///
    /// \return  Returns true if the Unicast Destination Bin ID is within the
    ///          valid range, or false otherwise.
    inline bool UcastBinIdIsInValidRange(BinId bin_id) const
    {
      return (bin_id <= kMaxUcastBinId);
    }

    /// \brief Check if an Interior Node Bin ID is within the valid range.
    ///
    /// Note that this does not check if the Interior Node Bin ID has been
    /// assigned or not.
    ///
    /// \param  bin_id  The Interior Node Bin ID to check.
    ///
    /// \return  Returns true if the Interior Node Bin ID is within the valid
    ///          range, or false otherwise.
    inline bool IntNodeBinIdIsInValidRange(BinId bin_id) const
    {
      return (bin_id <= kMaxBinId);
    }

    // ---------- BinIndex Operations ----------

    /// \brief Check if a Bin Index is currently assigned.
    ///
    /// \param  bin_idx  The Bin Index to check.
    ///
    /// \return  Returns true if the Bin Index is currently assigned, or false
    ///          otherwise.
    inline bool BinIndexIsAssigned(BinIndex bin_idx) const
    {
      return (((bin_idx >= dst_info_.offset_) &&
               (bin_idx < (dst_info_.offset_ + dst_info_.num_))) ||
              ((bin_idx >= int_info_.offset_) &&
               (bin_idx < (int_info_.offset_ + int_info_.num_))) ||
              ((bin_idx >= mcast_info_.offset_) &&
               (bin_idx < (mcast_info_.offset_ + mcast_info_.num_))));
    }

    /// \brief Query if the provided Bin Index is currently assigned to a
    ///        Unicast Destination (an Edge Node).
    ///
    /// \param  bin_idx  The Bin Index to check.
    ///
    /// \return  Returns true if the Bin Index is currently assigned to a
    ///          Unicast Destination, or false otherwise.
    inline bool IsUcastBinIndex(BinIndex bin_idx) const
    {
      return ((bin_idx >= dst_info_.offset_) &&
              (bin_idx < (dst_info_.offset_ + dst_info_.num_)));
    }

    /// \brief Query if the provided Bin Index is currently assigned to an
    ///        Interior Node.
    ///
    /// \param  bin_idx  The Bin Index to check.
    ///
    /// \return  Returns true if the Bin Index is currently assigned to an
    ///          Interior Node, or false otherwise.
    inline bool IsIntNodeBinIndex(BinIndex bin_idx) const
    {
      return ((bin_idx >= int_info_.offset_) &&
              (bin_idx < (int_info_.offset_ + int_info_.num_)));
    }

    /// \brief Query if the provided Bin Index is currently assigned to a
    ///        Multicast Group.
    ///
    /// \param  bin_idx  The Bin Index to check.
    ///
    /// \return  Returns true if the Bin Index is currently assigned to a
    ///          Multicast Group, or false otherwise.
    inline bool IsMcastBinIndex(BinIndex bin_idx) const
    {
      return ((bin_idx >= mcast_info_.offset_) &&
              (bin_idx < (mcast_info_.offset_ + mcast_info_.num_)));
    }

    /// \brief Query if the provided Bin Index is currently assigned to a
    ///        Destination (a unicast or multicast destination).
    ///
    /// \param  bin_idx  The Bin Index to check.
    ///
    /// \return  Returns true if the Bin Index is currently assigned to a
    ///          Destination, or false otherwise.
    inline bool IsDstBinIndex(BinIndex bin_idx) const
    {
      return (((bin_idx >= dst_info_.offset_) &&
               (bin_idx < (dst_info_.offset_ + dst_info_.num_))) ||
              ((bin_idx >= mcast_info_.offset_) &&
               (bin_idx < (mcast_info_.offset_ + mcast_info_.num_))));
    }

    /// \brief Query if the provided Bin Index is currently assigned to a
    ///        Physical Node (a Unicast Destination or Interior Node).
    ///
    /// \param  bin_idx  The Bin Index to check.
    ///
    /// \return  Returns true if the Bin Index is currently assigned to a
    ///          Physical Node, or false otherwise.
    inline bool IsPhyBinIndex(BinIndex bin_idx) const
    {
      return (((bin_idx >= dst_info_.offset_) &&
               (bin_idx < (dst_info_.offset_ + dst_info_.num_))) ||
              ((bin_idx >= int_info_.offset_) &&
               (bin_idx < (int_info_.offset_ + int_info_.num_))));
    }

    // ---------- DstVec Operations ----------

    /// \brief Get the number of Unicast Destination Bin IDs in a destination
    ///        bit vector.
    ///
    /// \param  dst_vec  The destination bit vector to be examined.
    ///
    /// \return  The number of Unicast Destination Bin IDs in the destination
    ///          bit vector.
    static size_t GetNumBinsInDstVec(DstVec dst_vec);

    /// \brief Check if the Bin ID for a Unicast Destination Bin Index is set
    ///        in a destination bit vector.
    ///
    /// \param  dst_vec  The destination bit vector to be examined.
    /// \param  bin_idx  The Unicast Destination Bin Index of interest.
    ///
    /// \return  Returns true if the Bin ID of the specified Unicast
    ///          Destination Bin Index is set in the destination bit vector,
    ///          or false otherwise.
    bool IsBinInDstVec(DstVec dst_vec, BinIndex bin_idx) const;

    /// \brief Check if the Bin ID for a Unicast Destination Bin Index is the
    ///        only Bin ID set in a destination bit vector.
    ///
    /// \param  dst_vec  The destination bit vector to be examined.
    /// \param  bin_idx  The Unicast Destination Bin Index of interest.
    ///
    /// \return  Returns true if the Bin ID of the specified Unicast
    ///          Destination Bin Index is the only one set in the destination
    ///          bit vector, or false otherwise.
    bool IsOnlyBinInDstVec(DstVec dst_vec, BinIndex bin_idx) const;

    /// \brief Add the Bin ID for a Unicast Destination Bin Index to a
    ///        destination bit vector.
    ///
    /// \param  dst_vec  The original destination bit vector to be modified.
    /// \param  bin_idx  The Unicast Destination Bin Index to be added.
    ///
    /// \return  The new destination bit vector that includes the Bin ID of
    ///          the specified Unicast Destination Bin Index.
    DstVec AddBinToDstVec(DstVec dst_vec, BinIndex bin_idx) const;

    /// \brief Remove the Bin ID for a Unicast Destination Bin Index from a
    ///        destination bit vector.
    ///
    /// \param  dst_vec  The original destination bit vector to be modified.
    /// \param  bin_idx  The Unicast Destination Bin Index to be removed.
    ///
    /// \return  The new destination bit vector that does not include the Bin
    ///          ID of the specified Unicast Destination Bin Index.
    DstVec RemoveBinFromDstVec(DstVec dst_vec, BinIndex bin_idx) const;

    /// \brief Subtract one destintaion bit vector from another.
    ///
    /// Note that the "subtract" destination bit vector must be a subset of
    /// the "original" destination bit vector, or a LogF() will occur.
    ///
    /// \param  original  The destination bit vector we are subtracting from.
    /// \param  subtract  The destination bit vector we want to remove from
    ///                   the original.
    ///
    /// \return  The new destination bit vector after subtracting.
    static DstVec DstVecSubtract(DstVec original, DstVec subtract);

    // ---------- Logging ----------

    /// \brief Return a string representation of the Bin ID for a Bin Index.
    ///
    /// \param  bin_idx     The Bin Index that we want to pretty-print.
    /// \param  suppress_m  An optional flag that suppresses the leading "M"
    ///                     on multicast information.  Defaults to false.
    ///
    /// \return  A string representation of the state associated with the Bin
    ///          Index.
    std::string GetIdToLog(BinIndex bin_idx, bool suppress_m = false) const;


    /// \brief Return an Ipv4Address that will resolve to a given bin index 
    ///
    /// \param  bin_idx     The Bin Index of the unicast or mcast destination
    ///
    /// \return  An Ipv4Address associated with the destination Bin Index
    Ipv4Address GetViableDestAddr(BinIndex bin_idx)
    {
      if (IsMcastBinIndex(bin_idx))
      {
	return mcast_info_.GetViableDestAddr(bin_idx);
      }
      else if (IsUcastBinIndex(bin_idx))
      {
	return dst_info_.GetViableDestAddr(bin_idx);
      }
      return Ipv4Address((uint32_t)0);
    }

    /// \brief  Print the internal state of the bin map.
    void Print() const;

   private:

    /// \brief Constructor.
    ///
    /// Note: This is private as the bin map is created in shared memory.
    BinMap();

    /// \brief Destructor.
    ///
    /// Note: This is private as the bin map is created in shared memory.
    virtual ~BinMap();

    /// Copy constructor.
    BinMap(const BinMap& bm);

    /// Copy operator.
    BinMap operator=(const BinMap& bm);

    /// \brief Add the Destination Bin ID of a Destination Bin Index to the
    ///        destination bit vector (DstVec) of a multicast group.
    ///
    /// If the multicast group does not already exist, it will be created
    /// automatically.
    ///
    /// \param  mcast_addr   The multicast IPv4 address of the group.
    /// \param  dst_bin_idx  The Destination Bin Index of the Destination Bin
    ///                      ID to be added.
    /// \param  forced_add   A flag controlling if the addition is being
    ///                      forced.  If true and this is a static multicast
    ///                      group, then the group is updated.
    /// \param  static_grp   A flag indicating if this is a static multicast
    ///                      group or not.  Only used if a multicast group
    ///                      needs to be created.
    void PrivAddDstToMcastGroup(const iron::Ipv4Address& mcast_addr,
                                BinIndex dst_bin_idx, bool forced_add,
                                bool static_grp);

    /// Stores a subnet, consisting of an IPv4 network address, a prefix
    /// length, and a subnet mask.
    class Subnet
    {

     public:

      /// Default no arg constructor.
      Subnet() : subnet_addr_(), prefix_len_(0), subnet_mask_(0) { }

      /// Destructor.
      virtual ~Subnet() { }

      /// Initialize the Subnet object.
      ///
      /// \param  network_str     The network IPv4 address string.
      /// \param  prefix_len_str  The prefix length string.
      ///
      /// \return  Returns true if the initialization is successful, or false
      ///          otherwise.
      bool Initialize(const std::string& network_str,
                      const std::string& prefix_len_str);

      /// \brief Determine if an IPv4 destination address is in the subnet.
      ///
      /// \param  dst_addr  The Ipv4 destination address to be tested.
      ///
      /// \return  Returns true if the destination address is in the subnet,
      ///          or false otherwise.
      bool IsInSubnet(const iron::Ipv4Address& dst_addr) const;

      /// \brief Get the subnet address.
      ///
      /// \return  The subnet address.
      inline iron::Ipv4Address GetSubnetAddress() const
      {
        return subnet_addr_;
      }

      /// \brief Get the prefix length.
      ///
      /// \return  The prefix length.
      inline int GetPrefixLength() const
      {
        return prefix_len_;
      }

      /// \brief Get a string representation of the Subnet object.
      ///
      /// \return  A string representation of the Subnet object.
      std::string ToString() const;

     private:

      /// Copy constructor.
      Subnet(const Subnet& other);

      /// Copy operator.
      Subnet& operator=(const Subnet& other);

      /// The subnet address.
      iron::Ipv4Address  subnet_addr_;

      /// The mask prefix length.
      int                prefix_len_;

      /// The subnet mask, in network byte order.
      uint32_t           subnet_mask_;

    }; // end class Subnet

    /// Stores information for a single Unicast Destination (Edge Node).
    class Dst
    {

     public:

      /// Default no arg constructor.
      Dst() : num_subnets_(0), subnet_() { }

      /// Destructor.
      virtual ~Dst() { };

      /// Add a subnet.
      ///
      /// \param  network_str     The network IPv4 address string.
      /// \param  prefix_len_str  The prefix length string.
      ///
      /// \return  Returns true if successful, or false otherwise.
      bool AddSubnet(const std::string& network_str,
                     const std::string& prefix_len_str);

      /// The number of subnets.
      size_t  num_subnets_;

      /// The array of subnets.
      Subnet  subnet_[kDefaultNumHostMasks];

    }; // end class Dst

    /// Stores common Bin Index information.
    class CommonBinIdxInfo
    {

     public:

      /// Default no arg constructor.
      CommonBinIdxInfo() : offset_(0), num_(0) { }

      /// Destructor.
      virtual ~CommonBinIdxInfo() { };

      /// Initialization.
      ///
      /// \param  offset  The starting Bin Index offset.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool Initialize(BinIndex offset);

      /// The starting Bin Index offset.
      BinIndex  offset_;

      /// The current number of Bin Indices in use.
      size_t    num_;

    }; // end class CommonBinIdxInfo

    /// Stores information for all Unicast Destinations (Edge Nodes).
    class DstInfo : public CommonBinIdxInfo
    {

     public:

      /// Default no arg constructor.
      DstInfo() : CommonBinIdxInfo(), idx_to_bin_id_(), ucast_dst_() { }

      /// Destructor.
      virtual ~DstInfo() { };

      /// Initialization.
      ///
      /// \param  offset  The starting Bin Index offset.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool Initialize(BinIndex offset);

      /// Add a Bin ID.
      ///
      /// \param  config_info  A reference to the configuration information.
      /// \param  bin_id_str   The Bin ID as a string.
      /// \param  bin_id       The Bin ID to add.
      /// \param  bin_idx      A reference to where the assigned Bin Index is
      ///                      placed on success.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool AddBinId(const ConfigInfo& config_info,
                    const std::string& bin_id_str, BinId bin_id,
                    BinIndex& bin_idx);

      /// Convert the information of a Bin Index into a string for logging.
      ///
      /// \param  bin_idx  The Bin Index being requested.
      ///
      /// \return  Returns a string capturing the Bin Index state.
      std::string ToString(BinIndex bin_idx);

      /// The Bin Index to Bin ID mapping, indexed by Bin Index minus the
      /// starting Bin Index offset.  Unused mapping entries are set to
      /// kInvalidBinId.
      BinId  idx_to_bin_id_[kMaxNumDsts];

      /// The Unicast Destination information array, indexed by Bin Index
      /// minus the starting Bin Index offset.
      Dst    ucast_dst_[kMaxNumDsts];

      /// \brief Return an Ipv4Address that will resolve to the given bin index 
      ///
      /// \param   bin_idx     The Bin Index of the unicast or mcast destination
      ///
      /// \return  An Ipv4Address associated with the destination Bin Index
      Ipv4Address GetViableDestAddr(BinIndex bin_idx)
      {
	if (ucast_dst_[bin_idx - offset_].num_subnets_ > 0)
	{
	  return ucast_dst_[bin_idx - offset_].subnet_[0].GetSubnetAddress();
	}
	return Ipv4Address((uint32_t)0);
      }

    }; // end class DstInfo

    /// Stores information for all Interior Nodes.
    class IntInfo : public CommonBinIdxInfo
    {

     public:

      /// Default no arg constructor.
      IntInfo() : CommonBinIdxInfo(), idx_to_bin_id_() { }

      /// Destructor.
      virtual ~IntInfo() { };

      /// Initialization.
      ///
      /// \param  offset  The starting Bin Index offset.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool Initialize(BinIndex offset);

      /// Add a Bin ID.
      ///
      /// \param  bin_id   The Bin ID to add.
      /// \param  bin_idx  A reference to where the assigned Bin Index is
      ///                  placed on success.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool AddBinId(BinId bin_id, BinIndex& bin_idx);

      /// The Bin Index to Bin ID mapping, indexed by Bin Index minus the
      /// starting Bin Index offset.  Unused mapping entries are set to
      /// kInvalidBinId.
      BinId  idx_to_bin_id_[kMaxNumIntNodes];

    }; // end class IntInfo

    /// Stores information for all Multicast Groups.
    class McastInfo : public CommonBinIdxInfo
    {

     public:

      /// Default no arg constructor.
      McastInfo() : CommonBinIdxInfo(), idx_to_mcast_id_(), mcast_addr_(),
                    mcast_dst_(), static_grp_() { }

      /// Destructor.
      virtual ~McastInfo() { };

      /// Initialization.
      ///
      /// \param  offset  The starting Bin Index offset.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool Initialize(BinIndex offset);

      /// Find a multicast group.
      ///
      /// \param  mcast_id  The Multicast ID value to find.
      ///
      /// \return  Returns the Bin Index of the multicast group entry on
      ///          success, or kInvalidBinIndex otherwise.
      BinIndex FindMcastGrp(McastId mcast_id);

      /// Add a multicast group.
      ///
      /// \param  mcast_addr  A reference to the multicast IPv4 address for
      ///                     the group.
      /// \param  mcast_id    The Multicast ID for the group.
      /// \param  dsts        The initial destinations for the group.
      /// \param  static_grp  A flag indicating if this is a static multicast
      ///                     group or not.
      /// \param  bin_idx     A reference to a location where the assigned Bin
      ///                     Index is placed on success.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool AddMcastGrp(const iron::Ipv4Address& mcast_addr, McastId mcast_id,
                       DstVec dsts, bool static_grp, BinIndex& bin_idx);

      /// Add a static multicast group at configuration time.
      ///
      /// \param  bin_map        A reference to the bin map.
      /// \param  id_map         A pointer to the Bin ID to Bin Index mapping
      ///                        array.
      /// \param  config_info    A reference to the configuration information.
      /// \param  config_prefix  The configuration key prefix string.
      /// \param  config_idx     The configuration key index.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool CfgAddMcastGrp(const BinMap& bin_map, const BinIndex* id_map,
                          const ConfigInfo& config_info,
                          const std::string& config_prefix,
                          uint32_t config_idx);

      /// Get the current destination bit vector for a multicast group.
      ///
      /// \param  mcast_bin_idx  The Bin Index of the multicast group.
      ///
      /// \return  The destination bit vector.
      DstVec GetDst(BinIndex mcast_bin_idx) const;

      /// Add a destination to a dynamic multicast group.
      ///
      /// \param  mcast_bin_idx  The Bin Index of the multicast group.
      /// \param  dst_vec        The destination to be added in a destination
      ///                        bit vector.
      /// \param  forced_add     A flag controlling if the addition is being
      ///                        forced.  If true and this is a static
      ///                        multicast group, then the group is updated.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool AddDst(BinIndex mcast_bin_idx, DstVec dst_vec, bool forced_add);

      /// Remove a destination from a dynamic multicast group.
      ///
      /// \param  mcast_bin_idx  The Bin Index of the multicast group.
      /// \param  dst_vec        The destination to be removed in a
      ///                        destination bit vector.
      ///
      /// \return  Returns true on success, or false otherwise.
      bool RemoveDst(BinIndex mcast_bin_idx, DstVec dst_vec);

      /// Remove a destination from all current dynamic multicast groups.
      ///
      /// \param  dst_vec  The destination to be removed in a destination bit
      ///                  vector.
      void PurgeDstFromDynMcastGrps(DstVec dst_vec);

      /// Convert the information of a Bin Index into a string for logging.
      ///
      /// \param  bin_idx  The Bin Index being requested.
      ///
      /// \return  Returns a string capturing the Bin Index state.
      std::string ToString(BinIndex bin_idx);

      /// The Bin Index to Multicast ID mapping, indexed by Bin Index minus
      /// the starting Bin Index offset.  Unused mapping entries are set to
      /// kInvalidMcastId.
      McastId            idx_to_mcast_id_[kMaxNumMcastGroups];

      /// The multicast group IPv4 address array, indexed by Bin Index minus
      /// the starting Bin Index offset.
      iron::Ipv4Address  mcast_addr_[kMaxNumMcastGroups];

      /// The multicast group destination bit vector array, indexed by Bin
      /// Index minus the starting Bin Index offset.
      DstVec             mcast_dst_[kMaxNumMcastGroups];

      /// The static multicast group flag array, indexed by Bin Index minus
      /// the starting Bin Index offset.  Set to true for multicast groups set
      /// in the BinMap configuration file, or false for dynamic multicast
      /// groups.
      bool               static_grp_[kMaxNumMcastGroups];

      /// \brief Return an Ipv4Address that will resolve to the given bin index 
      ///
      /// \param   bin_idx     The Bin Index of the multicast destination
      ///
      /// \return  An Ipv4Address associated with the destination Bin Index
      Ipv4Address GetViableDestAddr(BinIndex bin_idx)
      {
	return mcast_addr_[bin_idx - offset_];
      }
      
    }; // end class McastInfo

    /// True if and only if this instance has been initialized.
    bool       initialized_;

    /// The Unicast Destination (Edge Node) Bin Index information.
    DstInfo    dst_info_;

    /// The Interior Node Bin Index information.
    IntInfo    int_info_;

    /// The Multicast information.
    McastInfo  mcast_info_;

    /// The Bin ID to Bin Index mapping, indexed by Bin ID.  When set to
    /// kInvalidBinIndex, the Bin ID is unused.
    BinIndex   bin_id_to_idx_[kMaxBinId + 1];

  }; // end class BinMap

} // namespace iron

#endif // IRON_COMMON_BIN_MAP_H
