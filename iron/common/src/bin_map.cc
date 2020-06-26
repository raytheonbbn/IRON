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

#include "bin_map.h"
#include "list.h"
#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <sstream>

using ::iron::BinId;
using ::iron::BinIndex;
using ::iron::BinMap;
using ::iron::DstVec;
using ::iron::List;
using ::iron::McastId;
using ::iron::StringUtils;
using ::std::string;
using ::std::stringstream;


namespace
{
  /// Class names for logging.
  const char*  UNUSED(kClassName)   = "BinMap";
  const char*  UNUSED(kClassNameDT) = "BinMap::Dst";
  const char*  UNUSED(kClassNameDI) = "BinMap::DstInfo";
  const char*  UNUSED(kClassNameII) = "BinMap::IntInfo";
  const char*  UNUSED(kClassNameMI) = "BinMap::McastInfo";
  const char*  UNUSED(kClassNameSN) = "BinMap::Subnet";

  /// Default Bin Index offset for Destination Bin IDs.
  const BinIndex  kDefaultDstBinIdxOffset   = 0;

  /// Default Bin Index offset for Interior Node Bin IDs.
  const BinIndex  kDefaultIntBinIdxOffset   = 256;

  /// Default Bin Index offset for Multicast Bin IDs.
  const BinIndex  kDefaultMcastBinIdxOffset = 512;
}

//============================================================================
bool BinMap::Initialize(const ConfigInfo& config_info)
{
  if (initialized_)
  {
    LogF(kClassName, __func__, "BinMap already initialized or BinMap memory "
         "not zeroed before call.\n");
    return false;
  }

  // Assert that all assignable BinIndex values are less than the invalid
  // BinIndex value.  Note that 0 is always a valid BinIndex value.
  if (((kDefaultDstBinIdxOffset + kMaxNumDsts - 1) >= kInvalidBinIndex) ||
      ((kDefaultIntBinIdxOffset + kMaxNumIntNodes - 1) >= kInvalidBinIndex) ||
      ((kDefaultMcastBinIdxOffset + kMaxNumMcastGroups - 1) >=
       kInvalidBinIndex))
  {
    LogF(kClassName, __func__, "Error: The maximum BinIndex values (%" PRIu32
         ",%" PRIu32 ",%" PRIu32 ") cannot interfere with kInvalidBinIndex "
         "(%" PRIBinIndex ").\n",
         static_cast<uint32_t>(kDefaultDstBinIdxOffset + kMaxNumDsts - 1),
         static_cast<uint32_t>(kDefaultIntBinIdxOffset + kMaxNumIntNodes - 1),
         static_cast<uint32_t>(kDefaultMcastBinIdxOffset + kMaxNumMcastGroups
                               - 1), kInvalidBinIndex);
  }

  // Assert that kMaxBinId is small enough that we can represent that many
  // values of BinId, starting at 0 and going to kMaxBinId.  Also assert that
  // kMaxBinId does not collide with kInvalidBinId.
  if ((kMaxBinId > std::numeric_limits<BinId>::max()) ||
      (kMaxBinId >= kInvalidBinId))
  {
    LogF(kClassName, __func__, "Error: kMaxBinId (%" PRIu32 ") must be "
         "representable by BinId and must be less than kInvalidBinId (%"
         PRIBinId ".\n", kMaxBinId, kInvalidBinId);
  }

  // Assert that all unicast destination BinId values, from 0 to
  // kMaxUcastBinId, are within the valid BinId range of 0 to kMaxBinId.
  if (kMaxUcastBinId >= kMaxBinId)
  {
    LogF(kClassName, __func__, "Error: kMaxUcastBinId (%" PRIu32 ") must be "
         "less than kMaxBinId (%" PRIu32 ").", kMaxUcastBinId, kMaxBinId);
  }

  // Assert that all unicast destination BinId values, from 0 to
  // kMaxUcastBinId, can be represented in the DstVec bit vector.
  if (kMaxUcastBinId >= kDstVecBitsUsed)
  {
    LogF(kClassName, __func__, "Error: kMaxUcastBinId (%" PRIu32 ") must map "
         "to a valid bit index in DstVec, in which we only use %" PRIu8
         " bits.", kMaxUcastBinId, kDstVecBitsUsed);
  }

  // Assert that kMaxMcastId is small enough that we can represent that many
  // values of it, starting at 1 (since kInvalidMcastId is 0) and going all
  // the way up to kMaxMcastId.
  if (kMaxMcastId > std::numeric_limits<McastId>::max())
  {
    LogF(kClassName, __func__, "Error: kMaxMcastId (%" PRIu32 ") must be "
         "representable by McastID.", kMaxMcastId);
  }

  // Set the Bin Index starting offsets.
  dst_info_.Initialize(kDefaultDstBinIdxOffset);
  int_info_.Initialize(kDefaultIntBinIdxOffset);
  mcast_info_.Initialize(kDefaultMcastBinIdxOffset);

  // Initialize the Bin ID to Bin Index mapping entries to the invalid Bin
  // Index value.  This marks all of the Bin IDs as "unused".
  for (BinId i = 0; i <= kMaxBinId; ++i)
  {
    bin_id_to_idx_[i] = kInvalidBinIndex;
  }

  // Determine if configured to SendGrams.
  bool  grams_enabled = config_info.GetBool("Bpf.SendGrams",
                                            kDefaultSendGrams);

  // Extract the Unicast Destination (Edge Node) Bin ID information.
  string  dst_bin_ids_str = config_info.Get("BinMap.BinIds", "");

  if (dst_bin_ids_str.empty())
  {
    LogF(kClassName, __func__, "Error: No BinMap.BinIds value in BinMap "
         "configuration file.\n");
    return false;
  }

  List<string>  dst_bin_ids;

  StringUtils::Tokenize(dst_bin_ids_str, ",", dst_bin_ids);

  while (dst_bin_ids.size() > 0)
  {
    string  dst_bin_id_str;

    dst_bin_ids.Pop(dst_bin_id_str);

    BinId     dst_bin_id  = static_cast<BinId>(
      StringUtils::GetUint(dst_bin_id_str, kInvalidBinId));
    BinIndex  dst_bin_idx = kInvalidBinIndex;

    // Make sure that the Bin ID value is within the valid range.
    if (dst_bin_id > kMaxUcastBinId)
    {
      LogF(kClassName, __func__, "Error: Configured unicast destination Bin "
           "ID %" PRIBinId " exceeds the max Bin ID value (%" PRIu32 ").\n",
           dst_bin_id, kMaxUcastBinId);
      return false;
    }

    // Make sure that the Bin ID value is not already being used.
    if (bin_id_to_idx_[dst_bin_id] != kInvalidBinIndex)
    {
      LogF(kClassName, __func__, "Error: Configured unicast destination Bin "
           "ID %" PRIBinId " already in use.\n", dst_bin_id);
      return false;
    }

    // Add the Bin ID to the Unicast Destination information.
    if (!dst_info_.AddBinId(config_info, dst_bin_id_str, dst_bin_id,
                            dst_bin_idx))
    {
      LogF(kClassName, __func__, "Error: Unable to add the unicast "
           "destination Bin ID %" PRIBinId ".\n", dst_bin_id);
      return false;
    }

    // Add the Bin ID to the Bin ID to Bin Index mapping.
    bin_id_to_idx_[dst_bin_id] = dst_bin_idx;

    // If GRAMs are enabled, then add this destination to the static GRAM
    // multicast group.
    if (grams_enabled)
    {
      PrivAddDstToMcastGroup(kDefaultGramGrpAddr, dst_bin_idx, true, true);
    }
  }

  // Extract the Interior Node Bin ID information.
  string        int_node_bin_ids_str = config_info.Get("BinMap.IntBinIds",
                                                       "");
  List<string>  int_node_bin_ids;

  StringUtils::Tokenize(int_node_bin_ids_str, ",", int_node_bin_ids);

  while (int_node_bin_ids.size() > 0)
  {
    string  int_node_bin_id_str;

    int_node_bin_ids.Pop(int_node_bin_id_str);

    BinId     int_node_bin_id  = static_cast<BinId>(
      StringUtils::GetUint(int_node_bin_id_str, kInvalidBinId));
    BinIndex  int_node_bin_idx = kInvalidBinIndex;

    // Make sure that the Bin ID value is within the valid range.
    if (int_node_bin_id > kMaxBinId)
    {
      LogF(kClassName, __func__, "Error: Configured interior node Bin ID %"
           PRIBinId " exceeds the max Bin ID value (%" PRIu32 ").\n",
           int_node_bin_id, kMaxBinId);
      return false;
    }

    // Make sure that the Bin ID value is not already being used.
    if (bin_id_to_idx_[int_node_bin_id] != kInvalidBinIndex)
    {
      LogF(kClassName, __func__, "Error: Configured interior node Bin ID %"
           PRIBinId " already in use.\n", int_node_bin_id);
      return false;
    }

    // Add the Bin ID to the Interior Node information.
    if (!int_info_.AddBinId(int_node_bin_id, int_node_bin_idx))
    {
      LogF(kClassName, __func__, "Error: Unable to add the interior node Bin "
           "ID %" PRIBinId ".\n", int_node_bin_id);
      return false;
    }

    // Add the Bin ID to the Bin ID to Bin Index mapping.
    bin_id_to_idx_[int_node_bin_id] = int_node_bin_idx;
  }

  // Extract the Multicast Group information.  These are all static multicast
  // groups.
  uint32_t  num_mcast_grps = config_info.GetUint("BinMap.NumMcastGroups", 0,
                                                 false);

  for (uint32_t j = 0; j < num_mcast_grps; ++j)
  {
    string  config_prefix("BinMap.McastGroup.");
    config_prefix.append(StringUtils::ToString(static_cast<int>(j)));

    // Add the static Multicast Group to the Multicast Group information.
    if (!mcast_info_.CfgAddMcastGrp(*this, bin_id_to_idx_, config_info,
                                    config_prefix, j))
    {
      LogF(kClassName, __func__, "Error: Unable to add the multicast group "
           "at index %" PRIu32 ".\n", j);
      return false;
    }
  }

  // Dump the configuration information to the log file.
  LogC(kClassName, __func__, "Bin Map configuration:\n");

  // Log Unicast Destination Bin ID information.
  BinId     bid  = 0;
  BinIndex  bidx = 0;

  for (bid = 0; bid <= kMaxUcastBinId; ++bid)
  {
    bidx = bin_id_to_idx_[bid];

    if ((bidx != kInvalidBinIndex) && (bidx >= dst_info_.offset_) &&
        (bidx < (dst_info_.offset_ + dst_info_.num_)))
    {
      LogC(kClassName, __func__, "Bin ID %" PRIBinId " (Idx %" PRIBinIndex
           "): %s\n", bid, bidx, dst_info_.ToString(bidx).c_str());
    }
  }

  // Log the Interior Node Bin ID information.
  for (bid = 0; bid <= kMaxBinId; ++bid)
  {
    bidx = bin_id_to_idx_[bid];

    if ((bidx != kInvalidBinIndex) && (bidx >= int_info_.offset_) &&
        (bidx < (int_info_.offset_ + int_info_.num_)))
    {
      LogC(kClassName, __func__, "Interior Node BinId %" PRIBinId " (Idx %"
           PRIBinIndex ")\n", bid, bidx);
    }
  }

  // Log Multicast ID information.
  for (size_t k = 0; k < mcast_info_.num_; ++k)
  {
    bidx = (mcast_info_.offset_ + static_cast<BinIndex>(k));

    LogC(kClassName, __func__, "Mcast Id %" PRIMcastId " (Idx %" PRIBinIndex
         "): %s\n", mcast_info_.idx_to_mcast_id_[k], bidx,
         mcast_info_.ToString(bidx).c_str());
  }

  LogC(kClassName, __func__, "Bin Map configuration complete\n");

  initialized_ = true;

  return true;
}

//============================================================================
bool BinMap::GetFirstUcastBinIndex(BinIndex& bin_idx) const
{
  if (dst_info_.num_ == 0)
  {
    bin_idx = kInvalidBinIndex;
    return false;
  }

  bin_idx = dst_info_.offset_;
  return true;
}

//============================================================================
bool BinMap::GetNextUcastBinIndex(BinIndex& bin_idx) const
{
  if ((bin_idx >= dst_info_.offset_) &&
      (static_cast<int32_t>(bin_idx) <
       (static_cast<int32_t>(dst_info_.offset_ + dst_info_.num_) - 1)))
  {
    ++bin_idx;
    return true;
  }

  bin_idx = kInvalidBinIndex;
  return false;
}

//============================================================================
bool BinMap::GetFirstIntNodeBinIndex(BinIndex& bin_idx) const
{
  if (int_info_.num_ == 0)
  {
    bin_idx = kInvalidBinIndex;
    return false;
  }

  bin_idx = int_info_.offset_;
  return true;
}

//============================================================================
bool BinMap::GetNextIntNodeBinIndex(BinIndex& bin_idx) const
{
  if ((bin_idx >= int_info_.offset_) &&
      (static_cast<int32_t>(bin_idx) <
       (static_cast<int32_t>(int_info_.offset_ + int_info_.num_) - 1)))
  {
    ++bin_idx;
    return true;
  }

  bin_idx = kInvalidBinIndex;
  return false;
}

//============================================================================
bool BinMap::GetFirstMcastBinIndex(BinIndex& bin_idx) const
{
  if (mcast_info_.num_ == 0)
  {
    bin_idx = kInvalidBinIndex;
    return false;
  }

  bin_idx = mcast_info_.offset_;
  return true;
}

//============================================================================
bool BinMap::GetNextMcastBinIndex(BinIndex& bin_idx) const
{
  if ((bin_idx >= mcast_info_.offset_) &&
      (static_cast<int32_t>(bin_idx) <
       (static_cast<int32_t>(mcast_info_.offset_ + mcast_info_.num_) - 1)))
  {
    ++bin_idx;
    return true;
  }

  bin_idx = kInvalidBinIndex;
  return false;
}

//============================================================================
bool BinMap::GetFirstDstBinIndex(BinIndex& bin_idx) const
{
  if (dst_info_.num_ == 0)
  {
    if (mcast_info_.num_ == 0)
    {
      bin_idx = kInvalidBinIndex;
      return false;
    }

    bin_idx = mcast_info_.offset_;
    return true;
  }

  bin_idx = dst_info_.offset_;
  return true;
}

//============================================================================
bool BinMap::GetNextDstBinIndex(BinIndex& bin_idx) const
{
  if ((bin_idx >= dst_info_.offset_) &&
      (bin_idx < (dst_info_.offset_ + dst_info_.num_)))
  {
    // The last BinIndex retrieved was in the range of destination bin
    // indices, so try to get the next destination BinIndex.
    if (static_cast<int32_t>(bin_idx) <
        (static_cast<int32_t>(dst_info_.offset_ + dst_info_.num_) - 1))
    {
      ++bin_idx;
      return true;
    }

    // There are no more destination bin indices, so return the first
    // multicast BinIndex.
    if (mcast_info_.num_ == 0)
    {
      bin_idx = kInvalidBinIndex;
      return false;
    }

    bin_idx = mcast_info_.offset_;
    return true;
  }

  // The last BinIndex retrieved was in the range of multicast bin indices, so
  // simply get the next multicast BinIndex.
  if ((bin_idx >= mcast_info_.offset_) &&
      (static_cast<int32_t>(bin_idx) <
       (static_cast<int32_t>(mcast_info_.offset_ + mcast_info_.num_) - 1)))
  {
    ++bin_idx;
    return true;
  }

  bin_idx = kInvalidBinIndex;
  return false;
}

//============================================================================
bool BinMap::GetFirstPhyBinIndex(BinIndex& bin_idx) const
{
  if (dst_info_.num_ == 0)
  {
    if (int_info_.num_ == 0)
    {
      bin_idx = kInvalidBinIndex;
      return false;
    }

    bin_idx = int_info_.offset_;
    return true;
  }

  bin_idx = dst_info_.offset_;
  return true;
}

//============================================================================
bool BinMap::GetNextPhyBinIndex(BinIndex& bin_idx) const
{
  if ((bin_idx >= dst_info_.offset_) &&
      (bin_idx < (dst_info_.offset_ + dst_info_.num_)))
  {
    // The last BinIndex retrieved was in the range of destination bin
    // indices, so try to get the next destination BinIndex.
    if (static_cast<int32_t>(bin_idx) <
        (static_cast<int32_t>(dst_info_.offset_ + dst_info_.num_) - 1))
    {
      ++bin_idx;
      return true;
    }

    // There are no more destination bin indices, so return the first interior
    // node BinIndex.
    if (int_info_.num_ == 0)
    {
      bin_idx = kInvalidBinIndex;
      return false;
    }

    bin_idx = int_info_.offset_;
    return true;
  }

  // The last BinIndex retrieved was in the range of interior node bin
  // indices, so simply get the next interior node BinIndex.
  if ((bin_idx >= int_info_.offset_) &&
      (static_cast<int32_t>(bin_idx) <
       (static_cast<int32_t>(int_info_.offset_ + int_info_.num_) - 1)))
  {
    ++bin_idx;
    return true;
  }

  bin_idx = kInvalidBinIndex;
  return false;
}

//============================================================================
bool BinMap::GetFirstBinIndex(BinIndex& bin_idx) const
{
  if (dst_info_.num_ == 0)
  {
    if (int_info_.num_ == 0)
    {
      if (mcast_info_.num_ == 0)
      {
        bin_idx = kInvalidBinIndex;
        return false;
      }

      bin_idx = mcast_info_.offset_;
      return true;
    }

    bin_idx = int_info_.offset_;
    return true;
  }

  bin_idx = dst_info_.offset_;
  return true;
}

//============================================================================
bool BinMap::GetNextBinIndex(BinIndex& bin_idx) const
{
  if ((bin_idx >= dst_info_.offset_) &&
      (bin_idx < (dst_info_.offset_ + dst_info_.num_)))
  {
    // The last BinIndex retrieved was in the range of unicast bin indices, so
    // try to get the next unicast BinIndex.
    if (static_cast<int32_t>(bin_idx) <
        (static_cast<int32_t>(dst_info_.offset_ + dst_info_.num_) - 1))
    {
      ++bin_idx;
      return true;
    }

    // There are no more unicast bin indices, so return the first interior
    // node or multicast BinIndex.
    if (int_info_.num_ == 0)
    {
      if (mcast_info_.num_ == 0)
      {
        bin_idx = kInvalidBinIndex;
        return false;
      }

      bin_idx = mcast_info_.offset_;
      return true;
    }

    bin_idx = int_info_.offset_;
    return true;
  }

  if ((bin_idx >= int_info_.offset_) &&
      (bin_idx < (int_info_.offset_ + int_info_.num_)))
  {
    // The last BinIndex retrieved was in the range of interior node bin
    // indices, so try to get the next interior node BinIndex.
    if (static_cast<int32_t>(bin_idx) <
        (static_cast<int32_t>(int_info_.offset_ + int_info_.num_) - 1))
    {
      ++bin_idx;
      return true;
    }

    // There are no more interior node bin indices, so return the first
    // multicast BinIndex.
    if (mcast_info_.num_ == 0)
    {
      bin_idx = kInvalidBinIndex;
      return false;
    }

    bin_idx = mcast_info_.offset_;
    return true;
  }

  // The last BinIndex retrieved was in the range of multicast bin indices, so
  // simply get the next multicast BinIndex.
  if ((bin_idx >= mcast_info_.offset_) &&
      (static_cast<int32_t>(bin_idx) <
       (static_cast<int32_t>(mcast_info_.offset_ + mcast_info_.num_) - 1)))
  {
    ++bin_idx;
    return true;
  }

  bin_idx = kInvalidBinIndex;
  return false;
}

//============================================================================
BinIndex BinMap::GetDstBinIndexFromAddress(const Ipv4Address& ip_addr) const
{
  if (ip_addr.IsMulticast())
  {
    // Look for an exact Multicast ID match.
    McastId  mcast_id = GetMcastIdFromAddress(ip_addr);

    for (size_t i = 0; i < mcast_info_.num_; ++i)
    {
      if (mcast_info_.idx_to_mcast_id_[i] == mcast_id)
      {
        return (mcast_info_.offset_ + i);
      }
    }
  }
  else
  {
    // Look for the IP address being within one of the unicast destination
    // subnets.
    for (size_t j = 0; j < dst_info_.num_; ++j)
    {
      for (size_t k = 0; k < dst_info_.ucast_dst_[j].num_subnets_; ++k)
      {
        if (dst_info_.ucast_dst_[j].subnet_[k].IsInSubnet(ip_addr))
        {
          return (dst_info_.offset_ + j);
        }
      }
    }
  }

  return kInvalidBinIndex;
}

//============================================================================
BinIndex BinMap::GetPhyBinIndex(BinId bin_id) const
{
  if (bin_id <= kMaxBinId)
  {
    // Direct look-up.
    return bin_id_to_idx_[bin_id];
  }

  return kInvalidBinIndex;
}

//============================================================================
BinIndex BinMap::GetMcastBinIndex(McastId mcast_id) const
{
  // Loop over all multicast groups, looking for a Multicast ID match.
  for (size_t i = 0; i < mcast_info_.num_; ++i)
  {
    if (mcast_info_.idx_to_mcast_id_[i] == mcast_id)
    {
      return (mcast_info_.offset_ + i);
    }
  }

  return kInvalidBinIndex;
}

//============================================================================
BinId BinMap::GetPhyBinId(BinIndex bin_idx) const
{
  // If this is a unicast destination BinIndex, then use its mappings.
  if ((bin_idx >= dst_info_.offset_) &&
      (bin_idx < (dst_info_.offset_ + kMaxNumDsts)))
  {
    return dst_info_.idx_to_bin_id_[(bin_idx - dst_info_.offset_)];
  }

  // If this is an interior node BinIndex, then use its mappings.
  if ((bin_idx >= int_info_.offset_) &&
      (bin_idx < (int_info_.offset_ + kMaxNumIntNodes)))
  {
    return int_info_.idx_to_bin_id_[(bin_idx - int_info_.offset_)];
  }

  return kInvalidBinId;
}

//============================================================================
McastId BinMap::GetMcastId(BinIndex bin_idx) const
{
  // If this is a multicast BinIndex, then use its mappings.
  if ((bin_idx >= mcast_info_.offset_) &&
      (bin_idx < (mcast_info_.offset_ + kMaxNumMcastGroups)))
  {
    return mcast_info_.idx_to_mcast_id_[(bin_idx - mcast_info_.offset_)];
  }

  return kInvalidMcastId;
}

//============================================================================
void BinMap::AddDstToMcastGroup(const Ipv4Address& mcast_addr,
                                BinIndex dst_bin_idx)
{
  // Only add the destination if this is a dynamic multicast group.
  PrivAddDstToMcastGroup(mcast_addr, dst_bin_idx, false, false);
}

//============================================================================
void BinMap::RemoveDstFromMcastGroup(const Ipv4Address& mcast_addr,
                                      BinIndex dst_bin_idx)
{
  if (!mcast_addr.IsMulticast())
  {
    LogW(kClassName, __func__, "Address %s is not a multicast address.\n",
         mcast_addr.ToString().c_str());
    return;
  }

  // Create a destination bit vector with just the unicast destination in it.
  DstVec  dst_vec = 0;

  dst_vec = AddBinToDstVec(dst_vec, dst_bin_idx);

  // Get the Multicast ID.
  McastId  mcast_id = GetMcastIdFromAddress(mcast_addr);

  // Look for the multicast group.
  BinIndex  mcast_bin_idx = mcast_info_.FindMcastGrp(mcast_id);

  if (mcast_bin_idx == kInvalidBinIndex)
  {
    LogE(kClassName, __func__, "Error, multicast group %s not found.\n",
         mcast_addr.ToString().c_str());
    return;
  }

  // Remove the destination from the dynamic multicast group.
  if (!mcast_info_.RemoveDst(mcast_bin_idx, dst_vec))
  {
    LogE(kClassName, __func__, "Error, unable to remove destination Bin "
         "Index %" PRIBinIndex " from multicast group %s.\n", dst_bin_idx,
         mcast_addr.ToString().c_str());
  }
}

//============================================================================
void BinMap::PurgeDstFromMcastGroups(BinIndex dst_bin_idx)
{
  // Create a destination bit vector with just the unicast destination in it.
  DstVec  dst_vec = 0;

  dst_vec = AddBinToDstVec(dst_vec, dst_bin_idx);

  // Remove the destination from all dynamic multicast groups.
  mcast_info_.PurgeDstFromDynMcastGrps(dst_vec);
}

//============================================================================
DstVec BinMap::GetMcastDst(BinIndex bin_idx) const
{
  return mcast_info_.GetDst(bin_idx);
}

//============================================================================
size_t BinMap::GetNumBinsInDstVec(DstVec dst_vec)
{
  size_t  count = 0;

  while (dst_vec != 0)
  {
    if ((dst_vec & static_cast<DstVec>(1)) != 0)
    {
      count++;
    }

    dst_vec = static_cast<DstVec>(dst_vec >> 1);
  }

  return count;
}

//============================================================================
bool BinMap::IsBinInDstVec(DstVec dst_vec, BinIndex bin_idx) const
{
  if ((bin_idx < dst_info_.offset_) ||
      (bin_idx >= (dst_info_.offset_ + dst_info_.num_)))
  {
    return false;
  }

  BinId  bin_id = dst_info_.idx_to_bin_id_[bin_idx - dst_info_.offset_];

  if ((bin_id == kInvalidBinId) || (bin_id > kMaxUcastBinId))
  {
    return false;
  }

  return (dst_vec & (static_cast<DstVec>(1) << bin_id));
}

//============================================================================
bool BinMap::IsOnlyBinInDstVec(DstVec dst_vec, BinIndex bin_idx) const
{
  if ((bin_idx < dst_info_.offset_) ||
      (bin_idx >= (dst_info_.offset_ + dst_info_.num_)))
  {
    return false;
  }

  BinId  bin_id = dst_info_.idx_to_bin_id_[bin_idx - dst_info_.offset_];

  if ((bin_id == kInvalidBinId) || (bin_id > kMaxUcastBinId))
  {
    return false;
  }

  return (dst_vec == (static_cast<DstVec>(1) << bin_id));
}

//============================================================================
DstVec BinMap::AddBinToDstVec(DstVec dst_vec, BinIndex bin_idx) const
{
  if ((bin_idx < dst_info_.offset_) ||
      (bin_idx >= (dst_info_.offset_ + dst_info_.num_)))
  {
    return dst_vec;
  }

  BinId  bin_id = dst_info_.idx_to_bin_id_[bin_idx - dst_info_.offset_];

  if ((bin_id == kInvalidBinId) || (bin_id > kMaxUcastBinId))
  {
    return dst_vec;
  }

  return (dst_vec | (static_cast<DstVec>(1) << bin_id));
}

//============================================================================
DstVec BinMap::RemoveBinFromDstVec(DstVec dst_vec, BinIndex bin_idx) const
{
  if ((bin_idx < dst_info_.offset_) ||
      (bin_idx >= (dst_info_.offset_ + dst_info_.num_)))
  {
    return dst_vec;
  }

  BinId  bin_id = dst_info_.idx_to_bin_id_[bin_idx - dst_info_.offset_];

  if ((bin_id == kInvalidBinId) || (bin_id > kMaxUcastBinId))
  {
    return dst_vec;
  }

  return (dst_vec & (~(static_cast<DstVec>(1) << bin_id)));
}

//============================================================================
DstVec BinMap::DstVecSubtract(DstVec original, DstVec subtract)
{
  // First, check if "subtract" is a subset of "original".  xor (^) sets 1's
  // where the two are different.  If any of the xor result 1 values are also
  // 1 in the "subtract" DstVec (i.e., xor_result & subtract), then "subtract"
  // was not a subset of "original".
  if (((original ^ subtract) & subtract) != 0)
  {
    LogF(kClassName, __func__, "Subtracting a DstVec 0x%X that is not a "
         "subset of the original DstVec 0x%X\n", subtract, original);
  }

  // Subtract by removing the 1's in "subtract" from "original".
  return (original & (~subtract));
}

//============================================================================
string BinMap::GetIdToLog(BinIndex bin_idx, bool suppress_m) const
{
  stringstream  ret_ss;

  if (IsUcastBinIndex(bin_idx))
  {
    ret_ss << "D" <<
      static_cast<uint32_t>(
        dst_info_.idx_to_bin_id_[(bin_idx - dst_info_.offset_)]);
  }
  else if (IsIntNodeBinIndex(bin_idx))
  {
    ret_ss << "I" <<
      static_cast<uint32_t>(
        int_info_.idx_to_bin_id_[(bin_idx - int_info_.offset_)]);
  }
  else if (IsMcastBinIndex(bin_idx))
  {
    if (!suppress_m)
    {
      ret_ss << "M";
    }

    ret_ss <<
      Ipv4Address(mcast_info_.idx_to_mcast_id_[
                    (bin_idx - mcast_info_.offset_)]).ToString();
  }
  else
  {
    ret_ss << "INVALID BIN";
  }

  return ret_ss.str();
}

//============================================================================
void BinMap::Print() const
{
  if (!WouldLogD(kClassName))
  {
    return;
  }

  LogD(kClassName, __func__, "Bin Map has %zu destination bin ids defined.\n",
       dst_info_.num_);

  stringstream  ss_id;
  stringstream  ss_idx;

  ss_id.str("");
  ss_idx.str("");

  BinIndex  idx = 0;

  for (bool valid = GetFirstUcastBinIndex(idx);
       valid;
       valid = GetNextUcastBinIndex(idx))
  {
    ss_id  << StringUtils::ToString(
      dst_info_.idx_to_bin_id_[idx - dst_info_.offset_]) << ", ";
    ss_idx << StringUtils::ToString(idx) << ", ";
  }

  LogD(kClassName, __func__, "Dest Bin IDs: [ %s].\n", ss_id.str().c_str());
  LogD(kClassName, __func__, "Dest Bin Indices: [ %s].\n",
       ss_idx.str().c_str());

  idx = 0;

  ss_id.str(std::string());
  ss_idx.str(std::string());

  for (bool valid = GetFirstIntNodeBinIndex(idx);
       valid;
       valid = GetNextIntNodeBinIndex(idx))
  {
    ss_id  << StringUtils::ToString(
      int_info_.idx_to_bin_id_[idx - int_info_.offset_]) << ", ";
    ss_idx << StringUtils::ToString(idx) << ", ";
  }

  LogD(kClassName, __func__, "Int Bin IDs: [ %s].\n", ss_id.str().c_str());
  LogD(kClassName, __func__, "Int Bin Indices: [ %s].\n",
       ss_idx.str().c_str());

  idx = 0;

  ss_id.str(std::string());
  ss_idx.str(std::string());

  for (bool valid = GetFirstMcastBinIndex(idx);
       valid;
       valid = GetNextMcastBinIndex(idx))
  {
    ss_id  << StringUtils::ToString(
      mcast_info_.idx_to_mcast_id_[idx - mcast_info_.offset_])
           << ", ";
    ss_idx << StringUtils::ToString(idx) << ", ";
  }

  LogD(kClassName, __func__, "Mcast IDs: [ %s].\n", ss_id.str().c_str());
  LogD(kClassName, __func__, "Mcast Bin Indices: [ %s].\n",
       ss_idx.str().c_str());
}

//============================================================================
void BinMap::PrivAddDstToMcastGroup(const Ipv4Address& mcast_addr,
                                    BinIndex dst_bin_idx, bool forced_add,
                                    bool static_grp)
{
  if (!mcast_addr.IsMulticast())
  {
    LogW(kClassName, __func__, "Address %s is not a multicast address.\n",
         mcast_addr.ToString().c_str());
    return;
  }

  // Create a destination bit vector with just the unicast destination in it.
  DstVec  dst_vec = 0;

  dst_vec = AddBinToDstVec(dst_vec, dst_bin_idx);

  // Get the Multicast ID.
  McastId  mcast_id = GetMcastIdFromAddress(mcast_addr);

  // Look for the multicast group.
  BinIndex  mcast_bin_idx = mcast_info_.FindMcastGrp(mcast_id);

  if (mcast_bin_idx == kInvalidBinIndex)
  {
    // The multicast group does not yet exist.  If forced_add is false, then
    // only create the multicast group if this will be a dynamic multicast
    // group.
    if ((!forced_add) && static_grp)
    {
      LogW(kClassName, __func__, "Cannot create static multicast group %s "
           "without forcing the addition.\n", mcast_addr.ToString().c_str());
      return;
    }

    // Add the multicast group as the correct type with the one destination
    // being requested.
    LogI(kClassName, __func__, "Multicast group %s does not exist.\n",
         mcast_addr.ToString().c_str());

    if (!mcast_info_.AddMcastGrp(mcast_addr, mcast_id, dst_vec, static_grp,
                                 mcast_bin_idx))
    {
      LogE(kClassName, __func__, "Error, unable to add multicast group %s.\n",
           mcast_addr.ToString().c_str());
      return;
    }

    LogI(kClassName, __func__, "Added new %s multicast group for %s with "
         "Multicast ID %" PRIMcastId " (Bin Index %" PRIBinIndex ").\n",
         (static_grp ? "static" : "dynamic"), mcast_addr.ToString().c_str(),
         mcast_id, mcast_bin_idx);

    return;
  }

  // Add the destination to the multicast group.
  if (!mcast_info_.AddDst(mcast_bin_idx, dst_vec, forced_add))
  {
    LogE(kClassName, __func__, "Error, unable to add destination Bin Index %"
         PRIBinIndex " to multicast group %s.\n", dst_bin_idx,
         mcast_addr.ToString().c_str());
  }
}

//****************************************************************************
// BinMap::Subnet methods.
//****************************************************************************

//============================================================================
bool BinMap::Subnet::Initialize(const string& network_str,
                                const string& prefix_len_str)
{
  int  num_mask_bits = StringUtils::GetInt(prefix_len_str, INT_MAX);

  if ((num_mask_bits < 0) || (num_mask_bits > 32))
  {
    LogF(kClassNameSN, __func__, "Error: Prefix length %d out of range. "
         "Must be between 0 and 32.\n", num_mask_bits);
    return false;
  }

  subnet_addr_ = network_str;
  prefix_len_  = num_mask_bits;

  if (num_mask_bits == 0)
  {
    subnet_mask_ = htonl(0);
  }
  else
  {
    subnet_mask_ = htonl((0xffffffffU << (32 - num_mask_bits)));
  }

  return true;
}

//============================================================================
bool BinMap::Subnet::IsInSubnet(const Ipv4Address& dst_addr) const
{
  // The masking is done in network byte order.
  return ((dst_addr.address() & subnet_mask_) ==
          (subnet_addr_.address() & subnet_mask_));
}

//============================================================================
string BinMap::Subnet::ToString() const
{
  string  ret_str;

  ret_str.append(subnet_addr_.ToString());
  ret_str.append("/");
  ret_str.append(StringUtils::ToString(prefix_len_));

  return ret_str;
}

//****************************************************************************
// BinMap::Dst methods.
//****************************************************************************

//============================================================================
bool BinMap::Dst::AddSubnet(const std::string& network_str,
                            const std::string& prefix_len_str)
{
  if (num_subnets_ >= kDefaultNumHostMasks)
  {
    LogF(kClassNameDT, __func__, "Error: Attempting to create more than "
         "the maximum allowed number of Subnets (%" PRIu8 ")\n",
         kDefaultNumHostMasks);
    return false;
  }

  // Initialize the next subnet in the array.
  if (!subnet_[num_subnets_].Initialize(network_str, prefix_len_str))
  {
    return false;
  }

  // The addition was a success.
  ++num_subnets_;

  return true;
}

//****************************************************************************
// BinMap::CommonBinIdxInfo methods.
//****************************************************************************

//============================================================================
bool BinMap::CommonBinIdxInfo::Initialize(BinIndex offset)
{
  offset_ = offset;
  num_    = 0;

  return true;
}

//****************************************************************************
// BinMap::DstInfo methods.
//****************************************************************************

//============================================================================
bool BinMap::DstInfo::Initialize(BinIndex offset)
{
  if (!CommonBinIdxInfo::Initialize(offset))
  {
    return false;
  }

  // Initialize the Bin Index to Bin ID mapping entries to the invalid Bin ID
  // value.  The Dst constructor already has initialized the ucast_dst_ array
  // elements.
  for (BinIndex i = 0; i < kMaxNumDsts; ++i)
  {
    idx_to_bin_id_[i] = kInvalidBinId;
  }

  return true;
}

//============================================================================
bool BinMap::DstInfo::AddBinId(const ConfigInfo& config_info,
                               const string& bin_id_str, BinId bin_id,
                               BinIndex& bin_idx)
{
  if (num_ >= kMaxNumDsts)
  {
    LogF(kClassNameDI, __func__, "Error: Attempting to create more than "
         "the maximum allowed number of unicast destination bins (%" PRIu32
         ")\n", kMaxNumDsts);
    return false;
  }

  // Extract the BinId.x.HostMasks value from the configuration file.
  string  config_prefix  = "BinMap.BinId." + bin_id_str;
  string  host_masks_str = config_info.Get(config_prefix + ".HostMasks", "");

  if (host_masks_str.empty())
  {
    LogF(kClassNameDI, __func__, "Configuration must include HostMasks "
         "value for Bin ID %" PRIBinId ".\n", bin_id);
    return false;
  }

  // Tokenize the host_masks string so we can create and initialize the
  // required number of Subnet objects.
  List<string>  host_masks;

  StringUtils::Tokenize(host_masks_str, ",", host_masks);

  while (host_masks.size() > 0)
  {
    string  host_mask_str;

    host_masks.Pop(host_mask_str);

    List<string>  host_mask_parts;

    StringUtils::Tokenize(host_mask_str, "/", host_mask_parts);

    string  network_str;
    string  prefix_len_str;

    if (host_mask_parts.size() < 2)
    {
      network_str    = host_mask_str;
      prefix_len_str = "32";
    }
    else
    {
      host_mask_parts.Pop(network_str);
      host_mask_parts.Pop(prefix_len_str);
    }

    if (!ucast_dst_[num_].AddSubnet(network_str, prefix_len_str))
    {
      LogW(kClassNameDI, __func__, "Unable to add a new Subnet object for "
           "Bin ID %" PRIBinId ".\n", bin_id);
      return false;
    }
  }

  // The addition was a success.  Update the mappings and return the newly
  // assigned Bin Index.
  idx_to_bin_id_[num_] = bin_id;
  bin_idx              = (offset_ + num_);
  ++num_;

  return true;
}

//============================================================================
string BinMap::DstInfo::ToString(BinIndex bin_idx)
{
  string  ret_str;

  if ((bin_idx >= offset_) && (bin_idx < (offset_ + num_)))
  {
    size_t  idx = (bin_idx - offset_);

    ret_str.append("Host Masks: ");

    for (size_t i = 0; i < ucast_dst_[idx].num_subnets_; ++i)
    {
      if (i != 0)
      {
        ret_str.append(", ");
      }

      Ipv4Address  sna     = ucast_dst_[idx].subnet_[i].GetSubnetAddress();
      string       sna_str = sna.ToString();
      int          pfx_len = ucast_dst_[idx].subnet_[i].GetPrefixLength();

      ret_str.append(sna_str);
      ret_str.append("/");
      ret_str.append(StringUtils::ToString(pfx_len));
    }
  }
  else
  {
    ret_str.append("No info");
  }

  return ret_str;
}

//****************************************************************************
// BinMap::IntInfo methods.
//****************************************************************************

//============================================================================
bool BinMap::IntInfo::Initialize(BinIndex offset)
{
  if (!CommonBinIdxInfo::Initialize(offset))
  {
    return false;
  }

  // Initialize the Bin Index to Bin ID mapping entries to the invalid Bin ID
  // value.
  for (BinIndex i = 0; i < kMaxNumIntNodes; ++i)
  {
    idx_to_bin_id_[i] = kInvalidBinId;
  }

  return true;
}

//============================================================================
bool BinMap::IntInfo::AddBinId(BinId bin_id, BinIndex& bin_idx)
{
  if (num_ >= kMaxNumIntNodes)
  {
    LogF(kClassNameII, __func__, "Error: Attempting to create more than "
         "the maximum allowed number of interior nodes (%" PRIu32 ")\n",
         kMaxNumIntNodes);
    return false;
  }

  // The addition was a success.  Update the mappings and return the newly
  // assigned Bin Index.
  idx_to_bin_id_[num_] = bin_id;
  bin_idx              = (offset_ + num_);
  ++num_;

  return true;
}

//****************************************************************************
// BinMap::McastInfo methods.
//****************************************************************************

//============================================================================
bool BinMap::McastInfo::Initialize(BinIndex offset)
{
  if (!CommonBinIdxInfo::Initialize(offset))
  {
    return false;
  }

  // Initialize the Bin Index to Multicast ID mapping entries to the invalid
  // Multicast ID value.
  for (BinIndex i = 0; i < kMaxNumMcastGroups; ++i)
  {
    idx_to_mcast_id_[i] = kInvalidMcastId;
    mcast_addr_[i].set_address(0);
    mcast_dst_[i]       = 0;
    static_grp_[i]      = false;
  }

  return true;
}

//============================================================================
BinIndex BinMap::McastInfo::FindMcastGrp(McastId mcast_id)
{
  for (size_t i = 0; i < num_; ++i)
  {
    if (mcast_id == idx_to_mcast_id_[i])
    {
      return (offset_ + i);
    }
  }

  return kInvalidBinIndex;
}

//============================================================================
bool BinMap::McastInfo::AddMcastGrp(const iron::Ipv4Address& mcast_addr,
                                    McastId mcast_id, DstVec dsts,
                                    bool static_grp, BinIndex& bin_idx)
{
  if (num_ >= kMaxNumMcastGroups)
  {
    LogE(kClassNameMI, __func__, "Error: Attempting to create more than "
         "the maximum allowed number of multicast groups (%" PRIu32 ")\n",
         kMaxNumMcastGroups);
    return false;
  }

  // Make sure that the multicast address is not already specified.
  for (size_t i = 0; i < num_; ++i)
  {
    if (mcast_id == idx_to_mcast_id_[i])
    {
      LogE(kClassNameMI, __func__, "Error, multicast group %s is already "
           "present.\n", mcast_addr.ToString().c_str());
      return false;
    }
  }

  // The addition was a success.  Update the group's mappings, address, and
  // destination bit vector.  Return the assigned Bin Index.
  idx_to_mcast_id_[num_] = mcast_id;
  mcast_addr_[num_]      = mcast_addr;
  mcast_dst_[num_]       = dsts;
  static_grp_[num_]      = static_grp;
  bin_idx                = (offset_ + num_);
  ++num_;

  return true;
}

//============================================================================
bool BinMap::McastInfo::CfgAddMcastGrp(const BinMap& bin_map,
                                       const BinIndex* id_map,
                                       const ConfigInfo& config_info,
                                       const string& config_prefix,
                                       uint32_t config_idx)
{
  if (num_ >= kMaxNumMcastGroups)
  {
    LogF(kClassNameMI, __func__, "Error: Attempting to create more than "
         "the maximum allowed number of multicast groups (%" PRIu32 ")\n",
         kMaxNumMcastGroups);
    return false;
  }

  // Extract the BinMap.McastGroup.N.Addr and BinMap.McastGroup.N.Members
  // values from the configuration file.
  string  mcast_addr_str    = config_info.Get(config_prefix + ".Addr", "");
  string  mcast_members_str = config_info.Get(config_prefix + ".Members", "");

  if ((mcast_addr_str.empty()) || (mcast_members_str.empty()))
  {
    LogF(kClassNameMI, __func__, "Configuration of multicast group at index %"
         PRIu32 " must include Addr and Members values.\n", config_idx);
    return false;
  }

  // Parse the multicast address and validate it.
  Ipv4Address  mcast_addr;

  if ((!mcast_addr.SetAddress(mcast_addr_str)) || (!mcast_addr.IsMulticast()))
  {
    LogF(kClassNameMI, __func__, "Configuration of multicast group at index %"
         PRIu32 " has invalid Addr value (%s).\n", config_idx,
         mcast_addr_str.c_str());
    return false;
  }

  // Make sure that the multicast address is not already specified.
  for (size_t i = 0; i < num_; ++i)
  {
    if (mcast_addr == mcast_addr_[i])
    {
      LogF(kClassNameMI, __func__, "Configuration of multicast group at "
           "index %" PRIu32 " (%s) repeats an existing or reserved multicast "
           "group.\n", config_idx, mcast_addr_str.c_str());
      return false;
    }
  }

  // Tokenize the group member string so we can create the group destination
  // bit vector.
  DstVec        mcast_dst_vec = 0;
  List<string>  mcast_members;

  StringUtils::Tokenize(mcast_members_str, ",", mcast_members);

  while (mcast_members.size() > 0)
  {
    string  mcast_member_str;

    mcast_members.Pop(mcast_member_str);

    BinId  mcast_member_bin_id = StringUtils::GetUint(mcast_member_str,
                                                      kInvalidBinId);

    // Validate the member Bin ID specified.
    if ((mcast_member_bin_id == kInvalidBinId) ||
        (mcast_member_bin_id > kMaxUcastBinId))
    {
      LogF(kClassNameMI, __func__, "Configuration of multicast group at "
           "index %" PRIu32 " (%s) includes invalid Members value (%s).\n",
           config_idx, mcast_addr_str.c_str(), mcast_member_str.c_str());
      return false;
    }

    // Convert the member Bin ID to a Bin Index and make sure that it is a
    // Unicast Destination Bin Index.
    BinIndex  member_mcast_bin_idx = id_map[mcast_member_bin_id];

    if ((member_mcast_bin_idx == kInvalidBinIndex) ||
        (!bin_map.IsUcastBinIndex(member_mcast_bin_idx)))
    {
      LogF(kClassNameMI, __func__, "Configuration of multicast group at "
           "index %" PRIu32 " (%s) includes non-destination Members value "
           "(%s).\n", config_idx, mcast_addr_str.c_str(),
           mcast_member_str.c_str());
      return false;
    }

    // Add the member to the group's destination bit vector.
    DstVec  tmp = (static_cast<DstVec>(1) << mcast_member_bin_id);

    mcast_dst_vec |= tmp;
  }

  // The addition was a success.  Update the group's mappings, address, and
  // destination bit vector.  This is a static multicast group.
  idx_to_mcast_id_[num_] = bin_map.GetMcastIdFromAddress(mcast_addr);
  mcast_addr_[num_]      = mcast_addr;
  mcast_dst_[num_]       = mcast_dst_vec;
  static_grp_[num_]      = true;
  ++num_;

  return true;
}

//============================================================================
DstVec BinMap::McastInfo::GetDst(BinIndex mcast_bin_idx) const
{
  if ((mcast_bin_idx >= offset_) && (mcast_bin_idx < (offset_ + num_)))
  {
    return mcast_dst_[(mcast_bin_idx - offset_)];
  }

  return 0;
}

//============================================================================
bool BinMap::McastInfo::AddDst(BinIndex mcast_bin_idx, DstVec dst_vec,
                               bool forced_add)
{
  if ((mcast_bin_idx >= offset_) && (mcast_bin_idx < (offset_ + num_)))
  {
    // Only modify the destination bit vector if this add is being forced or
    // if this is a dynamic multicast group.
    if (forced_add || (!static_grp_[(mcast_bin_idx - offset_)]))
    {
      mcast_dst_[(mcast_bin_idx - offset_)] |= dst_vec;
    }

    return true;
  }

  return false;
}

//============================================================================
bool BinMap::McastInfo::RemoveDst(BinIndex mcast_bin_idx, DstVec dst_vec)
{
  if ((mcast_bin_idx >= offset_) && (mcast_bin_idx < (offset_ + num_)))
  {
    // Only modify the destination bit vector if this is a dynamic multicast
    // group.
    if (!static_grp_[(mcast_bin_idx - offset_)])
    {
      mcast_dst_[(mcast_bin_idx - offset_)] &= (~(dst_vec));
    }

    return true;
  }

  return false;
}

//============================================================================
void BinMap::McastInfo::PurgeDstFromDynMcastGrps(DstVec dst_vec)
{
  DstVec  tmp = (~(dst_vec));

  for (size_t idx = 0; idx < num_; ++idx)
  {
    // Only modify the destination bit vector if this is a dynamic multicast
    // group.
    if (!static_grp_[idx])
    {
      mcast_dst_[idx] &= tmp;
    }
  }
}

//============================================================================
string BinMap::McastInfo::ToString(BinIndex bin_idx)
{
  string  ret_str;

  if ((bin_idx >= offset_) && (bin_idx < (offset_ + num_)))
  {
    size_t  idx = (bin_idx - offset_);

    ret_str.append("Mcast Address: ");
    ret_str.append(mcast_addr_[idx].ToString());
    ret_str.append("  Dest Bin Ids:");

    for (uint32_t i = 0; i < kDstVecBitsUsed; ++i)
    {
      if ((mcast_dst_[idx] & (static_cast<DstVec>(1) << i)) != 0)
      {
        ret_str.append(" ");
        ret_str.append(StringUtils::ToString(i));
      }
    }

    ret_str.append("  (DstVec ");
    ret_str.append(StringUtils::ToString(mcast_dst_[idx]));
    ret_str.append(")");

    if (static_grp_[idx])
    {
      ret_str.append("  Static");
    }
    else
    {
      ret_str.append("  Dynamic");
    }
  }
  else
  {
    ret_str.append("No info");
  }

  return ret_str;
}
