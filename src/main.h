// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef IDENTIFI_MAIN_H
#define IDENTIFI_MAIN_H

#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "script.h"
#include "identifidb.h"

#include <list>

class CKeyItem;
class CReserveKey;

class CAddress;
class CInv;
class CNode;


/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 1000000;
/** The maximum size for mined blocks */
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = MAX_BLOCK_SIZE_GEN/5;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
/** The maximum number of orphan transactions kept in memory */
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100;
/** The maximum number of entries in an 'inv' protocol message */
static const unsigned int MAX_INV_SZ = 50000;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** Fake height value used in CCoins to signify they are only in the memory pool (since 0.8) */
static const unsigned int MEMPOOL_HEIGHT = 0x7FFFFFFF;
/** Fees smaller than this (in satoshi) are considered zero fee (for transaction creation) */
static const int64 MIN_TX_FEE = 10000;
/** Fees smaller than this (in satoshi) are considered zero fee (for relaying) */
static const int64 MIN_RELAY_TX_FEE = 10000;
/** No amount larger than this (in satoshi) is valid */
static const int64 MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
/** Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp. */
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
/** Maximum number of script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 16;
#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif






extern CCriticalSection cs_main;
extern const std::string strMessageMagic;
extern int64 nTimeBestReceived;
extern unsigned char pchMessageStart[4];
extern bool fImporting;
extern bool fReindex;
extern bool fBenchmark;

// Minimum disk space required - used in CheckDiskSpace()
static const uint64 nMinDiskSpace = 52428800;


class CReserveKey;
class CIdentifiDB;

/** Verify consistency of the block and coin databases */
bool VerifyDB();
/** Process protocol messages received from a given node */
bool ProcessMessages(CNode* pfrom);
/** Send queued protocol messages to be sent to a give node */
bool SendMessages(CNode* pto, bool fSendTrickle);
/** Get the number of active peers */
int GetNumBlocksOfPeers();
/** Format a string that describes several potential problems detected by the core */
std::string GetWarnings(std::string strFor);
/** Retrieve a transaction (from memory pool, or from disk, if possible) */
/** Abort with a message */
bool AbortNode(const std::string &msg);


extern CIdentifiDB* pidentifidb;

#endif
