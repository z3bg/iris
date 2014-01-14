// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef IDENTIFI_IDENTIFIDB_H
#define IDENTIFI_IDENTIFIDB_H

#include <boost/filesystem/path.hpp>
#include <sqlite3.h>
#include <vector>
#include <string>
#include "base58.h"
#include "main.h"
#include "data.h"

using namespace std;

class CIdentifiDB
{
public:
    CIdentifiDB(int sqliteMaxSize = 1000, const boost::filesystem::path &filename = (GetDataDir() / "db.sqlite"));
    ~CIdentifiDB();
    void Initialize();
    vector<CIdentifiPacket> GetPacketsAfterTimestamp(time_t timestamp, int limit = 500, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsAfterPacket(string packetHash, int limit = 500, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByIdentifier(pair<string, string> identifier, bool uniquePredicatesOnly = false, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByAuthor(pair<string, string> author, bool uniquePredicatesOnly = true, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByRecipient(pair<string, string> object, bool uniquePredicatesOnly = true, bool showUnpublished = true);
    string SavePacket(CIdentifiPacket &packet);
    void SavePacketSignature(CSignature &signature, string packetHash);
    void SetDefaultKey(string privKey);
    CKey GetDefaultKey();
    vector<pair<string, string> > GetMyKeys();
    vector<string> GetMyPubKeys();
    bool ImportPrivKey(string privKey, bool setDefault=false);
    int GetPacketCount();
    int GetPacketCountByAuthor(pair<string, string> author);
    int GetIdentifierCount();
    CIdentifiPacket GetPacketByHash(string hash);
    vector<CIdentifiPacket> GetPath(pair<string, string> start, pair<string, string> end, int searchDepth = 3, vector<uint256>* visitedPackets = 0);
    int GetPriority(CIdentifiPacket &packet);
    bool MakeFreeSpace(int nFreeBytesNeeded);
    void DropPacket(string strPacketHash);
    time_t GetLatestPacketTimestamp();
private:
    sqlite3 *db;
    vector<pair<string, string> > GetSubjectsByPacketHash(string packetHash);
    vector<pair<string, string> > GetObjectsByPacketHash(string packetHash);
    vector<CSignature> GetSignaturesByPacketHash(string packetHash);
    CIdentifiPacket GetPacketFromStatement(sqlite3_stmt *statement);
    void SavePacketSubject(string packetHash, int predicateID, string subjectHash);
    void SavePacketObject(string packetHash, int predicateID, string objectHash);
    int SavePredicate(string predicate);
    string SaveIdentifier(string identifier);
    vector<vector<string> > query(const char* query);
    void CheckDefaultKey();
    void CheckDefaultTrustList();
    void SetMaxSize(int sqliteMaxSize);
    void CheckDefaultUniquePredicates();
    bool HasTrustedSigner(CIdentifiPacket &packet, vector<string> trustedKeys, vector<uint256>* visitedPackets);
};

#endif // IDENTIFI_IDENTIFIDB_H
