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
    vector<CIdentifiPacket> GetPacketsByIdentifier(pair<string, string> identifier, bool trustPathablePredicatesOnly = false, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByAuthor(pair<string, string> author, bool trustPathablePredicatesOnly = true, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByRecipient(pair<string, string> object, bool trustPathablePredicatesOnly = true, bool showUnpublished = true);
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
    int GetPriority(CIdentifiPacket &packet);
    bool MakeFreeSpace(int nFreeBytesNeeded);
    void DropPacket(string strPacketHash);
    time_t GetLatestPacketTimestamp();
    vector<CIdentifiPacket> GetSavedPath(pair<string, string> start, pair<string, string> end, int searchDepth = 5, vector<uint256>* visitedPackets = 0);
    vector<CIdentifiPacket> SearchForPath(pair<string, string> start, pair<string, string> end = make_pair("", ""), bool savePath = true, int searchDepth = 5, vector<uint256>* visitedPackets = 0);
    vector<CIdentifiPacket> GetPath(pair<string, string> start, pair<string, string> end = make_pair("", ""), bool savePath = true, int searchDepth = 5, vector<uint256>* visitedPackets = 0);
    void SaveTrustStep(pair<string, string> start, pair<string,string> end, string nextStep);
    void SavePacketTrustPaths(CIdentifiPacket &packet);

private:
    sqlite3 *db;
    vector<pair<string, string> > GetAuthorsByPacketHash(string packetHash);
    vector<pair<string, string> > GetRecipientsByPacketHash(string packetHash);
    vector<CSignature> GetSignaturesByPacketHash(string packetHash);
    CIdentifiPacket GetPacketFromStatement(sqlite3_stmt *statement);
    void SavePacketAuthor(string packetHash, int predicateID, string authorHash);
    void SavePacketRecipient(string packetHash, int predicateID, string objectHash);
    int SavePredicate(string predicate);
    string SaveIdentifier(string identifier);
    vector<vector<string> > query(const char* query);
    void CheckDefaultKey();
    void CheckDefaultTrustList();
    void SetMaxSize(int sqliteMaxSize);
    void CheckDefaultUniquePredicates();
    void SearchForPathForMyKeys();
    bool HasTrustedSigner(CIdentifiPacket &packet, vector<string> trustedKeys, vector<uint256>* visitedPackets);
};

#endif // IDENTIFI_IDENTIFIDB_H
