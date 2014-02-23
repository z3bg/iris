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
    vector<CIdentifiPacket> GetLatestPackets(int limit = 10, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsAfterTimestamp(time_t timestamp, int limit = 500, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsAfterPacket(string packetHash, int limit = 500, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByIdentifier(string_pair identifier, bool trustPathablePredicatesOnly = false, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByAuthor(string_pair author, bool trustPathablePredicatesOnly = false, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByRecipient(string_pair object, bool trustPathablePredicatesOnly = false, bool showUnpublished = true);
    string SavePacket(CIdentifiPacket &packet);
    void SavePacketSignature(CSignature &signature, string packetHash);
    void SetDefaultKey(string privKey);
    CKey GetDefaultKey();
    vector<IdentifiKey> GetMyKeys();
    vector<string> GetMyPubKeyIDs();
    vector<string> GetMyPubKeys();
    string GetSavedKeyID(string pubKey);
    bool ImportPrivKey(string privKey, bool setDefault=false);
    int GetPacketCount();
    int GetPacketCountByAuthor(string_pair author);
    int GetIdentifierCount();
    string GetTrustStep(string_pair start, string_pair end);
    CIdentifiPacket GetPacketByHash(string hash);
    int GetPriority(CIdentifiPacket &packet);
    string_pair GetLinkedIdentifier(string_pair startID, vector<string> searchedPredicates);
    pair<string_pair, string_pair > GetPacketLinkedIdentifiers(CIdentifiPacket &packet, vector<string> searchedPredicates);    bool MakeFreeSpace(int nFreeBytesNeeded);
    void DropPacket(string strPacketHash);
    time_t GetLatestPacketTimestamp();
    vector<CIdentifiPacket> GetSavedPath(string_pair start, string_pair end, int searchDepth = 5, vector<uint256>* visitedPackets = 0);
    vector<CIdentifiPacket> SearchForPath(string_pair start, string_pair end = make_pair("", ""), bool savePath = true, int searchDepth = 5, vector<uint256>* visitedPackets = 0);
    vector<CIdentifiPacket> GetPath(string_pair start, string_pair end = make_pair("", ""), bool savePath = true, int searchDepth = 5, vector<uint256>* visitedPackets = 0);
    void SaveTrustStep(string_pair start, pair<string,string> end, string nextStep);
    void SavePacketTrustPaths(CIdentifiPacket &packet);

private:
    sqlite3 *db;
    vector<string_pair > GetAuthorsByPacketHash(string packetHash);
    vector<string_pair > GetRecipientsByPacketHash(string packetHash);
    vector<CSignature> GetSignaturesByPacketHash(string packetHash);
    CIdentifiPacket GetPacketFromStatement(sqlite3_stmt *statement);
    void SavePacketAuthor(string packetHash, int predicateID, int authorID);
    void SavePacketRecipient(string packetHash, int predicateID, int authorID);
    int SavePredicate(string predicate);
    int SaveIdentifier(string identifier);
    bool SavePubKey(string pubKey);
    vector<vector<string> > query(const char* query);
    void CheckDefaultKey();
    void CheckDefaultTrustList();
    void SetMaxSize(int sqliteMaxSize);
    void CheckDefaultTrustPathablePredicates();
    void SearchForPathForMyKeys();
    bool HasTrustedSigner(CIdentifiPacket &packet, vector<string> trustedKeyIDs, vector<uint256>* visitedPackets);
};

#endif // IDENTIFI_IDENTIFIDB_H
