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
    vector<CIdentifiPacket> GetLatestPackets(int limit = 10, int offset = 0, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsAfterTimestamp(time_t timestamp, int limit = 500, int offset = 0, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsAfterPacket(string packetHash, int limit = 500, int offset = 0, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsBeforePacket(string packetHash, int limit = 500, int offset = 0, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByIdentifier(string_pair identifier, int limit = 0, int offset = 0, bool trustPathablePredicatesOnly = false, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByAuthor(string_pair author, int limit = 0, int offset = 0, bool trustPathablePredicatesOnly = false, bool showUnpublished = true);
    vector<CIdentifiPacket> GetPacketsByRecipient(string_pair object, int limit = 0, int offset = 0, bool trustPathablePredicatesOnly = false, bool showUnpublished = true);
    vector<string_pair> SearchForID(string_pair query, int limit = 50, int offset = 0, bool trustPathablePredicatesOnly = false);
    string SavePacket(CIdentifiPacket &packet);
    void SetDefaultKey(string privKey);
    CKey GetDefaultKey();
    vector<IdentifiKey> GetMyKeys();
    vector<string> GetMyPubKeyIDs();
    vector<string> GetMyPubKeys();
    string GetSavedKeyID(string pubKey);
    bool ImportPrivKey(string privKey, bool setDefault=false);
    CKey GetNewKey();
    vector<CIdentifiPacket> GetConnectingPackets(string_pair id1, string_pair id2, int limit = 0, int offset = 0, bool showUnpublished = true);
    int GetPacketCount();
    int GetPacketCountByAuthor(string_pair author);
    int GetIdentifierCount();
    string GetTrustStep(string_pair start, string_pair end);
    CIdentifiPacket GetPacketByHash(string hash);
    int GetPriority(CIdentifiPacket &packet);
    vector<LinkedID> GetLinkedIdentifiers(string_pair startID, vector<string> searchedPredicates, int limit = 0, int offset = 0);
    pair<string, string> GetPacketLinkedNames(CIdentifiPacket &packet, bool cachedOnly = false);
    bool MakeFreeSpace(int nFreeBytesNeeded);
    void DropPacket(string strPacketHash);
    time_t GetLatestPacketTimestamp();
    vector<CIdentifiPacket> GetSavedPath(string_pair start, string_pair end, int searchDepth = 5);
    vector<CIdentifiPacket> SearchForPath(string_pair start, string_pair end = make_pair("", ""), bool savePath = true, int searchDepth = 3);
    vector<CIdentifiPacket> GetPath(string_pair start, string_pair end = make_pair("", ""), bool savePath = true, int searchDepth = 3);
    void SaveTrustStep(string_pair start, string_pair end, string nextStep, int distance);
    void SavePacketTrustPaths(CIdentifiPacket &packet);
    IDOverview GetIDOverview(string_pair id);
    string GetName(string_pair id, bool cachedOnly = false);
    string GetCachedName(string_pair id);
private:
    sqlite3 *db;
    vector<string_pair> GetAuthorsOrRecipientsByPacketHash(string packetHash, bool isRecipient);
    vector<string_pair > GetAuthorsByPacketHash(string packetHash);
    vector<string_pair > GetRecipientsByPacketHash(string packetHash);
    CIdentifiPacket GetPacketFromStatement(sqlite3_stmt *statement);
    vector<CIdentifiPacket> GetPacketsByAuthorOrRecipient(string_pair author, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished, bool isRecipient);
    void SavePacketAuthorOrRecipient(string packetHash, int predicateID, int identifierID, bool isRecipient);
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
    bool HasTrustedSigner(CIdentifiPacket &packet, vector<string> trustedKeyIDs);
    void UpdateCachedName(string_pair startID, string name);
};

#endif // IDENTIFI_IDENTIFIDB_H
