// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef IDENTIFI_IDENTIFIDB_H
#define IDENTIFI_IDENTIFIDB_H

#include <boost/filesystem/path.hpp>
#include <sqlite3.h>
#include <vector>
#include <queue>
#include <string>
#include "base58.h"
#include "main.h"
#include "data.h"
#include "addrman.h"

using namespace std;

class CIdentifiDB
{
public:
    CIdentifiDB(int sqliteMaxSize = 1000, const boost::filesystem::path &filename = (GetDataDir() / "db.sqlite"));
    ~CIdentifiDB();
    void Initialize();
    vector<CIdentifiPacket> GetLatestPackets(int limit = 10, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "");
    vector<CIdentifiPacket> GetPacketsAfterTimestamp(time_t timestamp, int limit = 500, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "");
    vector<CIdentifiPacket> GetPacketsAfterPacket(string packetHash, int limit = 500, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "");
    vector<CIdentifiPacket> GetPacketsBeforePacket(string packetHash, int limit = 500, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "");
    vector<CIdentifiPacket> GetPacketsByIdentifier(string_pair identifier, int limit = 0, int offset = 0, bool trustPathablePredicatesOnly = false, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "", bool latestOnly = false);
    vector<CIdentifiPacket> GetPacketsByAuthor(string_pair author, int limit = 0, int offset = 0, bool trustPathablePredicatesOnly = false, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "", bool latestOnly = false);
    vector<CIdentifiPacket> GetPacketsByRecipient(string_pair object, int limit = 0, int offset = 0, bool trustPathablePredicatesOnly = false, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "", bool latestOnly = false);
    vector<CIdentifiPacket> GetPacketsBySigner(string_pair keyID);
    vector<CIdentifiPacket> GetConnectingPackets(string_pair id1, string_pair id2, int limit = 0, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "");
    vector<LinkedID> GetLinkedIdentifiers(string_pair startID, vector<string> searchedPredicates, int limit = 0, int offset = 0, string_pair viewpoint = make_pair("",""), int maxDistance = 0);
    vector<CIdentifiPacket> GetSavedPath(string_pair start, string_pair end, int searchDepth = 5);
    vector<CIdentifiPacket> SearchForPath(string_pair start, string_pair end = make_pair("",""), bool savePath = true, int searchDepth = 3);
    vector<CIdentifiPacket> GetPath(string_pair start, string_pair end = make_pair("",""), bool savePath = true, int searchDepth = 3);
    vector<string_pair> SearchForID(string_pair query, int limit = 50, int offset = 0, bool trustPathablePredicatesOnly = false, string_pair viewpoint = make_pair("",""), int maxDistance = 0);
    string SavePacket(CIdentifiPacket &packet);
    void SavePacketTrustPaths(CIdentifiPacket &packet);
    void SetDefaultKey(string privKey);
    CKey GetDefaultKey();
    CKey GetDefaultKeyFromDB();
    vector<IdentifiKey> GetMyKeys();
    vector<string>& GetMyPubKeyIDs();
    vector<string>& GetMyPubKeyIDsFromDB();
    vector<string> GetMyPubKeys();
    string GetSavedKeyID(string pubKey);
    bool ImportPrivKey(string privKey, bool setDefault=false);
    CKey GetNewKey();
    int GetPacketCount();
    int GetPacketCountByAuthor(string_pair author);
    int GetIdentifierCount();
    void UpdateIsLatest(CIdentifiPacket &packet);
    void UpdatePacketPriorities(string_pair authorOrSigner);
    string GetTrustStep(string_pair start, string_pair end);
    CIdentifiPacket GetPacketByHash(string hash);
    void SetPacketPriority(string packetHash, int priority);
    int GetPriority(CIdentifiPacket &packet);
    pair<string, string> GetPacketLinkedNames(CIdentifiPacket &packet, bool cachedOnly = false);
    pair<string, string> GetPacketLinkedEmails(CIdentifiPacket &packet, bool authorOnly = false);
    bool MakeFreeSpace(int nFreeBytesNeeded);
    void DropPacket(string strPacketHash);
    void DeleteTrustPathsByPacket(string strPacketHash);
    time_t GetLatestPacketTimestamp();
    void SaveTrustStep(string_pair start, string_pair end, string nextStep, int distance);
    IDOverview GetIDOverview(string_pair id, string_pair viewpoint = make_pair("",""), int maxDistance = 0);
    string GetName(string_pair id, bool cachedOnly = false);
    string GetCachedName(string_pair id);
    string GetCachedEmail(string_pair id);
    int GetTrustMapSize(string_pair id);
    bool GenerateTrustMap(string_pair id, int searchDepth = 2);
    
    // Integrated from CAddrDB
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
    boost::filesystem::path pathAddr;
private:
    sqlite3 *db;
    CKey defaultKey;
    struct trustMapQueueItem { string_pair id; int searchDepth; };
    queue<trustMapQueueItem> generateTrustMapQueue;
    set<string_pair> generateTrustMapSet;
    vector<string> myPubKeyIDs;
    vector<string_pair> GetAuthorsOrRecipientsByPacketHash(string packetHash, bool isRecipient);
    vector<string_pair > GetAuthorsByPacketHash(string packetHash);
    vector<string_pair > GetRecipientsByPacketHash(string packetHash);
    CIdentifiPacket GetPacketFromStatement(sqlite3_stmt *statement);
    vector<CIdentifiPacket> GetPacketsByAuthorOrRecipient(string_pair author, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished, bool isRecipient, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string packetType = "", bool latestOnly = false);
    boost::thread* dbWorker;
    void DBWorker();
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
    void UpdateCachedValue(string valueType, string_pair startID, string value);
    void UpdateCachedName(string_pair startID, string name);
    void UpdateCachedEmail(string_pair startID, string name);
    string GetCachedValue(string valueType, string_pair id);
    void AddPacketFilterSQL(ostringstream &sql, string_pair viewpoint, int maxDistance, string &packetType);
    void AddPacketFilterSQLWhere(ostringstream &sql, string_pair viewpoint); 
    void DeletePreviousTrustPaths(vector<string_pair> &authors, vector<string_pair> &recipients); 
    string GetIdentifierById(int id);
    string GetPredicateById(int id);
};

#endif // IDENTIFI_IDENTIFIDB_H
