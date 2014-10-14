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

struct SearchQueueMessage {
    CIdentifiMessage msg;
    bool matchedByAuthor;
    string_pair matchedByIdentifier;
};

struct SearchResult {
    string_pair id;
    string email;
    string name;
};

class CIdentifiDB
{
public:
    CIdentifiDB(int sqliteMaxSize = 200, const boost::filesystem::path &filename = (GetDataDir() / "db.sqlite"));
    ~CIdentifiDB();
    void Initialize();
    vector<CIdentifiMessage> GetLatestMessages(int limit = 10, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "");
    vector<CIdentifiMessage> GetMessagesAfterTimestamp(time_t timestamp, int limit = 500, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "");
    vector<CIdentifiMessage> GetMessagesAfterMessage(string msgHash, int limit = 500, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "");
    vector<CIdentifiMessage> GetMessagesBeforeMessage(string msgHash, int limit = 500, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "");
    vector<CIdentifiMessage> GetMessagesByIdentifier(string_pair identifier, int limit = 0, int offset = 0, bool uniqueIdentifierTypesOnly = false, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "", bool latestOnly = false);
    vector<CIdentifiMessage> GetMessagesByAuthor(string_pair author, int limit = 0, int offset = 0, bool uniqueIdentifierTypesOnly = false, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "", bool latestOnly = false);
    vector<CIdentifiMessage> GetMessagesByRecipient(string_pair object, int limit = 0, int offset = 0, bool uniqueIdentifierTypesOnly = false, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "", bool latestOnly = false);
    vector<CIdentifiMessage> GetMessagesBySigner(string_pair keyID);
    vector<CIdentifiMessage> GetConnectingMessages(string_pair id1, string_pair id2, int limit = 0, int offset = 0, bool showUnpublished = true, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "");
    vector<LinkedID> GetLinkedIdentifiers(string_pair startID, vector<string> searchedPredicates, int limit = 0, int offset = 0, string_pair viewpoint = make_pair("",""), int maxDistance = 0);
    vector<string> GetPaths(string_pair start, string_pair end, int searchDepth);
    vector<SearchResult> SearchForID(string_pair query, int limit = 50, int offset = 0, bool uniqueIdentifierTypesOnly = false, string_pair viewpoint = make_pair("",""), int maxDistance = 0);
    string SaveMessage(CIdentifiMessage &msg);
    void SaveMessageTrustDistances(CIdentifiMessage &msg);
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
    int GetMessageCount();
    int GetMessageCountByAuthor(string_pair author);
    int GetIdentifierCount();
    void UpdateIsLatest(CIdentifiMessage &msg);
    void UpdateMessagePriorities(string_pair authorOrSigner);
    int GetTrustDistance(string_pair start, string_pair end);
    CIdentifiMessage GetMessageByHash(string hash);
    void SetMessagePriority(string msgHash, int priority);
    int GetPriority(CIdentifiMessage &msg);
    pair<string, string> GetMessageLinkedNames(CIdentifiMessage &msg, bool cachedOnly = false);
    pair<string, string> GetMessageLinkedEmails(CIdentifiMessage &msg, bool authorOnly = false);
    bool MakeFreeSpace(int nFreeBytesNeeded);
    void DropMessage(string strMessageHash);
    time_t GetLatestMessageTimestamp();
    void SaveTrustDistance(string_pair start, string_pair end, int distance);
    IDOverview GetIDOverview(string_pair id, string_pair viewpoint = make_pair("",""), int maxDistance = 0);
    string GetName(string_pair id, bool cachedOnly = false);
    string GetCachedName(string_pair id);
    string GetCachedEmail(string_pair id);
    int GetTrustMapSize(string_pair id);
    bool AddToTrustMapQueue(string_pair id, int searchDepth);
    bool GenerateTrustMap(string_pair id, int searchDepth);
    
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
    CIdentifiMessage GetMessageFromStatement(sqlite3_stmt *statement);
    vector<CIdentifiMessage> GetMessagesByAuthorOrRecipient(string_pair author, int limit, int offset, bool uniqueIdentifierTypesOnly, bool showUnpublished, bool isRecipient, string_pair viewpoint = make_pair("",""), int maxDistance = 0, string msgType = "", bool latestOnly = false);
    boost::thread* dbWorker;
    void DBWorker();
    void SaveMessageAuthorOrRecipient(string msgHash, string_pair identifier, bool isRecipient);
    void SaveMessageAuthor(string msgHash, string_pair author);
    void SaveMessageRecipient(string msgHash, string_pair author);
    bool SavePubKey(string pubKey);
    vector<vector<string> > query(const char* query);
    void CheckDefaultKey();
    void CheckDefaultTrustList();
    void SetMaxSize(int sqliteMaxSize);
    void CheckDefaultUniqueIdentifierTypes();
    void GenerateMyTrustMaps();
    bool HasTrustedSigner(CIdentifiMessage &msg, vector<string> trustedKeyIDs);
    string GetCachedValue(string valueType, string_pair id);
    void AddMessageFilterSQL(ostringstream &sql, string_pair viewpoint, int maxDistance, string &msgType);
    void AddMessageFilterSQLWhere(ostringstream &sql, string_pair viewpoint); 
};

#endif // IDENTIFI_IDENTIFIDB_H
