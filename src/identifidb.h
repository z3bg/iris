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
    vector<CIdentifiPacket> GetPacketsAfterTimestamp(time_t timestamp, int limit = 500);
    vector<CIdentifiPacket> GetPacketsAfterPacket(string packetHash, int limit = 500);
    vector<CIdentifiPacket> GetPacketsByIdentifier(string identifier);
    vector<CIdentifiPacket> GetPacketsBySubject(string subject);
    vector<CIdentifiPacket> GetPacketsByObject(string object);
    string SavePacket(CIdentifiPacket &packet);
    void SavePacketSignature(CSignature &signature);
    void SetDefaultKey(string privKey);
    CKey GetDefaultKey();
    vector<string> ListPrivKeys();
    bool ImportPrivKey(string privKey, bool setDefault=false);
    int GetPacketCount();
    int GetIdentifierCount();
    CIdentifiPacket GetPacketByHash(string hash);
    vector<CIdentifiPacket> GetPath(string start, string end, int searchDepth = 3);
    int GetTrustValue(CIdentifiPacket &packet);
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
};

#endif // IDENTIFI_IDENTIFIDB_H
