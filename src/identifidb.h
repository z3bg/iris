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
    vector<CRelation> GetRelationsAfterTimestamp(time_t timestamp, int limit = 500);
    vector<CRelation> GetRelationsAfterRelation(string relationHash, int limit = 500);
    vector<CRelation> GetRelationsByIdentifier(string identifier);
    vector<CRelation> GetRelationsBySubject(string subject);
    vector<CRelation> GetRelationsByObject(string object);
    string SaveRelation(CRelation &relation);
    void SaveRelationSignature(CSignature &signature);
    void SetDefaultKey(CKey &key);
    CKey GetDefaultKey();
    vector<string> ListPrivateKeys();
    int GetRelationCount();
    int GetIdentifierCount();
    CRelation GetRelationByHash(string hash);
    vector<CRelation> GetPath(string start, string end, int searchDepth = 3);
    int GetTrustValue(CRelation &relation);
    bool MakeFreeSpace(int nFreeBytesNeeded);
    void DropRelation(string strRelationHash);
    time_t GetLatestRelationTimestamp();
private:
    sqlite3 *db;
    vector<pair<string, string> > GetSubjectsByRelationHash(string relationHash);
    vector<pair<string, string> > GetObjectsByRelationHash(string relationHash);
    vector<CSignature> GetSignaturesByRelationHash(string relationHash);
    CRelation GetRelationFromStatement(sqlite3_stmt *statement);
    void SaveRelationSubject(string relationHash, int predicateID, string subjectHash);
    void SaveRelationObject(string relationHash, int predicateID, string objectHash);
    int SavePredicate(string predicate);
    string SaveIdentifier(string identifier);
    vector<vector<string> > query(const char* query);
    void CheckDefaultKey();
    void SetMaxSize(int sqliteMaxSize);
};

#endif // IDENTIFI_IDENTIFIDB_H
