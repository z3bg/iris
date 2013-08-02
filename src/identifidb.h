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
#include "main.h"
#include "data.h"

using namespace std;

class CIdentifiDB
{
public:
    CIdentifiDB(const boost::filesystem::path &filename = (GetDataDir() / "db.sqlite"));
    ~CIdentifiDB();
    void Initialize();
    vector<CRelation> GetRelationsBySubject(string subject);
    vector<CRelation> GetRelationsByObject(string object);
    string SaveRelation(CRelation &relation);
    void SaveRelationSignature(CSignature &signature);
    int GetRelationCount();
    int GetIdentifierCount();
private:
    sqlite3 *db;
    vector<pair<string, string> > GetSubjectsByRelationHash(string relationHash);
    vector<pair<string, string> > GetObjectsByRelationHash(string relationHash);
    vector<CSignature> GetSignaturesByRelationHash(string relationHash);
    void SaveRelationSubject(string relationHash, int predicateID, string subjectHash);
    void SaveRelationObject(string relationHash, int predicateID, string objectHash);
    int SavePredicate(string predicate);
    string SaveIdentifier(string identifier);
    void SaveRelationContentIdentifier(string relationHash, string identifierID);
    vector<vector<string> > query(const char* query);
};

#endif // IDENTIFI_IDENTIFIDB_H
