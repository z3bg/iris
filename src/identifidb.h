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
    vector<CRelation> GetRelationsBySubject(CIdentifier &subject);
    vector<CRelation> GetRelationsByObject(CIdentifier &object);
    int SaveIdentifier(CIdentifier &identifier);
    string SaveRelation(CRelation &relation);
    void SaveRelationSignature(CSignature &signature);
    int GetRelationCount();
    int GetIdentifierCount();
private:
    sqlite3 *db;
    vector<CIdentifier> GetSubjectsByRelationID(string relationID);
    vector<CIdentifier> GetObjectsByRelationID(string relationID);
    vector<CSignature> GetSignaturesByRelationID(string relationID);
    void SaveRelationSubject(string relationID, string subjectID);
    void SaveRelationObject(string relationID, string objectID);
    void SaveRelationContentIdentifier(string relationID, string identifierID);
    vector<vector<string> > query(const char* query);
};

#endif // IDENTIFI_IDENTIFIDB_H
