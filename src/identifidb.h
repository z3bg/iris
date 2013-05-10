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
    CIdentifiDB(const boost::filesystem::path &filename = (GetDataDir() / "sqlite.db"));
    ~CIdentifiDB();
    void Initialize();
    vector<CRelation> GetRelationsInvolvingID(CIdentifier &identifier);
    vector<CRelation> GetRelationsBySubject(CIdentifier &subject);
    vector<CRelation> GetRelationsByObject(CIdentifier &object);
    void SaveIdentifier(CIdentifier &identifier);
    void SaveRelation(CRelation &relation);
    int GetRelationCount();
    int GetIdentifierCount();
private:
    sqlite3 *db;
    vector<vector<string> > query(const char* query);
};

#endif // IDENTIFI_IDENTIFIDB_H
