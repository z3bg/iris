// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <boost/lexical_cast.hpp>
#include "identifidb.h"
#include "main.h"
#include "data.h"

using namespace std;

CIdentifiDB::CIdentifiDB(const boost::filesystem::path &filename) {
    if (sqlite3_open(filename.string().c_str(), &db) == SQLITE_OK) {
        Initialize();

        vector<CIdentifier> subjects;
        CIdentifier id1("type", "value");
        subjects.push_back(id1);
        CRelation r(string("o negative"), string("priceless"), subjects, subjects);
        SaveRelation(r);
        vector<CRelation> results = GetRelationsInvolvingID(id1);
    }
}

CIdentifiDB::~CIdentifiDB() {
    sqlite3_close(db);
}

vector<vector<string> > CIdentifiDB::query(const char* query)
{
    sqlite3_stmt *statement;
    vector<vector<string> > results;
 
    if(sqlite3_prepare_v2(db, query, -1, &statement, 0) == SQLITE_OK)
    {
        int cols = sqlite3_column_count(statement);
        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                vector<string> values;
                for(int col = 0; col < cols; col++)
                {
                    values.push_back((char*)sqlite3_column_text(statement, col));
                }
                results.push_back(values);
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }
     
    string error = sqlite3_errmsg(db);
    if(error != "not an error") cout << query << " " << error << endl;
     
    return results; 
}

void CIdentifiDB::Initialize() {
    ostringstream sql;
    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Identifiers (";
    sql << "Id      INTEGER         PRIMARY_KEY,";
    sql << "Type    NVARCHAR(255)   NOT NULL,";
    sql << "Value   NVARCHAR(255)   NOT NULL";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE UNIQUE INDEX IF NOT EXISTS type_and_value ON Identifiers (type, value);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Relations (";
    sql << "Id                  INTEGER         PRIMARY_KEY,";
    sql << "Type                NVARCHAR(255)   NOT NULL,";
    sql << "Value               NVARCHAR(255)   NOT NULL,";
    sql << "SubjectIdentifierID INTEGER         NOT NULL,";
    sql << "ObjectIdentifierID  INTEGER,";
    sql << "Created   DATETIME  DEFAULT CURRENT_TIMESTAMP";
    sql << ");";
    query(sql.str().c_str());
}

vector<CRelation> CIdentifiDB::GetRelationsInvolvingID(CIdentifier &identifier) {
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Relations AS rel ";
    sql << "INNER JOIN Identifiers AS id ON rel.SubjectIdentifierID = id.Id ";
    sql << "WHERE id.type = '" << identifier.GetType() << "' AND id.value = '" << identifier.GetValue() << "';";
    vector<vector<string> > result = query(sql.str().c_str());
    vector<CRelation> retval;
    return retval;
}

void CIdentifiDB::SaveIdentifier(CIdentifier &identifier) {
    ostringstream sql;
    sql.str("");
    sql << "INSERT OR IGNORE INTO Identifiers (Type, Value) VALUES ";
    sql << "('" << identifier.GetType() << "', '" << identifier.GetValue() << "');";
    query(sql.str().c_str());
}

void CIdentifiDB::SaveRelation(CRelation &relation) {
    vector<CIdentifier> subjects = relation.GetSubjects();
    for (vector<CIdentifier>::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        SaveIdentifier(*it);
    }

    ostringstream sql;
    sql.str("");
    sql << "INSERT INTO Relations (Type, Value, SubjectIdentifierID, ObjectIdentifierID) ";
    sql << "VALUES ('" << relation.GetType() << "', '";
    sql << relation.GetValue() << "', 1, 2);";
    query(sql.str().c_str());
}

int CIdentifiDB::GetIdentifierCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Identifiers");
    return boost::lexical_cast<int>(result[0][0]);
}

int CIdentifiDB::GetRelationCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Relations");
    return boost::lexical_cast<int>(result[0][0]);
}