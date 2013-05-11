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
        vector<CRelation> results = GetRelationsInvolvingIdentifier(id1);
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
    sql << "ID      INTEGER         PRIMARY_KEY,";
    sql << "Type    NVARCHAR(255)   NOT NULL,";
    sql << "Value   NVARCHAR(255)   NOT NULL";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE UNIQUE INDEX IF NOT EXISTS type_and_value ON Identifiers (type, value);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Relations (";
    sql << "ID                  INTEGER         PRIMARY_KEY,";
    sql << "Type                NVARCHAR(255)   NOT NULL,";
    sql << "Value               NVARCHAR(255)   NOT NULL,";
    sql << "Created   DATETIME  DEFAULT CURRENT_TIMESTAMP";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationSubjects (";
    sql << "RelationID          INTEGER         NOT NULL,";
    sql << "SubjectID           INTEGER         NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationObjects (";
    sql << "RelationID          INTEGER         NOT NULL,";
    sql << "ObjectID           INTEGER         NOT NULL);";
    query(sql.str().c_str());
}

vector<CIdentifier> CIdentifiDB::GetSubjectsByRelationID(int relationID) {
    vector<CIdentifier> subjects;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT * FROM Identifiers AS id ";
    sql << "INNER JOIN RelationSubjects AS rs ON rs.RelationID = @relationid ";
    sql << "WHERE id.ID = rs.ObjectID;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, relationID);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                vector<CIdentifier> subjects;
                string type = string((char*)sqlite3_column_text(statement, 1));
                string value = string((char*)sqlite3_column_text(statement, 2));
                subjects.push_back(CIdentifier(type, value));
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }
    
    return subjects;

    return subjects;
}

vector<CRelation> CIdentifiDB::GetRelationsInvolvingIdentifier(CIdentifier &identifier) {
    sqlite3_stmt *statement;
    vector<CRelation> relations;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Relations AS rel ";
    sql << "INNER JOIN Identifiers AS id ON rel.SubjectIdentifierID = id.ID ";
    sql << "WHERE id.type = @type AND id.value = @value;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, identifier.GetType().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, identifier.GetValue().c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                vector<CIdentifier> subjects;
                string type = string((char*)sqlite3_column_text(statement, 1));
                string value = string((char*)sqlite3_column_text(statement, 2));
                relations.push_back(CRelation(type, value, subjects, subjects));
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }
    
    return relations;
}

int CIdentifiDB::SaveIdentifier(CIdentifier &identifier) {
    sqlite3_stmt *statement;
    const char *sql = "INSERT OR IGNORE INTO Identifiers (Type, Value) VALUES (@type, @value);";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, identifier.GetType().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, identifier.GetValue().c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_step(statement);
    sqlite3_finalize(statement);
    return sqlite3_last_insert_rowid(db);
}

void CIdentifiDB::SaveRelationSubject(int relationID, int subjectID) {
    sqlite3_stmt *statement;
    const char *sql = "INSERT OR IGNORE INTO RelationSubjects (RelationID, SubjectID) VALUES (@relationid, @objectid);";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, relationID);
        sqlite3_bind_int(statement, 2, subjectID);
    }
    sqlite3_step(statement);
    sqlite3_finalize(statement);    
}

void CIdentifiDB::SaveRelationObject(int relationID, int objectID) {
    sqlite3_stmt *statement;
    const char *sql = "INSERT OR IGNORE INTO RelationObjects (RelationID, ObjectID) VALUES (@relationid, @objectid);";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, relationID);
        sqlite3_bind_int(statement, 2, objectID);
    }
    sqlite3_step(statement);
    sqlite3_finalize(statement);    
}

int CIdentifiDB::SaveRelation(CRelation &relation) {
    sqlite3_stmt *statement;
    string sql;
    int relationID, identifierID;

    sql = "INSERT INTO Relations (Type, Value) VALUES (@type, @value);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relation.GetType().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, relation.GetValue().c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_step(statement);
    sqlite3_finalize(statement);
    relationID = sqlite3_last_insert_rowid(db);

    vector<CIdentifier> subjects = relation.GetSubjects();
    for (vector<CIdentifier>::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        identifierID = SaveIdentifier(*it);
        SaveRelationSubject(relationID, identifierID);
    }
    vector<CIdentifier> objects = relation.GetObjects();
    for (vector<CIdentifier>::iterator it = objects.begin(); it != objects.end(); ++it) {
        identifierID = SaveIdentifier(*it);
        SaveRelationObject(relationID, identifierID);
    }

    return relationID;
}

int CIdentifiDB::GetIdentifierCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Identifiers");
    return boost::lexical_cast<int>(result[0][0]);
}

int CIdentifiDB::GetRelationCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Relations");
    return boost::lexical_cast<int>(result[0][0]);
}