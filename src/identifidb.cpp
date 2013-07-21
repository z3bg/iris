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
    sql << "ID      NVARCHAR(45)    PRIMARY KEY,";
    sql << "Type    NVARCHAR(255)   NOT NULL,";
    sql << "Value   NVARCHAR(255)   NOT NULL";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE UNIQUE INDEX IF NOT EXISTS type_and_value ON Identifiers (type, value);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Relations (";
    sql << "ID                  NVARCHAR(45)    PRIMARY KEY,";
    sql << "Data                NVARCHAR(1000)  NOT NULL,";
    sql << "Created   DATETIME  DEFAULT CURRENT_TIMESTAMP";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationSubjects (";
    sql << "RelationID          NVARCHAR(45)    NOT NULL,";
    sql << "SubjectID           NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationObjects (";
    sql << "RelationID          NVARCHAR(45)    NOT NULL,";
    sql << "ObjectID            NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationSignatures (";
    sql << "RelationID          NVARCHAR(45)    NOT NULL,";
    sql << "Signature           NVARCHAR(45)    NOT NULL,";
    sql << "PubKeyID            NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationContentIdentifiers (";
    sql << "RelationID          NVARCHAR(45)    NOT NULL,";
    sql << "IdentifierID        NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());
}

vector<CIdentifier> CIdentifiDB::GetSubjectsByRelationID(string relationID) {
    vector<CIdentifier> subjects;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT id.Type, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN RelationSubjects AS rs ON rs.RelationID = @relationid ";
    sql << "WHERE id.ID = rs.SubjectID;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationID.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW) {
                string type = string((char*)sqlite3_column_text(statement, 0));
                string value = string((char*)sqlite3_column_text(statement, 1));
                subjects.push_back(CIdentifier(type, value));
            } else {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }

    return subjects;
}

vector<CIdentifier> CIdentifiDB::GetObjectsByRelationID(string relationID) {
    vector<CIdentifier> objects;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT id.Type, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN RelationObjects AS ro ON ro.RelationID = @relationid ";
    sql << "WHERE id.ID = ro.ObjectID;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationID.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
            
            printf("hei");
            if(result == SQLITE_ROW) {
                string type = string((char*)sqlite3_column_text(statement, 0));
                string value = string((char*)sqlite3_column_text(statement, 1));
                printf("type: %s, value: %s", type.c_str(), value.c_str());
                objects.push_back(CIdentifier(type, value));
            } else {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    
    return objects;
}

vector<CSignature> CIdentifiDB::GetSignaturesByRelationID(string relationID) {
    vector<CSignature> signatures;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT PubKeyID, Signature FROM RelationSignatures ";
    sql << "WHERE RelationID = @relationid;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationID.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
            
            printf("hei");
            if(result == SQLITE_ROW) {
                string pubKeyID = string((char*)sqlite3_column_text(statement, 0));
                string signature = string((char*)sqlite3_column_text(statement, 1));
                printf("pubKeyID: %s, signature: %s", pubKeyID.c_str(), signature.c_str());
                signatures.push_back(CSignature(relationID, pubKeyID, signature));
            } else {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    
    return signatures;
}

vector<CRelation> CIdentifiDB::GetRelationsBySubject(CIdentifier &subject) {
    sqlite3_stmt *statement;
    vector<CRelation> relations;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Relations AS rel ";
    sql << "INNER JOIN RelationSubjects AS rs ON rs.RelationID = rel.ID ";
    sql << "INNER JOIN Identifiers AS id ON rs.SubjectID = id.ID ";
    sql << "WHERE id.Type = @type AND id.Value = @value;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, subject.GetType().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, subject.GetValue().c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                string relationID = string((char*)sqlite3_column_text(statement, 0));
                vector<CIdentifier> subjects = GetSubjectsByRelationID(relationID);
                vector<CIdentifier> objects = GetObjectsByRelationID(relationID);
                vector<CSignature> signatures = GetSignaturesByRelationID(relationID);
                string message = string((char*)sqlite3_column_text(statement, 1));
                relations.push_back(CRelation(message, subjects, objects, signatures));
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    
    return relations;
}

vector<CRelation> CIdentifiDB::GetRelationsByObject(CIdentifier &object) {
    sqlite3_stmt *statement;
    vector<CRelation> relations;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Relations AS rel ";
    sql << "INNER JOIN RelationObjects AS rs ON rs.RelationID = rel.ID ";
    sql << "INNER JOIN Identifiers AS id ON rs.ObjectID = id.ID ";
    sql << "WHERE id.Type = @type AND id.Value = @value;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, object.GetType().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, object.GetValue().c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                string relationID = string((char*)sqlite3_column_text(statement, 0));
                vector<CIdentifier> subjects = GetSubjectsByRelationID(relationID);
                vector<CIdentifier> objects = GetObjectsByRelationID(relationID);
                vector<CSignature> signatures = GetSignaturesByRelationID(relationID);
                string message = string((char*)sqlite3_column_text(statement, 1));
                relations.push_back(CRelation(message, subjects, subjects, signatures));
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

    const char *sql = "SELECT ID FROM Identifiers WHERE Type = @type AND Value = @value;";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, identifier.GetType().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, identifier.GetValue().c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) == SQLITE_ROW) {
        int rowid = sqlite3_column_int(statement, 0);
        sqlite3_finalize(statement);
        return rowid;
    } else {
        sql = "INSERT INTO Identifiers (Type, Value, ID) VALUES (@type, @value, @id);";
        if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, identifier.GetType().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, identifier.GetValue().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 3, identifier.GetHash().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
            sqlite3_finalize(statement);
        }
        return sqlite3_last_insert_rowid(db);
    }
}

void CIdentifiDB::SaveRelationSubject(string relationID, string subjectID) {
    sqlite3_stmt *statement;
    const char *sql = "INSERT OR IGNORE INTO RelationSubjects (RelationID, SubjectID) VALUES (@relationid, @objectid);";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationID.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, subjectID.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
        sqlite3_finalize(statement); 
    }   
}

void CIdentifiDB::SaveRelationObject(string relationID, string objectID) {
    sqlite3_stmt *statement;
    const char *sql = "INSERT OR IGNORE INTO RelationObjects (RelationID, ObjectID) VALUES (@relationid, @objectid);";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationID.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, objectID.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
        sqlite3_finalize(statement); 
    }   
}

void CIdentifiDB::SaveRelationSignature(CSignature &signature) {
    sqlite3_stmt *statement;
    const char *sql = "INSERT OR IGNORE INTO RelationSignatures (RelationID, PubKeyID, Signature) VALUES (@relationid, @pubkeyid, @signature);";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, signature.GetSignedHash().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, signature.GetSignerPubKeyHash().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, signature.GetSignature().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
        sqlite3_finalize(statement); 
    }   
}

void CIdentifiDB::SaveRelationContentIdentifier(string relationID, string identifierID) {
    sqlite3_stmt *statement;
    const char *sql = "INSERT OR IGNORE INTO RelationContentIdentifiers (RelationID, IdentifierID) VALUES (@relationid, @identifierid);";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationID.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, identifierID.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
        sqlite3_finalize(statement); 
    }  
}

string CIdentifiDB::SaveRelation(CRelation &relation) {
    sqlite3_stmt *statement;
    string sql;
    string relationHash;

    sql = "INSERT INTO Relations (ID, Data) VALUES (@id, @data);";
    relationHash = relation.GetHash();
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, relation.GetData().c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_step(statement);
    sqlite3_finalize(statement);

    vector<CIdentifier> subjects = relation.GetSubjects();
    for (vector<CIdentifier>::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        SaveIdentifier(*it);
        SaveRelationSubject(relationHash, it->GetHash());
    }
    vector<CIdentifier> objects = relation.GetObjects();
    for (vector<CIdentifier>::iterator it = objects.begin(); it != objects.end(); ++it) {
        SaveIdentifier(*it);
        SaveRelationObject(relationHash, it->GetHash());
    }
    vector<CSignature> signatures = relation.GetSignatures();
    for (vector<CSignature>::iterator it = signatures.begin(); it != signatures.end(); ++it) {
        SaveRelationSignature(*it);
    }

    return relationHash;
}

int CIdentifiDB::GetIdentifierCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Identifiers");
    return boost::lexical_cast<int>(result[0][0]);
}

int CIdentifiDB::GetRelationCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Relations");
    return boost::lexical_cast<int>(result[0][0]);
}