// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <deque>
#include <boost/lexical_cast.hpp>
#include <map>
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

void CIdentifiDB::CheckDefaultKey() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM PrivateKeys WHERE rowid = 0");
    if (boost::lexical_cast<int>(result[0][0]) != 1) {
        CKey newKey;
        newKey.MakeNewKey(false);
        SetDefaultKey(newKey);
    }
}

void CIdentifiDB::CheckHashtagValues() {
    query("INSERT OR IGNORE INTO HashtagValues VALUES ('#positive', 50)");
    query("INSERT OR IGNORE INTO HashtagValues VALUES ('#neutral', 0)");
    query("INSERT OR IGNORE INTO HashtagValues VALUES ('#negative', -50)");
    query("INSERT OR IGNORE INTO HashtagValues VALUES ('#authentic', 100)");
    query("INSERT OR IGNORE INTO HashtagValues VALUES ('#fake', -100)");
    query("INSERT OR IGNORE INTO HashtagValues VALUES ('#knows', 100)");
    query("INSERT OR IGNORE INTO HashtagValues VALUES ('#expired', 0)");

    vector<vector<string> > result = query("SELECT Hashtag, Value FROM HashtagValues");
    for (vector<vector<string> >::iterator row = result.begin(); row != result.end(); row++) {
        hashtagValues[row->at(0)] = boost::lexical_cast<int>(row->at(1));
    }
}

void CIdentifiDB::Initialize() {
    ostringstream sql;
    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Identifiers (";
    sql << "Hash      NVARCHAR(45)    PRIMARY KEY,";
    sql << "Value     NVARCHAR(255)   NOT NULL";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Predicates (";
    sql << "ID      INTEGER         PRIMARY KEY,";
    sql << "Value   NVARCHAR(255)   NOT NULL";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Relations (";
    sql << "Hash                NVARCHAR(45)    PRIMARY KEY,";
    sql << "Data                NVARCHAR(1000)  NOT NULL,";
    sql << "Created             DATETIME";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationSubjects (";
    sql << "RelationHash        NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "SubjectHash         NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationObjects (";
    sql << "RelationHash        NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "ObjectHash          NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationSignatures (";
    sql << "RelationHash        NVARCHAR(45)    NOT NULL,";
    sql << "Signature           NVARCHAR(100)   NOT NULL,";
    sql << "PubKeyHash          NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS RelationContentIdentifiers (";
    sql << "RelationHash        NVARCHAR(45)    NOT NULL,";
    sql << "IdentifierHash      NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PrivateKeys (";
    sql << "PubKeyHash        NVARCHAR(45)    PRIMARY KEY,";
    sql << "PrivateKey        NVARCHAR(1000)  NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS HashtagValues (";
    sql << "Hashtag           NVARCHAR(45)    PRIMARY KEY,";
    sql << "Value             INTEGER         NOT NULL CHECK (Value >= -100 AND Value <= 100));";
    query(sql.str().c_str());

    CheckDefaultKey();
    CheckHashtagValues();
}

vector<pair<string, string> > CIdentifiDB::GetSubjectsByRelationHash(string relationHash) {
    vector<pair<string, string> > subjects;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN RelationSubjects AS rs ON rs.RelationHash = @relationhash ";
    sql << "INNER JOIN Predicates AS p ON rs.PredicateID = p.ID ";
    sql << "WHERE id.Hash = rs.SubjectHash;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW) {
                string predicate = string((char*)sqlite3_column_text(statement, 0));
                string identifier = string((char*)sqlite3_column_text(statement, 1));
                subjects.push_back(make_pair(predicate, identifier));
            } else {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }

    return subjects;
}

vector<pair<string, string> > CIdentifiDB::GetObjectsByRelationHash(string relationHash) {
    vector<pair<string, string> > objects;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN RelationObjects AS ro ON ro.RelationHash = @relationhash ";
    sql << "INNER JOIN Predicates AS p ON ro.PredicateID = p.ID ";
    sql << "WHERE id.Hash = ro.ObjectHash;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
            
            if(result == SQLITE_ROW) {
                string predicate = string((char*)sqlite3_column_text(statement, 0));
                string identifier = string((char*)sqlite3_column_text(statement, 1));
                objects.push_back(make_pair(predicate, identifier));
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

vector<CSignature> CIdentifiDB::GetSignaturesByRelationHash(string relationHash) {
    vector<CSignature> signatures;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT id.Value, rs.Signature FROM RelationSignatures AS rs ";
    sql << "INNER JOIN Identifiers AS id ON id.Hash = rs.PubKeyHash ";
    sql << "WHERE rs.RelationHash = @relationhash;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
            
            if(result == SQLITE_ROW) {
                string pubKey = string((char*)sqlite3_column_text(statement, 0));
                string signature = string((char*)sqlite3_column_text(statement, 1));
                signatures.push_back(CSignature(relationHash, pubKey, signature));
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

vector<CRelation> CIdentifiDB::GetRelationsByIdentifier(string identifier) {
    sqlite3_stmt *statement;
    vector<CRelation> relations;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Relations AS rel ";
    sql << "INNER JOIN RelationSubjects AS rs ON rs.RelationHash = rel.Hash ";
    sql << "INNER JOIN RelationObjects AS ro ON ro.RelationHash = rel.Hash ";
    sql << "INNER JOIN Identifiers AS id ON (rs.SubjectHash = id.Hash ";
    sql << "OR ro.ObjectHash = id.Hash) ";
    sql << "WHERE id.Value = @value;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, identifier.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                string relationHash = string((char*)sqlite3_column_text(statement, 0));
                vector<pair<string, string> > subjects = GetSubjectsByRelationHash(relationHash);
                vector<pair<string, string> > objects = GetObjectsByRelationHash(relationHash);
                vector<CSignature> signatures = GetSignaturesByRelationHash(relationHash);
                string message = CRelation::GetMessageFromData((char*)sqlite3_column_text(statement, 1));
                time_t timestamp = time_t(sqlite3_column_int(statement, 2));
                relations.push_back(CRelation(message, subjects, objects, signatures, timestamp));
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

vector<CRelation> CIdentifiDB::GetRelationsBySubject(string subject) {
    sqlite3_stmt *statement;
    vector<CRelation> relations;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Relations AS rel ";
    sql << "INNER JOIN RelationSubjects AS rs ON rs.RelationHash = rel.Hash ";
    sql << "INNER JOIN Identifiers AS id ON rs.SubjectHash = id.Hash ";
    sql << "WHERE id.Value = @value;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, subject.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                string relationHash = string((char*)sqlite3_column_text(statement, 0));
                vector<pair<string, string> > subjects = GetSubjectsByRelationHash(relationHash);
                vector<pair<string, string> > objects = GetObjectsByRelationHash(relationHash);
                vector<CSignature> signatures = GetSignaturesByRelationHash(relationHash);
                string message = CRelation::GetMessageFromData((char*)sqlite3_column_text(statement, 1));
                time_t timestamp = time_t(sqlite3_column_int(statement, 2));
                relations.push_back(CRelation(message, subjects, objects, signatures, timestamp));
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

vector<CRelation> CIdentifiDB::GetRelationsByObject(string object) {
    sqlite3_stmt *statement;
    vector<CRelation> relations;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Relations AS rel ";
    sql << "INNER JOIN RelationObjects AS ro ON ro.RelationHash = rel.Hash ";
    sql << "INNER JOIN Identifiers AS id ON ro.ObjectHash = id.Hash ";
    sql << "WHERE id.Value = @value;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, object.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                string relationHash = string((char*)sqlite3_column_text(statement, 0));
                vector<pair<string, string> > subjects = GetSubjectsByRelationHash(relationHash);
                vector<pair<string, string> > objects = GetObjectsByRelationHash(relationHash);
                vector<CSignature> signatures = GetSignaturesByRelationHash(relationHash);
                string message = CRelation::GetMessageFromData((char*)sqlite3_column_text(statement, 1));
                time_t timestamp = time_t(sqlite3_column_int(statement, 2));
                relations.push_back(CRelation(message, subjects, objects, signatures, timestamp));
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

int CIdentifiDB::SavePredicate(string predicate) {
    sqlite3_stmt *statement;
    int rowid = -1;

    const char *sql = "SELECT rowid FROM Predicates WHERE Value = @value;";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, predicate.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) == SQLITE_ROW) {
        rowid = sqlite3_column_int(statement, 0);
        sqlite3_finalize(statement);
    } else {
        sql = "INSERT INTO Predicates (Value) VALUES (@value);";
        if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, predicate.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
            sqlite3_finalize(statement);
        }
        rowid = sqlite3_last_insert_rowid(db);
    }
    return rowid;
}

string CIdentifiDB::SaveIdentifier(string identifier) {
    sqlite3_stmt *statement;
    string hash;

    const char *sql = "SELECT Hash FROM Identifiers WHERE Value = @value;";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, identifier.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) == SQLITE_ROW) {
        hash = string((char*)sqlite3_column_text(statement, 0));
        sqlite3_finalize(statement);
    } else {
        sql = "INSERT INTO Identifiers (Value, Hash) VALUES (@value, @hash);";
        if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
            hash = EncodeBase58(Hash(identifier.begin(), identifier.end()));
            sqlite3_bind_text(statement, 1, identifier.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
            sqlite3_finalize(statement);
        }
    }
    return hash;
}

void CIdentifiDB::SaveRelationSubject(string relationHash, int predicateID, string subjectHash) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM RelationSubjects ";
    sql << "WHERE RelationHash = @relationhash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND SubjectHash = @subjecthash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_text(statement, 3, subjectHash.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO RelationSubjects (RelationHash, PredicateID, SubjectHash) ";
        sql << "VALUES (@relationhash, @predicateid, @subjectid);";
        
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 2, predicateID);
            sqlite3_bind_text(statement, 3, subjectHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
        }
    }
    sqlite3_finalize(statement);    
}

void CIdentifiDB::SaveRelationObject(string relationHash, int predicateID, string objectHash) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM RelationObjects ";
    sql << "WHERE RelationHash = @relationhash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND ObjectHash = @objecthash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_text(statement, 3, objectHash.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO RelationObjects (RelationHash, PredicateID, ObjectHash) ";
        sql << "VALUES (@relationhash, @predicateid, @objectid);";
        
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 2, predicateID);
            sqlite3_bind_text(statement, 3, objectHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
        }
    }
    sqlite3_finalize(statement);    
}

void CIdentifiDB::SaveRelationSignature(CSignature &signature) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM RelationSignatures WHERE RelationHash = @relationHash ";
    sql << "AND PubKeyHash = @pubKeyHash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, signature.GetSignedHash().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, signature.GetSignerPubKeyHash().c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO RelationSignatures (RelationHash, PubKeyHash, Signature) ";
        sql << "VALUES (@relationhash, @pubkeyhash, @signature);";
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, signature.GetSignedHash().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, signature.GetSignerPubKeyHash().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 3, signature.GetSignature().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
            sqlite3_finalize(statement); 
        }  
    }
    SaveIdentifier(signature.GetSignerPubKey());
}

void CIdentifiDB::SaveRelationContentIdentifier(string relationHash, string identifierHash) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM RelationContentIdentifiers ";
    sql << "WHERE RelationHash = @relationhash ";
    sql << "AND IdentifierHash = @identifierhash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, identifierHash.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO RelationContentIdentifiers (RelationHash, IdentifierHash) ";
        sql << "VALUES (@relationhash, @identifierhash);";
        
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, identifierHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
        } else {
            printf("DB Error: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(statement); 
}

string CIdentifiDB::SaveRelation(CRelation &relation) {
    sqlite3_stmt *statement;
    string sql;
    string relationHash;

    sql = "INSERT INTO Relations (Hash, Data, Created) VALUES (@id, @data, @timestamp);";
    relationHash = relation.GetHash();
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, relationHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, relation.GetData().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 3, relation.GetTimestamp());
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    sqlite3_step(statement);
    sqlite3_finalize(statement);

    vector<pair<string, string> > subjects = relation.GetSubjects();
    for (vector<pair<string, string> >::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        int predicateID = SavePredicate(it->first);
        string subjectHash = SaveIdentifier(it->second);
        SaveRelationSubject(relationHash, predicateID, subjectHash);
    }
    vector<pair<string, string> > objects = relation.GetObjects();
    for (vector<pair<string, string> >::iterator it = objects.begin(); it != objects.end(); ++it) {
        int predicateID = SavePredicate(it->first);
        string objectHash = SaveIdentifier(it->second);
        SaveRelationObject(relationHash, predicateID, objectHash);
    }
    vector<string> contentIdentifiers = relation.GetContentIdentifiers();
    for (vector<string>::iterator it = contentIdentifiers.begin(); it != contentIdentifiers.end(); ++it) {
        string identifierHash = SaveIdentifier(*it);
        SaveRelationContentIdentifier(relationHash, identifierHash);
    }
    vector<CSignature> signatures = relation.GetSignatures();
    for (vector<CSignature>::iterator it = signatures.begin(); it != signatures.end(); ++it) {
        SaveRelationSignature(*it);
    }

    return relationHash;
}

void CIdentifiDB::SetDefaultKey(CKey &key) {
    vector<unsigned char> pubKey = key.GetPubKey().Raw();
    string pubKeyStr = EncodeBase58(pubKey);
    string pubKeyHash = SaveIdentifier(pubKeyStr);
    bool compressed;
    CSecret secret = key.GetSecret(compressed);
    string privateKey = CIdentifiSecret(secret, compressed).ToString();

    sqlite3_stmt *statement;
    string sql;
    string relationHash;

    sql = "INSERT INTO PrivateKeys (rowid, PubKeyHash, PrivateKey) VALUES (0, @pubkeyhash, @privatekey);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, pubKeyHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, privateKey.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    sqlite3_step(statement);
    sqlite3_finalize(statement);    
}

CKey CIdentifiDB::GetDefaultKey() {
    string pubKey, privKey;

    sqlite3_stmt *statement;
    ostringstream sql;
    sql.str("");
    sql << "SELECT id.Value, pk.PrivateKey FROM PrivateKeys AS pk ";
    sql << "INNER JOIN Identifiers AS id ON pk.PubKeyHash = id.Hash ";
    sql << "WHERE pk.rowid = 0;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if(result == SQLITE_ROW)
        {
            pubKey = string((char*)sqlite3_column_text(statement, 0));
            privKey = string((char*)sqlite3_column_text(statement, 1));
        }
    }
    sqlite3_finalize(statement);

    CIdentifiSecret s;
    s.SetString(privKey);
    bool compressed = false;
    CSecret secret = s.GetSecret(compressed);

    CKey key;
    key.SetSecret(secret, false);

    return key;
}

vector<string> CIdentifiDB::ListPrivateKeys() {
    vector<string> keys;

    vector<vector<string> > result = query("SELECT PubKeyHash FROM PrivateKeys");
    for (vector<vector <string> >::iterator it = result.begin(); it != result.end(); it++) {
        keys.push_back(it->front());
    }

    return keys;
}

// Breadth-first search for the shortest trust path from id1 to id2
vector<CRelation> CIdentifiDB::GetPath(string start, string end, int searchDepth) {
    vector<CRelation> path;
    vector<string> visitedRelations;

    deque<CRelation> d;
    map<string, CRelation> previousRelations;

    vector<CRelation> relations = GetRelationsByIdentifier(start);
    d.insert(d.end(), relations.begin(), relations.end());

    while (!d.empty()) {
        CRelation currentNode = d.front();
        d.pop_front();
        if (find(visitedRelations.begin(), visitedRelations.end(), currentNode.GetHash()) != visitedRelations.end()) {
            continue;
        }
        visitedRelations.push_back(currentNode.GetHash());

        // TODO: Discard relations with untrusted signer
        
        // Discard relations with non-positive trust value
        bool positiveValue = false;
        vector<string> hashtags = currentNode.GetContentIdentifiers();
        for (vector<string>::iterator hashtag = hashtags.begin(); hashtag != hashtags.end(); hashtag++) {
            try {
                if (hashtagValues.at(*hashtag) > 0) {
                    positiveValue = true;
                } else {
                    positiveValue = false;
                    break;
                }
            } catch (const out_of_range& e) {}
        }
        if (!positiveValue)
            continue;

        vector<pair<string, string> > allIdentifiers = currentNode.GetSubjects();
        vector<pair<string, string> > objects = currentNode.GetObjects();
        allIdentifiers.insert(allIdentifiers.end(), objects.begin(), objects.end());
        for (vector<pair<string, string> >::iterator identifier = allIdentifiers.begin(); identifier != allIdentifiers.end(); identifier++) {
            if (identifier->second == end) {
                path.push_back(currentNode);

                CRelation previousRelation = currentNode;
                while (previousRelations.find(previousRelation.GetHash()) != previousRelations.end()) {
                    previousRelation = previousRelations.at(previousRelation.GetHash());
                    path.insert(path.begin(), previousRelation);
                }
                return path;
            } else {
                vector<CRelation> allRelations = GetRelationsByIdentifier(identifier->second);
                for (vector<CRelation>::iterator r = allRelations.begin(); r != allRelations.end(); r++) {
                    if (previousRelations.find(r->GetHash()) == previousRelations.end()
                        && find(visitedRelations.begin(), visitedRelations.end(), r->GetHash()) == visitedRelations.end())
                        previousRelations[r->GetHash()] = currentNode;
                }

                d.insert(d.end(), allRelations.begin(), allRelations.end());
            }
        }
    }

    return path;
}

CRelation CIdentifiDB::GetRelationByHash(string hash) {
    sqlite3_stmt *statement;
    vector<CRelation> relations;
    const char* sql = "SELECT * FROM Relations WHERE Relations.Hash = @hash;";

    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, hash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                string relationHash = string((char*)sqlite3_column_text(statement, 0));
                vector<pair<string, string> > subjects = GetSubjectsByRelationHash(relationHash);
                vector<pair<string, string> > objects = GetObjectsByRelationHash(relationHash);
                vector<CSignature> signatures = GetSignaturesByRelationHash(relationHash);
                string message = CRelation::GetMessageFromData((char*)sqlite3_column_text(statement, 1));
                time_t timestamp = time_t(sqlite3_column_int(statement, 2));
                sqlite3_finalize(statement);
                return CRelation(message, subjects, objects, signatures, timestamp);
            }
            else
            {
                break;
            }
        }
        
        sqlite3_finalize(statement);
    }
    throw runtime_error("relation not found");    
}

int CIdentifiDB::GetIdentifierCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Identifiers");
    return boost::lexical_cast<int>(result[0][0]);
}

int CIdentifiDB::GetRelationCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Relations");
    return boost::lexical_cast<int>(result[0][0]);
}

