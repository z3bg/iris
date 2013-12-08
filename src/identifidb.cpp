// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <deque>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <map>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

#include "identifidb.h"
#include "main.h"
#include "data.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

#ifndef RETRY_IF_DB_FULL
#define RETRY_IF_DB_FULL(statements)                            \
    int sqliteReturnCode = -1;                                  \
    do {                                                        \
        {statements}                                            \
        if (sqliteReturnCode == SQLITE_FULL) {                  \
            if (!MakeFreeSpace(10000))                          \
                throw runtime_error("Not enough DB space");     \
        }                                                       \
    } while (sqliteReturnCode == SQLITE_FULL);
#endif

CIdentifiDB::CIdentifiDB(int sqliteMaxSize, const filesystem::path &filename) {
    if (sqlite3_open(filename.string().c_str(), &db) == SQLITE_OK) {
        Initialize();
        SetMaxSize(sqliteMaxSize);
    }
}

CIdentifiDB::~CIdentifiDB() {
    sqlite3_close(db);
}

vector<vector<string> > CIdentifiDB::query(const char* query)
{
    sqlite3_stmt *statement;
    vector<vector<string> > results;
 
    if (sqlite3_prepare_v2(db, query, -1, &statement, 0) == SQLITE_OK)
    {
        int cols = sqlite3_column_count(statement);
        int result = 0;
        while (true) {
            result = sqlite3_step(statement);
             
            if (result == SQLITE_ROW) {
                vector<string> values;
                for (int col = 0; col < cols; col++)
                {
                    values.push_back((char*)sqlite3_column_text(statement, col));
                }
                results.push_back(values);
            } else {
                break;
            }
        }
        
        sqlite3_finalize(statement);
    }
     
    string error = sqlite3_errmsg(db);
    if (error != "not an error") cout << query << " " << error << endl;
     
    return results; 
}

void CIdentifiDB::SetMaxSize(int sqliteMaxSize) {
    if (sqliteMaxSize < 1)
        sqliteMaxSize = 1;
    int pageSize = lexical_cast<int>(query("PRAGMA page_size")[0][0]);
    int maxPageCount = sqliteMaxSize * (1 << 20) / pageSize;
    ostringstream sql;
    sql.str("");
    sql << "PRAGMA max_page_count = " << maxPageCount << "\n";
    query(sql.str().c_str())[0][0];
}

void CIdentifiDB::CheckDefaultUniquePredicates() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Predicates");
    if (lexical_cast<int>(result[0][0]) < 1) {
        query("INSERT INTO Predicates (Value, IsUniqueType) VALUES ('mbox', 1)");
        query("INSERT INTO Predicates (Value, IsUniqueType) VALUES ('url', 1)");
        query("INSERT INTO Predicates (Value, IsUniqueType) VALUES ('tel', 1)");
        query("INSERT INTO Predicates (Value, IsUniqueType) VALUES ('ecdsa_base58', 1)");
    }
}

void CIdentifiDB::CheckDefaultKey() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM PrivateKeys WHERE IsDefault = 1");
    if (lexical_cast<int>(result[0][0]) < 1) {
        CKey newKey;
        newKey.MakeNewKey(false);
        bool compressed;
        CSecret secret = newKey.GetSecret(compressed);
        string strPrivateKey = CIdentifiSecret(secret, compressed).ToString();
        SetDefaultKey(strPrivateKey);
    }
}

void CIdentifiDB::CheckDefaultTrustList() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Packets");
    if (lexical_cast<int>(result[0][0]) < 1) {
        CKey defaultKey = GetDefaultKey();
        vector<unsigned char> vchPubKey = defaultKey.GetPubKey().Raw();
        string strPubKey = EncodeBase58(vchPubKey);

        Array author, author1, recipient, recipient1, signatures;
        author1.push_back("ecdsa_base58");
        author1.push_back(strPubKey);
        author.push_back(author1);
        recipient1.push_back("ecdsa_base58");
        recipient1.push_back("NdudNBcekP9rQW425xpnpeVtDu1DLTFiMuAMkBsXRVpM8LheWfjPj7fiU7QNVxNbN1YbMXnXrhQEcuUovMB41fvm");
        recipient.push_back(recipient1);
        
        time_t now = time(NULL);

        json_spirit::Object data, signedData;
        signedData.push_back(Pair("timestamp", now));
        signedData.push_back(Pair("author", author));
        signedData.push_back(Pair("recipient", recipient));
        signedData.push_back(Pair("type", "rating"));
        signedData.push_back(Pair("comment", "Identifi developers' key, trusted by default"));
        signedData.push_back(Pair("rating", 1));
        signedData.push_back(Pair("maxRating", 1));
        signedData.push_back(Pair("minRating", -1));

        data.push_back(Pair("signedData", signedData));
        data.push_back(Pair("signatures", signatures));

        string strData = write_string(Value(data), false);
        CIdentifiPacket packet(strData);
        packet.Sign(defaultKey);
        SavePacket(packet);
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
    sql << "ID              INTEGER         PRIMARY KEY,";
    sql << "Value           NVARCHAR(255)   NOT NULL,";
    sql << "IsUniqueType    BOOL            DEFAULT 0";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Packets (";
    sql << "Hash                NVARCHAR(45)    PRIMARY KEY,";
    sql << "SignedData          NVARCHAR(1000)  NOT NULL,";
    sql << "Created             DATETIME,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "Rating              INTEGER         DEFAULT 0,";
    sql << "MinRating           INTEGER         DEFAULT 0,";
    sql << "MaxRating           INTEGER         DEFAULT 0,";
    sql << "Published           BOOL            DEFAULT 0,";
    sql << "TrustValue          INTEGER         DEFAULT 0";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PacketSubjects (";
    sql << "PacketHash          NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "SubjectHash         NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PacketObjects (";
    sql << "PacketHash          NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "ObjectHash          NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PacketSignatures (";
    sql << "PacketHash        NVARCHAR(45)    NOT NULL,";
    sql << "Signature           NVARCHAR(100)   NOT NULL,";
    sql << "PubKeyHash          NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PrivateKeys (";
    sql << "PubKeyHash        NVARCHAR(45)    PRIMARY KEY,";
    sql << "PrivateKey        NVARCHAR(1000)  NOT NULL,";
    sql << "IsDefault         BOOL            DEFAULT 0);";
    query(sql.str().c_str());

    CheckDefaultUniquePredicates();
    CheckDefaultKey();
    CheckDefaultTrustList();
}

vector<pair<string, string> > CIdentifiDB::GetSubjectsByPacketHash(string packetHash) {
    vector<pair<string, string> > subjects;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN PacketSubjects AS rs ON rs.PacketHash = @packethash ";
    sql << "INNER JOIN Predicates AS p ON rs.PredicateID = p.ID ";
    sql << "WHERE id.Hash = rs.SubjectHash;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);

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

vector<pair<string, string> > CIdentifiDB::GetObjectsByPacketHash(string packetHash) {
    vector<pair<string, string> > objects;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN PacketObjects AS ro ON ro.PacketHash = @packethash ";
    sql << "INNER JOIN Predicates AS p ON ro.PredicateID = p.ID ";
    sql << "WHERE id.Hash = ro.ObjectHash;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);

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

vector<CSignature> CIdentifiDB::GetSignaturesByPacketHash(string packetHash) {
    vector<CSignature> signatures;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT id.Value, rs.Signature FROM PacketSignatures AS rs ";
    sql << "INNER JOIN Identifiers AS id ON id.Hash = rs.PubKeyHash ";
    sql << "WHERE rs.PacketHash = @packethash;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
            
            if(result == SQLITE_ROW) {
                string pubKey = string((char*)sqlite3_column_text(statement, 0));
                string signature = string((char*)sqlite3_column_text(statement, 1));
                signatures.push_back(CSignature(pubKey, signature));
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

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByIdentifier(pair<string, string> identifier, bool uniquePredicatesOnly) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketSubjects AS ps ON ps.PacketHash = p.Hash ";
    sql << "INNER JOIN PacketObjects AS po ON po.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON (ps.SubjectHash = id.Hash ";
    sql << "OR po.ObjectHash = id.Hash) ";
    sql << "INNER JOIN Predicates AS pred ON (ps.PredicateID = pred.ID ";
    sql << "OR po.PredicateID = pred.ID) ";
    sql << "WHERE ";
    if (!identifier.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (uniquePredicatesOnly)
        sql << "pred.IsUniqueType = 1 AND ";
    sql << "id.Value = @idValue;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!identifier.first.empty()) {
            sqlite3_bind_text(statement, 1, identifier.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_text(statement, 1, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                packets.push_back(GetPacketFromStatement(statement));
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
    
    return packets;
}

CIdentifiPacket CIdentifiDB::GetPacketFromStatement(sqlite3_stmt *statement) {
    string strData = (char*)sqlite3_column_text(statement, 1);
    CIdentifiPacket packet(strData);
    if(sqlite3_column_int(statement, 7) == 1)
        packet.SetPublished();
    return packet;
}

vector<CIdentifiPacket> CIdentifiDB::getpacketsbyauthor(pair<string, string> subject, bool uniquePredicatesOnly) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketSubjects AS ps ON ps.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON ps.SubjectHash = id.Hash ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = ps.PredicateID WHERE ";
    if (!subject.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (uniquePredicatesOnly)
        sql << "pred.IsUniqueType = 1 AND ";
    sql << "id.Value = @idValue;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!subject.first.empty()) {
            sqlite3_bind_text(statement, 1, subject.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, subject.second.c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_text(statement, 1, subject.second.c_str(), -1, SQLITE_TRANSIENT);            
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                packets.push_back(GetPacketFromStatement(statement));
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
    
    return packets;
}

vector<CIdentifiPacket> CIdentifiDB::getpacketsbyrecipient(pair<string, string> object, bool uniquePredicatesOnly) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketObjects AS po ON po.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON po.ObjectHash = id.Hash ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = po.PredicateID WHERE ";
    if (!object.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (uniquePredicatesOnly)
        sql << "pred.IsUniqueType = 1 AND ";
    sql << "id.Value = @idValue;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!object.first.empty()) {
            sqlite3_bind_text(statement, 1, object.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, object.second.c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_text(statement, 1, object.second.c_str(), -1, SQLITE_TRANSIENT);
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                packets.push_back(GetPacketFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }
    
    return packets;
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
    } else {
        sql = "INSERT INTO Predicates (Value) VALUES (@value);";
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, predicate.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement);
            }
        )
        rowid = sqlite3_last_insert_rowid(db);
    }
    sqlite3_finalize(statement);
    return rowid;
}

string CIdentifiDB::SaveIdentifier(string identifier) {
    sqlite3_stmt *statement;
    string hash;

    const char *sql = "SELECT Hash FROM Identifiers WHERE Value = @value;";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, identifier.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(statement) == SQLITE_ROW) {
            hash = string((char*)sqlite3_column_text(statement, 0));
        } else {
            sql = "INSERT INTO Identifiers (Value, Hash) VALUES (@value, @hash);";
            RETRY_IF_DB_FULL(
                if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
                    hash = EncodeBase58(Hash(identifier.begin(), identifier.end()));
                    sqlite3_bind_text(statement, 1, identifier.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(statement, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_step(statement);
                    sqliteReturnCode = sqlite3_reset(statement);
                }
            )
        }
    }
    sqlite3_finalize(statement);
    return hash;
}

void CIdentifiDB::DropPacket(string strPacketHash) {
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "DELETE FROM Packets WHERE Hash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    // Remove identifiers that were mentioned in this packet only
    sql.str("");
    sql << "DELETE FROM Identifiers WHERE Hash IN ";
    sql << "(SELECT id.Hash FROM Identifiers AS id ";
    sql << "JOIN PacketObjects AS ro ON ro.ObjectHash = id.Hash ";
    sql << "JOIN PacketSubjects AS rs ON rs.SubjectHash = id.Hash ";
    sql << "WHERE ro.PacketHash = @relhash OR rs.PacketHash = @relhash) ";
    sql << "AND Hash NOT IN ";
    sql << "(SELECT id.Hash FROM Identifiers AS id ";
    sql << "JOIN PacketObjects AS ro ON ro.ObjectHash = id.Hash ";
    sql << "JOIN PacketSubjects AS rs ON rs.SubjectHash = id.Hash ";
    sql << "WHERE ro.PacketHash != @relhash AND rs.PacketHash != @relhash)";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sql.str("");
    sql << "DELETE FROM PacketObjects WHERE PacketHash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sql.str("");
    sql << "DELETE FROM PacketSubjects WHERE PacketHash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sql.str("");
    sql << "DELETE FROM PacketSignatures WHERE PacketHash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sqlite3_finalize(statement);
}

// This is called to drop the least valuable data when DB is full
bool CIdentifiDB::MakeFreeSpace(int nFreeBytesNeeded) {
    ostringstream sql;
    int nFreePages, nPageSize, nMaxPageCount;
    nPageSize = lexical_cast<int>(query("PRAGMA page_size")[0][0]);
    nMaxPageCount = lexical_cast<int>(query("PRAGMA max_page_count")[0][0]);

    if (nFreeBytesNeeded > nMaxPageCount * nPageSize)
        return false;

    do {
        sql.str("");
        sql << "SELECT Hash FROM Packets ORDER BY TrustValue ASC, Created ASC LIMIT 1";
        string packetToRemove = query(sql.str().c_str())[0][0];
        DropPacket(packetToRemove);
        nFreePages = lexical_cast<int>(query("PRAGMA freelist_count")[0][0]);
    } while (nFreePages * nPageSize < nFreeBytesNeeded);

    return true;
}

void CIdentifiDB::SavePacketSubject(string packetHash, int predicateID, string subjectHash) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM PacketSubjects ";
    sql << "WHERE PacketHash = @packethash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND SubjectHash = @subjecthash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_text(statement, 3, subjectHash.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO PacketSubjects (PacketHash, PredicateID, SubjectHash) ";
        sql << "VALUES (@packethash, @predicateid, @subjectid);";
        
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 2, predicateID);
                sqlite3_bind_text(statement, 3, subjectHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement);
            }
        )
    }
    sqlite3_finalize(statement);
}

void CIdentifiDB::SavePacketObject(string packetHash, int predicateID, string objectHash) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM PacketObjects ";
    sql << "WHERE PacketHash = @packethash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND ObjectHash = @objecthash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_text(statement, 3, objectHash.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO PacketObjects (PacketHash, PredicateID, ObjectHash) ";
        sql << "VALUES (@packethash, @predicateid, @objectid);";
        
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 2, predicateID);
                sqlite3_bind_text(statement, 3, objectHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement);
            }
        )
    }
    sqlite3_finalize(statement);
}

void CIdentifiDB::SavePacketSignature(CSignature &signature, string packetHash) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM PacketSignatures WHERE PacketHash = @packetHash ";
    sql << "AND PubKeyHash = @pubKeyHash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, signature.GetSignerPubKeyHash().c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO PacketSignatures (PacketHash, PubKeyHash, Signature) ";
        sql << "VALUES (@packethash, @pubkeyhash, @signature);";
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 2, signature.GetSignerPubKeyHash().c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 3, signature.GetSignature().c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement); 
            }
        )
    }
    sqlite3_finalize(statement);
    SaveIdentifier(signature.GetSignerPubKey());
}

// Arbitrary numeric trust metric
int CIdentifiDB::GetTrustValue(CIdentifiPacket &packet) {
    const int MAX_TRUST = 100;
    CKey myKey = GetDefaultKey();
    string strMyKey = EncodeBase58(myKey.GetPubKey().Raw());
    string keyType = "ecdsa_base58";

    int nShortestPathToSignature = 1000000;
    vector<CSignature> sigs = packet.GetSignatures();
    for (vector<CSignature>::iterator sig = sigs.begin(); sig != sigs.end(); sig++) {
        string signerPubKey = sig->GetSignerPubKey();
        if (signerPubKey == strMyKey) {
            nShortestPathToSignature = 1;
            break;            
        }
        int nPath = GetPath(make_pair(keyType, strMyKey), make_pair(keyType, signerPubKey)).size();
        if (nPath < nShortestPathToSignature)
            nShortestPathToSignature = nPath + 1;
    }

    int nShortestPathToSubject = 1000000;
    vector<pair<string, string> > subjects = packet.GetSubjects();
    for (vector<pair<string, string> >::iterator subject = subjects.begin(); subject != subjects.end(); subject++) {
        if (*subject == make_pair(keyType, strMyKey)) {
            nShortestPathToSubject = 1;
            break;            
        }
        int nPath = GetPath(make_pair(keyType, strMyKey), *subject).size();
        if (nPath < nShortestPathToSubject)
            nShortestPathToSubject = nPath + 1;
    }

    int nTrust = (MAX_TRUST / nShortestPathToSignature)
                    * (MAX_TRUST / nShortestPathToSubject);

    if (nTrust > 0)
        return nTrust / MAX_TRUST;
    else
        return 0;
}

string CIdentifiDB::SavePacket(CIdentifiPacket &packet) {
    sqlite3_stmt *statement;
    string sql;
    string packetHash;

    sql = "INSERT OR REPLACE INTO Packets (Hash, SignedData, Created, PredicateID, Rating, MaxRating, MinRating, Published, TrustValue) VALUES (@id, @data, @timestamp, @predicateid, @rating, @maxRating, @minRating, @published, @trust);";
    packetHash = EncodeBase58(packet.GetHash());
    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, packet.GetData().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(statement, 3, packet.GetTimestamp());
            sqlite3_bind_int(statement, 4, SavePredicate(packet.GetType()));
            sqlite3_bind_int(statement, 5, packet.GetRating());
            sqlite3_bind_int(statement, 6, packet.GetMaxRating());
            sqlite3_bind_int(statement, 7, packet.GetMinRating());
            sqlite3_bind_int(statement, 8, packet.IsPublished());
            sqlite3_bind_int(statement, 9, GetTrustValue(packet));
        } else {
            printf("DB Error: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_step(statement);
        sqliteReturnCode = sqlite3_reset(statement);
    )

    vector<pair<string, string> > subjects = packet.GetSubjects();
    for (vector<pair<string, string> >::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        int predicateID = SavePredicate(it->first);
        string subjectHash = SaveIdentifier(it->second);
        SavePacketSubject(packetHash, predicateID, subjectHash);
    }
    vector<pair<string, string> > objects = packet.GetObjects();
    for (vector<pair<string, string> >::iterator it = objects.begin(); it != objects.end(); ++it) {
        int predicateID = SavePredicate(it->first);
        string objectHash = SaveIdentifier(it->second);
        SavePacketObject(packetHash, predicateID, objectHash);
    }
    vector<CSignature> signatures = packet.GetSignatures();
    for (vector<CSignature>::iterator it = signatures.begin(); it != signatures.end(); ++it) {
        SavePacketSignature(*it, EncodeBase58(packet.GetHash()));
    }

    sqlite3_finalize(statement);
    return packetHash;
}


bool CIdentifiDB::ImportPrivKey(string privKey, bool setDefault) {
    CIdentifiSecret s;
    s.SetString(privKey);
    if (!s.IsValid())
        throw runtime_error("ImportPrivKey failed: invalid key");
    bool compressed = false;
    CSecret secret = s.GetSecret(compressed);

    CKey key;
    key.SetSecret(secret, false);
    vector<unsigned char> pubKey = key.GetPubKey().Raw();
    string pubKeyStr = EncodeBase58(pubKey);
    string pubKeyHash = SaveIdentifier(pubKeyStr);

    if (setDefault)
        query("UPDATE PrivateKeys SET IsDefault = 0");

    sqlite3_stmt *statement;
    string sql = "INSERT OR REPLACE INTO PrivateKeys (PubKeyHash, PrivateKey, IsDefault) VALUES (@pubkeyhash, @privatekey, @isdefault);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, pubKeyHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, privKey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 3, setDefault);
        sqlite3_step(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }   
    sqlite3_finalize(statement); 
    return true;
}

void CIdentifiDB::SetDefaultKey(string privKey) {
    ImportPrivKey(privKey, true);
}

CKey CIdentifiDB::GetDefaultKey() {
    string pubKey, privKey;

    sqlite3_stmt *statement;
    ostringstream sql;
    sql.str("");
    sql << "SELECT PrivateKey FROM PrivateKeys WHERE IsDefault = 1";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if(result == SQLITE_ROW)
        {
            privKey = string((char*)sqlite3_column_text(statement, 0));
        } else {
            throw runtime_error("Failed to retrieve default key");  
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



vector<string> CIdentifiDB::ListPrivKeys() {
    vector<string> keys;

    vector<vector<string> > result = query("SELECT PrivateKey FROM PrivateKeys");
    for (vector<vector <string> >::iterator it = result.begin(); it != result.end(); it++) {
        keys.push_back(it->front());
    }

    return keys;
}

bool CIdentifiDB::HasTrustedSigner(CIdentifiPacket &packet, string &trustedKey) {
    bool hasTrustedSigner = false;
    vector<CSignature> signatures = packet.GetSignatures();
    for (vector<CSignature>::iterator sig = signatures.begin(); sig != signatures.end(); sig++) {
        string strSignerPubKey = sig->GetSignerPubKey();
        if (strSignerPubKey == trustedKey
            || GetPath(make_pair("ecdsa_base58", trustedKey), make_pair("ecdsa_base58", strSignerPubKey)).size() > 0, 3) {
            hasTrustedSigner = true;
            break;                
        }
    }
    return hasTrustedSigner;
}

// Breadth-first search for the shortest trust path from id1 to id2
vector<CIdentifiPacket> CIdentifiDB::GetPath(pair<string, string> start, pair<string, string> end, int searchDepth) {
    string strDefaultKey = EncodeBase58(GetDefaultKey().GetPubKey().Raw());
    vector<CIdentifiPacket> path;
    vector<uint256> visitedPackets;

    deque<CIdentifiPacket> searchQueue;
    map<uint256, CIdentifiPacket> previousPackets;
    map<uint256, int> packetDistanceFromStart;

    vector<CIdentifiPacket> packets = GetPacketsByIdentifier(start, true);
    searchQueue.insert(searchQueue.end(), packets.begin(), packets.end());
    int currentDistanceFromStart = 1;

    while (!searchQueue.empty()) {
        CIdentifiPacket currentPacket = searchQueue.front();
        searchQueue.pop_front();
        if (find(visitedPackets.begin(), visitedPackets.end(), currentPacket.GetHash()) != visitedPackets.end()) {
            continue;
        }
        visitedPackets.push_back(currentPacket.GetHash());

        if (currentPacket.GetRating() <= (currentPacket.GetMaxRating() + currentPacket.GetMinRating()) / 2)
            continue;

        if (!HasTrustedSigner(currentPacket, strDefaultKey))
            continue;

        if (packetDistanceFromStart.find(currentPacket.GetHash()) != packetDistanceFromStart.end())
            currentDistanceFromStart = packetDistanceFromStart[currentPacket.GetHash()];

        vector<pair<string, string> > allIdentifiers = currentPacket.GetSubjects();
        vector<pair<string, string> > objects = currentPacket.GetObjects();
        allIdentifiers.insert(allIdentifiers.end(), objects.begin(), objects.end());
        for (vector<pair<string, string> >::iterator identifier = allIdentifiers.begin(); identifier != allIdentifiers.end(); identifier++) {
            if ((identifier->first.empty() || end.first.empty() || identifier->first == end.first)
                    && identifier->second == end.second) {
                // Path found: backtrack it from end to start and return it
                path.push_back(currentPacket);

                CIdentifiPacket previousPacket = currentPacket;
                while (previousPackets.find(previousPacket.GetHash()) != previousPackets.end()) {
                    previousPacket = previousPackets.at(previousPacket.GetHash());
                    path.insert(path.begin(), previousPacket);
                }
                return path;
            } else if (currentDistanceFromStart < searchDepth) {
                // No path found yet: add packets involving this identifier to search queue
                vector<CIdentifiPacket> allPackets = GetPacketsByIdentifier(*identifier, true);

                searchQueue.insert(searchQueue.end(), allPackets.begin(), allPackets.end());

                for (vector<CIdentifiPacket>::iterator p = allPackets.begin(); p != allPackets.end(); p++) {
                    if (previousPackets.find(p->GetHash()) == previousPackets.end()
                        && find(visitedPackets.begin(), visitedPackets.end(), p->GetHash()) == visitedPackets.end())
                        previousPackets[p->GetHash()] = currentPacket;
                    if (packetDistanceFromStart.find(p->GetHash()) == packetDistanceFromStart.end()
                        && find(visitedPackets.begin(), visitedPackets.end(), p->GetHash()) == visitedPackets.end()) {
                        packetDistanceFromStart[p->GetHash()] = currentDistanceFromStart + 1;
                    }
                }
            }
        }
    }

    return path;
}

CIdentifiPacket CIdentifiDB::GetPacketByHash(string hash) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    const char* sql = "SELECT * FROM Packets WHERE Packets.Hash = @hash;";

    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, hash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                CIdentifiPacket packet = GetPacketFromStatement(statement);
                sqlite3_finalize(statement);
                return packet;
            } else {
                break;
            }
        }
        
    }
    sqlite3_finalize(statement);
    throw runtime_error("packet not found");    
}

int CIdentifiDB::GetIdentifierCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Identifiers");
    return lexical_cast<int>(result[0][0]);
}

int CIdentifiDB::GetPacketCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Packets");
    return lexical_cast<int>(result[0][0]);
}

vector<CIdentifiPacket> CIdentifiDB::GetPacketsAfterTimestamp(time_t timestamp, int limit) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets WHERE Created >= @timestamp LIMIT @limit";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int64(statement, 1, timestamp);
        sqlite3_bind_int(statement, 2, limit);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                packets.push_back(GetPacketFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }
    
    return packets;
}

vector<CIdentifiPacket> CIdentifiDB::GetPacketsAfterPacket(string packetHash, int limit) {
    CIdentifiPacket rel = GetPacketByHash(packetHash);
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets WHERE ";
    sql << "(Created = @timestamp AND Hash > @packethash) OR ";
    sql << "(Created > @timestamp) ORDER BY Created, Hash LIMIT @limit";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 2, rel.GetTimestamp());
        sqlite3_bind_int(statement, 3, limit);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                packets.push_back(GetPacketFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }
    
    return packets;
}

time_t CIdentifiDB::GetLatestPacketTimestamp() {
    sqlite3_stmt *statement;
    time_t timestamp = 0;
    const char* sql = "SELECT Created FROM Packets ORDER BY Created DESC LIMIT 1";

    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if(result == SQLITE_ROW) {
            timestamp = sqlite3_column_int64(statement, 0);
        }
    }
    sqlite3_finalize(statement);
    return timestamp;
}