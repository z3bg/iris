// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <deque>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <map>
#include <cmath>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

#include "identifidb.h"
#include "main.h"
#include "data.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

typedef std::pair<string, string> string_pair;

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

void CIdentifiDB::CheckDefaultTrustPathablePredicates() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Predicates");
    if (lexical_cast<int>(result[0][0]) < 1) {
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('mbox', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('email', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('url', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('tel', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('base58pubkey', 1)");
    }
}

void CIdentifiDB::CheckDefaultKey() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Keys WHERE IsDefault = 1");
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
        author1.push_back("base58pubkey");
        author1.push_back(strPubKey);
        author.push_back(author1);
        recipient1.push_back("base58pubkey");
        recipient1.push_back("NdudNBcekP9rQW425xpnpeVtDu1DLTFiMuAMkBsXRVpM8LheWfjPj7fiU7QNVxNbN1YbMXnXrhQEcuUovMB41fvm");
        recipient.push_back(recipient1);
        
        time_t now = time(NULL);

        json_spirit::Object data, signedData;
        signedData.push_back(Pair("timestamp", lexical_cast<int64_t>(now)));
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
    int dbVersion = lexical_cast<int>(query("PRAGMA user_version")[0][0]);
    if (dbVersion == 0) {
        query("PRAGMA user_version = 1");
    } else if (dbVersion > 1) {
        throw runtime_error("Invalid database version");
    }

    ostringstream sql;

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Identifiers (";
    sql << "ID        INTEGER         PRIMARY KEY,";
    sql << "Value     NVARCHAR(255)   NOT NULL";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Predicates (";
    sql << "ID                  INTEGER         PRIMARY KEY,";
    sql << "Value               NVARCHAR(255)   NOT NULL,";
    sql << "TrustPathable       BOOL            DEFAULT 0";
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
    sql << "Priority            INTEGER         DEFAULT 0";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PacketAuthors (";
    sql << "PacketHash          NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "AuthorID            INTEGER         NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PacketRecipients (";
    sql << "PacketHash          NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "RecipientID         INTEGER         NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PacketSignatures (";
    sql << "PacketHash          NVARCHAR(45)    NOT NULL,";
    sql << "Signature           NVARCHAR(100)   NOT NULL,";
    sql << "PubKeyID            INTEGER         NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS TrustPaths (";
    sql << "StartID             INTEGER         NOT NULL,";
    sql << "StartPredicateID    INTEGER,";
    sql << "EndID               INTEGER         NOT NULL,";
    sql << "EndPredicateID      INTEGER,";
    sql << "NextStep            NVARCHAR(45)    NOT NULL);";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Keys (";
    sql << "PubKeyID            INTEGER         PRIMARY KEY,";
    sql << "BitcoinAddressID    INTEGER         DEFAULT NULL,";
    sql << "PrivateKey          NVARCHAR(1000)  DEFAULT NULL,";
    sql << "IsDefault           BOOL            DEFAULT 0);";
    query(sql.str().c_str());

    CheckDefaultTrustPathablePredicates();
    CheckDefaultKey();
    CheckDefaultTrustList();
    SearchForPathForMyKeys();
}

void CIdentifiDB::SearchForPathForMyKeys() {
    vector<string> myPubKeys = GetMyPubKeys();
    BOOST_FOREACH (string key, myPubKeys) {
        SearchForPath(make_pair("base58pubkey", key));
    } 
}

vector<string_pair> CIdentifiDB::GetAuthorsByPacketHash(string packetHash) {
    vector<string_pair> authors;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN PacketAuthors AS rs ON rs.PacketHash = @packethash ";
    sql << "INNER JOIN Predicates AS p ON rs.PredicateID = p.ID ";
    sql << "WHERE id.ID = rs.AuthorID;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW) {
                string predicate = string((char*)sqlite3_column_text(statement, 0));
                string identifier = string((char*)sqlite3_column_text(statement, 1));
                authors.push_back(make_pair(predicate, identifier));
            } else {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }

    return authors;
}

vector<string_pair> CIdentifiDB::GetRecipientsByPacketHash(string packetHash) {
    vector<string_pair> recipients;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN PacketRecipients AS ro ON ro.PacketHash = @packethash ";
    sql << "INNER JOIN Predicates AS p ON ro.PredicateID = p.ID ";
    sql << "WHERE id.ID = ro.RecipientID;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true) {
            result = sqlite3_step(statement);
            
            if(result == SQLITE_ROW) {
                string predicate = string((char*)sqlite3_column_text(statement, 0));
                string identifier = string((char*)sqlite3_column_text(statement, 1));
                recipients.push_back(make_pair(predicate, identifier));
            } else {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    
    return recipients;
}

vector<CSignature> CIdentifiDB::GetSignaturesByPacketHash(string packetHash) {
    vector<CSignature> signatures;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT id.Value, rs.Signature FROM PacketSignatures AS rs ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = rs.PubKeyID ";
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

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByIdentifier(string_pair identifier, bool trustPathablePredicatesOnly, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketAuthors AS ps ON ps.PacketHash = p.Hash ";
    sql << "INNER JOIN PacketRecipients AS po ON po.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON (ps.AuthorID = id.ID ";
    sql << "OR po.RecipientID = id.ID) ";
    sql << "INNER JOIN Predicates AS pred ON (ps.PredicateID = pred.ID ";
    sql << "OR po.PredicateID = pred.ID) ";
    sql << "WHERE ";
    if (!identifier.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
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
    packet.SetPriority(sqlite3_column_int(statement, 8));
    return packet;
}

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByAuthor(string_pair author, bool trustPathablePredicatesOnly, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketAuthors AS ps ON ps.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON ps.AuthorID = id.ID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = ps.PredicateID WHERE ";
    if (!author.first.empty())
        sql << "pred.Value = @predValue AND ";
    if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    sql << "id.Value = @idValue;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!author.first.empty()) {
            sqlite3_bind_text(statement, 1, author.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, author.second.c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_text(statement, 1, author.second.c_str(), -1, SQLITE_TRANSIENT);            
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

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByRecipient(string_pair recipient, bool trustPathablePredicatesOnly, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketRecipients AS po ON po.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON po.RecipientID = id.ID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = po.PredicateID WHERE ";
    if (!recipient.first.empty())
        sql << "pred.Value = @predValue AND ";
    if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    sql << "id.Value = @idValue;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!recipient.first.empty()) {
            sqlite3_bind_text(statement, 1, recipient.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, recipient.second.c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_text(statement, 1, recipient.second.c_str(), -1, SQLITE_TRANSIENT);
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

int CIdentifiDB::SaveIdentifier(string identifier) {
    sqlite3_stmt *statement;
    int rowid = -1;

    const char *sql = "SELECT ID FROM Identifiers WHERE Value = @value;";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, identifier.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(statement) == SQLITE_ROW) {
            rowid = sqlite3_column_int(statement, 0);
        } else {
            sql = "INSERT INTO Identifiers (Value) VALUES (@value);";
            RETRY_IF_DB_FULL(
                if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
                    sqlite3_bind_text(statement, 1, identifier.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_step(statement);
                    sqliteReturnCode = sqlite3_reset(statement);
                }
            )
            rowid = sqlite3_last_insert_rowid(db);
        }
    }
    sqlite3_finalize(statement);
    return rowid;
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
    sql << "(SELECT id.ID FROM Identifiers AS id ";
    sql << "JOIN PacketRecipients AS ro ON ro.RecipientID = id.ID ";
    sql << "JOIN PacketAuthors AS rs ON rs.AuthorID = id.ID ";
    sql << "WHERE ro.PacketHash = @relhash OR rs.PacketHash = @relhash) ";
    sql << "AND Hash NOT IN ";
    sql << "(SELECT id.ID FROM Identifiers AS id ";
    sql << "JOIN PacketRecipients AS ro ON ro.RecipientID = id.ID ";
    sql << "JOIN PacketAuthors AS rs ON rs.AuthorID = id.ID ";
    sql << "WHERE ro.PacketHash != @relhash AND rs.PacketHash != @relhash)";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sql.str("");
    sql << "DELETE FROM PacketRecipients WHERE PacketHash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sql.str("");
    sql << "DELETE FROM PacketAuthors WHERE PacketHash = @hash;";
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
        sql << "SELECT Hash FROM Packets ORDER BY Priority ASC, Created ASC LIMIT 1";
        string packetToRemove = query(sql.str().c_str())[0][0];
        DropPacket(packetToRemove);
        nFreePages = lexical_cast<int>(query("PRAGMA freelist_count")[0][0]);
    } while (nFreePages * nPageSize < nFreeBytesNeeded);

    return true;
}

void CIdentifiDB::SavePacketAuthor(string packetHash, int predicateID, int authorID) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM PacketAuthors ";
    sql << "WHERE PacketHash = @packethash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND AuthorID = @authorhash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_int(statement, 3, authorID);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO PacketAuthors (PacketHash, PredicateID, AuthorID) ";
        sql << "VALUES (@packethash, @predicateid, @authorid);";
        
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 2, predicateID);
                sqlite3_bind_int(statement, 3, authorID);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement);
            }
        )
    }
    sqlite3_finalize(statement);
}

void CIdentifiDB::SavePacketRecipient(string packetHash, int predicateID, int recipientID) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM PacketRecipients ";
    sql << "WHERE PacketHash = @packethash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND RecipientID = @recipienthash";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_int(statement, 3, recipientID);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO PacketRecipients (PacketHash, PredicateID, RecipientID) ";
        sql << "VALUES (@packethash, @predicateid, @recipientid);";
        
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 2, predicateID);
                sqlite3_bind_int(statement, 3, recipientID);
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
    sql << "AND PubKeyID = @pubKeyHash";

    string strPubKey = signature.GetSignerPubKey();
    SavePubKey(strPubKey);

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, SaveIdentifier(strPubKey));
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO PacketSignatures (PacketHash, PubKeyID, Signature) ";
        sql << "VALUES (@packethash, @pubkeyhash, @signature);";
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 2, SaveIdentifier(signature.GetSignerPubKey()));
                sqlite3_bind_text(statement, 3, signature.GetSignature().c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement); 
            }
        )
    }
    sqlite3_finalize(statement);
    SaveIdentifier(signature.GetSignerPubKey());
}

int CIdentifiDB::GetPacketCountByAuthor(string_pair author) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");
    sql << "SELECT COUNT(1) FROM Packets AS p ";
    sql << "INNER JOIN PacketAuthors AS ps ON ps.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = ps.AuthorID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = ps.PredicateID ";
    sql << "WHERE pred.Value = @type AND id.Value = @value";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, author.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, author.second.c_str(), -1, SQLITE_TRANSIENT);
    }

    if (sqlite3_step(statement) == SQLITE_ROW) {
        int count = sqlite3_column_int(statement, 1);
        sqlite3_finalize(statement);
        return count;
    } else {
        sqlite3_finalize(statement);
        throw runtime_error("GetPacketCountByAuthor failed");
    }
}

// Arbitrary storage priority metric
int CIdentifiDB::GetPriority(CIdentifiPacket &packet) {
    const int MAX_PRIORITY = 100;
    vector<string> myPubKeys = GetMyPubKeys();
    string keyType = "base58pubkey";

    int nShortestPathToSignature = 1000000;
    vector<CSignature> sigs = packet.GetSignatures();
    BOOST_FOREACH (CSignature sig, sigs) {
        string signerPubKey = sig.GetSignerPubKey();
        BOOST_FOREACH (string myPubKey, myPubKeys) {
            if (signerPubKey == myPubKey) {
                nShortestPathToSignature = 1;
                break;            
            }
            int nPath = GetSavedPath(make_pair(keyType, myPubKey), make_pair(keyType, signerPubKey)).size();
            if (nPath > 0 && nPath < nShortestPathToSignature)
                nShortestPathToSignature = nPath + 1;
        }
        if (nShortestPathToSignature == 1)
            break;
    } 

    int nShortestPathToAuthor = 1000000;
    int nMostPacketsFromAuthor = -1;
    bool isMyPacket = false;

    vector<string_pair> authors = packet.GetAuthors();
    BOOST_FOREACH (string_pair author, authors) {
        if (nShortestPathToAuthor > 1) {
            BOOST_FOREACH (string myPubKey, myPubKeys) {            
                if (author == make_pair(keyType, myPubKey)) {
                    nShortestPathToAuthor = 1;
                    isMyPacket = true;
                    break;            
                }
                int nPath = GetSavedPath(make_pair(keyType, myPubKey), author).size();
                if (nPath > 0 && nPath < nShortestPathToAuthor)
                    nShortestPathToAuthor = nPath + 1;
            }
        }
        int nPacketsFromAuthor = GetPacketCountByAuthor(author);
        if (nPacketsFromAuthor > nMostPacketsFromAuthor)
            nMostPacketsFromAuthor = nPacketsFromAuthor;
    }

    int nPriority = (MAX_PRIORITY / nShortestPathToSignature)
                    * (MAX_PRIORITY / nShortestPathToAuthor);

    if (!isMyPacket && nMostPacketsFromAuthor > 10)
        nPriority = nPriority / log10(nMostPacketsFromAuthor);

    if (nPriority == 0 && nShortestPathToSignature > 0)
        return 5 / nShortestPathToSignature;
    else
        return nPriority / MAX_PRIORITY;
}

string CIdentifiDB::SavePacket(CIdentifiPacket &packet) {
    int priority = GetPriority(packet);
    if (priority == 0 && !GetArg("-saveuntrustedpackets", false)) return "";

    sqlite3_stmt *statement;
    string sql;
    string packetHash;

    sql = "INSERT OR REPLACE INTO Packets (Hash, SignedData, Created, PredicateID, Rating, MaxRating, MinRating, Published, Priority) VALUES (@id, @data, @timestamp, @predicateid, @rating, @maxRating, @minRating, @published, @priority);";
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
            sqlite3_bind_int(statement, 9, priority);
        } else {
            printf("DB Error: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_step(statement);
        sqliteReturnCode = sqlite3_reset(statement);
    )

    vector<string_pair> authors = packet.GetAuthors();
    BOOST_FOREACH (string_pair author, authors) {
        int predicateID = SavePredicate(author.first);
        int authorID = SaveIdentifier(author.second);
        SavePacketAuthor(packetHash, predicateID, authorID);
    }
    vector<string_pair> recipients = packet.GetRecipients();
    BOOST_FOREACH (string_pair recipient, recipients) {
        int predicateID = SavePredicate(recipient.first);
        int recipientID = SaveIdentifier(recipient.second);
        SavePacketRecipient(packetHash, predicateID, recipientID);
    }
    vector<CSignature> signatures = packet.GetSignatures();
    BOOST_FOREACH (CSignature sig, signatures) {
        SavePacketSignature(sig, EncodeBase58(packet.GetHash()));
    }

    sqlite3_finalize(statement);

    SavePacketTrustPaths(packet);

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
    CPubKey pubKey = key.GetPubKey();
    vector<unsigned char> rawPubKey = pubKey.Raw();
    string pubKeyStr = EncodeBase58(rawPubKey);
    int pubKeyID = SaveIdentifier(pubKeyStr);

    CIdentifiAddress address(pubKey.GetID());
    int bitcoinAddressID = SaveIdentifier(address.ToString());

    if (setDefault)
        query("UPDATE Keys SET IsDefault = 0");

    sqlite3_stmt *statement;
    string sql = "INSERT OR REPLACE INTO Keys (PubKeyID, BitcoinAddressID, PrivateKey, IsDefault) VALUES (@pubkeyid, @bitcoinaddressid, @privatekey, @isdefault);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, pubKeyID);
        sqlite3_bind_int(statement, 2, bitcoinAddressID);
        sqlite3_bind_text(statement, 3, privKey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 4, setDefault);
        sqlite3_step(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }   
    sqlite3_finalize(statement); 
    return true;
}

bool CIdentifiDB::SavePubKey(string pubKey) {
    vector<unsigned char> vchPubKey;
    DecodeBase58(pubKey, vchPubKey);
    CPubKey key(vchPubKey);
    if (!key.IsValid())
        throw runtime_error("SavePubKey failed: invalid key");

    CIdentifiAddress address(key.GetID());
    int bitcoinAddressID = SaveIdentifier(address.ToString());
    int pubKeyID = SaveIdentifier(pubKey);

    sqlite3_stmt *statement;
    string sql = "INSERT OR IGNORE INTO Keys (PubKeyID, BitcoinAddressID) VALUES (@pubkeyid, @bitcoinaddressid);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, pubKeyID);
        sqlite3_bind_int(statement, 2, bitcoinAddressID);
        sqlite3_step(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(statement);
        return false;
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
    sql << "SELECT PrivateKey FROM Keys WHERE IsDefault = 1";

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


vector<string> CIdentifiDB::GetMyPubKeys() {
    vector<string> myPubKeys;

    string pubKey, privKey;

    ostringstream sql;
    sql.str("");
    sql << "SELECT id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN Keys AS pk ON pk.PubKeyID = id.ID ";
    sql << "WHERE pk.PrivateKey IS NOT NULL";

    vector<vector<string> > result = query(sql.str().c_str());

    BOOST_FOREACH (vector<string> vStr, result) {
        myPubKeys.push_back(vStr.front());
    }

    return myPubKeys;
}

vector<IdentifiKey> CIdentifiDB::GetMyKeys() {
    vector<IdentifiKey> myKeys;

    string pubKey, privKey;

    ostringstream sql;
    sql.str("");
    sql << "SELECT pubKeyID.Value, btcAddrID.Value, k.PrivateKey FROM Identifiers AS pubKeyID ";
    sql << "INNER JOIN Keys AS k ON k.PubKeyID = pubKeyID.ID ";
    sql << "INNER JOIN Identifiers AS btcAddrID ON k.BitcoinAddressID = btcAddrID.ID ";
    sql << "WHERE k.PrivateKey IS NOT NULL";

    vector<vector<string> > result = query(sql.str().c_str());

    BOOST_FOREACH (vector<string> vStr, result) {
        IdentifiKey key;
        key.pubKey = vStr[0];
        key.bitcoinAddress = vStr[1];
        key.privKey = vStr[2];
        myKeys.push_back(key);
    }

    return myKeys;
}

bool CIdentifiDB::HasTrustedSigner(CIdentifiPacket &packet, vector<string> trustedKeys, vector<uint256>* visitedPackets) {
    bool hasTrustedSigner = false;
    vector<CSignature> signatures = packet.GetSignatures();
    BOOST_FOREACH (CSignature sig, signatures) {
        string strSignerPubKey = sig.GetSignerPubKey();
        if (find(trustedKeys.begin(), trustedKeys.end(), strSignerPubKey) != trustedKeys.end()) {
            hasTrustedSigner = true;
            break;
        }
        BOOST_FOREACH (string key, trustedKeys) {
            if (GetSavedPath(make_pair("base58pubkey", key), make_pair("base58pubkey", strSignerPubKey), 3, visitedPackets).size() > 0) {
                hasTrustedSigner = true;
                break;
            }
        }
        if (hasTrustedSigner) break;
    }
    return hasTrustedSigner;
}

vector<CIdentifiPacket> CIdentifiDB::GetSavedPath(string_pair start, string_pair end, int searchDepth, vector<uint256>* visitedPackets) {
    sqlite3_stmt *statement;
    ostringstream sql;

    int startID = SaveIdentifier(start.second);
    string_pair current = end;
    string nextStep = current.second;

    sql.str("");
    sql << "SELECT tp.NextStep FROM TrustPaths AS tp ";
    sql << "LEFT JOIN Predicates AS startpred ON startpred.Value = @startpred ";
    sql << "INNER JOIN Predicates AS endpred ON endpred.Value = @endpred ";
    sql << "WHERE tp.StartPredicateID = startpred.ID ";
    sql << "AND tp.StartID = @startid ";
    sql << "AND tp.EndPredicateID = endpred.ID ";
    sql << "AND tp.EndID = @endid ";

    vector<CIdentifiPacket> path;

    while (true) {
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, current.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 3, startID);
            sqlite3_bind_int(statement, 4, SaveIdentifier(nextStep));

            int result = sqlite3_step(statement);
            if(result == SQLITE_ROW)
            {
                nextStep = string((char*)sqlite3_column_text(statement, 0));
                if (nextStep == current.second) break;
                path.push_back(GetPacketByHash(nextStep));

                current.first = "";
                current.second = nextStep;
            } else {
                //path.clear();
                break;
            }
        }
        sqlite3_finalize(statement);
    }
    return path;
}

void CIdentifiDB::SavePacketTrustPaths(CIdentifiPacket &packet) {
    vector<string> myPubKeys = GetMyPubKeys();
    CKey defaultKey = GetDefaultKey();
    vector<unsigned char> vchPubKey = defaultKey.GetPubKey().Raw();
    string strPubKey = EncodeBase58(vchPubKey);

    if (!HasTrustedSigner(packet, myPubKeys, 0))
        return;

    vector<string_pair> savedPacketAuthors = packet.GetAuthors();
    vector<string_pair> savedPacketRecipients = packet.GetRecipients();
    vector<string_pair> savedPacketIdentifiers;
    savedPacketIdentifiers.insert(savedPacketIdentifiers.begin(), savedPacketRecipients.begin(), savedPacketRecipients.end());
    savedPacketIdentifiers.insert(savedPacketIdentifiers.begin(), savedPacketAuthors.begin(), savedPacketAuthors.end());
    string savedPacketHash = EncodeBase58(packet.GetHash());

    // Check if packet is authored by our key
    bool isMyPacket = false;
    BOOST_FOREACH (string_pair author, savedPacketAuthors) {
        if (author.first == "base58pubkey") {
            BOOST_FOREACH (string myKey, myPubKeys) {
                if (myKey == author.second) {
                    // Save trust step from our key to this packet
                    SaveTrustStep(make_pair("base58pubkey", myKey), make_pair("",savedPacketHash), savedPacketHash);
                    
                    // Save trust steps from our key to packet's identifiers via the packet
                    BOOST_FOREACH (string_pair id, savedPacketIdentifiers) {
                        SaveTrustStep(make_pair("base58pubkey", myKey), id, savedPacketHash);
                    }
                    isMyPacket = true;
                    break;
                }
            }
        }
    }

    if (!isMyPacket) {
        vector<CIdentifiPacket> shortestPath;
        // Find the packet's author identifier with the shortest trust path to our keys
        BOOST_FOREACH (string_pair author, savedPacketAuthors) {
            BOOST_FOREACH (string myKey, myPubKeys) {
                vector<CIdentifiPacket> path = GetSavedPath(make_pair("base58pubkey", myKey), author);
                if ((shortestPath.empty() && !path.empty())
                    || (!path.empty() && path.size() < shortestPath.size())) {
                    shortestPath = path;
                }
                if (shortestPath.size() == 1) break;
            }
            if (shortestPath.size() == 1) break;
        }

        // If such a path is found, link this packet and its identifiers to it
        if (!shortestPath.empty()) {
            vector<string_pair> firstPacketAuthors = shortestPath.front().GetAuthors();
            string lastPacket = EncodeBase58(shortestPath.back().GetHash());
            BOOST_FOREACH (string_pair startID, firstPacketAuthors) {
                SaveTrustStep(startID, make_pair("", savedPacketHash), lastPacket);
                BOOST_FOREACH (string_pair endID, savedPacketIdentifiers) {
                    SaveTrustStep(startID, endID, savedPacketHash);
                }
            }
        }
    }
}

void CIdentifiDB::SaveTrustStep(string_pair start, pair<string,string> end, string nextStep) {
    if (start == end) return;

    sqlite3_stmt *statement;
    ostringstream sql;

    string endHash = EncodeBase58(Hash(end.second.begin(), end.second.end()));
    string_pair current = start;

    int startPredicateID = SavePredicate(start.first);
    int endPredicateID = SavePredicate(end.first);
    int startID = SaveIdentifier(start.second);
    int endID = SaveIdentifier(end.second);

    sql.str("");
    sql << "SELECT COUNT(1) FROM TrustPaths WHERE ";
    sql << "StartPredicateID = @startpredID ";
    sql << "AND StartID = @startID ";
    sql << "AND EndPredicateID = @endpredID ";
    sql << "AND EndID = @endID";
    sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0);
    sqlite3_bind_int(statement, 1, startPredicateID);
    sqlite3_bind_int(statement, 2, startID);
    sqlite3_bind_int(statement, 3, endPredicateID);
    sqlite3_bind_int(statement, 4, endID);
    sqlite3_step(statement);
    int exists = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);

    if (exists) return;

    sql.str("");
    sql << "INSERT OR REPLACE INTO TrustPaths ";
    sql << "(StartPredicateID, StartID, EndPredicateID, EndID, NextStep) ";
    sql << "VALUES (@startpredID, @startID, @endpredID, @endID, @nextstep)";

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_int(statement, 1, startPredicateID);
            sqlite3_bind_int(statement, 2, startID);
            sqlite3_bind_int(statement, 3, endPredicateID);
            sqlite3_bind_int(statement, 4, endID);
            sqlite3_bind_text(statement, 5, nextStep.c_str(), -1, SQLITE_TRANSIENT);
            sqliteReturnCode = sqlite3_step(statement);
        }
    )

    sqlite3_finalize(statement);
}

vector<CIdentifiPacket> CIdentifiDB::GetPath(string_pair start, string_pair end, bool savePath, int searchDepth, vector<uint256>* visitedPackets) {
    vector<CIdentifiPacket> path = GetSavedPath(start, end, searchDepth);
    if (path.empty())
        path = SearchForPath(start, end, savePath, searchDepth);
    return path;
}

string CIdentifiDB::GetTrustStep(pair<string, string> start, pair<string, string> end) {
    sqlite3_stmt *statement;
    ostringstream sql;

    string nextStep;

    sql.str("");
    sql << "SELECT tp.NextStep FROM TrustPaths AS tp ";
    sql << "LEFT JOIN Predicates AS startpred ON startpred.Value = @startpred ";
    sql << "INNER JOIN Predicates AS endpred ON endpred.Value = @endpred ";
    sql << "WHERE tp.StartPredicateID = startpred.ID ";
    sql << "AND tp.StartID = @starthash ";
    sql << "AND tp.EndPredicateID = endpred.ID ";
    sql << "AND tp.EndID = @endhash ";  

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, end.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 3, SaveIdentifier(start.second));
        sqlite3_bind_int(statement, 4, SaveIdentifier(end.second));

        int result = sqlite3_step(statement);
        if(result == SQLITE_ROW)
        {
            nextStep = string((char*)sqlite3_column_text(statement, 0));
        }
    }
    sqlite3_finalize(statement);

    return nextStep;
}

// Breadth-first search for the shortest trust paths to all known packets, starting from id1
vector<CIdentifiPacket> CIdentifiDB::SearchForPath(string_pair start, string_pair end, bool savePath, int searchDepth, vector<uint256>* visitedPackets) {
    bool outer = false;
    if (!visitedPackets) {
        visitedPackets = new vector<uint256>();
        outer = true;
    }

    bool generateTrustMap;
    if (savePath && (end.first == "" && end.second == ""))
        generateTrustMap = true;

    vector<CIdentifiPacket> path;
    deque<CIdentifiPacket> searchQueue;
    map<uint256, CIdentifiPacket> previousPackets;
    map<uint256, int> packetDistanceFromStart;

    vector<CIdentifiPacket> packets = GetPacketsByIdentifier(start, true);
    searchQueue.insert(searchQueue.end(), packets.begin(), packets.end());
    int currentDistanceFromStart = 1;

    while (!searchQueue.empty()) {
        CIdentifiPacket currentPacket = searchQueue.front();
        searchQueue.pop_front();
        if (find(visitedPackets->begin(), visitedPackets->end(), currentPacket.GetHash()) != visitedPackets->end()) {
            continue;
        }
        visitedPackets->push_back(currentPacket.GetHash());

        if (currentPacket.GetRating() <= (currentPacket.GetMaxRating() + currentPacket.GetMinRating()) / 2)
            continue;

        if (!HasTrustedSigner(currentPacket, GetMyPubKeys(), visitedPackets))
            continue;

        if (packetDistanceFromStart.find(currentPacket.GetHash()) != packetDistanceFromStart.end())
            currentDistanceFromStart = packetDistanceFromStart[currentPacket.GetHash()];

        if (currentDistanceFromStart > searchDepth) {
            path.clear();
            return path;
        }

        vector<string_pair> allIdentifiers = currentPacket.GetAuthors();
        vector<string_pair> recipients = currentPacket.GetRecipients();
        allIdentifiers.insert(allIdentifiers.end(), recipients.begin(), recipients.end());
        BOOST_FOREACH (string_pair identifier, allIdentifiers) {
            if (savePath)
                SaveTrustStep(start, identifier, EncodeBase58(currentPacket.GetHash()));

            if (path.empty()
                    && (identifier.first.empty() || end.first.empty() || identifier.first == end.first)
                    && identifier.second == end.second) {
                // Path found: backtrack it from end to start and return it
                path.push_back(currentPacket);

                CIdentifiPacket previousPacket = currentPacket;
                while (previousPackets.find(previousPacket.GetHash()) != previousPackets.end()) {
                    previousPacket = previousPackets.at(previousPacket.GetHash());
                    path.insert(path.begin(), previousPacket);
                }
                if (!generateTrustMap)
                    return path;
            }
            // add packets involving this identifier to search queue
            vector<CIdentifiPacket> allPackets = GetPacketsByIdentifier(identifier, true);

            searchQueue.insert(searchQueue.end(), allPackets.begin(), allPackets.end());

            BOOST_FOREACH (CIdentifiPacket p, allPackets) {
                if (previousPackets.find(p.GetHash()) == previousPackets.end()
                    && find(visitedPackets->begin(), visitedPackets->end(), p.GetHash()) == visitedPackets->end())
                    previousPackets[p.GetHash()] = currentPacket;
                if (packetDistanceFromStart.find(p.GetHash()) == packetDistanceFromStart.end()
                    && find(visitedPackets->begin(), visitedPackets->end(), p.GetHash()) == visitedPackets->end()) {
                    packetDistanceFromStart[p.GetHash()] = currentDistanceFromStart + 1;
                }
            }
        }
    }

    if (outer) delete(visitedPackets);
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

vector<CIdentifiPacket> CIdentifiDB::GetLatestPackets(int limit, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets ";
    if (!showUnpublished)
        sql << "WHERE Published = 1 ";
    sql << "ORDER BY Created DESC LIMIT @limit";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, limit);

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


vector<CIdentifiPacket> CIdentifiDB::GetPacketsAfterTimestamp(time_t timestamp, int limit, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets WHERE Created >= @timestamp ";
    if (!showUnpublished)
        sql << "AND Published = 1 ";
    sql << "LIMIT @limit";


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

vector<CIdentifiPacket> CIdentifiDB::GetPacketsAfterPacket(string packetHash, int limit, bool showUnpublished) {
    CIdentifiPacket rel = GetPacketByHash(packetHash);
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets WHERE ";
    sql << "((Created = @timestamp AND Hash > @packethash) OR ";
    sql << "(Created > @timestamp)) ";
    if (!showUnpublished)
        sql << "AND Published = 1 ";
    sql << "ORDER BY Created, Hash LIMIT @limit";

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
