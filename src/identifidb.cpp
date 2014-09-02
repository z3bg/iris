// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <deque>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <map>
#include <cmath>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

#include "identifidb.h"
#include "main.h"
#include "data.h"
#include "init.h"

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
        GetDefaultKeyFromDB();

        dbWorker = new thread(&CIdentifiDB::DBWorker, this);

        // from CAddrDB
        pathAddr = GetDataDir() / "peers.dat";
    }
}

CIdentifiDB::~CIdentifiDB() {
    sqlite3_close(db);

    dbWorker->join();
    delete dbWorker; dbWorker = NULL;
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
    }
    
    sqlite3_finalize(statement);
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
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('account', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('url', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('tel', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('keyID', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('base58pubkey', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('bitcoin_address', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('identifi_msg', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('twitter', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('facebook', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('google_oauth2', 1)");
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
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Messages");
    if (lexical_cast<int>(result[0][0]) < 3) {
        const char* devKeys[] = {"147cQZJ7Bd4ErnVYZahLfCaecJVkJVvqBP",
                                "1KMtj7J2Jjgjk5rivpb636y6KYAov1bpc6",
                                "16tzoJgKHUEW9y6AiWWFCUApi2R5yrffE3"};

        int n = 0;
        BOOST_FOREACH(const char* key, devKeys) {
            n++;
            CIdentifiAddress address(defaultKey.GetPubKey().GetID());

            mArray author, author1, recipient, recipient1, recipient2;
            mObject signature;
            author1.push_back("keyID");
            author1.push_back(address.ToString());
            author.push_back(author1);
            recipient1.push_back("keyID");
            recipient1.push_back(key);
            recipient2.push_back("nickname");
            char nickname[100];
            sprintf(nickname, "Identifi dev key %i", n);
            recipient2.push_back(nickname);
            recipient.push_back(recipient1);
            recipient.push_back(recipient2);
            
            time_t now = time(NULL);

            mObject data, signedData;
            signedData["timestamp"] = lexical_cast<int64_t>(now);
            signedData["author"] = author;
            signedData["recipient"] = recipient;
            signedData["type"] = "rating";
            signedData["comment"] = "Identifi developers' key, trusted by default";
            signedData["rating"] = 1;
            signedData["maxRating"] = 1;
            signedData["minRating"] = -1;

            data["signedData"] = signedData;
            data["signature"] = signature;

            string strData = write_string(mValue(data), false);
            CIdentifiMessage msg(strData);
            msg.Sign(defaultKey);
            SaveMessage(msg);
        }
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
    sql << "ID              INTEGER         PRIMARY KEY,";
    sql << "Value           NVARCHAR(255)   NOT NULL";
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
    sql << "CREATE TABLE IF NOT EXISTS Messages (";
    sql << "Hash                NVARCHAR(45)    PRIMARY KEY,";
    sql << "SignedData          NVARCHAR(1000)  NOT NULL,";
    sql << "Created             DATETIME        NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "Rating              INTEGER         DEFAULT 0 NOT NULL,";
    sql << "MinRating           INTEGER         DEFAULT 0 NOT NULL,";
    sql << "MaxRating           INTEGER         DEFAULT 0 NOT NULL,";
    sql << "Published           BOOL            DEFAULT 0 NOT NULL,";
    sql << "Priority            INTEGER         DEFAULT 0 NOT NULL,";
    sql << "SignerPubKeyID      INTEGER         NOT NULL,";
    sql << "Signature           NVARCHAR(100)   NOT NULL,";
    sql << "IsLatest            BOOL            DEFAULT 0 NOT NULL,";
    sql << "FOREIGN KEY(SignerPubKeyID)     REFERENCES Identifiers(ID)";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS MessageIdentifiers (";
    sql << "MessageHash         NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "IdentifierID        INTEGER         NOT NULL,";
    sql << "IsRecipient         BOOL            NOT NULL,";
    sql << "PRIMARY KEY(MessageHash, PredicateID, IdentifierID, IsRecipient),";
    sql << "FOREIGN KEY(IdentifierID)   REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(PredicateID)    REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(MessageHash)     REFERENCES Messages(Hash));";
    query(sql.str().c_str());
    query("CREATE INDEX IF NOT EXISTS PIIndex ON MessageIdentifiers(MessageHash)");
    query("CREATE INDEX IF NOT EXISTS PIIndex_predID ON MessageIdentifiers(PredicateID)");
    query("CREATE INDEX IF NOT EXISTS PIIndex_idID ON MessageIdentifiers(IdentifierID)");

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS TrustPaths (";
    sql << "StartID             INTEGER         NOT NULL,";
    sql << "StartPredicateID    INTEGER         NOT NULL,";
    sql << "EndID               INTEGER         NOT NULL,";
    sql << "EndPredicateID      INTEGER         NOT NULL,";
    sql << "NextStep            NVARCHAR(45)    NOT NULL,";
    sql << "Distance            INTEGER         NOT NULL,";
    sql << "PRIMARY KEY(StartID, StartPredicateID, EndID, EndPredicateID, NextStep),";
    sql << "FOREIGN KEY(StartID)            REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(StartPredicateID)   REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(EndID)              REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(EndPredicateID)     REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(NextStep)           REFERENCES Messages(Hash));";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Keys (";
    sql << "PubKeyID            INTEGER         PRIMARY KEY,";
    sql << "KeyIdentifierID     INTEGER         DEFAULT NULL,";
    sql << "PrivateKey          NVARCHAR(1000)  DEFAULT NULL,";
    sql << "IsDefault           BOOL            NOT NULL DEFAULT 0,";
    sql << "FOREIGN KEY(KeyIdentifierID)    REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(PubKeyID)           REFERENCES Identifiers(ID));";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS CachedNames (";
    sql << "IdentifierID        INTEGER         NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "CachedNameID        INTEGER         NOT NULL,";
    sql << "PRIMARY KEY(PredicateID, IdentifierID),";
    sql << "FOREIGN KEY(IdentifierID)   REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(PredicateID)    REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(CachedNameID)   REFERENCES Identifiers(ID))";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS CachedEmails (";
    sql << "IdentifierID        INTEGER         NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "CachedEmailID       INTEGER         NOT NULL,";
    sql << "PRIMARY KEY(PredicateID, IdentifierID),";
    sql << "FOREIGN KEY(IdentifierID)   REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(PredicateID)    REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(CachedEmailID)   REFERENCES Identifiers(ID))";
    query(sql.str().c_str());

    CheckDefaultTrustPathablePredicates();
    CheckDefaultKey();
    CheckDefaultTrustList();
    SearchForPathForMyKeys();
}

void CIdentifiDB::SearchForPathForMyKeys() {
    vector<string> myPubKeyIDs = GetMyPubKeyIDsFromDB();
    BOOST_FOREACH (string keyID, myPubKeyIDs) {
        GenerateTrustMap(make_pair("keyID", keyID));
    }
}

vector<string_pair> CIdentifiDB::GetAuthorsOrRecipientsByMessageHash(string msgHash, bool isRecipient) {
    vector<string_pair> authors;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = @msghash ";
    sql << "INNER JOIN Predicates AS p ON pi.PredicateID = p.ID ";
    sql << "WHERE id.ID = pi.IdentifierID AND pi.IsRecipient = @isrecipient;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, msgHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, isRecipient);

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
    }

    sqlite3_finalize(statement);
    return authors;
}

vector<string_pair> CIdentifiDB::GetAuthorsByMessageHash(string msgHash) {
    return GetAuthorsOrRecipientsByMessageHash(msgHash, false);
}

vector<string_pair> CIdentifiDB::GetRecipientsByMessageHash(string msgHash) {
    return GetAuthorsOrRecipientsByMessageHash(msgHash, true);
}

vector<CIdentifiMessage> CIdentifiDB::GetMessagesBySigner(string_pair keyID) {
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Messages ";
    sql << "INNER JOIN Keys ON Keys.PubKeyID = SignerPubKeyID ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = Keys.KeyIdentifierID ";
    sql << "WHERE id.Value = ?";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, keyID.second.c_str(), -1, SQLITE_TRANSIENT);
        while (true) {
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                msgs.push_back(GetMessageFromStatement(statement));
            } else break;
        }
    } else cout << sqlite3_errmsg(db) << "\n";
    sqlite3_finalize(statement);
    return msgs;
}

vector<CIdentifiMessage> CIdentifiDB::GetMessagesByIdentifier(string_pair identifier, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType, bool latestOnly) {
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT p.* FROM Messages AS p ";

    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON pi.IdentifierID = id.ID ";
    sql << "INNER JOIN Predicates AS pred ON pi.PredicateID = pred.ID ";
    sql << "WHERE ";

    if (filterMessageType)
        sql << "msgType.Value = @msgType AND ";

    if (!identifier.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    if (latestOnly)
        sql << "p.IsLatest = 1 AND ";
    sql << "id.Value = @idValue ";
    AddMessageFilterSQLWhere(sql, viewpoint);
    
    sql << "ORDER BY p.Created ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n = 3;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }

        if (filterMessageType) {
            sqlite3_bind_text(statement, 1+n, msgType.c_str(), -1, SQLITE_TRANSIENT);
            n++;
        }

        if (!identifier.first.empty()) {
            sqlite3_bind_text(statement, 1+n, identifier.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2+n, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 3+n, limit);
                sqlite3_bind_int(statement, 4+n, offset);            
            }
        } else {
            sqlite3_bind_text(statement, 1+n, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 2+n, limit);
                sqlite3_bind_int(statement, 3+n, offset);            
            }
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                msgs.push_back(GetMessageFromStatement(statement));
            }
            else
            {
                break;  
            }
        }        
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    
    sqlite3_finalize(statement);
    return msgs;
}

vector<CIdentifiMessage> CIdentifiDB::GetConnectingMessages(string_pair id1, string_pair id2, int limit, int offset, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType) {
    vector<CIdentifiMessage> results;
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT DISTINCT p.* FROM Messages AS p ";

    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "INNER JOIN MessageIdentifiers AS LinkAuthor ";
    sql << "ON (LinkAuthor.MessageHash = p.Hash AND LinkAuthor.IsRecipient = 0) ";
    sql << "INNER JOIN MessageIdentifiers AS LinkedID1 ";
    sql << "ON (LinkedID1.MessageHash = p.Hash AND LinkedID1.IsRecipient = 1) ";
    sql << "INNER JOIN MessageIdentifiers AS LinkedID2 ";
    sql << "ON (LinkedID2.MessageHash = p.Hash AND LinkedID2.IsRecipient = 1 ";
    sql << "AND NOT (LinkedID1.IdentifierID = LinkedID2.IdentifierID AND LinkedID1.PredicateID = LinkedID2.PredicateID)) ";
    sql << "INNER JOIN Predicates AS ID1type ON ID1type.ID = LinkedID1.PredicateID ";
    sql << "INNER JOIN Predicates AS ID2type ON ID2type.ID = LinkedID2.PredicateID ";
    sql << "INNER JOIN Identifiers AS ID1value ON ID1value.ID = LinkedID1.IdentifierID ";
    sql << "INNER JOIN Identifiers AS ID2value ON ID2value.ID = LinkedID2.IdentifierID ";
    sql << "WHERE ID1type.Value = @id1type AND ID1value.Value = @id1value AND ";
    sql << "ID2type.Value = @id2type AND ID2value.Value = @id2value ";
    AddMessageFilterSQLWhere(sql, viewpoint);

    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "AND msgType.Value != @msgType ";
        } else {
            sql << "AND msgType.Value = @msgType ";
        }
    }

    if (!showUnpublished)
        sql << "AND p.Published = 1 ";

    sql << "GROUP BY LinkAuthor.PredicateID, LinkAuthor.IdentifierID ";

    if (limit)
        sql << "LIMIT @limit OFFSET @offset";


    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n = 3;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }

        sqlite3_bind_text(statement, 1+n, id1.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2+n, id1.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3+n, id2.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4+n, id2.second.c_str(), -1, SQLITE_TRANSIENT);

        if (filterMessageType) {
            sqlite3_bind_text(statement, 5+n, msgType.c_str(), -1, SQLITE_TRANSIENT);
            n++;
        }

        if (limit) {
            sqlite3_bind_int(statement, 5+n, limit);
            sqlite3_bind_int(statement, 6+n, offset);            
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
            if(result == SQLITE_ROW)
                results.push_back(GetMessageFromStatement(statement));
            else
                break;
        }
    }

    sqlite3_finalize(statement);
    return results;
}

// "Find a 'name' or a 'nickname' for the author and recipient of this msg"
pair<string, string> CIdentifiDB::GetMessageLinkedNames(CIdentifiMessage &msg, bool cachedOnly) {
    string authorName, recipientName;

    vector<string_pair> authors = msg.GetAuthors();
    BOOST_FOREACH(string_pair author, authors) {
        authorName = GetName(author, cachedOnly);
        if (authorName != "") {
            break;
        }
    }

    vector<string_pair> recipients = msg.GetRecipients();
    BOOST_FOREACH(string_pair recipient, recipients) {
        recipientName = GetName(recipient, cachedOnly);
        if (recipientName != "") {
            break;
        }
    }

    return make_pair(authorName, recipientName);
}

pair<string, string> CIdentifiDB::GetMessageLinkedEmails(CIdentifiMessage &msg, bool authorOnly) {
    string authorEmail, recipientEmail;

    vector<string_pair> authors = msg.GetAuthors();
    BOOST_FOREACH(string_pair author, authors) {
        authorEmail = GetCachedEmail(author);
        if (authorEmail != "") {
            break;
        }
    }

    if (!authorOnly) {
        vector<string_pair> recipients = msg.GetRecipients();
        BOOST_FOREACH(string_pair recipient, recipients) {
            recipientEmail = GetCachedEmail(recipient);
            if (recipientEmail != "") {
                break;
            }
        }
    }

    return make_pair(authorEmail, recipientEmail);
}

string CIdentifiDB::GetName(string_pair id, bool cachedOnly) {
    if (id.first == "name" || id.first == "nickname") return id.second; 
    string name = GetCachedName(id);
    if (!cachedOnly && name.empty()) {
        vector<string> nameTypes;
        nameTypes.push_back("name");
        nameTypes.push_back("nickname");
        vector<LinkedID> linkedIDs = GetLinkedIdentifiers(id, nameTypes, 1);
        if (linkedIDs.size() == 1) {
            name = linkedIDs.front().id.second;
        }
    }

    return name;
}

string CIdentifiDB::GetCachedName(string_pair id) {
    return GetCachedValue("name", id);
}

string CIdentifiDB::GetCachedEmail(string_pair id) {
    return GetCachedValue("email", id);
}

string CIdentifiDB::GetCachedValue(string valueType, string_pair id) {
    if (valueType == id.first) return id.second;
    string value = "";

    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");

    if (valueType == "name") {
        sql << "SELECT nameID.Value FROM CachedNames AS cn ";
        sql << "INNER JOIN Identifiers AS searchedID ON cn.IdentifierID = searchedID.ID ";
        sql << "INNER JOIN Predicates AS searchedPred ON cn.PredicateID = searchedPred.ID ";
        sql << "INNER JOIN Identifiers AS nameID ON cn.CachedNameID = nameID.ID ";
        sql << "WHERE searchedPred.Value = @type AND searchedID.Value = @value";
    } else {
        sql << "SELECT emailID.Value FROM CachedEmails AS ce ";
        sql << "INNER JOIN Identifiers AS searchedID ON ce.IdentifierID = searchedID.ID ";
        sql << "INNER JOIN Predicates AS searchedPred ON ce.PredicateID = searchedPred.ID ";
        sql << "INNER JOIN Identifiers AS emailID ON ce.CachedEmailID = emailID.ID ";
        sql << "WHERE searchedPred.Value = @type AND searchedID.Value = @value";
    }

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id.second.c_str(), -1, SQLITE_TRANSIENT);

        int result = sqlite3_step(statement);

        if (result == SQLITE_ROW) {
            value = (char*)sqlite3_column_text(statement, 0);
        }
    }

    sqlite3_finalize(statement);
    return value;
}

// "Find all 'names' or a 'nicknames' linked to this identifier". Empty searchedPredicates catches all.
vector<LinkedID> CIdentifiDB::GetLinkedIdentifiers(string_pair startID, vector<string> searchedPredicates, int limit, int offset, string_pair viewpoint, int maxDistance) {
    vector<LinkedID> results;

    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");

    sql << "SELECT LinkedPredicate.Value AS IdType, LinkedID.Value AS IdValue, ";
    sql << "SUM(CASE WHEN MessageType.Value = 'confirm_connection' AND LinkedMessageID.IsRecipient THEN 1 ELSE 0 END) AS Confirmations, ";
    sql << "SUM(CASE WHEN MessageType.Value = 'refute_connection' AND LinkedMessageID.IsRecipient THEN 1 ELSE 0 END) AS Refutations ";
    sql << "FROM Messages AS p ";

    // TODO: always show self-linked identifiers?
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    string msgType;
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "INNER JOIN MessageIdentifiers AS SearchedMessageID ON p.Hash = SearchedMessageID.MessageHash ";
    sql << "INNER JOIN MessageIdentifiers AS LinkedMessageID ";
    sql << "ON (LinkedMessageID.MessageHash = SearchedMessageID.MessageHash ";
    sql << "AND LinkedMessageID.IsRecipient = SearchedMessageID.IsRecipient) ";

    // Only count one msg from author to recipient. Slows down the query somewhat.
    sql << "INNER JOIN (SELECT DISTINCT LinkAuthor.MessageHash AS ph FROM MessageIdentifiers AS LinkAuthor ";
    sql << "INNER JOIN MessageIdentifiers AS LinkRecipient ON (LinkRecipient.IsRecipient = 1 AND LinkAuthor.MessageHash = LinkRecipient.MessageHash) ";
    sql << "WHERE LinkAuthor.IsRecipient = 0 ";
    sql << "GROUP BY LinkAuthor.IdentifierID, LinkAuthor.PredicateID, LinkRecipient.PredicateID, LinkRecipient.IdentifierID ";
    sql << ") ON ph = p.Hash ";

    sql << "INNER JOIN Identifiers AS SearchedID ON SearchedMessageID.IdentifierID = SearchedID.ID ";
    sql << "INNER JOIN Predicates AS SearchedPredicate ON SearchedMessageID.PredicateID = SearchedPredicate.ID ";

    sql << "INNER JOIN Identifiers AS LinkedID ON LinkedMessageID.IdentifierID = LinkedID.ID ";
    sql << "INNER JOIN Predicates AS LinkedPredicate ON LinkedMessageID.PredicateID = LinkedPredicate.ID ";

    sql << "INNER JOIN Predicates AS MessageType ON p.PredicateID = MessageType.id ";

    sql << "WHERE SearchedPredicate.Value = @type ";
    sql << "AND SearchedID.Value = @value ";
    sql << "AND NOT (IdType = SearchedPredicate.Value AND IdValue = SearchedID.Value) ";

    if (!searchedPredicates.empty()) {
        vector<string> questionMarks(searchedPredicates.size(), "?");
        sql << "AND IdType IN (" << algorithm::join(questionMarks, ", ") << ") ";
    }
    AddMessageFilterSQLWhere(sql, viewpoint);

    sql << "GROUP BY IdType, IdValue ";
    sql << "ORDER BY Confirmations DESC, Refutations ASC ";

    if (limit > 0) {
        sql << "LIMIT " << limit;
        sql << " OFFSET " << offset;
    }

    int mostNameConfirmations = 0, mostEmailConfirmations = 0;
    string_pair mostConfirmedName;
    string mostConfirmedEmail;

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n = 3;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }

        sqlite3_bind_text(statement, 1+n, startID.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2+n, startID.second.c_str(), -1, SQLITE_TRANSIENT);

        if (!searchedPredicates.empty()) {
            for (unsigned int i = 0; i < searchedPredicates.size(); i++) {
                sqlite3_bind_text(statement, i + 3 + n, searchedPredicates.at(i).c_str(), -1, SQLITE_TRANSIENT);
            }
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
            if(result == SQLITE_ROW)
            {
                LinkedID id;
                string type = (char*)sqlite3_column_text(statement, 0);
                string value = (char*)sqlite3_column_text(statement, 1);
                id.id = make_pair(type, value);
                id.confirmations = sqlite3_column_int(statement, 2);
                id.refutations = sqlite3_column_int(statement, 3);
                results.push_back(id);
                if (startID.first != "name" && startID.first != "nickname") { 
                    if (type == "name" || (mostConfirmedName.second.empty() && type == "nickname")) {
                        if (id.confirmations >= mostNameConfirmations || (type == "name" && mostConfirmedName.first == "nickname")) {
                            mostConfirmedName = make_pair(type, value);
                            mostNameConfirmations = id.confirmations;
                        }
                    }
                }
                if (startID.first != "email") {
                    if (type == "email" && id.confirmations >= mostEmailConfirmations) {
                        mostConfirmedEmail = value;
                        mostEmailConfirmations = id.confirmations;
                    }
                }
            }
            else
            {
                break;  
            }
        }
    }

    if (!mostConfirmedName.second.empty())
        UpdateCachedName(startID, mostConfirmedName.second);
    if (!mostConfirmedEmail.empty())
        UpdateCachedEmail(startID, mostConfirmedEmail);

    sqlite3_finalize(statement);
    return results;
}

void CIdentifiDB::UpdateCachedValue(string valueType, string_pair startID, string value) {
    sqlite3_stmt *statement;

    const char* sql;
    if (valueType == "name")
        sql = "INSERT OR REPLACE INTO CachedNames (PredicateID, IdentifierID, CachedNameID) VALUES (?,?,?);";
    else
        sql = "INSERT OR REPLACE INTO CachedEmails (PredicateID, IdentifierID, CachedEmailID) VALUES (?,?,?);";
        
    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
            int predicateID = SavePredicate(startID.first);
            int identifierID = SaveIdentifier(startID.second);
            int valueID = SaveIdentifier(value);
            sqlite3_bind_int(statement, 1, predicateID);
            sqlite3_bind_int(statement, 2, identifierID);
            sqlite3_bind_int(statement, 3, valueID);
            sqlite3_step(statement);
        }
    )

    sqlite3_finalize(statement);
}

void CIdentifiDB::UpdateCachedName(string_pair startID, string name) {
    UpdateCachedValue("name", startID, name);
}

void CIdentifiDB::UpdateCachedEmail(string_pair startID, string name) {
    UpdateCachedValue("email", startID, name);
}

CIdentifiMessage CIdentifiDB::GetMessageFromStatement(sqlite3_stmt *statement) {
    string strData = (char*)sqlite3_column_text(statement, 1);
    CIdentifiMessage msg(strData, true);
    if(sqlite3_column_int(statement, 7) == 1)
        msg.SetPublished();
    msg.SetPriority(sqlite3_column_int(statement, 8));
    return msg;
}

vector<CIdentifiMessage> CIdentifiDB::GetMessagesByAuthorOrRecipient(string_pair author, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished, bool byRecipient, string_pair viewpoint, int maxDistance, string msgType, bool latestOnly) {
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT p.* FROM Messages AS p ";

    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON pi.IdentifierID = id.ID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = pi.PredicateID WHERE ";
    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "msgType.Value != @msgType AND ";
        } else {
            sql << "msgType.Value = @msgType AND ";
        }
    }
    if (byRecipient)
        sql << "pi.IsRecipient = 1 AND ";
    else
        sql << "pi.IsRecipient = 0 AND ";
    if (!author.first.empty())
        sql << "pred.Value = @predValue AND ";
    if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    if (latestOnly)
        sql << "p.IsLatest = 1 AND ";
    sql << "id.Value = @idValue ";
    AddMessageFilterSQLWhere(sql, viewpoint);
    sql << "ORDER BY p.Created DESC ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n = 3;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }
        if (filterMessageType) {
            sqlite3_bind_text(statement, 1+n, msgType.c_str(), -1, SQLITE_TRANSIENT);
            n++;
        }
        if (!author.first.empty()) {
            sqlite3_bind_text(statement, 1+n, author.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2+n, author.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 3+n, limit);
                sqlite3_bind_int(statement, 4+n, offset);
            }
        } else {
            sqlite3_bind_text(statement, 1+n, author.second.c_str(), -1, SQLITE_TRANSIENT); 
            if (limit) {
                sqlite3_bind_int(statement, 2+n, limit);
                sqlite3_bind_int(statement, 3+n, offset);
            }
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                msgs.push_back(GetMessageFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }
    
    sqlite3_finalize(statement);
    return msgs;
}

vector<CIdentifiMessage> CIdentifiDB::GetMessagesByAuthor(string_pair recipient, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType, bool latestOnly) {
    return GetMessagesByAuthorOrRecipient(recipient, limit, offset, trustPathablePredicatesOnly, showUnpublished, false, viewpoint, maxDistance, msgType, latestOnly);
}

vector<CIdentifiMessage> CIdentifiDB::GetMessagesByRecipient(string_pair recipient, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType, bool latestOnly) {
    return GetMessagesByAuthorOrRecipient(recipient, limit, offset, trustPathablePredicatesOnly, showUnpublished, true, viewpoint, maxDistance, msgType, latestOnly);
}

vector<string_pair> CIdentifiDB::SearchForID(string_pair query, int limit, int offset, bool trustPathablePredicatesOnly, string_pair viewpoint, int maxDistance) {
    vector<string_pair> results;
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());

    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT pred.Value, id.Value FROM Identifiers AS id, ";
    sql << "Predicates AS pred ";
    sql << "INNER JOIN MessageIdentifiers AS pi ";
    sql << "ON pi.PredicateID = pred.ID AND pi.IdentifierID = id.ID ";
    if (useViewpoint) {
        sql << "LEFT JOIN Predicates AS viewPred ON viewPred.Value = @viewpred ";
        sql << "LEFT JOIN Identifiers AS viewId ON viewId.Value = @viewid ";
        sql << "LEFT JOIN TrustPaths AS tp ON tp.EndPredicateID = pred.ID AND tp.EndID = id.ID ";
        sql << "AND tp.StartPredicateID = viewPred.ID AND tp.StartID = viewId.ID ";
    }
    sql << "WHERE ";
    if (!query.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    sql << "id.Value LIKE '%' || @query || '%' ";

    if (useViewpoint)
        sql << "ORDER BY CASE WHEN tp.Distance IS NULL THEN 1000 ELSE tp.Distance END ASC, pred.TrustPathable DESC ";

    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            sqlite3_bind_text(statement, 1, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            n = 2;
        }
        if (!query.first.empty()) {
            sqlite3_bind_text(statement, 1+n, query.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2+n, query.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 3+n, limit);
                sqlite3_bind_int(statement, 4+n, offset);
            }
        } else {
            sqlite3_bind_text(statement, 1+n, query.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 2+n, limit);
                sqlite3_bind_int(statement, 3+n, offset);
            }
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
            if(result == SQLITE_ROW)
            {
                string type = (char*)sqlite3_column_text(statement, 0);
                string value = (char*)sqlite3_column_text(statement, 1);
                results.push_back(make_pair(type, value));
            }
            else
            {
                break;  
            }
        }
    }
    
    sqlite3_finalize(statement);
    return results;
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

void CIdentifiDB::DropMessage(string strMessageHash) {
    sqlite3_stmt *statement;
    ostringstream sql;
    
    CIdentifiMessage msg = GetMessageByHash(strMessageHash);
    DeleteTrustPathsByMessage(strMessageHash);

    sql.str("");
    sql << "DELETE FROM MessageIdentifiers WHERE MessageHash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strMessageHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    // Remove identifiers that were mentioned in this msg only
    sql.str("");
    sql << "DELETE FROM Identifiers WHERE ID IN ";
    sql << "(SELECT id.ID FROM Identifiers AS id ";
    sql << "JOIN MessageIdentifiers AS pi ON pi.IdentifierID = id.ID ";
    sql << "WHERE pi.MessageHash = @msghash) ";
    sql << "AND ID NOT IN ";
    sql << "(SELECT id.ID FROM Identifiers AS id ";
    sql << "JOIN MessageIdentifiers AS pi ON pi.IdentifierID = id.ID ";
    sql << "WHERE pi.MessageHash != @msghash)";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strMessageHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, strMessageHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sql.str("");
    sql << "DELETE FROM Messages WHERE Hash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strMessageHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    UpdateIsLatest(msg);

    sqlite3_finalize(statement);
}

string CIdentifiDB::GetIdentifierById(int id) {
    sqlite3_stmt *statement;
    const char *sql = "SELECT Value FROM Identifiers WHERE ID = ?";
    
    if (sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, id);
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            string strId = (char*)sqlite3_column_text(statement, 0);
            sqlite3_finalize(statement);
            return strId;
        }
    }
    sqlite3_finalize(statement);
    throw runtime_error("Identifier not found");
}

string CIdentifiDB::GetPredicateById(int id) {
    sqlite3_stmt *statement;
    const char *sql = "SELECT Value FROM Predicates WHERE ID = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, id);
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            string pred = (char*)sqlite3_column_text(statement, 0);
            sqlite3_finalize(statement);
            return pred;
        }        
    }
    sqlite3_finalize(statement);
    throw runtime_error("Predicate not found");
}

void CIdentifiDB::DeleteTrustPathsByMessage(string strMessageHash) {
    sqlite3_stmt *statement;
    ostringstream sql, deleteTrustPathSql;

    string_pair start = make_pair("identifi_msg", strMessageHash);

    // find endpoints for trustpaths that go through this msg
    sql.str("");
    sql << "SELECT tp.EndID, tp.EndPredicateID FROM TrustPaths AS tp ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = tp.StartPredicateID ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = tp.StartID ";
    sql << "WHERE pred.Value = @pred AND id.Value = @id ";

    vector<int_pair> endpoints;
    
    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (true) {
            sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, start.second.c_str(), -1, SQLITE_TRANSIENT);
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                int endId = sqlite3_column_int(statement, 0);
                int endPred = sqlite3_column_int(statement, 1);
                endpoints.push_back(make_pair(endPred, endId));
            } else { 
                break;
            }
        }
    }

    // identifiers in this msg can also be trustpath endpoints
    sql.str("");
    sql << "SELECT PredicateID, IdentifierID FROM MessageIdentifiers WHERE MessageHash = ?";
    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (true) {
            sqlite3_bind_text(statement, 1, strMessageHash.c_str(), -1, SQLITE_TRANSIENT);
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                int endPred = sqlite3_column_int(statement, 0);
                int endId = sqlite3_column_int(statement, 1);
                endpoints.push_back(make_pair(endPred, endId));
            } else { 
                break;
            }
        }
    }

    // Iterate over trust steps and delete them
    sql.str("");
    sql << "SELECT tp.StartID, tp.StartPredicateID, tp.NextStep FROM TrustPaths AS tp ";
    sql << "INNER JOIN Predicates AS startPred ON startPred.ID = tp.StartPredicateID ";
    sql << "INNER JOIN Identifiers AS startID ON startID.ID = tp.StartID ";
    sql << "WHERE tp.EndPredicateID = @endpredid AND tp.EndID = @endid ";
    sql << "AND startPred.Value = @pred AND startID.Value = @id ";

    deleteTrustPathSql.str("");
    deleteTrustPathSql << "DELETE FROM TrustPaths WHERE ";
    deleteTrustPathSql << "StartID = ? AND StartPredicateID = ? AND ";
    deleteTrustPathSql << "EndID = ? AND EndPredicateID = ? AND NextStep = ?";

    string_pair current = start;
    string nextStep = current.second;

    BOOST_FOREACH(int_pair endpoint, endpoints) {
        while (true) {
            if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_int(statement, 1, endpoint.first);
                sqlite3_bind_int(statement, 2, endpoint.second);
                sqlite3_bind_text(statement, 3, current.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 4, current.second.c_str(), -1, SQLITE_TRANSIENT);

                int result = sqlite3_step(statement);
                if (result == SQLITE_ROW) {
                    int startID = sqlite3_column_int(statement, 0);
                    int startPredID = sqlite3_column_int(statement, 1);
                    nextStep = string((char*)sqlite3_column_text(statement, 2));

                    if(sqlite3_prepare_v2(db, deleteTrustPathSql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                        sqlite3_bind_int(statement, 1, startID);
                        sqlite3_bind_int(statement, 2, startPredID);
                        sqlite3_bind_int(statement, 3, endpoint.second);
                        sqlite3_bind_int(statement, 4, endpoint.first);
                        sqlite3_bind_text(statement, 5, nextStep.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(statement);
                    }

                    bool startsFromOurKey = (current.first == "keyID" && find(myPubKeyIDs.begin(), myPubKeyIDs.end(), current.second) != myPubKeyIDs.end());
                    if (startsFromOurKey) {
                        string endPred = GetPredicateById(endpoint.first);
                        string endId = GetIdentifierById(endpoint.second);
                        UpdateMessagePriorities(make_pair(endPred, endId));
                    }

                    if (nextStep == current.second) break;

                    current.first = "identifi_msg";
                    current.second = nextStep;
                } else {
                    break;
                }
            }
        }
    }
    
    // Delete trustpaths backwards
    sql.str("");
    sql << "SELECT startPred.ID, startID.ID, startPred.Value, startID.Value FROM TrustPaths AS tp ";
    sql << "INNER JOIN Predicates AS startPred ON startPred.ID = tp.StartPredicateID ";
    sql << "INNER JOIN Identifiers AS startID ON startID.ID = tp.StartID ";
    sql << "WHERE tp.EndPredicateID = @endpredid AND tp.EndID = @endid AND tp.NextStep = @nextstep ";

    current = start;

    BOOST_FOREACH(int_pair endpoint, endpoints) {
        deque<string> deleteQueue;
        deleteQueue.push_front(strMessageHash);
        while (!deleteQueue.empty()) {
            nextStep = deleteQueue.front();
            while (true) {
                if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                    sqlite3_bind_int(statement, 1, endpoint.first);
                    sqlite3_bind_int(statement, 2, endpoint.second);
                    sqlite3_bind_text(statement, 3, nextStep.c_str(), -1, SQLITE_TRANSIENT);

                    int result = sqlite3_step(statement);
                    if (result == SQLITE_ROW) {
                        int startPredID = sqlite3_column_int(statement, 0);
                        int startID = sqlite3_column_int(statement, 1);
                        current.first = string((char*)sqlite3_column_text(statement, 2));
                        current.second = string((char*)sqlite3_column_text(statement, 3));

                        if(sqlite3_prepare_v2(db, deleteTrustPathSql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                            sqlite3_bind_int(statement, 1, startID);
                            sqlite3_bind_int(statement, 2, startPredID);
                            sqlite3_bind_int(statement, 3, endpoint.second);
                            sqlite3_bind_int(statement, 4, endpoint.first);
                            sqlite3_bind_text(statement, 5, nextStep.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_step(statement);
                        }

                        bool startsFromOurKey = (current.first == "keyID" && find(myPubKeyIDs.begin(), myPubKeyIDs.end(), current.second) != myPubKeyIDs.end());
                        if (startsFromOurKey) {
                            string endPred = GetPredicateById(endpoint.first);
                            string endId = GetIdentifierById(endpoint.second);
                            UpdateMessagePriorities(make_pair(endPred, endId));
                        }

                        if (current.first == "identifi_msg") deleteQueue.push_back(current.second);
                    } else break;
                } else break;
            }
            deleteQueue.pop_front();
        }
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
        sql << "SELECT Hash FROM Messages ORDER BY Priority ASC, Created ASC LIMIT 1";
        string msgToRemove = query(sql.str().c_str())[0][0];
        DropMessage(msgToRemove);
        nFreePages = lexical_cast<int>(query("PRAGMA freelist_count")[0][0]);
    } while (nFreePages * nPageSize < nFreeBytesNeeded);

    return true;
}

void CIdentifiDB::SaveMessageAuthorOrRecipient(string msgHash, int predicateID, int identifierID, bool isRecipient) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM MessageIdentifiers ";
    sql << "WHERE MessageHash = @msghash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND IdentifierID = @idid ";
    sql << "AND IsRecipient = @isrecipient";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, msgHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_int(statement, 3, identifierID);
        sqlite3_bind_int(statement, 4, isRecipient);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO MessageIdentifiers (MessageHash, PredicateID, IdentifierID, IsRecipient) ";
        sql << "VALUES (@msghash, @predicateid, @identifierid, @isRecipient);";
        
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, msgHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 2, predicateID);
                sqlite3_bind_int(statement, 3, identifierID);
                sqlite3_bind_int(statement, 4, isRecipient);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement);
            }
        )
    }
    sqlite3_finalize(statement);
}

void CIdentifiDB::SaveMessageAuthor(string msgHash, int predicateID, int authorID) {
    SaveMessageAuthorOrRecipient(msgHash, predicateID, authorID, false);
}

void CIdentifiDB::SaveMessageRecipient(string msgHash, int predicateID, int recipientID) {
    SaveMessageAuthorOrRecipient(msgHash, predicateID, recipientID, true);
}

int CIdentifiDB::GetTrustMapSize(string_pair id) {
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT COUNT(1) FROM ";
    sql << "(SELECT DISTINCT tp.EndPredicateID, tp.EndID FROM TrustPaths AS tp ";
    sql << "INNER JOIN Predicates AS pred ON tp.StartPredicateID = pred.ID ";
    sql << "INNER JOIN Identifiers AS id ON tp.StartID = id.ID ";
    sql << "WHERE pred.Value = @type AND id.Value = @value)";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id.second.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(statement) == SQLITE_ROW) {
        int count = sqlite3_column_int(statement, 0);
        sqlite3_finalize(statement);
        return count;
    } else {
        sqlite3_finalize(statement);
        throw runtime_error("GetMessageCountByAuthor failed");
    }
}

bool CIdentifiDB::GenerateTrustMap(string_pair id, int searchDepth) {
    if (generateTrustMapSet.find(id) == generateTrustMapSet.end()) {
        trustMapQueueItem i;
        i.id = id;
        i.searchDepth = searchDepth;
        generateTrustMapQueue.push(i);
        generateTrustMapSet.insert(id);
    }
    return true;
}

int CIdentifiDB::GetMessageCountByAuthor(string_pair author) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");
    sql << "SELECT COUNT(1) FROM Messages AS p ";
    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = pi.IdentifierID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = pi.PredicateID ";
    sql << "WHERE pred.Value = @type AND id.Value = @value AND pi.IsRecipient = 0";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, author.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, author.second.c_str(), -1, SQLITE_TRANSIENT);
    }

    if (sqlite3_step(statement) == SQLITE_ROW) {
        int count = sqlite3_column_int(statement, 0);
        sqlite3_finalize(statement);
        return count;
    } else {
        sqlite3_finalize(statement);
        throw runtime_error("GetMessageCountByAuthor failed");
    }
}

// Arbitrary storage priority metric
int CIdentifiDB::GetPriority(CIdentifiMessage &msg) {
    const int MAX_PRIORITY = 100;
    string keyType = "keyID";

    int nShortestPathToSignature = 1000000;
    CSignature sig = msg.GetSignature();

    string signerPubKeyID = GetSavedKeyID(sig.GetSignerPubKey());
    if (!signerPubKeyID.empty()) {
        BOOST_FOREACH (string myPubKeyID, myPubKeyIDs) {
            if (signerPubKeyID == myPubKeyID) {
                nShortestPathToSignature = 1;
                break;            
            }
            int nPath = GetSavedPath(make_pair(keyType, myPubKeyID), make_pair(keyType, signerPubKeyID)).size();
            if (nPath > 0 && nPath < nShortestPathToSignature)
                nShortestPathToSignature = nPath + 1;
        }
    }

    int nShortestPathToAuthor = 1000000;
    int nMostMessagesFromAuthor = -1;
    bool isMyMessage = false;

    vector<string_pair> authors = msg.GetAuthors();
    BOOST_FOREACH (string_pair author, authors) {
        if (nShortestPathToAuthor > 1) {
            BOOST_FOREACH (string myPubKeyID, myPubKeyIDs) {            
                if (author == make_pair(keyType, myPubKeyID)) {
                    nShortestPathToAuthor = 1;
                    isMyMessage = true;
                    break;            
                }
                int nPath = GetSavedPath(make_pair(keyType, myPubKeyID), author).size();
                if (nPath > 0 && nPath < nShortestPathToAuthor)
                    nShortestPathToAuthor = nPath + 1;
            }
        }
        int nMessagesFromAuthor = GetMessageCountByAuthor(author);
        if (nMessagesFromAuthor > nMostMessagesFromAuthor)
            nMostMessagesFromAuthor = nMessagesFromAuthor;
    }

    int nPriority = (MAX_PRIORITY / nShortestPathToSignature)
                    * (MAX_PRIORITY / nShortestPathToAuthor);

    if (!isMyMessage && nMostMessagesFromAuthor > 10)
        nPriority = nPriority / log10(nMostMessagesFromAuthor);

    if (nPriority == 0 && nShortestPathToSignature > 0)
        return 5 / nShortestPathToSignature;
    else
        return nPriority / MAX_PRIORITY;
}

void CIdentifiDB::DeletePreviousTrustPaths(vector<string_pair> &authors, vector<string_pair> &recipients) {
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Hash FROM Messages AS p ";
    sql << "INNER JOIN MessageIdentifiers AS author ON author.MessageHash = p.Hash AND author.IsRecipient = 0 ";
    sql << "INNER JOIN MessageIdentifiers AS recipient ON recipient.MessageHash = p.Hash AND recipient.IsRecipient = 1 ";
    sql << "INNER JOIN Identifiers AS authorID ON authorID.ID = author.IdentifierID ";
    sql << "INNER JOIN Predicates AS authorPred ON authorPred.ID = author.PredicateID AND authorPred.TrustPathable = 1 ";
    sql << "INNER JOIN Identifiers AS recipientID ON recipientID.ID = recipient.IdentifierID ";
    sql << "INNER JOIN Predicates AS recipientPred ON recipientPred.ID = recipient.PredicateID AND recipientPred.TrustPathable = 1 ";
    sql << "INNER JOIN TrustPaths AS tp ON tp.NextStep = p.Hash ";
    sql << "WHERE authorPred.Value = ? AND authorID.Value = ? AND recipientPred.Value = ? AND recipientID.Value = ?";

    set<string> msgHashes;

    BOOST_FOREACH(string_pair author, authors) {
        BOOST_FOREACH(string_pair recipient, recipients) {
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, author.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 2, author.second.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 3, recipient.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 4, recipient.second.c_str(), -1, SQLITE_TRANSIENT);
                int result;
                do {
                    result = sqlite3_step(statement);
                    if(result == SQLITE_ROW)
                    {
                        string msgHash = string((char*)sqlite3_column_text(statement, 0));
                        msgHashes.insert(msgHash);
                    }
                } while (result == SQLITE_ROW);
            }
        }
    }

    BOOST_FOREACH(string msgHash, msgHashes) {
        DeleteTrustPathsByMessage(msgHash);
    }

    sqlite3_finalize(statement);
}

string CIdentifiDB::SaveMessage(CIdentifiMessage &msg) {
    int priority = GetPriority(msg);
    if (priority == 0 && !GetArg("-saveuntrustedmsgs", true)) return "";

    sqlite3_stmt *statement;
    ostringstream sql;

    string msgHash = msg.GetHashStr();

    vector<string_pair> authors = msg.GetAuthors();
    BOOST_FOREACH (string_pair author, authors) {
        int predicateID = SavePredicate(author.first);
        int authorID = SaveIdentifier(author.second);
        SaveMessageAuthor(msgHash, predicateID, authorID);
        /*
        sql.str("");
        sql << "UPDATE Messages SET IsLatest = 0 ";
        sql << "WHERE Hash IN ";
        sql << "(SELECT author.MessageHash FROM MessageIdentifiers AS author ";
        sql << "INNER JOIN MessageIdentifiers AS recipient ON recipient.MessageHash = author.MessageHash ";
        sql << "WHERE aPred.TrustPathable = 1 AND pred.Value = @type ";
        sql << "AND id.Value = @value AND IsRecipient = 0)";
        */
    }
    vector<string_pair> recipients = msg.GetRecipients();
    BOOST_FOREACH (string_pair recipient, recipients) {
        int predicateID = SavePredicate(recipient.first);
        int recipientID = SaveIdentifier(recipient.second);
        SaveMessageRecipient(msgHash, predicateID, recipientID);
    }

    if (!msg.IsPositive()) {
        DeletePreviousTrustPaths(authors, recipients);
    }

    CSignature sig = msg.GetSignature();
    string strPubKey = sig.GetSignerPubKey();
    SavePubKey(strPubKey);
    int signerPubKeyID = SaveIdentifier(strPubKey);

    sql.str("");
    sql << "INSERT OR REPLACE INTO Messages ";
    sql << "(Hash, SignedData, Created, PredicateID, Rating, ";
    sql << "MaxRating, MinRating, Published, Priority, SignerPubKeyID, Signature) ";
    sql << "VALUES (@id, @data, @timestamp, @predicateid, @rating, ";
    sql << "@maxRating, @minRating, @published, @priority, @signerPubKeyID, @signature);";

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, msgHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, msg.GetData().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(statement, 3, msg.GetTimestamp());
            sqlite3_bind_int(statement, 4, SavePredicate(msg.GetType()));
            sqlite3_bind_int(statement, 5, msg.GetRating());
            sqlite3_bind_int(statement, 6, msg.GetMaxRating());
            sqlite3_bind_int(statement, 7, msg.GetMinRating());
            sqlite3_bind_int(statement, 8, msg.IsPublished());
            sqlite3_bind_int(statement, 9, priority);
            sqlite3_bind_int(statement, 10, signerPubKeyID);
            sqlite3_bind_text(statement, 11, sig.GetSignature().c_str(), -1, SQLITE_TRANSIENT);
        } else {
            printf("DB Error: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_step(statement);
        sqliteReturnCode = sqlite3_reset(statement);
    )

    sqlite3_finalize(statement);
    UpdateIsLatest(msg);
    SaveMessageTrustPaths(msg);

    return msgHash;
}

void CIdentifiDB::SetMessagePriority(string msgHash, int priority) {
    sqlite3_stmt *statement;
    const char *sql = "UPDATE Messages SET Priority = ? WHERE Hash = ?";
    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, priority);
        sqlite3_bind_text(statement, 2, msgHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    } else cout << sqlite3_errmsg(db) << "\n";
    sqlite3_finalize(statement);
}

void CIdentifiDB::UpdateMessagePriorities(string_pair authorOrSigner) {
    vector<CIdentifiMessage> msgsToUpdate = GetMessagesByAuthor(authorOrSigner);
    if (authorOrSigner.first == "keyID") {
        vector<CIdentifiMessage> msgsBySigner = GetMessagesBySigner(authorOrSigner);
        msgsToUpdate.insert(msgsToUpdate.begin(), msgsBySigner.begin(), msgsBySigner.end());
    }

    BOOST_FOREACH(CIdentifiMessage msg, msgsToUpdate) {
        SetMessagePriority(msg.GetHashStr(), GetPriority(msg));
    }
}

// There should probably be a separate table for old msgs
void CIdentifiDB::UpdateIsLatest(CIdentifiMessage &msg) {
    sqlite3_stmt *statement;
    ostringstream sql;

    // Delete possible previous msg from A->B created less than minMessageInterval ago
    sql.str("");
    sql << "SELECT p.Hash FROM Messages AS p ";
    sql << "INNER JOIN MessageIdentifiers AS author ON author.MessageHash = p.Hash AND author.IsRecipient = 0 ";
    sql << "INNER JOIN MessageIdentifiers AS recipient ON recipient.MessageHash = p.Hash AND recipient.IsRecipient = 1 ";
    sql << "INNER JOIN Identifiers AS authorID ON authorID.ID = author.IdentifierID ";
    sql << "INNER JOIN Predicates AS authorPred ON authorPred.ID = author.PredicateID AND authorPred.TrustPathable = 1 ";
    sql << "INNER JOIN Identifiers AS recipientID ON recipientID.ID = recipient.IdentifierID ";
    sql << "INNER JOIN Predicates AS recipientPred ON recipientPred.ID = recipient.PredicateID AND recipientPred.TrustPathable = 1 ";
    sql << "INNER JOIN Predicates AS msgType ON msgType.ID = p.PredicateID ";
    sql << "WHERE msgType.Value = ? AND authorPred.Value = ? AND authorID.Value = ? ";
    sql << "AND recipientPred.Value = ? AND recipientID.Value = ? ";
    sql << "AND p.IsLatest = 1 AND p.Created < @newMessageCreated AND (@newMessageCreated - p.Created) < @minMessageInterval ";

    vector<string_pair> authors = msg.GetAuthors();
    vector<string_pair> recipients = msg.GetRecipients();
    vector<string> msgsToDelete;

    int64 minMessageInterval = GetArg("-minmsginterval", 30 * 24 * 60 * 60);
    BOOST_FOREACH(string_pair author, authors) {
        BOOST_FOREACH(string_pair recipient, recipients) {
            if(msg.GetType() == "confirm_connection" || msg.GetType() == "refute_connection") continue;
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, msg.GetType().c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 2, author.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 3, author.second.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 4, recipient.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 5, recipient.second.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(statement, 6, msg.GetTimestamp());
                sqlite3_bind_int64(statement, 7, minMessageInterval);
                int result = sqlite3_step(statement);
                if (result == SQLITE_ROW) {
                    string msgHash = string((char*)sqlite3_column_text(statement, 0));
                    msgsToDelete.push_back(msgHash);
                }
            } else { cout << sqlite3_errmsg(db) << "\n"; }
        }
    }

    if (!msgsToDelete.empty()) {
        BOOST_FOREACH(string msgHash, msgsToDelete) {
            DropMessage(msgHash);
        }
    } else {
        sql.str("");
        sql << "UPDATE Messages SET IsLatest = 0 ";
        sql << "WHERE Hash IN (SELECT p.Hash FROM Messages AS p ";
        sql << "INNER JOIN MessageIdentifiers AS author ON author.MessageHash = p.Hash AND author.IsRecipient = 0 ";
        sql << "INNER JOIN MessageIdentifiers AS recipient ON recipient.MessageHash = p.Hash AND recipient.IsRecipient = 1 ";
        sql << "INNER JOIN Identifiers AS authorID ON authorID.ID = author.IdentifierID ";
        sql << "INNER JOIN Predicates AS authorPred ON authorPred.ID = author.PredicateID AND authorPred.TrustPathable = 1 ";
        sql << "INNER JOIN Identifiers AS recipientID ON recipientID.ID = recipient.IdentifierID ";
        sql << "INNER JOIN Predicates AS recipientPred ON recipientPred.ID = recipient.PredicateID AND recipientPred.TrustPathable = 1 ";
        sql << "INNER JOIN Predicates AS msgType ON msgType.ID = p.PredicateID ";
        sql << "WHERE msgType.Value = ? AND authorPred.Value = ? AND authorID.Value = ? ";
        sql << "AND recipientPred.Value = ? AND recipientID.Value = ? ";
        sql << "AND p.IsLatest = 1) ";

        BOOST_FOREACH(string_pair author, authors) {
            BOOST_FOREACH(string_pair recipient, recipients) {
                if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                    sqlite3_bind_text(statement, 1, msg.GetType().c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(statement, 2, author.first.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(statement, 3, author.second.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(statement, 4, recipient.first.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(statement, 5, recipient.second.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_step(statement);
                } else { cout << sqlite3_errmsg(db) << "\n"; }
            }
        }
    }

    // TODO: some better way than doing this twice?
    sql.str("");
    sql << "UPDATE Messages SET IsLatest = 1 ";
    sql << "WHERE Hash IN (SELECT p.Hash FROM Messages AS p ";
    sql << "INNER JOIN MessageIdentifiers AS author ON author.MessageHash = p.Hash AND author.IsRecipient = 0 ";
    sql << "INNER JOIN MessageIdentifiers AS recipient ON recipient.MessageHash = p.Hash AND recipient.IsRecipient = 1 ";
    sql << "INNER JOIN Identifiers AS authorID ON authorID.ID = author.IdentifierID ";
    sql << "INNER JOIN Predicates AS authorPred ON authorPred.ID = author.PredicateID AND authorPred.TrustPathable = 1 ";
    sql << "INNER JOIN Identifiers AS recipientID ON recipientID.ID = recipient.IdentifierID ";
    sql << "INNER JOIN Predicates AS recipientPred ON recipientPred.ID = recipient.PredicateID AND recipientPred.TrustPathable = 1 ";
    sql << "INNER JOIN Predicates AS msgType ON msgType.ID = p.PredicateID ";
    sql << "WHERE msgType.Value = ? AND authorPred.Value = ? AND authorID.Value = ? ";
    sql << "AND recipientPred.Value = ? AND recipientID.Value = ? ";
    sql << "ORDER BY p.Created DESC, p.Hash DESC LIMIT 1)"; 

    BOOST_FOREACH(string_pair author, authors) {
        BOOST_FOREACH(string_pair recipient, recipients) {
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, msg.GetType().c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 2, author.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 3, author.second.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 4, recipient.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 5, recipient.second.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(statement);
            } else { cout << sqlite3_errmsg(db) << "\n"; }
        }
    }
    sqlite3_finalize(statement);
}


void CIdentifiDB::SaveMessageTrustPaths(CIdentifiMessage &msg) {
    if (!msg.IsPositive()) return;
    if (!HasTrustedSigner(msg, GetMyPubKeyIDs())) return;
    vector<string_pair> authors = msg.GetAuthors();
    vector<string_pair> recipients = msg.GetRecipients();
    BOOST_FOREACH(string_pair author, authors) {
        BOOST_FOREACH(string_pair recipient, recipients) {
            SaveTrustStep(author, recipient, msg.GetHashStr(), 1);
        }
    }
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
    int keyIdentifierID = SaveIdentifier(address.ToString());

    if (setDefault) {
        query("UPDATE Keys SET IsDefault = 0");
        defaultKey = key;
    }

    sqlite3_stmt *statement;
    string sql = "INSERT OR REPLACE INTO Keys (PubKeyID, KeyIdentifierID, PrivateKey, IsDefault) VALUES (@pubkeyid, @keyIdentifierID, @privatekey, @isdefault);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, pubKeyID);
        sqlite3_bind_int(statement, 2, keyIdentifierID);
        sqlite3_bind_text(statement, 3, privKey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 4, setDefault);
        sqlite3_step(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }   
    sqlite3_finalize(statement);
    GetMyPubKeyIDsFromDB();
    return true;
}

bool CIdentifiDB::SavePubKey(string pubKey) {
    vector<unsigned char> vchPubKey;
    DecodeBase58(pubKey, vchPubKey);
    CPubKey key(vchPubKey);
    if (!key.IsValid())
        throw runtime_error("SavePubKey failed: invalid key");

    CIdentifiAddress address(key.GetID());
    int KeyIdentifierID = SaveIdentifier(address.ToString());
    int pubKeyID = SaveIdentifier(pubKey);

    sqlite3_stmt *statement;
    string sql = "INSERT OR IGNORE INTO Keys (PubKeyID, KeyIdentifierID) VALUES (@pubkeyid, @KeyIdentifierID);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, pubKeyID);
        sqlite3_bind_int(statement, 2, KeyIdentifierID);
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

CKey CIdentifiDB::GetDefaultKeyFromDB() {
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

    defaultKey.SetSecret(secret, false);

    return defaultKey;
}

CKey CIdentifiDB::GetDefaultKey() {
    return defaultKey;
}

vector<string> CIdentifiDB::GetMyPubKeys() {
    vector<string> myPubKeys;

    string pubKey, privKey;

    ostringstream sql;
    sql.str("");
    sql << "SELECT id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN Keys AS k ON k.PubKeyID = id.ID ";
    sql << "WHERE k.PrivateKey IS NOT NULL";

    vector<vector<string> > result = query(sql.str().c_str());

    BOOST_FOREACH (vector<string> vStr, result) {
        myPubKeys.push_back(vStr.front());
    }

    return myPubKeys;
}

vector<string>& CIdentifiDB::GetMyPubKeyIDsFromDB() {
    string pubKey, privKey;
    vector<string> ids;

    ostringstream sql;
    sql.str("");
    sql << "SELECT id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN Keys AS k ON k.KeyIdentifierID = id.ID ";
    sql << "WHERE k.PrivateKey IS NOT NULL";

    vector<vector<string> > result = query(sql.str().c_str());

    BOOST_FOREACH (vector<string> vStr, result) {
        ids.push_back(vStr.front());
    }

    myPubKeyIDs = ids;
    return myPubKeyIDs;
}

vector<string>& CIdentifiDB::GetMyPubKeyIDs() {
    return myPubKeyIDs;
}

vector<IdentifiKey> CIdentifiDB::GetMyKeys() {
    vector<IdentifiKey> myKeys;

    string pubKey, privKey;

    ostringstream sql;
    sql.str("");
    sql << "SELECT pubKeyID.Value, keyID.Value, k.PrivateKey FROM Identifiers AS pubKeyID ";
    sql << "INNER JOIN Keys AS k ON k.PubKeyID = pubKeyID.ID ";
    sql << "INNER JOIN Identifiers AS keyID ON k.KeyIdentifierID = keyID.ID ";
    sql << "WHERE k.PrivateKey IS NOT NULL";

    vector<vector<string> > result = query(sql.str().c_str());

    BOOST_FOREACH (vector<string> vStr, result) {
        IdentifiKey key;
        key.pubKey = vStr[0];
        key.keyID = vStr[1];
        key.privKey = vStr[2];
        myKeys.push_back(key);
    }

    return myKeys;
}

string CIdentifiDB::GetSavedKeyID(string pubKey) {
    sqlite3_stmt *statement;
    ostringstream sql;
    sql.str("");
    sql << "SELECT keyID.Value FROM Identifiers AS keyID ";
    sql << "INNER JOIN Keys AS k ON keyID.ID = k.KeyIdentifierID ";
    sql << "INNER JOIN Identifiers AS pubKey ON k.PubKeyID = pubKey.ID ";
    sql << "WHERE pubKey.Value = @pubkey";

    string keyID = "";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, pubKey.c_str(), -1, SQLITE_TRANSIENT);
        int result = sqlite3_step(statement);
        if(result == SQLITE_ROW)
        {
            keyID = string((char*)sqlite3_column_text(statement, 0));
        }
    }
    sqlite3_finalize(statement);
    return keyID;
}

bool CIdentifiDB::HasTrustedSigner(CIdentifiMessage &msg, vector<string> trustedKeyIDs) {
    CSignature sig = msg.GetSignature();

    string strSignerKeyID = GetSavedKeyID(sig.GetSignerPubKey());
    if (strSignerKeyID.empty())
        return false;
    if (find(trustedKeyIDs.begin(), trustedKeyIDs.end(), strSignerKeyID) != trustedKeyIDs.end()) {
        return true;
    }
    BOOST_FOREACH (string key, trustedKeyIDs) {
        if (GetSavedPath(make_pair("keyID", key), make_pair("keyID", strSignerKeyID)).size() > 0) {
            return true;
        }
    }

    return false;
}

vector<CIdentifiMessage> CIdentifiDB::GetSavedPath(string_pair start, string_pair end, int searchDepth) {
    vector<CIdentifiMessage> path;

    if (start == end || (end.first == "" && end.second == ""))
        return path;

    sqlite3_stmt *statement;
    ostringstream sql;

    int endID = SaveIdentifier(end.second);
    string_pair current = start;
    string nextStep = current.second;

    sql.str("");
    sql << "SELECT tp.NextStep FROM TrustPaths AS tp ";
    sql << "INNER JOIN Predicates AS startpred ON startpred.Value = @startpred ";
    sql << "INNER JOIN Predicates AS endpred ON endpred.Value = @endpred ";
    sql << "WHERE tp.StartPredicateID = startpred.ID ";
    sql << "AND tp.StartID = @startid ";
    sql << "AND tp.EndPredicateID = endpred.ID ";
    sql << "AND tp.EndID = @endid ";

    while (true) {
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, current.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, end.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 3, SaveIdentifier(nextStep));
            sqlite3_bind_int(statement, 4, endID);

            int result = sqlite3_step(statement);
            if(result == SQLITE_ROW)
            {
                nextStep = string((char*)sqlite3_column_text(statement, 0));
                if (nextStep == current.second) break;
                path.push_back(GetMessageByHash(nextStep));

                current.first = "identifi_msg";
                current.second = nextStep;
            } else {
                //path.clear();
                break;
            }
        }
    }

    sqlite3_finalize(statement);
    return path;
}

void CIdentifiDB::SaveTrustStep(string_pair start, string_pair end, string nextStep, int distance) {
    if (start == end) return;

    sqlite3_stmt *statement;
    ostringstream sql;

    string endHash = EncodeBase58(Hash(end.second.begin(), end.second.end()));

    int startPredicateID = SavePredicate(start.first);
    int endPredicateID = SavePredicate(end.first);
    int startID = SaveIdentifier(start.second);
    int endID = SaveIdentifier(end.second);

    sql.str("");
    sql << "SELECT startPred.TrustPathable, endPred.TrustPathable FROM Predicates AS startPred ";
    sql << "INNER JOIN Predicates AS endPred ON endPred.ID = @endID ";
    sql << "WHERE startPred.ID = @startID";
    sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0);
    sqlite3_bind_int(statement, 1, endPredicateID);
    sqlite3_bind_int(statement, 2, startPredicateID);
    sqlite3_step(statement);
    int startTrustPathable = sqlite3_column_int(statement, 0);
    int endTrustPathable = sqlite3_column_int(statement, 1);
    sqlite3_finalize(statement);

    if (!startTrustPathable || !endTrustPathable) return; 

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

    if (exists) return; // TODO: fix?

    sql.str("");
    sql << "INSERT OR REPLACE INTO TrustPaths ";
    sql << "(StartPredicateID, StartID, EndPredicateID, EndID, NextStep, Distance) ";
    sql << "VALUES (@startpredID, @startID, @endpredID, @endID, @nextstep, @distance)";

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_int(statement, 1, startPredicateID);
            sqlite3_bind_int(statement, 2, startID);
            sqlite3_bind_int(statement, 3, endPredicateID);
            sqlite3_bind_int(statement, 4, endID);
            sqlite3_bind_text(statement, 5, nextStep.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 6, distance);
            sqliteReturnCode = sqlite3_step(statement);
        }
    )

    bool startsFromOurKey = (start.first == "keyID" && find(myPubKeyIDs.begin(), myPubKeyIDs.end(), start.second) != myPubKeyIDs.end());
    if (startsFromOurKey) {
        UpdateMessagePriorities(make_pair(end.first, end.second));
    }

    sqlite3_finalize(statement);
}

vector<CIdentifiMessage> CIdentifiDB::GetPath(string_pair start, string_pair end, bool savePath, int searchDepth) {
    vector<CIdentifiMessage> path = GetSavedPath(start, end, searchDepth);
    if (path.empty()) {
        if (savePath && (end.first == "" && end.second == ""))
            GenerateTrustMap(start);
        else
            path = SearchForPath(start, end, savePath, searchDepth);
    }
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

struct SearchQueueMessage {
    CIdentifiMessage msg;
    bool matchedByAuthor;
    string_pair matchedByIdentifier;
};

// Breadth-first search for the shortest trust paths to all known msgs, starting from id1
vector<CIdentifiMessage> CIdentifiDB::SearchForPath(string_pair start, string_pair end, bool savePath, int searchDepth) {
    vector<CIdentifiMessage> path;
    if (start == end)
        return path;

    bool generateTrustMap = false;
    if (savePath && (end.first == "" && end.second == ""))
        generateTrustMap = true;

    if (!generateTrustMap) {
        vector<CIdentifiMessage> endMessages = GetMessagesByIdentifier(end, 1, 0, true, true, make_pair("",""), 0, "", true);
        if (endMessages.empty())
            return path; // Return if the end ID is not involved in any msgs
    }

    deque<SearchQueueMessage> searchQueue;
    map<uint256, CIdentifiMessage> previousMessages;
    map<uint256, int> msgDistanceFromStart;
    vector<uint256> visitedMessages;

    vector<CIdentifiMessage> msgs = GetMessagesByAuthor(start, 0, 0, true, true, make_pair("",""), 0, "", true);
    BOOST_FOREACH(CIdentifiMessage p, msgs) {
        SearchQueueMessage sqp;
        sqp.msg = p;
        sqp.matchedByAuthor = true;
        sqp.matchedByIdentifier = start;
        searchQueue.push_back(sqp);
    }
    int currentDistanceFromStart = 1;

    while (!searchQueue.empty() && !ShutdownRequested()) {
        CIdentifiMessage currentMessage = searchQueue.front().msg;
        bool matchedByAuthor = searchQueue.front().matchedByAuthor;
        string_pair matchedByIdentifier = searchQueue.front().matchedByIdentifier;
        searchQueue.pop_front();
        if (find(visitedMessages.begin(), visitedMessages.end(), currentMessage.GetHash()) != visitedMessages.end())
            continue;

        visitedMessages.push_back(currentMessage.GetHash());

        if (!currentMessage.IsPositive())
            continue;

        if (!HasTrustedSigner(currentMessage, myPubKeyIDs))
            continue;

        if (msgDistanceFromStart.find(currentMessage.GetHash()) != msgDistanceFromStart.end())
            currentDistanceFromStart = msgDistanceFromStart[currentMessage.GetHash()];

        if (currentDistanceFromStart > searchDepth)
            return path;

        vector<string_pair> authors;
        vector<string_pair> allIdentifiers = currentMessage.GetRecipients();
        if (matchedByAuthor) {
            authors = currentMessage.GetAuthors();
            allIdentifiers.insert(allIdentifiers.end(), authors.begin(), authors.end());            
        }
        BOOST_FOREACH (string_pair identifier, allIdentifiers) {
            if (identifier != matchedByIdentifier) {
                bool pathFound = path.empty()
                        && (identifier.first.empty() || end.first.empty() || identifier.first == end.first)
                        && identifier.second == end.second;

                if (pathFound || savePath) {
                    if (pathFound)
                        path.push_back(currentMessage);

                    CIdentifiMessage msgIter = currentMessage;
                    int depth = 0;
                    while (previousMessages.find(msgIter.GetHash()) != previousMessages.end()) {
                        if (savePath) {
                            string msgIterHash = EncodeBase58(msgIter.GetHash());
                            string previousMessageHash = EncodeBase58(previousMessages.at(msgIter.GetHash()).GetHash());
                            SaveTrustStep(make_pair("identifi_msg", previousMessageHash), identifier, msgIterHash, currentDistanceFromStart - depth);
                        }
                        msgIter = previousMessages.at(msgIter.GetHash());
                        if (pathFound)
                            path.insert(path.begin(), msgIter);
                        depth++;
                    }

                    if (savePath) {
                        string msgHash = EncodeBase58(msgIter.GetHash());
                        SaveTrustStep(start, identifier, msgHash, currentDistanceFromStart);
                    }

                    if (pathFound && !generateTrustMap)
                        return path;
                }

                vector<CIdentifiMessage> allMessages;
                vector<CIdentifiMessage> authors2 = GetMessagesByAuthor(identifier, 0, 0, true, true, make_pair("",""), 0, "", true);
                vector<CIdentifiMessage> recipients2 = GetMessagesByRecipient(identifier, 0, 0, true, true, make_pair("",""), 0, "", true);
                allMessages.insert(allMessages.end(), authors2.begin(), authors2.end());
                allMessages.insert(allMessages.end(), recipients2.begin(), recipients2.end());

                BOOST_FOREACH(CIdentifiMessage p, authors2) {
                    SearchQueueMessage sqp;
                    sqp.msg = p;
                    sqp.matchedByAuthor = true;
                    sqp.matchedByIdentifier = identifier;
                    searchQueue.push_back(sqp);
                }

                BOOST_FOREACH(CIdentifiMessage p, recipients2) {
                    SearchQueueMessage sqp;
                    sqp.msg = p;
                    sqp.matchedByAuthor = false;
                    sqp.matchedByIdentifier = identifier;
                    searchQueue.push_back(sqp);
                }

                BOOST_FOREACH (CIdentifiMessage p, allMessages) {
                    if (previousMessages.find(p.GetHash()) == previousMessages.end()
                        && find(visitedMessages.begin(), visitedMessages.end(), p.GetHash()) == visitedMessages.end())
                        previousMessages[p.GetHash()] = currentMessage;
                    if (msgDistanceFromStart.find(p.GetHash()) == msgDistanceFromStart.end()
                        && find(visitedMessages.begin(), visitedMessages.end(), p.GetHash()) == visitedMessages.end()) {
                        msgDistanceFromStart[p.GetHash()] = currentDistanceFromStart + 1;
                    }
                }
            }
        }
    }

    return path;
}

CIdentifiMessage CIdentifiDB::GetMessageByHash(string hash) {
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    const char* sql = "SELECT * FROM Messages WHERE Messages.Hash = @hash;";

    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, hash.c_str(), -1, SQLITE_TRANSIENT);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                CIdentifiMessage msg = GetMessageFromStatement(statement);
                sqlite3_finalize(statement);
                return msg;
            } else {
                break;
            }
        }
        
    }
    sqlite3_finalize(statement);
    throw runtime_error("msg not found");    
}

int CIdentifiDB::GetIdentifierCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Identifiers");
    return lexical_cast<int>(result[0][0]);
}

int CIdentifiDB::GetMessageCount() {
    vector<vector<string> > result = query("SELECT COUNT(1) FROM Messages");
    return lexical_cast<int>(result[0][0]);
}

vector<CIdentifiMessage> CIdentifiDB::GetLatestMessages(int limit, int offset, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType) {
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT p.* FROM Messages AS p ";
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "WHERE 1 ";

    if (!showUnpublished)
        sql << "AND Published = 1 ";

    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "AND msgType.Value != @msgType ";
        } else {
            sql << "AND msgType.Value = @msgType ";
        }
    }

    AddMessageFilterSQLWhere(sql, viewpoint);

    sql << "ORDER BY Created DESC LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n += 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n++;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }
        
        if (filterMessageType) {
            sqlite3_bind_text(statement, 1+n, msgType.c_str(), -1, SQLITE_TRANSIENT);
            n++;
        }

        sqlite3_bind_int(statement, 1+n, limit);
        sqlite3_bind_int(statement, 2+n, offset);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                msgs.push_back(GetMessageFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
    }
    
    sqlite3_finalize(statement);
    return msgs;
}


vector<CIdentifiMessage> CIdentifiDB::GetMessagesAfterTimestamp(time_t timestamp, int limit, int offset, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType) {
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT p.* FROM Messages AS p ";
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "WHERE Created >= @timestamp ";
    if (!showUnpublished)
        sql << "AND p.Published = 1 ";

    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "AND msgType.Value != @msgType ";
        } else {
            sql << "AND msgType.Value = @msgType ";
        }
    }
    AddMessageFilterSQLWhere(sql, viewpoint);
    sql << "ORDER BY p.Created ASC LIMIT @limit OFFSET @offset";


    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                sqlite3_bind_int(statement, 3, maxDistance);
                n = 3;
            }
        }

        sqlite3_bind_int64(statement, 1+n, timestamp);

        if (filterMessageType) {
            sqlite3_bind_text(statement, 2+n, msgType.c_str(), -1, SQLITE_TRANSIENT);
            n++;
        }

        sqlite3_bind_int(statement, 2+n, limit);
        sqlite3_bind_int(statement, 3+n, offset);

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                msgs.push_back(GetMessageFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
    }
    
    sqlite3_finalize(statement);
    return msgs;
}

vector<CIdentifiMessage> CIdentifiDB::GetMessagesAfterMessage(string msgHash, int limit, int offset, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType) {
    CIdentifiMessage msg = GetMessageByHash(msgHash);
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT p.* FROM Messages AS p ";
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "WHERE ";
    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "msgType.Value != @msgType AND ";
        } else {
            sql << "msgType.Value = @msgType AND ";
        }
    }
    sql << "((Created = @timestamp AND Hash > @msghash) OR ";
    sql << "(Created > @timestamp)) ";
    if (!showUnpublished)
        sql << "AND Published = 1 ";
    AddMessageFilterSQLWhere(sql, viewpoint);
    sql << "ORDER BY Created ASC, Hash ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n = 3;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }
        if (filterMessageType) {
            sqlite3_bind_text(statement, 1+n, msgType.c_str(), -1, SQLITE_TRANSIENT);
            n++;
        }

        sqlite3_bind_int64(statement, 1+n, msg.GetTimestamp());
        sqlite3_bind_text(statement, 2+n, msgHash.c_str(), -1, SQLITE_TRANSIENT);
        if (limit) {
            sqlite3_bind_int(statement, 3+n, limit);
            sqlite3_bind_int(statement, 4+n, offset);            
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                msgs.push_back(GetMessageFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
    }
    
    sqlite3_finalize(statement);
    return msgs;
}

vector<CIdentifiMessage> CIdentifiDB::GetMessagesBeforeMessage(string msgHash, int limit, int offset, bool showUnpublished, string_pair viewpoint, int maxDistance, string msgType) {
    CIdentifiMessage msg = GetMessageByHash(msgHash);
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT p.* FROM Messages AS p ";
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "WHERE ";
    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "msgType.Value != @msgType AND ";
        } else {
            sql << "msgType.Value = @msgType AND ";
        }
    }
    sql << "((Created = @timestamp AND Hash > @msghash) OR ";
    sql << "(Created < @timestamp)) ";
    if (!showUnpublished)
        sql << "AND Published = 1 ";
    AddMessageFilterSQLWhere(sql, viewpoint);
    sql << "ORDER BY Created ASC, Hash ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n = 3;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }
        if (filterMessageType) {
            sqlite3_bind_text(statement, 1+n, msgType.c_str(), -1, SQLITE_TRANSIENT);
            n++;
        }

        sqlite3_bind_int64(statement, 1+n, msg.GetTimestamp());
        sqlite3_bind_text(statement, 2+n, msgHash.c_str(), -1, SQLITE_TRANSIENT);
        if (limit) {
            sqlite3_bind_int(statement, 3+n, limit);
            sqlite3_bind_int(statement, 4+n, offset);            
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
             
            if(result == SQLITE_ROW)
            {
                msgs.push_back(GetMessageFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
    }
    
    sqlite3_finalize(statement);
    return msgs;
}

time_t CIdentifiDB::GetLatestMessageTimestamp() {
    sqlite3_stmt *statement;
    time_t timestamp = 0;
    const char* sql = "SELECT Created FROM Messages ORDER BY Created DESC LIMIT 1";

    if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if(result == SQLITE_ROW) {
            timestamp = sqlite3_column_int64(statement, 0);
        }
    }
    sqlite3_finalize(statement);
    return timestamp;
}

IDOverview CIdentifiDB::GetIDOverview(string_pair id, string_pair viewpoint, int maxDistance) {
    IDOverview overview;

    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");
    sql << "SELECT ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating > (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating == (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating < (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    if (!useViewpoint) {
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating > (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating == (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating < (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    } else {
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating > (p.MinRating + p.MaxRating) / 2 AND ";
        sql << "(tp.StartID IS NOT NULL OR (author.IdentifierID = viewpointID.ID AND author.PredicateID = viewpointPred.ID)) THEN 1 ELSE 0 END), ";
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating == (p.MinRating + p.MaxRating) / 2 AND ";
        sql << "(tp.StartID IS NOT NULL OR (author.IdentifierID = viewpointID.ID AND author.PredicateID = viewpointPred.ID)) THEN 1 ELSE 0 END), ";
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating < (p.MinRating + p.MaxRating) / 2 AND  ";
        sql << "(tp.StartID IS NOT NULL OR (author.IdentifierID = viewpointID.ID AND author.PredicateID = viewpointPred.ID)) THEN 1 ELSE 0 END), ";
    }
    sql << "MIN(p.Created) ";
    sql << "FROM Messages AS p ";

    string msgType = "";
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = pi.IdentifierID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = pi.PredicateID ";
    sql << "INNER JOIN Predicates AS msgType ON p.PredicateID = msgType.ID ";
    sql << "WHERE msgType.Value = 'rating' ";
    sql << "AND p.IsLatest = 1 ";
    sql << "AND pred.Value = @type AND id.Value = @value ";
    AddMessageFilterSQLWhere(sql, viewpoint);

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (useViewpoint) {
            n = 2;
            sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            if (maxDistance > 0) {
                n = 3;
                sqlite3_bind_int(statement, 3, maxDistance);
            }
        }

        sqlite3_bind_text(statement, 1+n, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2+n, id.second.c_str(), -1, SQLITE_TRANSIENT);
    }

    if (sqlite3_step(statement) == SQLITE_ROW) {
        overview.authoredPositive = sqlite3_column_int(statement, 0);
        overview.authoredNeutral = sqlite3_column_int(statement, 1);
        overview.authoredNegative = sqlite3_column_int(statement, 2);
        overview.receivedPositive = sqlite3_column_int(statement, 3);
        overview.receivedNeutral = sqlite3_column_int(statement, 4);
        overview.receivedNegative = sqlite3_column_int(statement, 5);
        overview.firstSeen = sqlite3_column_int64(statement, 6);
        sqlite3_finalize(statement);
    } else {
        sqlite3_finalize(statement);
    }

    return overview;
}

CKey CIdentifiDB::GetNewKey() {
    CKey newKey;
    newKey.MakeNewKey(false);
    bool compressed;
    CSecret secret = newKey.GetSecret(compressed);
    string strPrivateKey = CIdentifiSecret(secret, compressed).ToString();
    ImportPrivKey(strPrivateKey);
    return newKey;
}

void CIdentifiDB::AddMessageFilterSQL(ostringstream &sql, string_pair viewpoint, int maxDistance, string &msgType) {
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    bool filterMessageType = !msgType.empty();
    if (filterMessageType) {
        sql << "INNER JOIN Predicates AS msgType ON msgType.ID = p.PredicateID ";
        vector<string> strs;
        split(strs, msgType, is_any_of("/"));
        if (strs.size() > 1 && strs.front() == "rating") {
            char oper = '>';
            if (strs.back() == "neutral") oper = '=';
            if (strs.back() == "negative") oper = '<';
            sql << "INNER JOIN Messages AS p2 ON (p.Hash = p2.Hash AND "; // Some better way to do this?
            sql << "p2.Rating " << oper << " (p2.MaxRating + p2.MinRating) / 2) ";
            msgType = "rating";
        }
    }
    if (useViewpoint) {
        sql << "INNER JOIN MessageIdentifiers AS author ON (author.MessageHash = p.Hash AND author.IsRecipient = 0) ";
        sql << "INNER JOIN Identifiers AS viewpointID ON viewpointID.Value = @viewpointID ";
        sql << "INNER JOIN Predicates AS viewpointPred ON viewpointPred.Value = @viewpointPred ";
        sql << "LEFT JOIN TrustPaths AS tp ON ";
        sql << "(tp.StartID = viewpointID.ID AND ";
        sql << "tp.StartPredicateID = viewpointPred.ID AND ";
        sql << "tp.EndID = author.IdentifierID AND ";
        sql << "tp.EndPredicateID = author.PredicateID ";
        if (maxDistance > 0)
            sql << "AND tp.Distance <= @maxDistance";
        else
            sql << "AND tp.Distance >= 0"; // Makes the query not last several minutes, for some reason
        sql << ") ";
    }
}

void CIdentifiDB::AddMessageFilterSQLWhere(ostringstream &sql, string_pair viewpoint) {
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    if (useViewpoint)
        sql << "AND (tp.StartID IS NOT NULL OR (author.IdentifierID = viewpointID.ID AND author.PredicateID = viewpointPred.ID)) ";
}

void CIdentifiDB::DBWorker() {
    while(!ShutdownRequested() && !this_thread::interruption_requested()) {
        if (generateTrustMapQueue.empty())
            this_thread::sleep(posix_time::milliseconds(1000));
        else {
            string_pair id = generateTrustMapQueue.front().id;
            int searchDepth = generateTrustMapQueue.front().searchDepth;
            SearchForPath(id, make_pair("",""), true, searchDepth);
            generateTrustMapSet.erase(generateTrustMapQueue.front().id);
            generateTrustMapQueue.pop();
        }
    }
}

bool CIdentifiDB::Write(const CAddrMan& addr)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    RAND_bytes((unsigned char *)&randv, sizeof(randv));
    std::string tmpfn = strprintf("peers.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssPeers(SER_DISK, CLIENT_VERSION);
    ssPeers << FLATDATA(pchMessageStart);
    ssPeers << addr;
    uint256 hash = Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = GetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout = CAutoFile(file, SER_DISK, CLIENT_VERSION);
    if (!fileout)
        return error("CAddrman::Write() : open failed");

    // Write and commit header, data
    try {
        fileout << ssPeers;
    }
    catch (std::exception &e) {
        return error("CAddrman::Write() : I/O error");
    }
    FileCommit(fileout);
    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if (!RenameOver(pathTmp, pathAddr))
        return error("CAddrman::Write() : Rename-into-place failed");

    return true;
}

bool CIdentifiDB::Read(CAddrMan& addr)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathAddr.string().c_str(), "rb");
    CAutoFile filein = CAutoFile(file, SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CAddrman::Read() : open failed");

    // use file size to size memory buffer
    int fileSize = GetFilesize(filein);
    int dataSize = fileSize - sizeof(uint256);
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (std::exception &e) {
        return error("CAddrman::Read() 2 : I/O error or stream data corrupted");
    }
    filein.fclose();

    CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssPeers.begin(), ssPeers.end());
    if (hashIn != hashTmp)
        return error("CAddrman::Read() : checksum mismatch; data corrupted");

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (pchMessageStart magic number) and
        ssPeers >> FLATDATA(pchMsgTmp);

        // verify the network matches ours
        if (memcmp(pchMsgTmp, pchMessageStart, sizeof(pchMsgTmp)))
            return error("CAddrman::Read() : invalid network magic number");

        // de-serialize address data into one CAddrMan object
        ssPeers >> addr;
    }
    catch (std::exception &e) {
        return error("CAddrman::Read() : I/O error or stream data corrupted");
    }

    return true;
}
