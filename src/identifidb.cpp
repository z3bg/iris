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
    vector<vector<string> > result = query("SELECT COUNT(1) FROM TrustPathablePredicates");
    if (lexical_cast<int>(result[0][0]) < 1) {
        query("INSERT INTO TrustPathablePredicates VALUES ('mbox')");
        query("INSERT INTO TrustPathablePredicates VALUES ('email')");
        query("INSERT INTO TrustPathablePredicates VALUES ('account')");
        query("INSERT INTO TrustPathablePredicates VALUES ('url')");
        query("INSERT INTO TrustPathablePredicates VALUES ('tel')");
        query("INSERT INTO TrustPathablePredicates VALUES ('keyID')");
        query("INSERT INTO TrustPathablePredicates VALUES ('base58pubkey')");
        query("INSERT INTO TrustPathablePredicates VALUES ('bitcoin_address')");
        query("INSERT INTO TrustPathablePredicates VALUES ('identifi_msg')");
        query("INSERT INTO TrustPathablePredicates VALUES ('twitter')");
        query("INSERT INTO TrustPathablePredicates VALUES ('facebook')");
        query("INSERT INTO TrustPathablePredicates VALUES ('google_oauth2')");
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
    } else {
        defaultKey = GetDefaultKeyFromDB();
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
    sql << "CREATE TABLE IF NOT EXISTS TrustPathablePredicates (";
    sql << "Value               NVARCHAR(255)   PRIMARY KEY";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Messages (";
    sql << "Hash                NVARCHAR(45)    PRIMARY KEY,";
    sql << "SignedData          NVARCHAR(1000)  NOT NULL,";
    sql << "Created             DATETIME        NOT NULL,";
    sql << "Predicate           INTEGER         NOT NULL,";
    sql << "Rating              INTEGER         DEFAULT 0 NOT NULL,";
    sql << "MinRating           INTEGER         DEFAULT 0 NOT NULL,";
    sql << "MaxRating           INTEGER         DEFAULT 0 NOT NULL,";
    sql << "Published           BOOL            DEFAULT 0 NOT NULL,";
    sql << "Priority            INTEGER         DEFAULT 0 NOT NULL,";
    sql << "SignerPubKey        NVARCHAR(255)   NOT NULL,";
    sql << "Signature           NVARCHAR(100)   NOT NULL,";
    sql << "IsLatest            BOOL            DEFAULT 0 NOT NULL";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS MessageIdentifiers (";
    sql << "MessageHash         NVARCHAR(45)    NOT NULL,";
    sql << "Predicate           NVARCHAR(255)   NOT NULL,";
    sql << "Identifier          NVARCHAR(255)   NOT NULL,";
    sql << "IsRecipient         BOOL            NOT NULL,";
    sql << "PRIMARY KEY(MessageHash, Predicate, Identifier, IsRecipient),";
    sql << "FOREIGN KEY(MessageHash)     REFERENCES Messages(Hash));";
    query(sql.str().c_str());
    query("CREATE INDEX IF NOT EXISTS PIIndex ON MessageIdentifiers(MessageHash)");
    query("CREATE INDEX IF NOT EXISTS PIIndex_predID ON MessageIdentifiers(Predicate)");
    query("CREATE INDEX IF NOT EXISTS PIIndex_idID ON MessageIdentifiers(Identifier)");

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS TrustPaths (";
    sql << "StartID             NVARCHAR(255)   NOT NULL,";
    sql << "StartPredicate      NVARCHAR(255)   NOT NULL,";
    sql << "EndID               NVARCHAR(255)   NOT NULL,";
    sql << "EndPredicate        NVARCHAR(255)   NOT NULL,";
    sql << "NextStep            NVARCHAR(45)    NOT NULL,";
    sql << "Distance            INTEGER         NOT NULL,";
    sql << "PRIMARY KEY(StartID, StartPredicate, EndID, EndPredicate, NextStep, Distance),";
    sql << "FOREIGN KEY(NextStep)           REFERENCES Messages(Hash));";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Keys (";
    sql << "PubKey              NVARCHAR(255)   PRIMARY KEY,";
    sql << "KeyID               NVARCHAR(255)   DEFAULT NULL,";
    sql << "PrivateKey          NVARCHAR(1000)  DEFAULT NULL,";
    sql << "IsDefault           BOOL            NOT NULL DEFAULT 0)";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS CachedNames (";
    sql << "Identifier          NVARCHAR(255)   NOT NULL,";
    sql << "Predicate           NVARCHAR(255)   NOT NULL,";
    sql << "CachedName          NVARCHAR(255)   NOT NULL,";
    sql << "PRIMARY KEY(Predicate, Identifier))";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS CachedEmails (";
    sql << "Identifier        NVARCHAR(255)         NOT NULL,";
    sql << "Predicate         NVARCHAR(255)         NOT NULL,";
    sql << "CachedEmail       NVARCHAR(255)         NOT NULL,";
    sql << "PRIMARY KEY(Predicate, Identifier))";
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

vector<CIdentifiMessage> CIdentifiDB::GetMessagesBySigner(string_pair keyID) {
    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Messages ";
    sql << "INNER JOIN Keys ON Keys.PubKey = SignerPubKey ";
    sql << "WHERE Keys.KeyID = ?";
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
    sql << "WHERE ";

    if (filterMessageType)
        sql << "p.Predicate = @msgType AND ";

    if (!identifier.first.empty())
        sql << "pi.Predicate = @predValue AND ";
    else if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    if (latestOnly)
        sql << "p.IsLatest = 1 AND ";
    sql << "pi.Identifier = @idValue ";
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
    sql << "AND NOT (LinkedID1.Identifier = LinkedID2.Identifier AND LinkedID1.Predicate = LinkedID2.Predicate)) ";
    sql << "WHERE LinkedID1.Predicate = @id1type AND LinkedID1.Identifier = @id1value AND ";
    sql << "LinkedID2.Predicate = @id2type AND LinkedID2.Identifier = @id2value ";
    AddMessageFilterSQLWhere(sql, viewpoint);

    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "AND p.Predicate != @msgType ";
        } else {
            sql << "AND p.Predicate = @msgType ";
        }
    }

    if (!showUnpublished)
        sql << "AND p.Published = 1 ";

    sql << "GROUP BY LinkAuthor.Predicate, LinkAuthor.Identifier ";

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
        sql << "SELECT CachedName FROM CachedNames AS cn ";
        sql << "WHERE Predicate = @type AND Identifier = @value";
    } else {
        sql << "SELECT CachedEmail FROM CachedEmails AS ce ";
        sql << "WHERE Predicate = @type AND Identifier = @value";
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

    sql << "SELECT LinkedMessageID.Predicate AS IdType, LinkedMessageID.Identifier AS IdValue, ";
    sql << "SUM(CASE WHEN p.Predicate = 'confirm_connection' AND LinkedMessageID.IsRecipient THEN 1 ELSE 0 END) AS Confirmations, ";
    sql << "SUM(CASE WHEN p.Predicate = 'refute_connection' AND LinkedMessageID.IsRecipient THEN 1 ELSE 0 END) AS Refutations ";
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
    sql << "GROUP BY LinkAuthor.Identifier, LinkAuthor.Predicate, LinkRecipient.Predicate, LinkRecipient.Identifier ";
    sql << ") ON ph = p.Hash ";

    sql << "WHERE SearchedMessageID.Predicate = @type ";
    sql << "AND SearchedMessageID.Identifier = @value ";
    sql << "AND NOT (IdType = SearchedMessageID.Predicate AND IdValue = SearchedMessageID.Identifier) ";

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
        sql = "INSERT OR REPLACE INTO CachedNames (Predicate, Identifier, CachedNameID) VALUES (?,?,?);";
    else
        sql = "INSERT OR REPLACE INTO CachedEmails (Predicate, Identifier, CachedEmailID) VALUES (?,?,?);";
        
    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, startID.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, startID.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 3, value.c_str(), -1, SQLITE_TRANSIENT);
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
    if (trustPathablePredicatesOnly) {
        sql << "INNER JOIN TrustPathablePredicates AS tpp ON tpp.Value = pi.Predicate ";
    }
    sql << "WHERE ";
    if (filterMessageType) {
        if (msgType[0] == '!') {
            sql << "p.Predicate != @msgType AND ";
        } else {
            sql << "p.Predicate = @msgType AND ";
        }
    }
    if (byRecipient)
        sql << "pi.IsRecipient = 1 AND ";
    else
        sql << "pi.IsRecipient = 0 AND ";
    if (!author.first.empty())
        sql << "pi.Predicate = @predValue AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    if (latestOnly)
        sql << "p.IsLatest = 1 AND ";
    sql << "pi.Identifier = @idValue ";
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
    sql << "SELECT DISTINCT Predicate, Identifier FROM MessageIdentifiers AS pi ";
    if (useViewpoint) {
        sql << "LEFT JOIN TrustPaths AS tp ON tp.EndPredicate = Predicate AND tp.EndID = Identifier ";
        sql << "AND tp.StartPredicate = @viewPredicate AND tp.StartID = @viewID ";
    }
    sql << "WHERE ";
    sql << "Identifier LIKE '%' || @query || '%' ";

    if (!query.first.empty())
      sql << "AND Predicate = @pred ";

    if (useViewpoint)
        sql << "ORDER BY CASE WHEN tp.Distance IS NULL THEN 1000 ELSE tp.Distance END ASC ";

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
            sqlite3_bind_text(statement, 1+n, query.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2+n, query.first.c_str(), -1, SQLITE_TRANSIENT);
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

    sql.str("");
    sql << "DELETE FROM Messages WHERE Hash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strMessageHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    UpdateIsLatest(msg);

    sqlite3_finalize(statement);
}

void CIdentifiDB::DeleteTrustPathsByMessage(string strMessageHash) {
    sqlite3_stmt *statement;
    ostringstream sql, deleteTrustPathSql;

    string_pair start = make_pair("identifi_msg", strMessageHash);

    // find endpoints for trustpaths that go through this msg
    sql.str("");
    sql << "SELECT tp.EndPredicate, tp.EndID, FROM TrustPaths AS tp ";
    sql << "WHERE tp.StartPredicate = @startpred AND tp.StartID = @id ";

    vector<string_pair> endpoints;
    
    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (true) {
            sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, start.second.c_str(), -1, SQLITE_TRANSIENT);
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                string endPred = string((char*)sqlite3_column_text(statement, 0));
                string endId = string((char*)sqlite3_column_text(statement, 1));
                endpoints.push_back(make_pair(endPred, endId));
            } else { 
                break;
            }
        }
    }
    
    // identifiers in this msg can also be trustpath endpoints
    sql.str("");
    sql << "SELECT Predicate, Identifier FROM MessageIdentifiers WHERE MessageHash = ?";
    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (true) {
            sqlite3_bind_text(statement, 1, strMessageHash.c_str(), -1, SQLITE_TRANSIENT);
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                string endPred = string((char*)sqlite3_column_text(statement, 0));
                string endId = string((char*)sqlite3_column_text(statement, 1));
                endpoints.push_back(make_pair(endPred, endId));
            } else { 
                break;
            }
        }
    }

    // Iterate over trust steps and delete them
    sql.str("");
    sql << "SELECT tp.StartPredicate, tp.StartID, tp.NextStep FROM TrustPaths AS tp ";
    sql << "WHERE tp.EndPredicate = @endpred AND tp.EndID = @endId ";
    sql << "AND tp.StartPredicate = @startpred AND tp.StartID = @startid ";

    deleteTrustPathSql.str("");
    deleteTrustPathSql << "DELETE FROM TrustPaths WHERE ";
    deleteTrustPathSql << "StartPredicate = ? AND StartID = ? AND ";
    deleteTrustPathSql << "EndPredicate = ? AND EndID = ? AND NextStep = ?";

    string_pair current = start;
    string nextStep = current.second;

    BOOST_FOREACH(string_pair endpoint, endpoints) {
        while (true) {
            if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, endpoint.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 2, endpoint.second.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 3, current.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 4, current.second.c_str(), -1, SQLITE_TRANSIENT);

                int result = sqlite3_step(statement);
                if (result == SQLITE_ROW) {
                    string startPred = string((char*)sqlite3_column_text(statement, 0));
                    string startID = string((char*)sqlite3_column_text(statement, 1));
                    nextStep = string((char*)sqlite3_column_text(statement, 2));

                    if(sqlite3_prepare_v2(db, deleteTrustPathSql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                        sqlite3_bind_text(statement, 1, startPred.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(statement, 2, startID.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(statement, 3, endpoint.first.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(statement, 4, endpoint.second.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(statement, 5, nextStep.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(statement);
                    }

                    bool startsFromOurKey = (current.first == "keyID" && find(myPubKeyIDs.begin(), myPubKeyIDs.end(), current.second) != myPubKeyIDs.end());
                    if (startsFromOurKey) {
                        UpdateMessagePriorities(endpoint);
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
    sql << "SELECT tp.StartPredicate, tp.StartID FROM TrustPaths AS tp ";
    sql << "WHERE tp.EndPredicate = @endpred AND tp.EndID = @endid AND tp.NextStep = @nextstep ";

    current = start;

    BOOST_FOREACH(string_pair endpoint, endpoints) {
        deque<string> deleteQueue;
        deleteQueue.push_front(strMessageHash);
        while (!deleteQueue.empty()) {
            nextStep = deleteQueue.front();
            while (true) {
                if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                    sqlite3_bind_text(statement, 1, endpoint.first.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(statement, 2, endpoint.second.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(statement, 3, nextStep.c_str(), -1, SQLITE_TRANSIENT);

                    int result = sqlite3_step(statement);
                    if (result == SQLITE_ROW) {
                        current.first = string((char*)sqlite3_column_text(statement, 0));
                        current.second = string((char*)sqlite3_column_text(statement, 1));

                        if(sqlite3_prepare_v2(db, deleteTrustPathSql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                            sqlite3_bind_text(statement, 1, current.first.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(statement, 2, current.second.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(statement, 3, endpoint.first.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(statement, 4, endpoint.second.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(statement, 5, nextStep.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_step(statement);
                        } 

                        bool startsFromOurKey = (current.first == "keyID" && find(myPubKeyIDs.begin(), myPubKeyIDs.end(), current.second) != myPubKeyIDs.end());
                        if (startsFromOurKey) {
                            UpdateMessagePriorities(endpoint);
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

void CIdentifiDB::SaveMessageAuthorOrRecipient(string msgHash, string_pair identifier, bool isRecipient) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM MessageIdentifiers ";
    sql << "WHERE MessageHash = @msghash ";
    sql << "AND Predicate = @predicate ";
    sql << "AND Identifier = @idid ";
    sql << "AND IsRecipient = @isrecipient";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, msgHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, identifier.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 4, isRecipient);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO MessageIdentifiers (MessageHash, Predicate, Identifier, IsRecipient) ";
        sql << "VALUES (@msghash, @predicateid, @identifierid, @isRecipient);";
        
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, msgHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 2, identifier.first.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(statement, 3, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 4, isRecipient);
                sqlite3_step(statement);
                sqliteReturnCode = sqlite3_reset(statement);
            }
        )
    }
    sqlite3_finalize(statement);
}

void CIdentifiDB::SaveMessageAuthor(string msgHash, string_pair author) {
    SaveMessageAuthorOrRecipient(msgHash, author, false);
}

void CIdentifiDB::SaveMessageRecipient(string msgHash, string_pair recipient) {
    SaveMessageAuthorOrRecipient(msgHash, recipient, true);
}

int CIdentifiDB::GetTrustMapSize(string_pair id) {
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT COUNT(1) FROM ";
    sql << "(SELECT DISTINCT tp.EndPredicate, tp.EndID FROM TrustPaths AS tp ";
    sql << "WHERE tp.StartPredicate = @type AND tp.StartID = @value)";

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
        throw runtime_error("GetTrustMapSize failed");
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
    sql << "SELECT COUNT(1) FROM MessageIdentifiers ";
    sql << "WHERE Predicate = @type AND Identifier = @value AND IsRecipient = 0";

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
    sql << "INNER JOIN TrustPathablePredicates AS ap ON ap.Value = author.Predicate ";
    sql << "INNER JOIN TrustPathablePredicates AS rp ON rp.Value = recipient.Predicate ";
    sql << "INNER JOIN TrustPaths AS tp ON tp.NextStep = p.Hash ";
    sql << "WHERE author.Predicate = ? AND author.Identifier = ? AND recipient.Predicate = ? AND recipient.Identifier = ?";

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
        SaveMessageAuthor(msgHash, author);
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
        SaveMessageRecipient(msgHash, recipient);
    }

    if (!msg.IsPositive()) {
        DeletePreviousTrustPaths(authors, recipients);
    }

    CSignature sig = msg.GetSignature();
    string strPubKey = sig.GetSignerPubKey();
    SavePubKey(strPubKey);

    sql.str("");
    sql << "INSERT OR REPLACE INTO Messages ";
    sql << "(Hash, SignedData, Created, Predicate, Rating, ";
    sql << "MaxRating, MinRating, Published, Priority, SignerPubKey, Signature) ";
    sql << "VALUES (@id, @data, @timestamp, @predicateid, @rating, ";
    sql << "@maxRating, @minRating, @published, @priority, @signerPubKeyID, @signature);";

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, msgHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, msg.GetData().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(statement, 3, msg.GetTimestamp());
            sqlite3_bind_text(statement, 4, msg.GetType().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 5, msg.GetRating());
            sqlite3_bind_int(statement, 6, msg.GetMaxRating());
            sqlite3_bind_int(statement, 7, msg.GetMinRating());
            sqlite3_bind_int(statement, 8, msg.IsPublished());
            sqlite3_bind_int(statement, 9, priority);
            sqlite3_bind_text(statement, 10, strPubKey.c_str(), -1, SQLITE_TRANSIENT);
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
    sql << "INNER JOIN TrustPathablePredicates AS ap ON ap.Value = author.Predicate ";
    sql << "INNER JOIN TrustPathablePredicates AS rp ON rp.Value = recipient.Predicate ";
    sql << "WHERE p.Predicate = ? AND author.Predicate = ? AND author.Identifier = ? ";
    sql << "AND recipient.Predicate = ? AND recipient.Identifier = ? ";
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
        sql << "INNER JOIN TrustPathablePredicates AS ap ON ap.Value = author.Predicate ";
        sql << "INNER JOIN TrustPathablePredicates AS rp ON rp.Value = recipient.Predicate ";
        sql << "WHERE p.Predicate = ? AND author.Predicate = ? AND author.Identifier = ? ";
        sql << "AND recipient.Predicate = ? AND recipient.Identifier = ? ";
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
    sql << "INNER JOIN TrustPathablePredicates AS ap ON ap.Value = author.Predicate ";
    sql << "INNER JOIN TrustPathablePredicates AS rp ON rp.Value = recipient.Predicate ";
    sql << "WHERE p.Predicate = ? AND author.Predicate = ? AND author.Identifier = ? ";
    sql << "AND recipient.Predicate = ? AND recipient.Identifier = ? ";
    sql << "ORDER BY p.Created DESC, p.Hash DESC LIMIT 1) ";

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

    CIdentifiAddress address(pubKey.GetID());

    if (setDefault) {
        query("UPDATE Keys SET IsDefault = 0");
        defaultKey = key;
    }

    sqlite3_stmt *statement;
    string sql = "INSERT OR REPLACE INTO Keys (PubKey, KeyID, PrivateKey, IsDefault) VALUES (@pubkey, @keyId, @privatekey, @isdefault);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, pubKeyStr.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, address.ToString().c_str(), -1, SQLITE_TRANSIENT);
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

    sqlite3_stmt *statement;
    string sql = "INSERT OR IGNORE INTO Keys (PubKey, KeyID) VALUES (@pubkeyid, @KeyID);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, pubKey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, address.ToString().c_str(), -1, SQLITE_TRANSIENT);
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
    sql << "SELECT PubKey FROM Keys ";
    sql << "WHERE PrivateKey IS NOT NULL";

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
    sql << "SELECT KeyID FROM Keys ";
    sql << "WHERE PrivateKey IS NOT NULL";

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
    sql << "SELECT PubKey, KeyID, PrivateKey FROM Keys ";
    sql << "WHERE PrivateKey IS NOT NULL";

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
    sql << "SELECT KeyID FROM Keys ";
    sql << "WHERE PubKey = @pubkey";

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
    if (strSignerKeyID.empty()) {
        return false;}
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

    string_pair current = start;
    string nextStep = current.second;

    sql.str("");
    sql << "SELECT tp.NextStep FROM TrustPaths AS tp ";
    sql << "WHERE tp.StartPredicate = @startPred ";
    sql << "AND tp.StartID = @startid ";
    sql << "AND tp.EndPredicate = @endPred ";
    sql << "AND tp.EndID = @endid ";

    while (true) {
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, current.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, current.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 3, end.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 4, end.second.c_str(), -1, SQLITE_TRANSIENT);

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

    sql.str("");
    sql << "INSERT OR REPLACE INTO TrustPaths ";
    sql << "(StartPredicate, StartID, EndPredicate, EndID, NextStep, Distance) ";
    sql << "VALUES (@startpred, @startID, @endpred, @endID, @nextstep, @distance)";

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, start.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 3, end.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 4, end.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 5, nextStep.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 6, distance);
            sqliteReturnCode = sqlite3_step(statement);
        } else cout << sqlite3_errmsg(db) << "\n";
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
    sql << "WHERE tp.StartPredicate = @startpred ";
    sql << "AND tp.StartID = @startid ";
    sql << "AND tp.EndPredicate = @endpred ";
    sql << "AND tp.EndID = @endid ";  

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, start.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, end.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, end.second.c_str(), -1, SQLITE_TRANSIENT);

        int result = sqlite3_step(statement);
        if(result == SQLITE_ROW)
        {
            nextStep = string((char*)sqlite3_column_text(statement, 0));
        }
    } else cout << sqlite3_errmsg(db) << "\n";
    sqlite3_finalize(statement);

    return nextStep;
}

struct SearchQueueMessage {
    CIdentifiMessage msg;
    bool matchedByAuthor;
    string_pair matchedByIdentifier;
};

/*
vector<string> CIdentifiDB::GetAllPaths(string_pair start, string_pair end) {
    sqlite3_stmt *statement;
    ostringstream sql;

    string nextStep;

    sql.str("");
    sql << "WITH RECURSIVE transitive_closure(pr1val, id1val, pr2val, id2val, distance, path_string) AS ";
    sql << "(";
    sql << "SELECT pr1.Value, id1.Value, pr2.Value, id2.Value, 1 AS distance, ";
    sql << "         pr1val || ':' || id1val || '.' || pr2val || ':' || id2val || '.' AS path_string ";
    sql << "FROM Messages AS m ";
    sql << "INNER JOIN MessageIdentifiers AS mid1 ON m.Hash = id1.MessageHash AND mid1.IsRecipient = 0 ";
    sql << "INNER JOIN PacketIdentifiers AS mid2 ON m.Hash = mid2.MessageHash AND mid2.ID != mid1.ID ";
    sql << "INNER JOIN Predicates AS pr1 ON pr1.ID = mid1.Predicate ";
    sql << "INNER JOIN Identifiers AS id1 ON id1.ID = mid1.Identifier ";
    sql << "INNER JOIN Predicates AS pr2 ON pr2.ID = mid2.Predicate ";
    sql << "INNER JOIN Identifiers AS id2 ON id2.ID = mid2.Identifier ";
    sql << "WHERE pr1.Value = @startPred AND id1.Value = @startId ";

    sql << "UNION ALL ";

    sql << "SELECT tc.pr1val, tc.id1val, pr2.Value, id2.Value, tc.distance + 1, ";
    sql << "tc.path_string || pr2.Value || ':' || id2.Value || '.' AS path_string ";
    sql << "FROM Messages AS m ";
    sql << "INNER JOIN MessageIdentifiers AS mid1 ON m.Hash = mid1.MessageHash AND mid1.IsRecipient = 0 ";
    sql << "INNER JOIN MessageIdentifiers AS mid2 ON m.Hash = mid2.MessageHash AND mid2.ID != mid1.ID ";
    sql << "INNER JOIN Predicates AS pr1 ON pr1.ID = mid1.Predicate ";
    sql << "INNER JOIN Identifiers AS id1 ON id1.ID = mid1.Identifier ";
    sql << "INNER JOIN Predicates AS pr2 ON pr2.ID = mid2.Predicate ";
    sql << "INNER JOIN Identifiers AS id2 ON id2.ID = mid2.Identifier ";
    sql << "JOIN transitive_closure AS tc ON pr1.Value = tc.pr2val AND id1.Value = tc.id2val ";
    sql << "WHERE tc.path_string NOT LIKE '%' || pr2.Value || ':' || id2.Value || '.%' ";
    sql << ") ";
    sql << "SELECT * FROM transitive_closure ";
    sql << "WHERE pr2val = @endPred AND id2val = @endId ";
    sql << "ORDER BY distance; ";

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
*/

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
    vector<vector<string> > result = query("SELECT COUNT(DISTINCT Identifier) FROM MessageIdentifiers");
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
            sql << "AND p.Predicate != @msgType ";
        } else {
            sql << "AND p.Predicate = @msgType ";
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
            sql << "AND p.Predicate != @msgType ";
        } else {
            sql << "AND p.Predicate = @msgType ";
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
            sql << "p.Predicate != @msgType AND ";
        } else {
            sql << "p.Predicate = @msgType AND ";
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
            sql << "p.Predicate != @msgType AND ";
        } else {
            sql << "p.Predicate = @msgType AND ";
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
        sql << "(tp.StartID IS NOT NULL OR (author.Identifier = @viewpointID AND author.Predicate = @viewpointPred)) THEN 1 ELSE 0 END), ";
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating == (p.MinRating + p.MaxRating) / 2 AND ";
        sql << "(tp.StartID IS NOT NULL OR (author.Identifier = @viewpointID AND author.Predicate = @viewpointPred)) THEN 1 ELSE 0 END), ";
        sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating < (p.MinRating + p.MaxRating) / 2 AND  ";
        sql << "(tp.StartID IS NOT NULL OR (author.Identifier = @viewpointID AND author.Predicate = @viewpointPred)) THEN 1 ELSE 0 END), ";
    }
    sql << "MIN(p.Created) ";
    sql << "FROM Messages AS p ";

    string msgType = "";
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = p.Hash ";
    sql << "WHERE p.Predicate = 'rating' ";
    sql << "AND p.IsLatest = 1 ";
    sql << "AND pi.Predicate = @type AND pi.Identifier = @value ";
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
        sql << "LEFT JOIN TrustPaths AS tp ON ";
        sql << "(tp.StartID = @viewpointID AND ";
        sql << "tp.StartPredicate = @viewpointPred AND ";
        sql << "tp.EndID = author.Identifier AND ";
        sql << "tp.EndPredicate = author.Predicate ";
        if (maxDistance > 0)
            sql << "AND tp.Distance <= @maxDistance";
        sql << ") ";
    }
}

void CIdentifiDB::AddMessageFilterSQLWhere(ostringstream &sql, string_pair viewpoint) {
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());
    if (useViewpoint)
        sql << "AND (tp.StartID IS NOT NULL OR (author.Identifier = @viewpointID AND author.Predicate = @viewpointPred)) ";
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
