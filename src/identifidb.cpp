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
            printf("Db full, pruning\n");                       \
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
        query("INSERT INTO TrustPathablePredicates VALUES ('bitcoin')");
        query("INSERT INTO TrustPathablePredicates VALUES ('identifi_msg')");
        query("INSERT INTO TrustPathablePredicates VALUES ('twitter')");
        query("INSERT INTO TrustPathablePredicates VALUES ('facebook')");
        query("INSERT INTO TrustPathablePredicates VALUES ('google_oauth2')");
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
    query("CREATE INDEX IF NOT EXISTS PIIndex ON MessageIdentifiers(MessageHash, IsRecipient)");
    query("CREATE INDEX IF NOT EXISTS PIIndex_pred ON MessageIdentifiers(Predicate, Identifier)");

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS TrustPaths (";
    sql << "StartID             NVARCHAR(255)   NOT NULL,";
    sql << "StartPredicate      NVARCHAR(255)   NOT NULL,";
    sql << "EndID               NVARCHAR(255)   NOT NULL,";
    sql << "EndPredicate        NVARCHAR(255)   NOT NULL,";
    sql << "Distance            INTEGER         NOT NULL,";
    sql << "PRIMARY KEY(StartID, StartPredicate, EndID, EndPredicate))";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Identities (";
    sql << "IdentityID                INTEGER         NOT NULL,";
    sql << "Predicate                 NVARCHAR(255)   NOT NULL,";
    sql << "Identifier                NVARCHAR(255)   NOT NULL,";
    sql << "ViewpointPredicate        NVARCHAR(255)   NOT NULL,";
    sql << "ViewpointID               NVARCHAR(255)   NOT NULL,";
    sql << "Confirmations             INTEGER         NOT NULL,";
    sql << "Refutations               INTEGER         NOT NULL,";
    sql << "PRIMARY KEY(Predicate, Identifier, ViewpointPredicate, ViewpointID))";
    query(sql.str().c_str());
    query("CREATE INDEX IF NOT EXISTS IdentitiesIndex_viewpoint ON Identities(ViewpointPredicate, ViewpointID, IdentityID)");

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS Keys (";
    sql << "PubKey              NVARCHAR(255)   PRIMARY KEY,";
    sql << "KeyID               NVARCHAR(255)   NOT NULL)";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PrivateKeys (";
    sql << "PubKey              NVARCHAR(255)   PRIMARY KEY,";
    sql << "PrivateKey          NVARCHAR(1000)  NOT NULL,";
    sql << "IsDefault           BOOL            NOT NULL DEFAULT 0,";
    sql << "FOREIGN KEY(PubKey)                 REFERENCES Keys(PubKey));";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS CachedNames (";
    sql << "Predicate NVARCHAR(255) NOT NULL,";
    sql << "Identifier NVARCHAR(255) NOT NULL,";
    sql << "CachedName NVARCHAR(255) NOT NULL,";
    sql << "PRIMARY KEY(Predicate, Identifier))";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS CachedEmails (";
    sql << "Predicate NVARCHAR(255) NOT NULL,";
    sql << "Identifier NVARCHAR(255) NOT NULL,";
    sql << "CachedName NVARCHAR(255) NOT NULL,";
    sql << "PRIMARY KEY(Predicate, Identifier))";
    query(sql.str().c_str());

    CheckDefaultTrustPathablePredicates();
    CheckDefaultKey();
    CheckDefaultTrustList();
    GenerateMyTrustMaps();
}

void CIdentifiDB::GenerateMyTrustMaps() {
    vector<string> myPubKeyIDs = GetMyPubKeyIDsFromDB();
    BOOST_FOREACH (string keyID, myPubKeyIDs) {
        AddToTrustMapQueue(make_pair("keyID", keyID), GetArg("-generatetrustmapdepth", 4));
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
        BOOST_FOREACH(LinkedID linkedID, linkedIDs) {
            if (linkedID.confirmations > linkedID.refutations) {
                name = linkedIDs.front().id.second;
                break;
            }
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
        sql << "SELECT CachedName FROM CachedNames ";
        sql << "WHERE Predicate = @type AND Identifier = @value";
    } else {
        sql << "SELECT CachedEmail FROM CachedEmails ";
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

vector<LinkedID> CIdentifiDB::GetLinkedIdentifiers(string_pair startID, vector<string> searchedPredicates, int limit, int offset, string_pair viewpoint, int maxDistance) {
    vector<LinkedID> results;

    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    bool useViewpoint = (viewpoint.first != "" && viewpoint.second != ""); 
    sql.str("");

    sql << "WITH RECURSIVE transitive_closure(pr1val, id1val, pr2val, id2val, distance, path_string, confirmations, refutations) AS ";
    sql << "( ";
    sql << "SELECT id1.Predicate, id1.Identifier, id2.Predicate, id2.Identifier, 1 AS distance, ";
    sql << "printf('%s:%s:%s:%s:',replace(id1.Predicate,':','::'),replace(id1.Identifier,':','::'),replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) AS path_string, ";
    sql << "SUM(CASE WHEN p.Predicate = 'confirm_connection' AND id2.IsRecipient THEN 1 ELSE 0 END) AS Confirmations, ";
    sql << "SUM(CASE WHEN p.Predicate = 'refute_connection' AND id2.IsRecipient THEN 1 ELSE 0 END) AS Refutations ";
    sql << "FROM Messages AS p ";
    sql << "INNER JOIN MessageIdentifiers AS id1 ON p.Hash = id1.MessageHash AND id1.IsRecipient = 1 ";
    sql << "INNER JOIN MessageIdentifiers AS id2 ON p.Hash = id2.MessageHash AND id2.IsRecipient = 1 AND (id1.Predicate != id2.Predicate OR id1.Identifier != id2.Identifier) ";
    
    string msgType;
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);

    sql << "WHERE p.Predicate IN ('confirm_connection', 'refute_connection') AND id1.Predicate = @pred AND id1.Identifier = @id ";
    AddMessageFilterSQLWhere(sql, viewpoint);
    sql << "GROUP BY id2.Predicate, id2.Identifier ";

    sql << "UNION ALL ";

    sql << "SELECT tc.pr1val, tc.id1val, id2.Predicate, id2.Identifier, tc.distance + 1, ";
    sql << "printf('%s%s:%s:',tc.path_string,replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) AS path_string, ";
    sql << "SUM(CASE WHEN p.Predicate = 'confirm_connection' AND id2.IsRecipient THEN 1 ELSE 0 END) AS Confirmations, ";
    sql << "SUM(CASE WHEN p.Predicate = 'refute_connection' AND id2.IsRecipient THEN 1 ELSE 0 END) AS Refutations ";
    sql << "FROM Messages AS p ";
    sql << "JOIN MessageIdentifiers AS id1 ON p.Hash = id1.MessageHash AND id1.IsRecipient = 1 ";
    sql << "JOIN TrustPathablePredicates AS tpp1 ON tpp1.Value = id1.Predicate ";
    sql << "JOIN MessageIdentifiers AS id2 ON p.Hash = id2.MessageHash AND id2.IsRecipient = 1 AND (id1.Predicate != id2.Predicate OR id1.Identifier != id2.Identifier) ";
    sql << "JOIN transitive_closure AS tc ON tc.confirmations > tc.refutations AND id1.Predicate = tc.pr2val AND id1.Identifier = tc.id2val ";
    sql << "INNER JOIN TrustPathablePredicates AS tpp2 ON tpp2.Value = tc.pr1val ";
    
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);
    
    sql << "WHERE p.Predicate IN ('confirm_connection','refute_connections') AND tc.distance < 10 ";
    AddMessageFilterSQLWhere(sql, viewpoint);
    sql << "AND tc.path_string NOT LIKE printf('%%%s:%s:%%',replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::'))";
    sql << "GROUP BY id2.Predicate, id2.Identifier ";
    sql << ") ";

    int identityID = lexical_cast<int>(query("SELECT IFNULL(MAX(IdentityID), 0) + 1 FROM Identities")[0][0]);
    sql << "INSERT OR REPLACE INTO Identities ";
    sql << "SELECT " << identityID << ", pr2val, id2val, @viewpointPred, @viewpointID, SUM(confirmations), SUM(refutations) FROM transitive_closure ";
    sql << "GROUP BY pr2val, id2val ";
    sql << "UNION SELECT " << identityID << ", @pred, @id, @viewpointPred, @viewpointID, 1, 1 ";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 2;
        if (useViewpoint)
            n = 0;
        sqlite3_bind_text(statement, 1+n, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2+n, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
        if (maxDistance > 0) {
            n++;
            sqlite3_bind_int(statement, 3, maxDistance);
        }

        if (useViewpoint)
            n = 2;
        else 
            n = 0;
        sqlite3_bind_text(statement, 1+n, startID.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2+n, startID.second.c_str(), -1, SQLITE_TRANSIENT);

        if (!searchedPredicates.empty()) {
            for (unsigned int i = 0; i < searchedPredicates.size(); i++) {
                sqlite3_bind_text(statement, i + 3 + n, searchedPredicates.at(i).c_str(), -1, SQLITE_TRANSIENT);
            }
        }

        sqlite3_step(statement);
    } else cout << sqlite3_errmsg(db) << "\n";

    sql.str("");
    sql << "SELECT Predicate, Identifier, Confirmations AS c, Refutations AS r, 1 FROM Identities WHERE NOT (Predicate = @searchedpred AND Identifier = @searchedid) AND IdentityID = (SELECT MAX(IdentityID) FROM Identities) ";
    sql << "ORDER BY c-r DESC ";

    int mostNameConfirmations = 0, mostEmailConfirmations = 0;
    string mostConfirmedEmail;
    string_pair mostConfirmedName;
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, startID.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, startID.second.c_str(), -1, SQLITE_TRANSIENT);
        while(true) {
            int result = sqlite3_step(statement);
            if(result == SQLITE_ROW) {
                LinkedID id;
                string type = (char*)sqlite3_column_text(statement, 0);
                string value = (char*)sqlite3_column_text(statement, 1);
                id.id = make_pair(type, value);
                id.confirmations = sqlite3_column_int(statement, 2);
                id.refutations = sqlite3_column_int(statement, 3);
                id.distance = sqlite3_column_int(statement, 4);
                results.push_back(id);
                if (startID.first != "name" && startID.first != "nickname") {
                    if (type == "name" || (mostConfirmedName.second.empty() && type == "nickname")) {
                        if ((id.refutations == 0 || id.confirmations > id.refutations)
                            && (id.confirmations >= mostNameConfirmations || (type == "name" && mostConfirmedName.first == "nickname"))) {
                            mostConfirmedName = make_pair(type, value);
                            mostNameConfirmations = id.confirmations;
                        }
                    }
                }
                if (startID.first != "email") {
                    if (type == "email" && id.confirmations > id.refutations && id.confirmations >= mostEmailConfirmations) {
                        mostConfirmedEmail = value;
                        mostEmailConfirmations = id.confirmations;
                    }
                }
            } else {
                break;  
            }
        }
    } else cout << sqlite3_errmsg(db) << "\n";

    UpdateCachedName(startID, mostConfirmedName.second);
    UpdateCachedEmail(startID, mostConfirmedEmail);

    sqlite3_finalize(statement);
    return results;
}

void CIdentifiDB::UpdateCachedValue(string valueType, string_pair startID, string value) {
    sqlite3_stmt *statement;

    const char* sql;
    if (valueType == "name") {
        if (value.empty())
            sql = "DELETE FROM CachedNames WHERE Predicate = ? AND Identifier = ?";
        else
            sql = "INSERT OR REPLACE INTO CachedNames (Predicate, Identifier, CachedName) VALUES (?,?,?);";
    } else {
        if (value.empty())
            sql = "DELETE FROM CachedEmails WHERE Predicate = ? AND Identifier = ?";
        else
            sql = "INSERT OR REPLACE INTO CachedEmails (Predicate, Identifier, CachedEmail) VALUES (?,?,?);";
    }

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, startID.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, startID.second.c_str(), -1, SQLITE_TRANSIENT);
            if (!value.empty())
                sqlite3_bind_text(statement, 3, value.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(statement);
            sqliteReturnCode = sqlite3_reset(statement);
        } else cout << sqlite3_errmsg(db) << "\n";
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
    string emptyMsgType = "";
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT p.* FROM Messages AS p ";
    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = p.Hash ";
    sql << "INNER JOIN TrustPathablePredicates AS tpp ON tpp.Value = pi.Predicate ";
    sql << "INNER JOIN Identities AS i ON (i.Predicate = pi.Predicate AND i.Identifier = pi.Identifier AND i.IdentityID = ";
    sql << "(SELECT IdentityID FROM Identities WHERE ViewpointPredicate = @viewpointPred AND ViewpointID = @viewpointID ";
    sql << "AND Predicate = @pred AND Identifier = @id)) ";

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
    if (byRecipient)
        sql << "pi.IsRecipient = 1 AND ";
    else
        sql << "pi.IsRecipient = 0 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    if (latestOnly)
        sql << "p.IsLatest = 1 AND ";
    sql << "1 ";
    AddMessageFilterSQLWhere(sql, viewpoint);
    sql << "ORDER BY p.Created DESC ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        sqlite3_bind_text(statement, 1, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, author.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, author.second.c_str(), -1, SQLITE_TRANSIENT);
        if (maxDistance > 0) {
            sqlite3_bind_int(statement, 5+n, maxDistance);
            n++;
        }
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
            {
                msgs.push_back(GetMessageFromStatement(statement));
            }
            else
            {
                break;  
            }
        }
    } else {
        cout << sqlite3_errmsg(db) << "\n";
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

vector<SearchResult> CIdentifiDB::SearchForID(string_pair query, int limit, int offset, bool trustPathablePredicatesOnly, string_pair viewpoint, int maxDistance) {
    vector<SearchResult> results;
    bool useViewpoint = (!viewpoint.first.empty() && !viewpoint.second.empty());

    sqlite3_stmt *statement;
    vector<CIdentifiMessage> msgs;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT pred, id, IFNULL(CachedName,''), IFNULL(CachedEmail,CASE WHEN pred = 'email' THEN id ELSE '' END) FROM (";

    sql << "SELECT DISTINCT Predicate AS pred, Identifier AS id FROM MessageIdentifiers ";
    sql << "WHERE ";
    sql << "id LIKE '%' || @query || '%' ";
    if (!query.first.empty())
        sql << "AND pred = @pred ";
    sql << ") ";

    if (useViewpoint) {
        sql << "LEFT JOIN TrustPaths AS tp ON tp.EndPredicate = pred AND tp.EndID = id ";
        sql << "AND tp.StartPredicate = @viewPredicate AND tp.StartID = @viewID ";
    }
    sql << "LEFT JOIN CachedNames AS cn ON cn.Predicate = pred AND cn.Identifier = id ";
    sql << "LEFT JOIN CachedEmails AS ce ON ce.Predicate = pred AND ce.Identifier = id ";

    if (useViewpoint)
        sql << "ORDER BY CASE WHEN tp.Distance IS NULL THEN 1000 ELSE tp.Distance END ASC, id ASC ";

    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int n = 0;
        if (!query.first.empty()) {
            sqlite3_bind_text(statement, 1, query.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, query.first.c_str(), -1, SQLITE_TRANSIENT);
            n += 2;
        } else {
            sqlite3_bind_text(statement, 1, query.second.c_str(), -1, SQLITE_TRANSIENT);
            n += 1;
        }
        if (useViewpoint) {
            sqlite3_bind_text(statement, 1+n, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2+n, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
            n += 2;
        }
        if (limit) {
            sqlite3_bind_int(statement, 1+n, limit);
            sqlite3_bind_int(statement, 2+n, offset);
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
            if(result == SQLITE_ROW)
            {
                string type = (char*)sqlite3_column_text(statement, 0);
                string value = (char*)sqlite3_column_text(statement, 1);
                string name = (char*)sqlite3_column_text(statement, 2);
                string email = (char*)sqlite3_column_text(statement, 3);
                SearchResult r;
                r.id = make_pair(type,value);
                r.name = name;
                r.email = email;
                results.push_back(r);
            }
            else
            {
                break;  
            }
        }
    } else cout << sqlite3_errmsg(db) << "\n";
    
    sqlite3_finalize(statement);
    return results;
}

void CIdentifiDB::DropMessage(string strMessageHash) {
    sqlite3_stmt *statement;
    ostringstream sql;
    
    CIdentifiMessage msg = GetMessageByHash(strMessageHash);

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
    GenerateMyTrustMaps();

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

bool CIdentifiDB::AddToTrustMapQueue(string_pair id, int searchDepth) {
    if (generateTrustMapSet.find(id) == generateTrustMapSet.end()) {
        trustMapQueueItem i;
        i.id = id;
        i.searchDepth = searchDepth;
        generateTrustMapQueue.push(i);
        generateTrustMapSet.insert(id);
    }
    return true;
}

bool CIdentifiDB::GenerateTrustMap(string_pair id, int searchDepth) {
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("DELETE FROM TrustPaths WHERE StartPredicate = ? AND StartID = ?");
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    } else cout << sqlite3_errmsg(db) << "\n";

    sql.str("");
    sql << "WITH RECURSIVE transitive_closure(pr1val, id1val, pr2val, id2val, distance, path_string) AS ";
    sql << "(";
    sql << "SELECT id1.Predicate, id1.Identifier, id2.Predicate, id2.Identifier, 1 AS distance, "; 
    sql << "printf('%s:%s:%s:%s:',replace(id1.Predicate,':','::'),replace(id1.Identifier,':','::'),replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) AS path_string "; 
    sql << "FROM Messages AS m "; 
    sql << "INNER JOIN MessageIdentifiers AS id1 ON m.Hash = id1.MessageHash AND id1.IsRecipient = 0 "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp1 ON tpp1.Value = id1.Predicate ";
    sql << "INNER JOIN MessageIdentifiers AS id2 ON m.Hash = id2.MessageHash AND (id1.Predicate != id2.Predicate OR id1.Identifier != id2.Identifier) "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp2 ON tpp2.Value = id2.Predicate ";
    sql << "WHERE m.IsLatest AND m.Rating > (m.MinRating + m.MaxRating) / 2 AND id1.Predicate = @id1pred AND id1.Identifier = @id1 ";

    sql << "UNION ALL "; 

    sql << "SELECT tc.pr1val, tc.id1val, id2.Predicate, id2.Identifier, tc.distance + 1, "; 
    sql << "printf('%s%s:%s:',tc.path_string,replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) AS path_string "; 
    sql << "FROM Messages AS m "; 
    sql << "INNER JOIN MessageIdentifiers AS id1 ON m.Hash = id1.MessageHash AND id1.IsRecipient = 0 "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp1 ON tpp1.Value = id1.Predicate ";
    sql << "INNER JOIN MessageIdentifiers AS id2 ON m.Hash = id2.MessageHash AND (id1.Predicate != id2.Predicate OR id1.Identifier != id2.Identifier) "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp2 ON tpp2.Value = id2.Predicate ";
    sql << "JOIN transitive_closure AS tc ON id1.Predicate = tc.pr2val AND id1.Identifier = tc.id2val "; 
    sql << "WHERE m.IsLatest AND m.Rating > (m.MinRating + m.MaxRating) / 2 AND tc.distance < ? AND tc.path_string NOT LIKE printf('%%%s:%s:%%',replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) "; 
    sql << ") "; 
    sql << "INSERT OR REPLACE INTO TrustPaths (StartPredicate, StartID, EndPredicate, EndID, Distance) SELECT @id1pred, @id1, pr2val, id2val, distance FROM transitive_closure "; 

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 3, searchDepth);

        while (true) {
            int result = sqlite3_step(statement);
            if (result != SQLITE_ROW)
                break;
        }
    } else cout << sqlite3_errmsg(db) << "\n";
    
    sqlite3_finalize(statement);
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
            int distance = GetTrustDistance(make_pair(keyType, myPubKeyID), make_pair(keyType, signerPubKeyID));
            if (distance > 0 && distance < nShortestPathToSignature)
                nShortestPathToSignature = distance + 1;
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
                int distance = GetTrustDistance(make_pair(keyType, myPubKeyID), author);
                if (distance > 0 && distance < nShortestPathToAuthor)
                    nShortestPathToAuthor = distance + 1;
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
            SaveTrustPath(author, recipient, 1);
        }
    }
}


bool CIdentifiDB::ImportPrivKey(string privKey, bool setDefault) {
    sqlite3_stmt *statement;
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

    string sql = "INSERT INTO Keys (PubKey, KeyID) VALUES (?,?)";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, pubKeyStr.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, address.ToString().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    } else {
        printf("DB Error: %s\n", sqlite3_errmsg(db));
    }   

    if (setDefault) {
        query("UPDATE PrivateKeys SET IsDefault = 0");
        defaultKey = key;
    }

    sql = "INSERT OR REPLACE INTO PrivateKeys (PubKey, PrivateKey, IsDefault) VALUES (@pubkey, @privatekey, @isdefault);";
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, pubKeyStr.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, privKey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 3, setDefault);
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
    sql << "SELECT PubKey FROM Keys AS keys ";
    sql << "INNER JOIN PrivateKeys AS priv ON priv.PubKey = keys.PubKey ";

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
    sql << "SELECT KeyID FROM Keys AS keys ";
    sql << "INNER JOIN PrivateKeys AS priv ON priv.PubKey = keys.PubKey ";

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
    sql << "SELECT keys.PubKey, keys.KeyID, priv.PrivateKey FROM Keys AS keys ";
    sql << "INNER JOIN PrivateKeys AS priv ON priv.PubKey = keys.PubKey";

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
        if (GetTrustDistance(make_pair("keyID", key), make_pair("keyID", strSignerKeyID)) > 0) {
            return true;
        }
    }

    return false;
}

void CIdentifiDB::SaveTrustPath(string_pair start, string_pair end, int distance) {
    if (start == end) return;

    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT COUNT(1) FROM TrustPaths WHERE ";
    sql << "StartPredicate = ? AND StartID = ? AND EndPredicate = ? AND EndID = ? ";
    sql << "AND Distance <= ?";

    bool exists = false;
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, start.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, end.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, end.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 5, distance);
        int sqliteReturnCode = sqlite3_step(statement);
        if (sqliteReturnCode == SQLITE_ROW)
            exists = sqlite3_column_int(statement, 0);
    } else
          cout << sqlite3_errmsg(db) << "\n";

    if (exists) {
        sqlite3_finalize(statement);
        return;
    }

    sql.str("");
    sql << "INSERT OR REPLACE INTO TrustPaths ";
    sql << "(StartPredicate, StartID, EndPredicate, EndID, Distance) ";
    sql << "VALUES (@startpred, @startID, @endpred, @endID, @distance)";

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, start.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 3, end.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 4, end.second.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement, 5, distance);
            sqliteReturnCode = sqlite3_step(statement);
        } else
              cout << sqlite3_errmsg(db) << "\n";
    )

    bool startsFromOurKey = (start.first == "keyID" && find(myPubKeyIDs.begin(), myPubKeyIDs.end(), start.second) != myPubKeyIDs.end());
    if (startsFromOurKey) {
        UpdateMessagePriorities(make_pair(end.first, end.second));
    }

    sqlite3_finalize(statement);
}

int CIdentifiDB::GetTrustDistance(pair<string, string> start, pair<string, string> end) {
    sqlite3_stmt *statement;
    ostringstream sql;

    int distance = -1;

    sql.str("");
    sql << "SELECT tp.Distance FROM TrustPaths AS tp ";
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
            distance = sqlite3_column_int(statement, 0);
        }
    } else cout << sqlite3_errmsg(db) << "\n";
    sqlite3_finalize(statement);

    return distance;
}

vector<string> CIdentifiDB::GetPaths(string_pair start, string_pair end, int searchDepth) {
    sqlite3_stmt *statement;
    ostringstream sql;

    vector<string> paths;

    sql.str("");
    sql << "WITH RECURSIVE transitive_closure(pr1val, id1val, pr2val, id2val, distance, path_string) AS ";
    sql << "(";
    sql << "SELECT id1.Predicate, id1.Identifier, id2.Predicate, id2.Identifier, 1 AS distance, "; 
    sql << "printf('%s:%s:%s:%s:',replace(id1.Predicate,':','::'),replace(id1.Identifier,':','::'),replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) AS path_string "; 
    sql << "FROM Messages AS m "; 
    sql << "INNER JOIN MessageIdentifiers AS id1 ON m.Hash = id1.MessageHash AND id1.IsRecipient = 0 "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp1 ON tpp1.Value = id1.Predicate ";
    sql << "INNER JOIN MessageIdentifiers AS id2 ON m.Hash = id2.MessageHash AND (id1.Predicate != id2.Predicate OR id1.Identifier != id2.Identifier) "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp2 ON tpp2.Value = id2.Predicate ";
    sql << "WHERE m.IsLatest AND m.Rating > (m.MinRating + m.MaxRating) / 2 AND id1.Predicate = ? AND id1.Identifier = ? ";

    sql << "UNION ALL "; 

    sql << "SELECT tc.pr1val, tc.id1val, id2.Predicate, id2.Identifier, tc.distance + 1, "; 
    sql << "printf('%s%s:%s:',tc.path_string,replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) AS path_string "; 
    sql << "FROM Messages AS m "; 
    sql << "INNER JOIN MessageIdentifiers AS id1 ON m.Hash = id1.MessageHash AND id1.IsRecipient = 0 "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp1 ON tpp1.Value = id1.Predicate ";
    sql << "INNER JOIN MessageIdentifiers AS id2 ON m.Hash = id2.MessageHash AND (id1.Predicate != id2.Predicate OR id1.Identifier != id2.Identifier) "; 
    sql << "INNER JOIN TrustPathablePredicates AS tpp2 ON tpp2.Value = id2.Predicate ";
    sql << "JOIN transitive_closure AS tc ON id1.Predicate = tc.pr2val AND id1.Identifier = tc.id2val "; 
    sql << "WHERE m.IsLatest AND m.Rating > (m.MinRating + m.MaxRating) / 2 AND tc.distance < ? AND tc.path_string NOT LIKE printf('%%%s:%s:%%',replace(id2.Predicate,':','::'),replace(id2.Identifier,':','::')) "; 
    sql << ") "; 
    sql << "SELECT DISTINCT path_string FROM transitive_closure "; 
    sql << "WHERE pr2val = ? AND id2val = ? ";
    sql << "ORDER BY distance ";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, start.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, start.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 3, searchDepth);
        sqlite3_bind_text(statement, 4, end.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 5, end.second.c_str(), -1, SQLITE_TRANSIENT);

        while (true) {
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                paths.push_back(string((char*)sqlite3_column_text(statement, 0)));
            } else break;
        }
    } else cout << sqlite3_errmsg(db) << "\n";
    
    sqlite3_finalize(statement);
    return paths;
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
    string msgType = "";

    bool useViewpoint = (viewpoint.first != "" && viewpoint.second != "");

    ostringstream sql;
    sql.str("");
    sql << "SELECT ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating > (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating == (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating < (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
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
    sql << "INNER JOIN MessageIdentifiers AS pi ON pi.MessageHash = p.Hash ";
    sql << "INNER JOIN TrustPathablePredicates AS tpp ON tpp.Value = pi.Predicate ";
    sql << "INNER JOIN Identities AS i ON pi.Predicate = i.Predicate AND pi.Identifier = i.Identifier AND i.IdentityID = ";
    sql << "(SELECT IdentityID FROM Identities WHERE ViewpointID = @viewpointID AND ViewpointPredicate = @viewpointPred ";
    sql << "AND Predicate = @pred AND Identifier = @id) ";
    AddMessageFilterSQL(sql, viewpoint, maxDistance, msgType);
    sql << "WHERE p.Predicate = 'rating' ";
    sql << "AND p.IsLatest = 1 ";

    if (useViewpoint) {
        sql << "AND (tp.StartID IS NOT NULL OR (author.Identifier = @viewpointID AND author.Predicate = @viewpointPred) ";
        sql << "OR (author.Predicate = @pred AND author.Identifier = @id)) ";
    }

    sql << "GROUP BY pi.Identifier, pi.Predicate ";
    
    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, viewpoint.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, viewpoint.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, id.second.c_str(), -1, SQLITE_TRANSIENT);
        if (maxDistance > 0) {
            sqlite3_bind_int(statement, 5, maxDistance);
        }
    } else cout << sqlite3_errmsg(db) << "\n"; 

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
        overview.authoredPositive = 0;
        overview.authoredNeutral = 0;
        overview.authoredNegative = 0;
        overview.receivedPositive = 0;
        overview.receivedNeutral = 0;
        overview.receivedNegative = 0;
        overview.firstSeen = 0;
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
        sql << "INNER JOIN TrustPathablePredicates AS authorTpp ON author.Predicate = authorTpp.Value ";
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
            GenerateTrustMap(id, searchDepth);
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
