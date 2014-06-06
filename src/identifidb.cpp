// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <deque>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string/join.hpp>
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
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('account', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('url', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('tel', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('keyID', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('base58pubkey', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('bitcoin_address', 1)");
        query("INSERT INTO Predicates (Value, TrustPathable) VALUES ('identifi_packet', 1)");
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
    if (lexical_cast<int>(result[0][0]) < 3) {
        const char* devKeys[] = {"147cQZJ7Bd4ErnVYZahLfCaecJVkJVvqBP",
                                "1KMtj7J2Jjgjk5rivpb636y6KYAov1bpc6",
                                "16tzoJgKHUEW9y6AiWWFCUApi2R5yrffE3"};

        int n = 0;
        BOOST_FOREACH(const char* key, devKeys) {
            n++;
            CKey defaultKey = GetDefaultKey();
            CIdentifiAddress address(defaultKey.GetPubKey().GetID());

            Array author, author1, recipient, recipient1, recipient2;
            Object signature;
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

            json_spirit::Object data, signedData;
            signedData.push_back(Pair("timestamp", lexical_cast<int64_t>(now)));
            signedData.push_back(Pair("author", author));
            signedData.push_back(Pair("recipient", recipient));
            signedData.push_back(Pair("type", "review"));
            signedData.push_back(Pair("comment", "Identifi developers' key, trusted by default"));
            signedData.push_back(Pair("rating", 1));
            signedData.push_back(Pair("maxRating", 1));
            signedData.push_back(Pair("minRating", -1));

            data.push_back(Pair("signedData", signedData));
            data.push_back(Pair("signature", signature));

            string strData = write_string(Value(data), false);
            CIdentifiPacket packet(strData);
            packet.Sign(defaultKey);
            SavePacket(packet);
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
    sql << "CREATE TABLE IF NOT EXISTS Packets (";
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
    sql << "FOREIGN KEY(SignerPubKeyID)     REFERENCES Identifiers(ID)";
    sql << ");";
    query(sql.str().c_str());

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS PacketIdentifiers (";
    sql << "PacketHash          NVARCHAR(45)    NOT NULL,";
    sql << "PredicateID         INTEGER         NOT NULL,";
    sql << "IdentifierID        INTEGER         NOT NULL,";
    sql << "IsRecipient         BOOL            NOT NULL,";
    sql << "PRIMARY KEY(PacketHash, PredicateID, IdentifierID, IsRecipient),";
    sql << "FOREIGN KEY(IdentifierID)   REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(PredicateID)    REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(PacketHash)     REFERENCES Packets(Hash));";
    query(sql.str().c_str());
    query("CREATE INDEX IF NOT EXISTS PIIndex ON PacketIdentifiers(PacketHash)");
    query("CREATE INDEX IF NOT EXISTS PIIndex_predID ON PacketIdentifiers(PredicateID)");
    query("CREATE INDEX IF NOT EXISTS PIIndex_idID ON PacketIdentifiers(IdentifierID)");

    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS TrustPaths (";
    sql << "StartID             INTEGER         NOT NULL,";
    sql << "StartPredicateID    INTEGER         NOT NULL,";
    sql << "EndID               INTEGER         NOT NULL,";
    sql << "EndPredicateID      INTEGER         NOT NULL,";
    sql << "NextStep            NVARCHAR(45)    NOT NULL,";
    sql << "PRIMARY KEY(StartID, StartPredicateID, EndID, EndPredicateID, NextStep),";
    sql << "FOREIGN KEY(StartID)            REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(StartPredicateID)   REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(EndID)              REFERENCES Identifiers(ID),";
    sql << "FOREIGN KEY(EndPredicateID)     REFERENCES Predicates(ID),";
    sql << "FOREIGN KEY(NextStep)           REFERENCES Packets(PacketHash));";
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

    CheckDefaultTrustPathablePredicates();
    CheckDefaultKey();
    CheckDefaultTrustList();
    SearchForPathForMyKeys();
}

void CIdentifiDB::SearchForPathForMyKeys() {
    vector<string> myPubKeyIDs = GetMyPubKeyIDs();
    BOOST_FOREACH (string keyID, myPubKeyIDs) {
        // Generate and save trust maps for our keys
        SearchForPath(make_pair("keyID", keyID), make_pair("",""), true, 3);
    } 
}

vector<string_pair> CIdentifiDB::GetAuthorsOrRecipientsByPacketHash(string packetHash, bool isRecipient) {
    vector<string_pair> authors;
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "SELECT p.Value, id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN PacketIdentifiers AS pi ON pi.PacketHash = @packethash ";
    sql << "INNER JOIN Predicates AS p ON pi.PredicateID = p.ID ";
    sql << "WHERE id.ID = pi.IdentifierID AND pi.IsRecipient = @isrecipient;";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
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
        
        sqlite3_finalize(statement);
    }

    return authors;
}

vector<string_pair> CIdentifiDB::GetAuthorsByPacketHash(string packetHash) {
    return GetAuthorsOrRecipientsByPacketHash(packetHash, false);
}

vector<string_pair> CIdentifiDB::GetRecipientsByPacketHash(string packetHash) {
    return GetAuthorsOrRecipientsByPacketHash(packetHash, true);
}

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByIdentifier(string_pair identifier, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketIdentifiers AS pi ON pi.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON pi.IdentifierID = id.ID ";
    sql << "INNER JOIN Predicates AS pred ON pi.PredicateID = pred.ID ";
    sql << "WHERE ";
    if (!identifier.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    if (!showUnpublished)
        sql << "p.Published = 1 AND ";
    sql << "id.Value = @idValue ";
    sql << "ORDER BY p.Created ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!identifier.first.empty()) {
            sqlite3_bind_text(statement, 1, identifier.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 3, limit);
                sqlite3_bind_int(statement, 4, offset);            
            }
        } else {
            sqlite3_bind_text(statement, 1, identifier.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 2, limit);
                sqlite3_bind_int(statement, 3, offset);            
            }
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

vector<CIdentifiPacket> CIdentifiDB::GetConnectingPackets(string_pair id1, string_pair id2, int limit, int offset, bool showUnpublished) {
    vector<CIdentifiPacket> results;
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketIdentifiers AS LinkAuthor ";
    sql << "ON (LinkAuthor.PacketHash = p.Hash AND LinkAuthor.IsRecipient = 0) ";
    sql << "INNER JOIN PacketIdentifiers AS LinkedID1 ";
    sql << "ON (LinkedID1.PacketHash = p.Hash AND LinkedID1.IsRecipient = 1) ";
    sql << "INNER JOIN PacketIdentifiers AS LinkedID2 ";
    sql << "ON (LinkedID2.PacketHash = p.Hash AND LinkedID2.IsRecipient = 1 ";
    sql << "AND NOT (LinkedID1.IdentifierID = LinkedID2.IdentifierID AND LinkedID1.PredicateID = LinkedID2.PredicateID)) ";
    sql << "INNER JOIN Predicates AS ID1type ON ID1type.ID = LinkedID1.PredicateID ";
    sql << "INNER JOIN Predicates AS ID2type ON ID2type.ID = LinkedID2.PredicateID ";
    sql << "INNER JOIN Identifiers AS ID1value ON ID1value.ID = LinkedID1.IdentifierID ";
    sql << "INNER JOIN Identifiers AS ID2value ON ID2value.ID = LinkedID2.IdentifierID ";
    sql << "WHERE ID1type.Value = @id1type AND ID1value.Value = @id1value ";
    sql << "AND ID2type.Value = @id2type AND ID2value.Value = @id2value ";

    if (!showUnpublished)
        sql << "AND p.Published = 1 ";

    sql << "GROUP BY LinkAuthor.PredicateID, LinkAuthor.IdentifierID ";

    if (limit)
        sql << "LIMIT @limit OFFSET @offset";


    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, id1.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id1.second.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, id2.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, id2.second.c_str(), -1, SQLITE_TRANSIENT);

        if (limit) {
            sqlite3_bind_int(statement, 5, limit);
            sqlite3_bind_int(statement, 6, offset);            
        }

        int result = 0;
        while(true)
        {
            result = sqlite3_step(statement);
            if(result == SQLITE_ROW)
                results.push_back(GetPacketFromStatement(statement));
            else
                break;
        }
        
        sqlite3_finalize(statement);
    }

    return results;
}

// "Find a 'name' or a 'nickname' for the author and recipient of this packet"
pair<string, string> CIdentifiDB::GetPacketLinkedNames(CIdentifiPacket &packet, bool cachedOnly) {
    string authorName, recipientName;

    vector<string_pair> authors = packet.GetAuthors();
    BOOST_FOREACH(string_pair author, authors) {
        authorName = GetName(author, cachedOnly);
        if (authorName != "") {
            break;
        }
    }

    vector<string_pair> recipients = packet.GetRecipients();
    BOOST_FOREACH(string_pair recipient, recipients) {
        recipientName = GetName(recipient, cachedOnly);
        if (recipientName != "") {
            break;
        }
    }

    return make_pair(authorName, recipientName);
}

string CIdentifiDB::GetName(string_pair id, bool cachedOnly) {
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
    string name = "";

    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT nameID.Value FROM CachedNames AS cn ";
    sql << "INNER JOIN Identifiers AS searchedID ON cn.IdentifierID = searchedID.ID ";
    sql << "INNER JOIN Predicates AS searchedPred ON cn.PredicateID = searchedPred.ID ";
    sql << "INNER JOIN Identifiers AS nameID ON cn.CachedNameID = nameID.ID ";
    sql << "WHERE searchedPred.Value = @type AND searchedID.Value = @value";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id.second.c_str(), -1, SQLITE_TRANSIENT);

        int result = sqlite3_step(statement);

        if (result == SQLITE_ROW) {
            name = (char*)sqlite3_column_text(statement, 0);
        }
    }

    return name;
}

// "Find all 'names' or a 'nicknames' linked to this identifier". Empty searchedPredicates catches all.
vector<LinkedID> CIdentifiDB::GetLinkedIdentifiers(string_pair startID, vector<string> searchedPredicates, int limit, int offset) {
    vector<LinkedID> results;

    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");

    sql << "SELECT LinkedPredicate.Value AS IdType, LinkedID.Value AS IdValue, ";
    sql << "SUM(CASE WHEN PacketType.Value = 'confirm_connection' AND LinkedPacketID.IsRecipient THEN 1 ELSE 0 END) AS Confirmations, ";
    sql << "SUM(CASE WHEN PacketType.Value = 'refute_connection' AND LinkedPacketID.IsRecipient THEN 1 ELSE 0 END) AS Refutations ";
    sql << "FROM Packets AS p ";

    sql << "INNER JOIN PacketIdentifiers AS SearchedPacketID ON p.Hash = SearchedPacketID.PacketHash ";
    sql << "INNER JOIN PacketIdentifiers AS LinkedPacketID ";
    sql << "ON (LinkedPacketID.PacketHash = SearchedPacketID.PacketHash ";
    sql << "AND LinkedPacketID.IsRecipient = SearchedPacketID.IsRecipient) ";

    // Only count one packet from author to recipient. Slows down the query somewhat.
    sql << "INNER JOIN (SELECT DISTINCT LinkAuthor.PacketHash AS ph FROM PacketIdentifiers AS LinkAuthor ";
    sql << "INNER JOIN PacketIdentifiers AS LinkRecipient ON (LinkRecipient.IsRecipient = 1 AND LinkAuthor.PacketHash = LinkRecipient.PacketHash) ";
    sql << "WHERE LinkAuthor.IsRecipient = 0 ";
    sql << "GROUP BY LinkAuthor.IdentifierID, LinkAuthor.PredicateID, LinkRecipient.PredicateID, LinkRecipient.IdentifierID ";
    sql << ") ON ph = p.Hash ";

    sql << "INNER JOIN Identifiers AS SearchedID ON SearchedPacketID.IdentifierID = SearchedID.ID ";
    sql << "INNER JOIN Predicates AS SearchedPredicate ON SearchedPacketID.PredicateID = SearchedPredicate.ID ";

    sql << "INNER JOIN Identifiers AS LinkedID ON LinkedPacketID.IdentifierID = LinkedID.ID ";
    sql << "INNER JOIN Predicates AS LinkedPredicate ON LinkedPacketID.PredicateID = LinkedPredicate.ID ";

    sql << "INNER JOIN Predicates AS PacketType ON p.PredicateID = PacketType.id ";

    sql << "WHERE SearchedPredicate.Value = @type ";
    sql << "AND SearchedID.Value = @value ";
    sql << "AND NOT (IdType = SearchedPredicate.Value AND IdValue = SearchedID.Value) ";

    if (!searchedPredicates.empty()) {
        vector<string> questionMarks(searchedPredicates.size(), "?");
        sql << "AND IdType IN (" << algorithm::join(questionMarks, ", ") << ") ";
    }

    sql << "GROUP BY IdType, IdValue ";
    sql << "ORDER BY Confirmations DESC ";

    if (limit > 0) {
        sql << "LIMIT " << limit;
        sql << " OFFSET " << offset;
    }

    int mostConfirmations = 0;
    string mostConfirmedName;

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, startID.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, startID.second.c_str(), -1, SQLITE_TRANSIENT);

        if (!searchedPredicates.empty()) {
            for (unsigned int i = 0; i < searchedPredicates.size(); i++) {
                sqlite3_bind_text(statement, i + 3, searchedPredicates.at(i).c_str(), -1, SQLITE_TRANSIENT);
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
                if (type == "name" || type == "nickname") {
                    if (id.confirmations >= mostConfirmations) {
                        mostConfirmedName = value;
                    }
                }
            }
            else
            {
                break;  
            }
        }
        
        sqlite3_finalize(statement);
    }

    if (!mostConfirmedName.empty())
        UpdateCachedName(startID, mostConfirmedName);

    return results;
}

void CIdentifiDB::UpdateCachedName(string_pair startID, string name) {
    sqlite3_stmt *statement;

    const char* sql = "INSERT OR REPLACE INTO CachedNames (PredicateID, IdentifierID, CachedNameID) VALUES (?,?,?);";
    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql, -1, &statement, 0) == SQLITE_OK) {
            int predicateID = SavePredicate(startID.first);
            int identifierID = SaveIdentifier(startID.second);
            int nameID = SaveIdentifier(name);
            sqlite3_bind_int(statement, 1, predicateID);
            sqlite3_bind_int(statement, 2, identifierID);
            sqlite3_bind_int(statement, 3, nameID);
            sqlite3_step(statement);
        }
    )

    sqlite3_finalize(statement);
}

CIdentifiPacket CIdentifiDB::GetPacketFromStatement(sqlite3_stmt *statement) {
    string strData = (char*)sqlite3_column_text(statement, 1);
    CIdentifiPacket packet(strData, true);
    if(sqlite3_column_int(statement, 7) == 1)
        packet.SetPublished();
    packet.SetPriority(sqlite3_column_int(statement, 8));
    return packet;
}

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByAuthorOrRecipient(string_pair author, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished, bool byRecipient) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets AS p ";
    sql << "INNER JOIN PacketIdentifiers AS pi ON pi.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON pi.IdentifierID = id.ID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = pi.PredicateID WHERE ";
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
    sql << "id.Value = @idValue ";
    sql << "ORDER BY p.Created DESC ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!author.first.empty()) {
            sqlite3_bind_text(statement, 1, author.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, author.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 3, limit);
                sqlite3_bind_int(statement, 4, offset);
            }
        } else {
            sqlite3_bind_text(statement, 1, author.second.c_str(), -1, SQLITE_TRANSIENT); 
            if (limit) {
                sqlite3_bind_int(statement, 2, limit);
                sqlite3_bind_int(statement, 3, offset);
            }           
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

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByAuthor(string_pair recipient, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished) {
    return GetPacketsByAuthorOrRecipient(recipient, limit, offset, trustPathablePredicatesOnly, showUnpublished, false);
}

vector<CIdentifiPacket> CIdentifiDB::GetPacketsByRecipient(string_pair recipient, int limit, int offset, bool trustPathablePredicatesOnly, bool showUnpublished) {
    return GetPacketsByAuthorOrRecipient(recipient, limit, offset, trustPathablePredicatesOnly, showUnpublished, true);
}

vector<string_pair> CIdentifiDB::SearchForID(string_pair query, int limit, int offset, bool trustPathablePredicatesOnly) {
    vector<string_pair> results;

    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT DISTINCT pred.Value, id.Value FROM Identifiers AS id, ";
    sql << "Predicates AS pred ";
    sql << "INNER JOIN PacketIdentifiers AS pi ";
    sql << "ON pi.PredicateID = pred.id AND pi.IdentifierID = id.ID ";
    sql << "WHERE ";
    if (!query.first.empty())
        sql << "pred.Value = @predValue AND ";
    else if (trustPathablePredicatesOnly)
        sql << "pred.TrustPathable = 1 AND ";
    sql << "id.Value LIKE @query || '%' ";

    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (!query.first.empty()) {
            sqlite3_bind_text(statement, 1, query.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, query.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 3, limit);
                sqlite3_bind_int(statement, 4, offset);
            }
        } else {
            sqlite3_bind_text(statement, 1, query.second.c_str(), -1, SQLITE_TRANSIENT);
            if (limit) {
                sqlite3_bind_int(statement, 2, limit);
                sqlite3_bind_int(statement, 3, offset);
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
        
        sqlite3_finalize(statement);
    }
    
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

void CIdentifiDB::DropPacket(string strPacketHash) {
    sqlite3_stmt *statement;
    ostringstream sql;

    sql.str("");
    sql << "DELETE FROM PacketIdentifiers WHERE PacketHash = @hash;";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    // Remove identifiers that were mentioned in this packet only
    sql.str("");
    sql << "DELETE FROM Identifiers WHERE ID IN ";
    sql << "(SELECT id.ID FROM Identifiers AS id ";
    sql << "JOIN PacketIdentifiers AS pi ON pi.IdentifierID = id.ID ";
    sql << "WHERE pi.PacketHash = @packethash) ";
    sql << "AND ID NOT IN ";
    sql << "(SELECT id.ID FROM Identifiers AS id ";
    sql << "JOIN PacketIdentifiers AS pi ON pi.IdentifierID = id.ID ";
    sql << "WHERE pi.PacketHash != @packethash)";
    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, strPacketHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
    }

    sql.str("");
    sql << "DELETE FROM Packets WHERE Hash = @hash;";
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

void CIdentifiDB::SavePacketAuthorOrRecipient(string packetHash, int predicateID, int identifierID, bool isRecipient) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");

    sql << "SELECT * FROM PacketIdentifiers ";
    sql << "WHERE PacketHash = @packethash ";
    sql << "AND PredicateID = @predicateid ";
    sql << "AND IdentifierID = @idid ";
    sql << "AND IsRecipient = @isrecipient";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, predicateID);
        sqlite3_bind_int(statement, 3, identifierID);
        sqlite3_bind_int(statement, 4, isRecipient);
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sql.str("");
        sql << "INSERT OR IGNORE INTO PacketIdentifiers (PacketHash, PredicateID, IdentifierID, IsRecipient) ";
        sql << "VALUES (@packethash, @predicateid, @identifierid, @isRecipient);";
        
        RETRY_IF_DB_FULL(
            if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
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

void CIdentifiDB::SavePacketAuthor(string packetHash, int predicateID, int authorID) {
    SavePacketAuthorOrRecipient(packetHash, predicateID, authorID, false);
}

void CIdentifiDB::SavePacketRecipient(string packetHash, int predicateID, int recipientID) {
    SavePacketAuthorOrRecipient(packetHash, predicateID, recipientID, true);
}

int CIdentifiDB::GetPacketCountByAuthor(string_pair author) {
    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");
    sql << "SELECT COUNT(1) FROM Packets AS p ";
    sql << "INNER JOIN PacketIdentifiers AS pi ON pi.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = pi.IdentifierID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = pi.PredicateID ";
    sql << "WHERE pred.Value = @type AND id.Value = @value AND pi.IsRecipient = 0";

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
    vector<string> myPubKeyIDs = GetMyPubKeyIDs();
    string keyType = "keyID";

    int nShortestPathToSignature = 1000000;
    CSignature sig = packet.GetSignature();

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
    int nMostPacketsFromAuthor = -1;
    bool isMyPacket = false;

    vector<string_pair> authors = packet.GetAuthors();
    BOOST_FOREACH (string_pair author, authors) {
        if (nShortestPathToAuthor > 1) {
            BOOST_FOREACH (string myPubKeyID, myPubKeyIDs) {            
                if (author == make_pair(keyType, myPubKeyID)) {
                    nShortestPathToAuthor = 1;
                    isMyPacket = true;
                    break;            
                }
                int nPath = GetSavedPath(make_pair(keyType, myPubKeyID), author).size();
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
    ostringstream sql;

    string packetHash = EncodeBase58(packet.GetHash());

    vector<string_pair> authors = packet.GetAuthors();
    BOOST_FOREACH (string_pair author, authors) {
        int predicateID = SavePredicate(author.first);
        int authorID = SaveIdentifier(author.second);
        SavePacketAuthor(packetHash, predicateID, authorID);
        /*
        sql.str("");
        sql << "UPDATE Packets SET IsLatest = 0 ";
        sql << "WHERE Hash IN ";
        sql << "(SELECT author.PacketHash FROM PacketIdentifiers AS author ";
        sql << "INNER JOIN PacketIdentifiers AS recipient ON recipient.PacketHash = author.PacketHash ";
        sql << "WHERE aPred.TrustPathable = 1 AND pred.Value = @type ";
        sql << "AND id.Value = @value AND IsRecipient = 0)";
        */
    }
    vector<string_pair> recipients = packet.GetRecipients();
    BOOST_FOREACH (string_pair recipient, recipients) {
        int predicateID = SavePredicate(recipient.first);
        int recipientID = SaveIdentifier(recipient.second);
        SavePacketRecipient(packetHash, predicateID, recipientID);
    }

    CSignature sig = packet.GetSignature();
    string strPubKey = sig.GetSignerPubKey();
    SavePubKey(strPubKey);
    int signerPubKeyID = SaveIdentifier(strPubKey);

    sql.str("");
    sql << "INSERT OR REPLACE INTO Packets ";
    sql << "(Hash, SignedData, Created, PredicateID, Rating, ";
    sql << "MaxRating, MinRating, Published, Priority, SignerPubKeyID, Signature) ";
    sql << "VALUES (@id, @data, @timestamp, @predicateid, @rating, ";
    sql << "@maxRating, @minRating, @published, @priority, @signerPubKeyID, @signature);";

    RETRY_IF_DB_FULL(
        if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement, 2, packet.GetData().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(statement, 3, packet.GetTimestamp());
            sqlite3_bind_int(statement, 4, SavePredicate(packet.GetType()));
            sqlite3_bind_int(statement, 5, packet.GetRating());
            sqlite3_bind_int(statement, 6, packet.GetMaxRating());
            sqlite3_bind_int(statement, 7, packet.GetMinRating());
            sqlite3_bind_int(statement, 8, packet.IsPublished());
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
    int keyIdentifierID = SaveIdentifier(address.ToString());

    if (setDefault)
        query("UPDATE Keys SET IsDefault = 0");

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
    sql << "INNER JOIN Keys AS k ON k.PubKeyID = id.ID ";
    sql << "WHERE k.PrivateKey IS NOT NULL";

    vector<vector<string> > result = query(sql.str().c_str());

    BOOST_FOREACH (vector<string> vStr, result) {
        myPubKeys.push_back(vStr.front());
    }

    return myPubKeys;
}

vector<string> CIdentifiDB::GetMyPubKeyIDs() {
    vector<string> myPubKeys;

    string pubKey, privKey;

    ostringstream sql;
    sql.str("");
    sql << "SELECT id.Value FROM Identifiers AS id ";
    sql << "INNER JOIN Keys AS k ON k.KeyIdentifierID = id.ID ";
    sql << "WHERE k.PrivateKey IS NOT NULL";

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

bool CIdentifiDB::HasTrustedSigner(CIdentifiPacket &packet, vector<string> trustedKeyIDs) {
    CSignature sig = packet.GetSignature();

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

vector<CIdentifiPacket> CIdentifiDB::GetSavedPath(string_pair start, string_pair end, int searchDepth) {
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

    vector<CIdentifiPacket> path;

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
                path.push_back(GetPacketByHash(nextStep));

                current.first = "identifi_packet";
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
    vector<string> myPubKeyIDs = GetMyPubKeyIDs();
    CKey defaultKey = GetDefaultKey();
    vector<unsigned char> vchPubKey = defaultKey.GetPubKey().Raw();
    string strPubKey = EncodeBase58(vchPubKey);

    if (!HasTrustedSigner(packet, myPubKeyIDs))
        return;

    vector<string_pair> savedPacketAuthors = packet.GetAuthors();
    vector<string_pair> savedPacketRecipients = packet.GetRecipients();
    vector<string_pair> savedPacketIdentifiers;
    savedPacketIdentifiers.insert(savedPacketIdentifiers.begin(), savedPacketRecipients.begin(), savedPacketRecipients.end());
    savedPacketIdentifiers.insert(savedPacketIdentifiers.begin(), savedPacketAuthors.begin(), savedPacketAuthors.end());
    string savedPacketHash = EncodeBase58(packet.GetHash());

    // Check if packet is authored by our key
    // bool isMyPacket = false;
    BOOST_FOREACH (string_pair author, savedPacketAuthors) {
        if (author.first == "keyID") {
            BOOST_FOREACH (string myKeyID, myPubKeyIDs) {
                if (myKeyID == author.second) {
                    // Save trust steps from our key to packet's identifiers via the packet
                    BOOST_FOREACH (string_pair id, savedPacketIdentifiers) {
                        SaveTrustStep(make_pair("keyID", myKeyID), id, savedPacketHash);
                    }
                    // isMyPacket = true;
                    break;
                }
            }
        }
    }
}

void CIdentifiDB::SaveTrustStep(string_pair start, string_pair end, string nextStep) {
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

vector<CIdentifiPacket> CIdentifiDB::GetPath(string_pair start, string_pair end, bool savePath, int searchDepth) {
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

struct SearchQueuePacket {
    CIdentifiPacket packet;
    bool matchedByAuthor;
    string_pair matchedByIdentifier;
};

// Breadth-first search for the shortest trust paths to all known packets, starting from id1
vector<CIdentifiPacket> CIdentifiDB::SearchForPath(string_pair start, string_pair end, bool savePath, int searchDepth) {
    vector<CIdentifiPacket> path;
    if (start == end)
        return path;

    vector<CIdentifiPacket> endPackets = GetPacketsByIdentifier(end, 1);
    if (endPackets.empty())
        return path; // Return if the end ID is not involved in any packets

    bool generateTrustMap = false;
    if (savePath && (end.first == "" && end.second == ""))
        generateTrustMap = true;

    deque<SearchQueuePacket> searchQueue;
    map<uint256, CIdentifiPacket> previousPackets;
    map<uint256, int> packetDistanceFromStart;
    vector<uint256> visitedPackets;

    vector<CIdentifiPacket> packets = GetPacketsByAuthor(start, 0, 0, true);
    BOOST_FOREACH(CIdentifiPacket p, packets) {
        SearchQueuePacket sqp;
        sqp.packet = p;
        sqp.matchedByAuthor = true;
        sqp.matchedByIdentifier = start;
        searchQueue.push_back(sqp);
    }
    int currentDistanceFromStart = 1;

    while (!searchQueue.empty()) {
        CIdentifiPacket currentPacket = searchQueue.front().packet;
        bool matchedByAuthor = searchQueue.front().matchedByAuthor;
        string_pair matchedByIdentifier = searchQueue.front().matchedByIdentifier;
        searchQueue.pop_front();
        if (find(visitedPackets.begin(), visitedPackets.end(), currentPacket.GetHash()) != visitedPackets.end()) {
            continue;
        }
        visitedPackets.push_back(currentPacket.GetHash());

        if (currentPacket.GetRating() <= (currentPacket.GetMaxRating() + currentPacket.GetMinRating()) / 2)
            continue;

        if (!HasTrustedSigner(currentPacket, GetMyPubKeyIDs())) {
            continue;
        }

        if (packetDistanceFromStart.find(currentPacket.GetHash()) != packetDistanceFromStart.end())
            currentDistanceFromStart = packetDistanceFromStart[currentPacket.GetHash()];

        if (currentDistanceFromStart > searchDepth) {
            return path;
        }

        vector<string_pair> authors;
        vector<string_pair> allIdentifiers = currentPacket.GetRecipients();
        if (matchedByAuthor) {
            authors = currentPacket.GetAuthors();
            allIdentifiers.insert(allIdentifiers.end(), authors.begin(), authors.end());            
        }
        BOOST_FOREACH (string_pair identifier, allIdentifiers) {
            if (identifier != matchedByIdentifier) {
                bool pathFound = path.empty()
                        && (identifier.first.empty() || end.first.empty() || identifier.first == end.first)
                        && identifier.second == end.second;

                if (pathFound || savePath) {
                    if (pathFound)
                        path.push_back(currentPacket);

                    CIdentifiPacket previousPacket = currentPacket;
                    while (previousPackets.find(previousPacket.GetHash()) != previousPackets.end()) {
                        if (savePath)
                            SaveTrustStep(make_pair("identifi_packet", EncodeBase58(previousPackets.at(previousPacket.GetHash()).GetHash())), identifier, EncodeBase58(previousPacket.GetHash()));
                        previousPacket = previousPackets.at(previousPacket.GetHash());
                        if (pathFound)
                            path.insert(path.begin(), previousPacket);
                    }

                    if (savePath)
                        SaveTrustStep(start, identifier, EncodeBase58(previousPacket.GetHash()));

                    if (pathFound && !generateTrustMap) {
                        return path;
                    }
                }

                vector<CIdentifiPacket> allPackets;
                vector<CIdentifiPacket> authors2 = GetPacketsByAuthor(identifier, 0, 0, true);
                vector<CIdentifiPacket> recipients2 = GetPacketsByRecipient(identifier, 0, 0, true);
                allPackets.insert(allPackets.end(), authors2.begin(), authors2.end());
                allPackets.insert(allPackets.end(), recipients2.begin(), recipients2.end());

                BOOST_FOREACH(CIdentifiPacket p, authors2) {
                    SearchQueuePacket sqp;
                    sqp.packet = p;
                    sqp.matchedByAuthor = true;
                    sqp.matchedByIdentifier = identifier;
                    searchQueue.push_back(sqp);
                }

                BOOST_FOREACH(CIdentifiPacket p, recipients2) {
                    SearchQueuePacket sqp;
                    sqp.packet = p;
                    sqp.matchedByAuthor = false;
                    sqp.matchedByIdentifier = identifier;
                    searchQueue.push_back(sqp);
                }

                BOOST_FOREACH (CIdentifiPacket p, allPackets) {
                    if (previousPackets.find(p.GetHash()) == previousPackets.end()
                        && find(visitedPackets.begin(), visitedPackets.end(), p.GetHash()) == visitedPackets.end())
                        previousPackets[p.GetHash()] = currentPacket;
                    if (packetDistanceFromStart.find(p.GetHash()) == packetDistanceFromStart.end()
                        && find(visitedPackets.begin(), visitedPackets.end(), p.GetHash()) == visitedPackets.end()) {
                        packetDistanceFromStart[p.GetHash()] = currentDistanceFromStart + 1;
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

vector<CIdentifiPacket> CIdentifiDB::GetLatestPackets(int limit, int offset, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets ";
    if (!showUnpublished)
        sql << "WHERE Published = 1 ";
    sql << "ORDER BY Created DESC LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int(statement, 1, limit);
        sqlite3_bind_int(statement, 2, offset);

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


vector<CIdentifiPacket> CIdentifiDB::GetPacketsAfterTimestamp(time_t timestamp, int limit, int offset, bool showUnpublished) {
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets WHERE Created >= @timestamp ";
    if (!showUnpublished)
        sql << "AND Published = 1 ";
    sql << "ORDER BY Created ASC ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";


    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int64(statement, 1, timestamp);
        if (limit) {
            sqlite3_bind_int(statement, 2, limit);
            sqlite3_bind_int(statement, 3, offset);
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

vector<CIdentifiPacket> CIdentifiDB::GetPacketsAfterPacket(string packetHash, int limit, int offset, bool showUnpublished) {
    CIdentifiPacket packet = GetPacketByHash(packetHash);
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets WHERE ";
    sql << "((Created = @timestamp AND Hash > @packethash) OR ";
    sql << "(Created > @timestamp)) ";
    if (!showUnpublished)
        sql << "AND Published = 1 ";
    sql << "ORDER BY Created ASC, Hash ";
    if (limit)
        sql << "LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_int64(statement, 1, packet.GetTimestamp());
        sqlite3_bind_text(statement, 2, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        if (limit) {
            sqlite3_bind_int(statement, 3, limit);
            sqlite3_bind_int(statement, 4, offset);            
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

vector<CIdentifiPacket> CIdentifiDB::GetPacketsBeforePacket(string packetHash, int limit, int offset, bool showUnpublished) {
    CIdentifiPacket packet = GetPacketByHash(packetHash);
    sqlite3_stmt *statement;
    vector<CIdentifiPacket> packets;
    ostringstream sql;
    sql.str("");
    sql << "SELECT * FROM Packets WHERE ";
    sql << "((Created = @timestamp AND Hash < @packethash) OR ";
    sql << "(Created < @timestamp)) ";
    if (!showUnpublished)
        sql << "AND Published = 1 ";
    sql << "ORDER BY Created DESC, Hash LIMIT @limit OFFSET @offset";

    if(sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, packetHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 2, packet.GetTimestamp());
        sqlite3_bind_int(statement, 3, limit);
        sqlite3_bind_int(statement, 4, offset);

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

IDOverview CIdentifiDB::GetIDOverview(string_pair id) {
    IDOverview overview;

    sqlite3_stmt *statement;

    ostringstream sql;
    sql.str("");
    sql << "SELECT ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating > (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating == (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 0 AND p.Rating < (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating > (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating == (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "SUM(CASE WHEN pi.IsRecipient = 1 AND p.Rating < (p.MinRating + p.MaxRating) / 2 THEN 1 ELSE 0 END), ";
    sql << "MIN(p.Created) ";
    sql << "FROM Packets AS p ";
    sql << "INNER JOIN PacketIdentifiers AS pi ON pi.PacketHash = p.Hash ";
    sql << "INNER JOIN Identifiers AS id ON id.ID = pi.IdentifierID ";
    sql << "INNER JOIN Predicates AS pred ON pred.ID = pi.PredicateID ";
    sql << "INNER JOIN Predicates AS packetType ON p.PredicateID = packetType.ID ";
    sql << "WHERE packetType.Value = 'review' ";
    sql << "AND pred.Value = @type AND id.Value = @value ";

    if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, id.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id.second.c_str(), -1, SQLITE_TRANSIENT);
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
        throw runtime_error("GetIDOverview failed");
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