// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/lexical_cast.hpp>
#include <algorithm>
#include "main.h"
#include "identifirpc.h"
#include "data.h"
#include "net.h"

using namespace json_spirit;
using namespace std;

Array msgVectorToJSONArray(vector<CIdentifiMessage> msgs, bool findNames = true, bool authorEmailOnly = true) {
    Array msgsJSON;
    BOOST_FOREACH(CIdentifiMessage msg, msgs) {
        Object msgJSON = msg.GetJSON().get_obj();
        if (findNames) {            
            pair<string, string> linkedNames = pidentifidb->GetMessageLinkedNames(msg, true);
            pair<string, string> linkedEmails = pidentifidb->GetMessageLinkedEmails(msg, authorEmailOnly);

            CSignature signature = msg.GetSignature();
            string signerName = pidentifidb->GetCachedName(make_pair("keyID", signature.GetSignerKeyID()));

            msgJSON.push_back(Pair("authorName", linkedNames.first));
            msgJSON.push_back(Pair("recipientName", linkedNames.second));
            msgJSON.push_back(Pair("authorEmail", linkedEmails.first));
            if (!authorEmailOnly)
                msgJSON.push_back(Pair("recipientEmail", linkedEmails.second));
            msgJSON.push_back(Pair("signerName", signerName));
        }
        msgsJSON.push_back(msgJSON);
    }
    return msgsJSON; 
}

string getDefaultKeyID() {
    CKey defaultKey = pidentifidb->GetDefaultKey();
    IdentifiKey key = CKeyToIdentifiKey(defaultKey);
    return key.keyID;
}

Value getmsgcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmsgcount\n"
            "Returns the number of stored msgs.");

    return pidentifidb->GetMessageCount();
}

Value getidentifiercount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmsgcount\n"
            "Returns the number of stored identifiers.");

    return pidentifidb->GetIdentifierCount();
}

Value getmsgbyhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getmsgbyhash <hash>\n"
            "Looks for a msg that matches the given hash.");

    vector<CIdentifiMessage> msgs;
    try {
        CIdentifiMessage msg = pidentifidb->GetMessageByHash(params[0].get_str()); 
        msgs.push_back(msg);       
    } catch (runtime_error) {

    }

    return msgVectorToJSONArray(msgs);
}

Value gettrustdistance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw runtime_error(
            "gettrustdistance <start_predicate> <start_id> <end_predicate> <end_id>\n"
            "Returns the trust path length from start_id to end_id.");

    int distance = pidentifidb->GetTrustDistance(make_pair(params[0].get_str(), params[1].get_str()), make_pair(params[2].get_str(), params[3].get_str()));

    return distance;
}

Value getmsgsbyauthor(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 8)
        throw runtime_error(
            "getmsgsbyauthor <id_type> <id_value> <limit=20> <offset=0> (<viewpointIdType> <viewpointIdValue> <maxDistance=0>) <msgType>\n"
            "Returns a list of msgs associated with the given author identifier.");

    vector<CIdentifiMessage> msgs;
    int limit = 20, offset = 0, maxDistance = 0;
    string viewpointIdType, viewpointIdValue, msgType;

    if (params.size() > 2)
        limit = boost::lexical_cast<int>(params[2].get_str());
    if (params.size() > 3)
        offset = boost::lexical_cast<int>(params[3].get_str());

    if (params.size() > 4) {
        viewpointIdType = params[4].get_str();
        viewpointIdValue = params[5].get_str();
    }

    if (params.size() > 6)
        maxDistance = boost::lexical_cast<int>(params[6].get_str());

    if (params.size() > 7) {
        msgType = params[7].get_str();
    }

    msgs = pidentifidb->GetMessagesByAuthor(make_pair(params[0].get_str(), params[1].get_str()), limit, offset, false, true, make_pair(viewpointIdType, viewpointIdValue), maxDistance, msgType);

    return msgVectorToJSONArray(msgs);
}

Value getmsgsbyrecipient(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 8 )
        throw runtime_error(
            "getmsgsbyrecipient <id_type> <id_value> <limit=20> <offset=0> (<viewpointIdType> <viewpointIdValue> <maxDistance=0>) <msgType>\n"
            "Returns a list of msgs associated with the given recipient identifier.");

    vector<CIdentifiMessage> msgs;
    int limit = 20, offset = 0, maxDistance = 0;
    string viewpointIdType, viewpointIdValue, msgType;

    if (params.size() > 2)
        limit = boost::lexical_cast<int>(params[2].get_str());
    if (params.size() > 3)
        offset = boost::lexical_cast<int>(params[3].get_str());

    if (params.size() > 4) {
        viewpointIdType = params[4].get_str();
        viewpointIdValue = params[5].get_str();
    }

    if (params.size() > 6) {
        maxDistance = boost::lexical_cast<int>(params[6].get_str());
    }

    if (params.size() > 7) {
        msgType = params[7].get_str();
    }

    msgs = pidentifidb->GetMessagesByRecipient(make_pair(params[0].get_str(), params[1].get_str()), limit, offset, false, true, make_pair(viewpointIdType, viewpointIdValue), maxDistance, msgType);

    return msgVectorToJSONArray(msgs);

}

Value getmsgsafter(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 7 )
        throw runtime_error(
            "getmsgsafter <timestamp> <limit=20> <offset=0> (<viewpointIdType> <viewpointIdValue> <maxDistance=0>) <msgType>\n"
            "Get a list of msgs after the given timestamp, limited to the given number of entries.");

    time_t timestamp = boost::lexical_cast<int>(params[0].get_str());
    int limit = 20, offset = 0, maxDistance = 0;
    string viewpointIdType, viewpointIdValue, msgType;

    if (params.size() > 1)
        limit = boost::lexical_cast<int>(params[1].get_str());
    
    if (params.size() > 2)
        offset = boost::lexical_cast<int>(params[2].get_str());

    if (params.size() > 3) {
        viewpointIdType = params[3].get_str();
        viewpointIdValue = params[4].get_str();
    }

    if (params.size() > 5) {
        maxDistance = boost::lexical_cast<int>(params[5].get_str());
    }

    if (params.size() > 6) {
        msgType = params[6].get_str();
    }

    vector<CIdentifiMessage> msgs = pidentifidb->GetMessagesAfterTimestamp(timestamp, limit, offset, true, make_pair(viewpointIdType, viewpointIdValue), maxDistance, msgType);
    return msgVectorToJSONArray(msgs);

}

Value getlatestmsgs(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 6)
        throw runtime_error(
            "getlatestmsgs <limit=20> <offset=0> (<viewpointIdType> <viewpointIdValue> <maxDistance=0>) <msgType>\n"
            "Get a list of msgs after the given timestamp, limited to the given number of entries.");

    int limit = 20, offset = 0, maxDistance = 0;
    string viewpointIdType, viewpointIdValue, msgType;
    if (params.size() > 0)
        limit = boost::lexical_cast<int>(params[0].get_str());

    if (params.size() > 1)
        offset = boost::lexical_cast<int>(params[1].get_str());

    if (params.size() > 3) {
        viewpointIdType = params[2].get_str();
        viewpointIdValue = params[3].get_str();
    }

    if (params.size() > 4) {
        maxDistance = boost::lexical_cast<int>(params[4].get_str());
    }

    if (params.size() > 5) {
        msgType = params[5].get_str();
    }

    vector<CIdentifiMessage> msgs = pidentifidb->GetLatestMessages(limit, offset, true, make_pair(viewpointIdType, viewpointIdValue), maxDistance, msgType);
    return msgVectorToJSONArray(msgs);

}

Value getpaths(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw runtime_error(
            "getpaths <id1_type> <id1> <id2_type> <id2> <search_depth=3>\n"
            "Returns an array of trust paths that connect id1 and id2.");

    Array paths;
    int searchDepth = 3;
    if (params.size() > 4)
        searchDepth = boost::lexical_cast<int>(params[4].get_str());
    string_pair start = make_pair(params[0].get_str(), params[1].get_str());
    string_pair end = make_pair(params[2].get_str(), params[3].get_str());
    vector<string> strPaths = pidentifidb->GetPaths(start, end, searchDepth);

    regex re("(?<!:):(?!:)");
    BOOST_FOREACH(string s, strPaths) {
        boost::sregex_token_iterator i(s.begin(), s.end(), re, -1);
        boost::sregex_token_iterator j;
        Array path;
        Array id;
        while (i != j) {
            string str = *i++;
            replace_all(str, "::", ":");
            id.push_back(Value(str));
            if (id.size() == 2) {
                path.push_back(id);
                id.clear();
            }
        }
        paths.push_back(path);
    }

    return Value(paths);
}

Value getpathlength(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw runtime_error(
            "getpathlength <id1_type> <id1> <id2_type> <id2>\n"
            "Returns the length of trust path from id1 to id2.");

    Array msgsJSON;
    int i = pidentifidb->GetTrustDistance(make_pair(params[0].get_str(), params[1].get_str()), make_pair(params[2].get_str(), params[3].get_str()));

    return i;
}

Value search(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 6)
        throw runtime_error(
            "search <query> <predicate=\"\"> <limit=10> <offset=0> <viewpointType> <viewpointValue>\n"
            "Returns a list of predicate / identifier pairs matching the query and predicate (optional).");

    Array resultsJSON;
    string_pair query, viewpoint;
    string viewpointType, viewpointValue;
    int limit = 10, offset = 0;
    if (params.size() == 1)
        query = make_pair("", params[0].get_str());
    if (params.size() >= 2)
        query = make_pair(params[1].get_str(), params[0].get_str());
    if (params.size() >= 3)
        limit = boost::lexical_cast<int>(params[2].get_str());
    if (params.size() >= 4)
        offset = boost::lexical_cast<int>(params[3].get_str());
    if (params.size() > 5) {
        viewpointType = params[4].get_str();
        viewpointValue = params[5].get_str();
        viewpoint = make_pair(viewpointType, viewpointValue);
    }

    vector<SearchResult> results = pidentifidb->SearchForID(query, limit, offset, false, viewpoint);

    BOOST_FOREACH(SearchResult r, results) {
        Object o;
        o.push_back(Pair("type",r.id.first));
        o.push_back(Pair("value",r.id.second));
        o.push_back(Pair("name",r.name));
        o.push_back(Pair("email",r.email));
        resultsJSON.push_back(o);
    }

    return resultsJSON;
}

Value overview(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 5 || params.size() < 2)
        throw runtime_error(
            "overview <id_type> <id_value> (<viewpointIdType> <viewpointIdValue> <maxDistance=0>)\n"
            "Gives an overview of an identifier.");

    int maxDistance = 0;
    string viewpointIdType, viewpointIdValue;

    if (params.size() > 2) {
        viewpointIdType = params[2].get_str();
        viewpointIdValue = params[3].get_str();
    }

    if (params.size() > 4) {
        maxDistance = boost::lexical_cast<int>(params[4].get_str());
    }

    string_pair id = make_pair(params[0].get_str(), params[1].get_str());
    int trustMapSize = pidentifidb->GetTrustMapSize(id);
    IDOverview overview = pidentifidb->GetIDOverview(id, make_pair(viewpointIdType, viewpointIdValue), maxDistance);
    Object overviewJSON;
    overviewJSON.push_back(Pair("authoredPositive", overview.authoredPositive));
    overviewJSON.push_back(Pair("authoredNeutral", overview.authoredNeutral));
    overviewJSON.push_back(Pair("authoredNegative", overview.authoredNegative));
    overviewJSON.push_back(Pair("receivedPositive", overview.receivedPositive));
    overviewJSON.push_back(Pair("receivedNeutral", overview.receivedNeutral));
    overviewJSON.push_back(Pair("receivedNegative", overview.receivedNegative));
    overviewJSON.push_back(Pair("firstSeen", overview.firstSeen));
    overviewJSON.push_back(Pair("trustMapSize", trustMapSize));

    string name = pidentifidb->GetName(id);
    overviewJSON.push_back(Pair("name", name));
    string email = pidentifidb->GetCachedEmail(id);
    overviewJSON.push_back(Pair("email", email));

    return overviewJSON;
}

Value rate(const Array& params, bool fHelp) {
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "rate <recipient_id_type> <recipient_id_value> <rating[-10..10]> <msg_comment=""> <publish=true>\n"
            "Save a rating for an identifier, authored by your default key");

    Value defaultKeyID = getDefaultKeyID();
    Array p;
    p.push_back("keyID");
    p.push_back(defaultKeyID);
    p.insert(p.end(), params.begin(), params.end());
    return saverating(p, false);
}

Value saverating(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 5 || params.size() > 7)
        throw runtime_error(
            "saverating <author_id_type> <author_id_value> <recipient_id_type> <recipient_id_value> <rating[-10..10]> <msg_comment=""> <publish=true>\n"
            "Save a rating from author to recipient");

    mArray author, author1, recipient, recipient1;
    mObject signature;
    author1.push_back(params[0].get_str());
    author1.push_back(params[1].get_str());
    author.push_back(author1);
    recipient1.push_back(params[2].get_str());
    recipient1.push_back(params[3].get_str());
    recipient.push_back(recipient1);

    time_t now = time(NULL);
    mObject data, signedData;
    signedData["timestamp"] = lexical_cast<int64_t>(now);
    signedData["author"] = author;
    signedData["recipient"] = recipient;
    signedData["type"] = "rating";
    signedData["rating"] = lexical_cast<int>(params[4].get_str());
    signedData["maxRating"] = 10;
    signedData["minRating"] = -10;
    
    if (params.size() > 5)
        signedData["comment"] = params[5].get_str();

    data["signedData"] = signedData;
    data["signature"] = signature;

    string strData = write_string(mValue(data), false);
    CIdentifiMessage msg(strData);
    CKey defaultKey = pidentifidb->GetDefaultKey();
    msg.Sign(defaultKey);

    bool publish = (params.size() < 7 || params[6].get_str() == "true");
    if (publish) {
        msg.SetPublished();
        RelayMessage(msg);
    }
    return pidentifidb->SaveMessage(msg);
}

Value confirmOrRefuteConnection(const Array& params, bool fHelp, bool confirm)
{
    if (fHelp || params.size() < 6 || params.size() > 7)
        throw runtime_error(
            "saveconnection <author_id_type> <author_id_value> <connected_id1_type> <connected_id1_value> <connected_id2_type> <connected_id2_value> <publish=true>\n"
            "Save a connection between id1 and id2");

    mArray author, author1, recipient, connected1, connected2;
    mObject signature;
    author1.push_back(params[0].get_str());
    author1.push_back(params[1].get_str());
    author.push_back(author1);
    connected1.push_back(params[2].get_str());
    connected1.push_back(params[3].get_str());
    connected2.push_back(params[4].get_str());
    connected2.push_back(params[5].get_str());
    recipient.push_back(connected1);
    recipient.push_back(connected2);
    sort(recipient.begin(), recipient.end());

    time_t now = time(NULL);
    mObject data, signedData;
    signedData["timestamp"] = lexical_cast<int64_t>(now);
    signedData["author"] = author;
    signedData["recipient"] = recipient;
    if (confirm)
        signedData["type"] = "confirm_connection";
    else
        signedData["type"] = "refute_connection";

    data["signedData"] = signedData;
    data["signature"] = signature;

    string strData = write_string(mValue(data), false);
    CIdentifiMessage msg(strData);
    CKey defaultKey = pidentifidb->GetDefaultKey();
    msg.Sign(defaultKey);

    bool publish = (params.size() < 7 || params[6].get_str() == "true");
    if (publish) {
        msg.SetPublished();
        RelayMessage(msg);
    }
    return pidentifidb->SaveMessage(msg);
}

Value saveconnection(const Array& params, bool fHelp) {
    return confirmOrRefuteConnection(params, fHelp, true);
}

Value refuteconnection(const Array& params, bool fHelp) {
    if (fHelp || params.size() < 6 || params.size() > 7)
    throw runtime_error(
        "refuteconnection <author_id_type> <author_id_value> <disconnected_id1_type> <disconnected_id1_value> <disconnected_id2_type> <disconnected_id2_value> <publish=true>\n"
        "Save a connection between id1 and id2");

    return confirmOrRefuteConnection(params, fHelp, false);
}  

Value generatetrustmap(const Array& params, bool fHelp) {
    if (fHelp || params.size() > 3)
    throw runtime_error(
        "generatetrustmap <id_type=keyID> <id_value=nodeDefaultKey> <search_depth=2>\n"
        "Add an identifier to trust map generation queue.");
    
    string_pair id;
    if (params.size() == 0) { 
        id = make_pair("keyID", getDefaultKeyID());
    } else { 
        id = make_pair(params[0].get_str(), params[1].get_str());
    }
    int searchDepth = GetArg("-generatetrustmapdepth", 4);
    if (params.size() == 3) searchDepth = boost::lexical_cast<int>(params[2].get_str());
    return pidentifidb->AddToTrustMapQueue(id, searchDepth);
}


Value gettrustmapsize(const Array& params, bool fHelp) {
    if (fHelp || params.size() < 2)
    throw runtime_error(
        "gettrustmapsize <id_type> <id_value>\n"
        "Get the size of the cached trustmap of an identifier.");
    
    string_pair id = make_pair(params[0].get_str(), params[1].get_str());
    return pidentifidb->GetTrustMapSize(id);
}

Value getconnections(const Array& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 7)
    throw runtime_error(
        "getconnections <id_type> <id_value> <limit=20> <offset=0> (<viewpointIdType> <viewpointIdValue> <maxDistance=0>)\n"
        "Get identifiers linked to the given identifier");

    int limit = 20, offset = 0, maxDistance = 0;
    string viewpointIdType, viewpointIdValue;
    if (params.size() > 2)
        limit = boost::lexical_cast<int>(params[2].get_str());

    if (params.size() > 3)
        offset = boost::lexical_cast<int>(params[3].get_str());

    if (params.size() > 4) {
        viewpointIdType = params[4].get_str();
        viewpointIdValue = params[5].get_str();
    }

    if (params.size() > 6) {
        maxDistance = boost::lexical_cast<int>(params[6].get_str());
    }

    vector<string> searchTypes;
    vector<LinkedID> results = pidentifidb->GetLinkedIdentifiers(make_pair(params[0].get_str(), params[1].get_str()), searchTypes, limit, offset, make_pair(viewpointIdType, viewpointIdValue), maxDistance);
    Array resultsJSON;
    BOOST_FOREACH(LinkedID result, results) {
        Object id;
        id.push_back(Pair("type", result.id.first));
        id.push_back(Pair("value", result.id.second));
        id.push_back(Pair("confirmations", result.confirmations));
        id.push_back(Pair("refutations", result.refutations));
        resultsJSON.push_back(id);
    }
    return resultsJSON;
}

Value getconnectingmsgs(const Array& params, bool fHelp) {
    if (fHelp || params.size() < 4 || params.size() > 10)
    throw runtime_error(
        "getconnectingmsgs <id1_type> <id1_value> <id2_type> <id2_value> <limit=20> <offset=0> (<viewpointIdType> <viewpointIdValue> <maxDistance=0>) <msgType>\n"
        "Get msgs that link id1 and id2");

    int limit = 20, offset = 0, maxDistance = 0;
    string viewpointIdType, viewpointIdValue, msgType;
    if (params.size() > 4)
        limit = boost::lexical_cast<int>(params[4].get_str());

    if (params.size() > 5)
        offset = boost::lexical_cast<int>(params[5].get_str());

    if (params.size() > 6) {
        viewpointIdType = params[6].get_str();
        viewpointIdValue = params[7].get_str();
    }

    if (params.size() > 8) {
        maxDistance = boost::lexical_cast<int>(params[8].get_str());
    }

    if (params.size() > 9) {
        msgType = params[9].get_str();
    }

    vector<CIdentifiMessage> results = pidentifidb->GetConnectingMessages(make_pair(params[0].get_str(), params[1].get_str()), make_pair(params[2].get_str(), params[3].get_str()), limit, offset, true, make_pair(viewpointIdType,viewpointIdValue), maxDistance, msgType);
    return msgVectorToJSONArray(results);
}

Value savemsgfromdata(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "savemsgfromdata <msg_json_data> <publish=true> <sign=true>\n"
            "Save a msg.");

    // Canonicalize
    mValue val;
    read_string(params[0].get_str(), val);
    mObject data = val.get_obj();
    mObject signedData = data["signedData"].get_obj();
    mArray authors = signedData["author"].get_array();
    mArray recipients = signedData["recipient"].get_array();
    sort(authors.begin(), authors.end());
    sort(recipients.begin(), recipients.end());
    signedData["author"] = authors;
    signedData["recipient"] = recipients;
    data["signedData"] = signedData;
    string strData = write_string(mValue(data), false);

    CIdentifiMessage msg;
    msg.SetData(strData);
    CKey defaultKey = pidentifidb->GetDefaultKey();
    bool publish = (params.size() < 2 || params[1].get_str() == "true");
    if (msg.GetSignature().GetSignature().empty()) {
        if (publish || !(params.size() == 3 && params[2].get_str() == "false")) {
            msg.Sign(defaultKey);
        }
    }
    if (publish) {
        msg.SetPublished();
        RelayMessage(msg);
    }
    return pidentifidb->SaveMessage(msg);
}

Value getname(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "getname <id_type> <id_value>\n"
            "Find the name related to an identifier.");

    return pidentifidb->GetName(make_pair(params[0].get_str(), params[1].get_str()));
}

Value getcachedemail(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "getcachedemail <id_type> <id_value>\n"
            "Find the cached email address related to an identifier.");

    return pidentifidb->GetCachedEmail(make_pair(params[0].get_str(), params[1].get_str()));
}

Value deletemsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "deletemsg <msg_hash>\n"
            "Delete a msg from the local database");

    pidentifidb->DropMessage(params[0].get_str());

    return true;
}


Value listmykeys(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "listmykeys\n"
            "List the private keys you own");

    CKey defaultKey = pidentifidb->GetDefaultKey();
    string strDefaultKey = EncodeBase58(defaultKey.GetPubKey().Raw());
    vector<IdentifiKey> keys = pidentifidb->GetMyKeys();
    Array keysJSON;

    for (vector<IdentifiKey>::iterator key = keys.begin(); key != keys.end(); ++key) {
        string name = pidentifidb->GetName(make_pair("keyID", key->keyID));
        Object keyJSON;
        keyJSON.push_back(Pair("pubkey", key->pubKey));
        keyJSON.push_back(Pair("pubkey ID", key->keyID));
        keyJSON.push_back(Pair("privkey", key->privKey));
        if (!name.empty())
            keyJSON.push_back(Pair("name", name));
        keyJSON.push_back(Pair("default", key->pubKey == strDefaultKey));
        keysJSON.push_back(keyJSON);
    }
    return keysJSON;
}

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importprivkey <key>\n"
            "Import a private key");
    pidentifidb->ImportPrivKey(params[0].get_str());

    return true;
}

Value getnewkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getnewkey\n"
            "Create a new keypair");

    CKey newKey = pidentifidb->GetNewKey();
    IdentifiKey identifiKey = CKeyToIdentifiKey(newKey);

    Object keyJSON;
    keyJSON.push_back(Pair("pubkey", identifiKey.pubKey));
    keyJSON.push_back(Pair("pubkey ID", identifiKey.keyID));
    keyJSON.push_back(Pair("privkey", identifiKey.privKey));

    return keyJSON;
}

Value setdefaultkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setdefaultkey <key>\n"
            "Set the default signing key");

    pidentifidb->SetDefaultKey(params[0].get_str());

    return true;
}

Value addsignature(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "addsignature <signed_msg_hash> <signer_pubkey> <signature>\n"
            "Add a signature to a msg");

    CSignature sig(params[1].get_str(), params[2].get_str());
    CIdentifiMessage msg = pidentifidb->GetMessageByHash(params[0].get_str());

    if (!msg.AddSignature(sig))
        throw runtime_error("Invalid signature");

    pidentifidb->SaveMessage(msg);

    return true;
}

Value publish(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "publish <msg_hash>\n"
            "Publish a previously local-only msg to the network");

    CIdentifiMessage rel = pidentifidb->GetMessageByHash(params[0].get_str());
    rel.SetPublished();
    RelayMessage(rel);
    pidentifidb->SaveMessage(rel);

    return true;
}
