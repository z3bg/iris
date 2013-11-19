// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/lexical_cast.hpp>
#include "main.h"
#include "identifirpc.h"
#include "data.h"
#include "net.h"

using namespace json_spirit;
using namespace std;

Value getpacketcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getpacketcount\n"
            "Returns the number of stored packets.");

    return pidentifidb->GetPacketCount();
}

Value getidentifiercount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getpacketcount\n"
            "Returns the number of stored identifiers.");

    return pidentifidb->GetIdentifierCount();
}

Value getpacketsbysubject(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getpacketsbysubject <id_value>\n"
            "Returns a list of packets associated with the given subject identifier.");

    Array packetsJSON;
    vector<CIdentifiPacket> packets = pidentifidb->GetPacketsBySubject(params[0].get_str());
    for (vector<CIdentifiPacket>::iterator it = packets.begin(); it != packets.end(); ++it) {
        packetsJSON.push_back(it->GetJSON());
    }

    return packetsJSON;
}

Value getpacketsbyobject(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getpacketsbyobject <id_value>\n"
            "Returns a list of packets associated with the given object identifier.");

    Array packetsJSON;
    vector<CIdentifiPacket> packets = pidentifidb->GetPacketsByObject(params[0].get_str());
    for (vector<CIdentifiPacket>::iterator it = packets.begin(); it != packets.end(); ++it) {
        packetsJSON.push_back(it->GetJSON());
    }

    return packetsJSON;
}

Value getpacketsafter(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2 )
        throw runtime_error(
            "getpacketsafter <timestamp> <limit=20>\n"
            "Get a list of packets after the given timestamp, limited to the given number of entries.");

    time_t timestamp = boost::lexical_cast<int>(params[0].get_str());
    int nLimit;
    if (params.size() == 2)
        nLimit = boost::lexical_cast<int>(params[1].get_str());
    else
        nLimit = 20;

    Array packetsJSON;
    vector<CIdentifiPacket> packets = pidentifidb->GetPacketsAfterTimestamp(timestamp, nLimit);
    for (vector<CIdentifiPacket>::iterator it = packets.begin(); it != packets.end(); ++it) {
        packetsJSON.push_back(it->GetJSON());
    }

    return packetsJSON;
}

Value getpath(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "getpath <id1> <id2> <search_depth=3>\n"
            "Returns an array of packets that connect id1 and id2, with optional max search depth.");

    Array packetsJSON;
    vector<CIdentifiPacket> packets;
    if (params.size() == 2)
        packets = pidentifidb->GetPath(params[0].get_str(), params[1].get_str(), 3);
    else
        packets = pidentifidb->GetPath(params[0].get_str(), params[1].get_str(), boost::lexical_cast<int>(params[2].get_str()));
    for (vector<CIdentifiPacket>::iterator it = packets.begin(); it != packets.end(); ++it) {
        packetsJSON.push_back(it->GetJSON());
    }

    return packetsJSON;
}

Value savepacket(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 6 || params.size() > 7)
        throw runtime_error(
            "savepacket <subject_id_type> <subject_id_value> <object_id_type> <object_id_value> <packet_comment> <rating[-10..10]> <publish=false>\n"
            "Save a packet");

    vector<pair<string, string> > subjects, objects;
    vector<CSignature> signatures;
    subjects.push_back(make_pair(params[0].get_str(),params[1].get_str()));
    objects.push_back(make_pair(params[2].get_str(),params[3].get_str()));
    bool publish = (params.size() == 7 && params[6].get_str() == "true");
    Object message;
    message.push_back(Pair("type", "review"));
    message.push_back(Pair("comment",params[4].get_str()));
    message.push_back(Pair("rating",lexical_cast<int>(params[5].get_str())));
    message.push_back(Pair("maxRating",10));
    message.push_back(Pair("minRating",-10));
    CIdentifiPacket packet(message, subjects, objects, signatures);
    CKey defaultKey = pidentifidb->GetDefaultKey();
    packet.Sign(defaultKey);
    if (publish) {
        packet.SetPublished();
        RelayPacket(packet);
    }
    return pidentifidb->SavePacket(packet);
}

Value savepacketfromdata(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "savepacketfromdata <packet_json_data> <publish=false> <sign=true>\n"
            "Save a packet.");

    CIdentifiPacket packet;
    packet.SetData(params[0].get_str());
    CKey defaultKey = pidentifidb->GetDefaultKey();
    bool publish = (params.size() >= 2 && params[1].get_str() == "true");
    if (publish || !(params.size() == 3 && params[2].get_str() == "false")) {
        packet.Sign(defaultKey);
    }
    if (publish) {
        packet.SetPublished();
        RelayPacket(packet);
    }
    return pidentifidb->SavePacket(packet);
}

Value deletepacket(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "deletepacket <packet_hash>\n"
            "Delete a packet from the local database");

    pidentifidb->DropPacket(params[0].get_str());

    return true;
}


Value listprivkeys(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "listprivkeys\n"
            "List the private keys you own");

    vector<string> keys = pidentifidb->ListPrivKeys();
    Array keysJSON;    

    for (vector<string>::iterator it = keys.begin(); it != keys.end(); ++it) {
        keysJSON.push_back(*it);
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
            "addsignature <signed_packet_hash> <signer_pubkey> <signature>\n"
            "Add a signature to a packet");

    CSignature sig(params[0].get_str(), params[1].get_str(), params[2].get_str());
    CIdentifiPacket rel = pidentifidb->GetPacketByHash(params[0].get_str());

    if (!rel.AddSignature(sig))
        throw runtime_error("Invalid signature");

    pidentifidb->SavePacket(rel);

    return true;
}

Value publish(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "publish <packet_hash>\n"
            "Publish a previously local-only packet to the network");

    CIdentifiPacket rel = pidentifidb->GetPacketByHash(params[0].get_str());
    rel.SetPublished();
    RelayPacket(rel);
    pidentifidb->SavePacket(rel);

    return true;
}