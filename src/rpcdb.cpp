// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "identifirpc.h"
#include "data.h"
#include "net.h"

using namespace json_spirit;
using namespace std;

Value getrelationcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrelationcount\n"
            "Returns the number of stored relations.");

    return pidentifidb->GetRelationCount();
}

Value getidentifiercount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrelationcount\n"
            "Returns the number of stored identifiers.");

    return pidentifidb->GetIdentifierCount();
}

Value getrelationsbysubject(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getrelationsbysubject <id_value>\n"
            "Returns a list of relations associated with the given subject identifier.");

    Array relationsJSON;
    vector<CRelation> relations = pidentifidb->GetRelationsBySubject(params[0].get_str());
    for (vector<CRelation>::iterator it = relations.begin(); it != relations.end(); ++it) {
        relationsJSON.push_back(it->GetJSON());
    }

    return relationsJSON;
}

Value getrelationsbyobject(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getrelationsbyobject <id_value>\n"
            "Returns a list of relations associated with the given object identifier.");

    Array relationsJSON;
    vector<CRelation> relations = pidentifidb->GetRelationsByObject(params[0].get_str());
    for (vector<CRelation>::iterator it = relations.begin(); it != relations.end(); ++it) {
        relationsJSON.push_back(it->GetJSON());
    }

    return relationsJSON;
}

Value getpath(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "getpath <id1> <id2>\n"
            "Returns an array of relations that connect id1 and id2.");

    Array relationsJSON;
    vector<CRelation> relations = pidentifidb->GetPath(params[0].get_str(), params[1].get_str());
    for (vector<CRelation>::iterator it = relations.begin(); it != relations.end(); ++it) {
        relationsJSON.push_back(it->GetJSON());
    }

    return relationsJSON;
}

Value saverelation(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 5 || params.size() > 6)
        throw runtime_error(
            "saverelation <subject_id_type> <subject_id_value> <object_id_type> <object_id_value> <relation_message> <publish=false>\n"
            "Save a relation");

    vector<pair<string, string> > *subjects = new vector<pair<string, string> >();
    vector<pair<string, string> > *objects = new vector<pair<string, string> >();
    vector<CSignature> *signatures = new vector<CSignature>();
    subjects->push_back(make_pair(params[0].get_str(),params[1].get_str()));
    objects->push_back(make_pair(params[2].get_str(),params[3].get_str()));
    bool publish = (params.size() == 6 && params[5].get_str() == "true");
    CRelation relation(params[4].get_str(), *subjects, *objects, *signatures);
    CKey defaultKey = pidentifidb->GetDefaultKey();
    relation.Sign(defaultKey);
    if (publish) {
        relation.SetPublished();
        RelayRelation(relation);
    }
    return pidentifidb->SaveRelation(relation);
}

Value saverelationfromdata(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "saverelationfromdata <relation_json_data> <publish=false>\n"
            "Save a relation");

    CRelation relation;
    relation.SetData(params[0].get_str());
    CKey defaultKey = pidentifidb->GetDefaultKey();
    relation.Sign(defaultKey);
    bool publish = (params.size() == 2 && params[1].get_str() == "true");
    if (publish) {
        relation.SetPublished();
        RelayRelation(relation);
    }
    return pidentifidb->SaveRelation(relation);
}

Value listprivatekeys(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "listprivatekeys\n"
            "List public key hashes for private keys you own");

    vector<string> keys = pidentifidb->ListPrivateKeys();
    Array keysJSON;    

    for (vector<string>::iterator it = keys.begin(); it != keys.end(); ++it) {
        keysJSON.push_back(*it);
    }   
    return keysJSON;
}

Value addsignature(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "addsignature <signed_relation_hash> <signer_pubkey> <signature>\n"
            "Add a signature to a relation");

    CSignature sig(params[0].get_str(), params[1].get_str(), params[2].get_str());
    CRelation rel = pidentifidb->GetRelationByHash(params[0].get_str());

    if (!rel.AddSignature(sig))
        throw runtime_error("Invalid signature");

    pidentifidb->SaveRelation(rel);

    return true;
}

Value publish(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "publish <relation_hash>\n"
            "Publish a previously local-only relation to the network");

    CRelation rel = pidentifidb->GetRelationByHash(params[0].get_str());
    rel.SetPublished();
    RelayRelation(rel);
    pidentifidb->SaveRelation(rel);

    return true;
}