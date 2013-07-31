// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Identifi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "identifirpc.h"
#include "data.h"

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

Value saverelation(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
        throw runtime_error(
            "saverelation <subject_id_type> <subject_id_value> <object_id_type> <object_id_value> <relation_message>\n"
            "Save a relation");

    vector<pair<string, string> > *subjects = new vector<pair<string, string> >();
    vector<pair<string, string> > *objects = new vector<pair<string, string> >();
    vector<CSignature> *signatures = new vector<CSignature>();
    subjects->push_back(make_pair(params[0].get_str(),params[1].get_str()));
    objects->push_back(make_pair(params[2].get_str(),params[3].get_str()));
    CRelation relation(params[4].get_str(), *subjects, *objects, *signatures);
    relation.Sign();
    return pidentifidb->SaveRelation(relation);
}