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
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "getrelationsbysubject <id_type> <id_value>\n"
            "Returns a list of relations associated with the given subject identifier.");

    CIdentifier identifier(params[0].get_str(), params[1].get_str());
    return pidentifidb->GetRelationsBySubject(identifier).size();
}

Value getrelationsbyobject(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "getrelationsbyobject <id_type> <id_value>\n"
            "Returns a list of relations associated with the given object identifier.");

    CIdentifier identifier(params[0].get_str(), params[1].get_str());
    return pidentifidb->GetRelationsByObject(identifier).size();
}

Value saverelation(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
        throw runtime_error(
            "saverelation <subject_id_type> <subject_id_value> <object_id_type> <object_id_value> <relation_message>\n"
            "Save a relation");

    CIdentifier identifier1(params[0].get_str(), params[1].get_str());
    CIdentifier identifier2(params[2].get_str(), params[3].get_str());
    vector<CIdentifier> *subjects = new vector<CIdentifier>();
    vector<CIdentifier> *objects = new vector<CIdentifier>();
    subjects->push_back(identifier1);
    objects->push_back(identifier2);
    CRelation relation(params[4].get_str(), *subjects, *objects);
    relation.Sign();
    return pidentifidb->SaveRelation(relation);
}