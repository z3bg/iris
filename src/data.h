#ifndef IDENTIFI_DATA_H
#define IDENTIFI_DATA_H

#include <string>
#include <vector>
#include <boost/regex.hpp>
#include "hash.h"
#include "util.h"
#include "key.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

using namespace std;
using namespace boost;

class CSignature {
public:
    CSignature(string signedHash, string signerPubKey, string signature) : signedHash(signedHash), signerPubKey(signerPubKey), signature(signature) {
        signerPubKeyHash = EncodeBase64(Hash(signerPubKey.begin(), signerPubKey.end()));
    }
    string GetSignedHash();
    string GetSignerPubKey();
    string GetSignerPubKeyHash();
    string GetSignature();
    bool IsValid();
    json_spirit::Value GetJSON();
private:
    string signedHash;
    string signerPubKey;
    string signerPubKeyHash;
    string signature;
};

class CRelation {
public:
    CRelation(string message = "", vector<pair<string, string> > subjects = vector<pair<string, string> >(), vector<pair<string, string> > objects = vector<pair<string, string> >(), vector<CSignature> signatures = vector<CSignature>(), time_t timestamp = time(NULL)) : message(message), subjects(subjects), objects(objects), signatures(signatures), timestamp(timestamp) {
        contentIdentifiers = FindHashtags(message);
    }
    bool operator== (const CRelation &r) const {
        return (r.message == message && r.timestamp == timestamp);
    }
    bool operator!= (const CRelation &r) const {
        return (r.message != message || r.timestamp != timestamp);
    }
    static CRelation fromData(string data);
    static string GetMessageFromData(string data);
    bool Sign(CKey& key);
    bool AddSignature(CSignature signature);
    string GetMessage();
    string GetData();
    string GetHash();
    time_t GetTimestamp();
    vector<pair<string, string> > GetSubjects();
    vector<pair<string, string> > GetObjects();
    vector<string> GetContentIdentifiers();
    vector<CSignature> GetSignatures();
    json_spirit::Value GetJSON();
private:
    string message;
    vector<pair<string, string> > subjects;
    vector<pair<string, string> > objects;
    vector<string> contentIdentifiers;
    vector<CSignature> signatures;
    vector<string> FindHashtags(string text);
    time_t timestamp;
};

#endif // IDENTIFI_DATA_H