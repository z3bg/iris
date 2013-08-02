#ifndef IDENTIFI_DATA_H
#define IDENTIFI_DATA_H

#include <string>
#include <vector>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

using namespace std;

class CSignature {
public:
    CSignature(string signedHash, string signerPubKeyHash, string signature) : signedHash(signedHash), signerPubKeyHash(signerPubKeyHash), signature(signature) {}
    string GetSignedHash();
    string GetSignerPubKeyHash();
    string GetSignature();
    json_spirit::Value GetJSON();
private:
    string signedHash;
    string signerPubKeyHash;
    string signature;
};

class CRelation {
public:
    CRelation(string message, vector<pair<string, string> > subjects, vector<pair<string, string> > objects, vector<CSignature> signatures, time_t timestamp = 0) : message(message), subjects(subjects), objects(objects), signatures(signatures), timestamp(timestamp) {}
    static CRelation fromData(string data);
    bool Sign();
    bool AddSignature(CSignature signature);
    string GetMessage();
    string GetData();
    string GetHash();
    time_t GetTimestamp();
    vector<pair<string, string> > GetSubjects();
    vector<pair<string, string> > GetObjects();
    vector<CSignature> GetSignatures();
    json_spirit::Value GetJSON();
private:
    string message;
    vector<pair<string, string> > subjects;
    vector<pair<string, string> > objects;
    vector<CSignature> signatures;
    time_t timestamp;
};

#endif // IDENTIFI_DATA_H