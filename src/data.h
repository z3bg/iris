#ifndef IDENTIFI_DATA_H
#define IDENTIFI_DATA_H

#include <string>
#include <vector>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

using namespace std;

class CIdentifier {
public:
    CIdentifier(string type, string value) : type(type), value(value) {}
    string GetType();
    string GetValue();
    string GetHash();
    json_spirit::Value GetJSON();
private:
    string type;
    string value;
};

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
    CRelation(string message, vector<CIdentifier> subjects, vector<CIdentifier> objects, vector<CSignature> signatures) : message(message), subjects(subjects), objects(objects), signatures(signatures) {}
    bool Sign();
    string GetMessage();
    string GetData();
    string GetHash();
    time_t GetTimestamp();
    vector<CIdentifier> GetSubjects();
    vector<CIdentifier> GetObjects();
    vector<CSignature> GetSignatures();
    json_spirit::Value GetJSON();
private:
    string message;
    time_t timestamp;
    vector<CIdentifier> subjects;
    vector<CIdentifier> objects;
    vector<CSignature> signatures;
};

#endif // IDENTIFI_DATA_H