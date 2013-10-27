#include <string>
#include <sstream>
#include <boost/lexical_cast.hpp>
#include "data.h"
#include "base58.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

Object CIdentifiPacket::GetMessage() const {
    return message;
}

uint256 CIdentifiPacket::GetHash() const {
    string data = GetData();
    return Hash(data.begin(), data.end());
}

string CIdentifiPacket::GetData() const {
    return data;
}

string CIdentifiPacket::MakeData() {
    Array data, subjectsJSON, objectsJSON;

    for (vector<pair<string, string> >::const_iterator it = subjects.begin(); it != subjects.end(); ++it) {
        Array subject;
        subject.push_back(it->first);
        subject.push_back(it->second);
        subjectsJSON.push_back(subject);
    }

    for (vector<pair<string, string> >::const_iterator it = objects.begin(); it != objects.end(); ++it) {
        Array object;
        object.push_back(it->first);
        object.push_back(it->second);
        objectsJSON.push_back(object);
    }

    data.push_back(timestamp);
    data.push_back(subjectsJSON);
    data.push_back(objectsJSON);
    data.push_back(message);

    return write_string(Value(data), false);
}

Object CIdentifiPacket::GetMessageFromData(string data) {
    Value json;
    read_string(data, json);
    Array arr = json.get_array();
    return arr[3].get_obj();
}

void CIdentifiPacket::SetVarsFromMessage() {
    type = find_value(message, "type").get_str();

    bool hasRating;
    Value val;
    try {
        val = find_value(message, "rating");
        hasRating = true;
    } catch (json_spirit::Object& objError) {}

    if (hasRating) {
        rating = val.get_int();
        minRating = find_value(message, "minRating").get_int();
        maxRating = find_value(message, "maxRating").get_int();
        if (maxRating <= minRating ||
            rating > maxRating ||
            rating < minRating)
            throw runtime_error("Invalid rating");
    }
}

void CIdentifiPacket::SetData(string data) {
    Value json;
    Array array, subjectsArray, objectsArray;
    subjects.clear();
    objects.clear();
    signatures.clear();

    read_string(data, json);

    array = json.get_array();

    if (array.size() != 4)
        throw runtime_error("Invalid JSON array length");

    timestamp = array[0].get_int();
    subjectsArray = array[1].get_array();
    objectsArray = array[2].get_array();
    message = array[3].get_obj();
    SetVarsFromMessage();

    if (subjectsArray.empty())
        throw runtime_error("Packets must have at least 1 subject");

    if (objectsArray.empty())
        throw runtime_error("Packets must have at least 1 object");

    for (Array::iterator it = subjectsArray.begin(); it != subjectsArray.end(); it++) {
        Array subject = it->get_array();
        if (subject.size() != 2)
            throw runtime_error("Invalid packet subject length");
        subjects.push_back(make_pair(subject[0].get_str(), subject[1].get_str()));
    }

    for (Array::iterator it = objectsArray.begin(); it != objectsArray.end(); it++) {
        Array object = it->get_array();
        if (object.size() != 2)
            throw runtime_error("Invalid packet object length");
        objects.push_back(make_pair(object[0].get_str(), object[1].get_str()));        
    }

    CIdentifiPacket::data = data;
}

bool CIdentifiPacket::Sign(CKey& key) {
    string data = GetData();
    uint256 hashToSign = Hash(data.begin(), data.end());

    vector<unsigned char> vchPubKey = key.GetPubKey().Raw();
    string pubKeyStr = EncodeBase58(vchPubKey);

    vector<unsigned char> vchSig;
    key.Sign(hashToSign, vchSig);
    string signatureString = EncodeBase58(vchSig);

    CSignature signature(EncodeBase58(GetHash()), pubKeyStr, signatureString);

    signatures.push_back(signature);
    return true;
}

bool CIdentifiPacket::AddSignature(CSignature signature) {
    if (signature.GetSignedHash() == EncodeBase58(GetHash()) && signature.IsValid()) {
        signatures.push_back(signature);
        return true;
    }
    return false;
}

vector<pair<string, string> > CIdentifiPacket::GetSubjects() const {
    return subjects;
}

vector<pair<string, string> > CIdentifiPacket::GetObjects() const {
    return objects;
}

vector<CSignature> CIdentifiPacket::GetSignatures() const {
    return signatures;
}

time_t CIdentifiPacket::GetTimestamp() const {
    return timestamp;
}

Value CIdentifiPacket::GetJSON() const {
    Object packetJSON;
    Array subjectsJSON, objectsJSON, signaturesJSON;

    for (vector<pair<string, string> >::const_iterator it = subjects.begin(); it != subjects.end(); ++it) {
        Array pairArray;
        pairArray.push_back(it->first);
        pairArray.push_back(it->second);
        subjectsJSON.push_back(pairArray);
    }

    for (vector<pair<string, string> >::const_iterator it = objects.begin(); it != objects.end(); ++it) {
        Array pairArray;
        pairArray.push_back(it->first);
        pairArray.push_back(it->second);
        objectsJSON.push_back(pairArray);    }

    for (vector<CSignature>::const_iterator it = signatures.begin(); it != signatures.end(); ++it) {
        signaturesJSON.push_back(it->GetJSON());
    }

    packetJSON.push_back(Pair("hash", EncodeBase58(GetHash())));
    packetJSON.push_back(Pair("timestamp", timestamp));
    packetJSON.push_back(Pair("subjects", subjectsJSON));
    packetJSON.push_back(Pair("objects", objectsJSON));
    packetJSON.push_back(Pair("message", message));
    packetJSON.push_back(Pair("signatures", signaturesJSON));
    packetJSON.push_back(Pair("published", published));

    return packetJSON;
}

void CIdentifiPacket::SetPublished() {
    published = true;
}

bool CIdentifiPacket::IsPublished() {
    return published;
}

int CIdentifiPacket::GetRating() const {
    return rating;
}

int CIdentifiPacket::GetMinRating() const {
    return minRating;
}

int CIdentifiPacket::GetMaxRating() const {
    return maxRating;
}

string CIdentifiPacket::GetComment() const {
    return comment;
}

string CIdentifiPacket::GetType() const {
    return type;
}

string CSignature::GetSignedHash() const {
    return signedHash;
}

string CSignature::GetSignerPubKey() const {
    return signerPubKey;
}

string CSignature::GetSignerPubKeyHash() const {
    return EncodeBase58(Hash(signerPubKey.begin(), signerPubKey.end()));
}

string CSignature::GetSignature() const {
    return signature;
}

bool CSignature::IsValid() const {    
    vector<unsigned char> vchHash, vchPubKey, vchSig;
    if (!DecodeBase58(signedHash, vchHash) ||
        !DecodeBase58(signerPubKey, vchPubKey) ||
        !DecodeBase58(signature.c_str(), vchSig)) {
        return false;
    }

    CKey key;
    CPubKey pubKey(vchPubKey);
    key.SetPubKey(pubKey);

    uint256 rawHash;

    if (vchHash.size() > sizeof(uint256)) {
        return false;
    } else
        memcpy(&rawHash, &vchHash[0], vchHash.size());

    return key.Verify(rawHash, vchSig);
}

Value CSignature::GetJSON() const {
    Object signatureJSON;
    signatureJSON.push_back(Pair("signerPubKey", signerPubKey));
    signatureJSON.push_back(Pair("signature", signature));
    return signatureJSON;
}