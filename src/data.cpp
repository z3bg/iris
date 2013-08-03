#include <string>
#include <sstream>
#include "util.h"
#include "key.h"
#include "hash.h"
#include "data.h"

using namespace std;
using namespace json_spirit;

string CRelation::GetMessage() {
    return message;
}

string CRelation::GetHash() {
    string data = GetData();
    uint256 hash = Hash(data.begin(), data.end());
    return EncodeBase64(hash);
}

string CRelation::GetData() {
    Array data, subjectsJSON, objectsJSON;

    for (vector<pair<string, string> >::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        Array subject;
        subject.push_back(it->first);
        subject.push_back(it->second);
        subjectsJSON.push_back(subject);
    }

    for (vector<pair<string, string> >::iterator it = objects.begin(); it != objects.end(); ++it) {
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

CRelation CRelation::fromData(string data) {
    Value json;
    Array array, subjectsArray, objectsArray;
    vector<pair<string, string> > subjects, objects;
    vector<CSignature> signatures;

    read_string(data, json);

    array = json.get_array();

    if (array.size() != 4)
        throw runtime_error("Invalid JSON array length");

    time_t timestamp = array[0].get_int();
    subjectsArray = array[1].get_array();
    objectsArray = array[2].get_array();

    if (subjectsArray.empty())
        throw runtime_error("Relations must have at least 1 subject");

    if (objectsArray.empty())
        throw runtime_error("Relations must have at least 1 object");

    for (Array::iterator it = subjectsArray.begin(); it != subjectsArray.end(); it++) {
        Array subject = it->get_array();
        if (subject.size() != 2)
            throw runtime_error("Invalid relation subject length");
        subjects.push_back(make_pair(subject[0].get_str(), subject[1].get_str()));
    }

    for (Array::iterator it = objectsArray.begin(); it != objectsArray.end(); it++) {
        Array object = it->get_array();
        if (object.size() != 2)
            throw runtime_error("Invalid relation object length");
        objects.push_back(make_pair(object[0].get_str(), object[1].get_str()));        
    }

    string message = array[3].get_str();

    return CRelation(message, subjects, objects, signatures, timestamp);
}

string CRelation::GetMessageFromData(string data) {
    Value json;
    read_string(data, json);
    Array arr = json.get_array();
    return arr.back().get_str();    
}

bool CRelation::Sign(CKey& key) {
    string data = GetData();
    uint256 signatureHash = Hash(data.begin(), data.end());

    uint256 pubKeyHash = key.GetPubKey().GetHash();
    string pubKeyString = EncodeBase64(pubKeyHash);

    vector<unsigned char> vchSig;
    key.Sign(signatureHash, vchSig);
    string signatureString = EncodeBase64(&vchSig[0], sizeof(vchSig));

    CSignature signature(GetHash(), pubKeyString, signatureString);

    signatures.push_back(signature);
    return true;
}

bool CRelation::AddSignature(CSignature signature) {
    return false;
}

vector<pair<string, string> > CRelation::GetSubjects() {
    return subjects;
}

vector<pair<string, string> > CRelation::GetObjects() {
    return objects;
}

vector<string> CRelation::GetContentIdentifiers() {
    return contentIdentifiers;
}

vector<CSignature> CRelation::GetSignatures() {
    return signatures;
}

time_t CRelation::GetTimestamp() {
    return timestamp;
}

Value CRelation::GetJSON() {
    Object relationJSON;
    Array subjectsJSON, objectsJSON, signaturesJSON, hashtagsJSON;

    for (vector<pair<string, string> >::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        Array pairArray;
        pairArray.push_back(it->first);
        pairArray.push_back(it->second);
        subjectsJSON.push_back(pairArray);
    }

    for (vector<pair<string, string> >::iterator it = objects.begin(); it != objects.end(); ++it) {
        Array pairArray;
        pairArray.push_back(it->first);
        pairArray.push_back(it->second);
        objectsJSON.push_back(pairArray);    }

    for (vector<string>::iterator it = contentIdentifiers.begin(); it != contentIdentifiers.end(); ++it) {
        hashtagsJSON.push_back(*it);
    }

    for (vector<CSignature>::iterator it = signatures.begin(); it != signatures.end(); ++it) {
        signaturesJSON.push_back(it->GetJSON());
    }

    relationJSON.push_back(Pair("timestamp", timestamp));
    relationJSON.push_back(Pair("subjects", subjectsJSON));
    relationJSON.push_back(Pair("objects", objectsJSON));
    relationJSON.push_back(Pair("message", message));
    relationJSON.push_back(Pair("hashtags", hashtagsJSON));
    relationJSON.push_back(Pair("signatures", signaturesJSON));

    return relationJSON;
}

vector<string> CRelation::FindHashtags(string text) {
    vector<string> results;
    //regex hashtagExp("(^|[^0-9A-Z&/]+)(#|\uFF03)([0-9A-Z_]*[A-Z_]+[a-z0-9_\\u00c0-\\u00d6\\u00d8-\\u00f6\\u00f8-\\u00ff]*)");
    regex hashtagExp("#\\w\\w+");
    sregex_iterator it(text.begin(), text.end(), hashtagExp);
    sregex_iterator end;

    for (; it != end; it++) {
        results.push_back(it->str());
    }

    return results;
}

string CSignature::GetSignedHash() {
    return signedHash;
}

string CSignature::GetSignerPubKeyHash() {
    return signerPubKeyHash;
}

string CSignature::GetSignature() {
    return signature;
}

Value CSignature::GetJSON() {
    Object signatureJSON;
    signatureJSON.push_back(Pair("signerPubKeyHash", signerPubKeyHash));
    signatureJSON.push_back(Pair("signature", signature));
    return signatureJSON;
}