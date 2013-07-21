#include <string>
#include <sstream>
#include "util.h"
#include "key.h"
#include "hash.h"
#include "data.h"

using namespace std;
using namespace json_spirit;

string CIdentifier::GetType() {
    return type;
}

string CIdentifier::GetValue() {
    return value;
}

string CIdentifier::GetHash() {
    string typeAndValue = type + value;
    uint256 hash = Hash(typeAndValue.begin(), typeAndValue.end());
    return EncodeBase64(hash);
}

Value CIdentifier::GetJSON() {
    Object identifierJSON;
    identifierJSON.push_back(Pair("type", type));
    identifierJSON.push_back(Pair("value", value));
    return identifierJSON;
}

string CRelation::GetMessage() {
    return message;
}

string CRelation::GetHash() {
    string data = GetData();
    uint256 hash = Hash(data.begin(), data.end());
    return EncodeBase64(hash);
}

string CRelation::GetData() {
    ostringstream data;
    data.str("");
    data << timestamp;
    data << " [";

    for (vector<CIdentifier>::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        data << it->GetType();
        data << ":";
        data << it->GetValue();
        if (it != subjects.end() - 1) {
            data << ",";
        }
    }

    data << "] [";

    for (vector<CIdentifier>::iterator it = objects.begin(); it != objects.end(); ++it) {
        data << it->GetType();
        data << ":";
        data << it->GetValue();
        if (it != objects.end() - 1) {
            data << ",";
        }
    }

    data << "] ";
    data << message;
    return data.str();
}

bool CRelation::Sign() {
    CKey newKey;
    newKey.MakeNewKey(false);

    string data = GetData();
    uint256 signatureHash = Hash(data.begin(), data.end());

    uint256 pubKeyHash = newKey.GetPubKey().GetHash();
    string pubKeyString = EncodeBase64(pubKeyHash);

    vector<unsigned char> vchSig;
    newKey.Sign(signatureHash, vchSig);
    string signatureString = EncodeBase64(&vchSig[0], sizeof(vchSig));

    CSignature signature(GetHash(), pubKeyString, signatureString);

    signatures.push_back(signature);
    return true;
}

vector<CIdentifier> CRelation::GetSubjects() {
    return subjects;
}

vector<CIdentifier> CRelation::GetObjects() {
    return objects;
}

vector<CSignature> CRelation::GetSignatures() {
    return signatures;
}

Value CRelation::GetJSON() {
    Object relationJSON;
    Array subjectsJSON, objectsJSON, signaturesJSON;

    for (vector<CIdentifier>::iterator it = subjects.begin(); it != subjects.end(); ++it) {
        subjectsJSON.push_back(it->GetJSON());
    }

    for (vector<CIdentifier>::iterator it = objects.begin(); it != objects.end(); ++it) {
        objectsJSON.push_back(it->GetJSON());
    }

    for (vector<CSignature>::iterator it = signatures.begin(); it != signatures.end(); ++it) {
        signaturesJSON.push_back(it->GetJSON());
    }

    relationJSON.push_back(Pair("timestamp", timestamp));
    relationJSON.push_back(Pair("subjects", subjectsJSON));
    relationJSON.push_back(Pair("objects", objectsJSON));
    relationJSON.push_back(Pair("message", message));
    relationJSON.push_back(Pair("signatures", signaturesJSON));

    return relationJSON;
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