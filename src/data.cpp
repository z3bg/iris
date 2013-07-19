#include <string>
#include <sstream>
#include "util.h"
#include "key.h"
#include "hash.h"
#include "data.h"

using namespace std;

CIdentifier::~CIdentifier() {}

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
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchSig;
    newKey.Sign(hash, vchSig);

    string signatureString = EncodeBase64(&vchSig[0], sizeof(vchSig));
    CIdentifier signatureIdentifier("ecdsa_sig", signatureString);

    signatures.push_back(signatureIdentifier);
    return true;
}

vector<CIdentifier> CRelation::GetSubjects() {
    return subjects;
}

vector<CIdentifier> CRelation::GetObjects() {
    return objects;
}

vector<CIdentifier> CRelation::GetSignatures() {
    return signatures;
}

CRelation::~CRelation() {}