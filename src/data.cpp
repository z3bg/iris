#include <string>
#include <sstream>
#include <boost/lexical_cast.hpp>
#include "data.h"
#include "base58.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

uint256 CIdentifiPacket::GetHash() const {
    //return Hash(strData.begin(), strData.end());
    return GetSignedDataHash();
}

uint256 CIdentifiPacket::GetSignedDataHash() const {
    string signedData = GetSignedData();
    return Hash(signedData.begin(), signedData.end());
}

string CIdentifiPacket::GetData() const {
    return strData;
}

string CIdentifiPacket::GetSignedData() const {
    Value json;
    read_string(strData, json);
    return write_string(Value(find_value(json.get_obj(), "signedData").get_obj()), false);
}

void CIdentifiPacket::UpdateSignatures() {
    Value packet;
    Object data, newData, signedData;
    Array signaturesJSON;

    read_string(strData, packet);
    data = packet.get_obj();
    signedData = find_value(data, "signedData").get_obj();

    for (vector<CSignature>::const_iterator it = signatures.begin(); it != signatures.end(); ++it) {
        Object signature;
        signature.push_back(Pair("pubKey", it->GetSignerPubKey()));
        signature.push_back(Pair("signature", it->GetSignature()));
        signaturesJSON.push_back(signature);
    }

    newData.push_back(Pair("signedData", signedData));
    newData.push_back(Pair("signatures", signaturesJSON));

    strData = write_string(Value(newData), false);
}

void CIdentifiPacket::SetData(string strData) {
    Value json;
    Object data, signedData;
    Array authorsArray, recipientsArray, signaturesArray;
    authors.clear();
    recipients.clear();
    signatures.clear();

    read_string(strData, json);

    data = json.get_obj();
    signedData = find_value(data, "signedData").get_obj();
    string strSignedData = write_string(Value(signedData), false);

    timestamp = find_value(signedData, "timestamp").get_int();
    authorsArray = find_value(signedData, "author").get_array();
    recipientsArray = find_value(signedData, "recipient").get_array();
    signaturesArray = find_value(data, "signatures").get_array();
    type = find_value(signedData, "type").get_str();

    bool hasRating;
    Value val;
    try {
        val = find_value(signedData, "rating");
        hasRating = true;
    } catch (json_spirit::Object& objError) {}

    if (hasRating) {
        rating = val.get_int();
        minRating = find_value(signedData, "minRating").get_int();
        maxRating = find_value(signedData, "maxRating").get_int();
        if (maxRating <= minRating ||
            rating > maxRating ||
            rating < minRating)
            throw runtime_error("Invalid rating");
    }

    if (authorsArray.empty())
        throw runtime_error("Packets must have at least 1 subject");

    if (recipientsArray.empty())
        throw runtime_error("Packets must have at least 1 object");

    for (Array::iterator it = authorsArray.begin(); it != authorsArray.end(); it++) {
        Array subject = it->get_array();
        if (subject.size() != 2)
            throw runtime_error("Invalid packet subject length");
        authors.push_back(make_pair(subject[0].get_str(), subject[1].get_str()));
    }

    for (Array::iterator it = recipientsArray.begin(); it != recipientsArray.end(); it++) {
        Array object = it->get_array();
        if (object.size() != 2)
            throw runtime_error("Invalid packet object length");
        recipients.push_back(make_pair(object[0].get_str(), object[1].get_str()));        
    }

    for (Array::iterator it = signaturesArray.begin(); it != signaturesArray.end(); it++) {
        Object signature = it->get_obj();
        string pubKey = find_value(signature, "pubKey").get_str();
        string strSignature = find_value(signature, "signature").get_str();
        CSignature sig(pubKey, strSignature);
        if (!sig.IsValid(strSignedData))
            throw runtime_error("Invalid signature");
        signatures.push_back(sig);
    }

    CIdentifiPacket::strData = strData;
}

bool CIdentifiPacket::Sign(CKey& key) {
    string signedData = GetSignedData();
    uint256 hashToSign = Hash(signedData.begin(), signedData.end());

    vector<unsigned char> vchPubKey = key.GetPubKey().Raw();
    string pubKeyStr = EncodeBase58(vchPubKey);

    vector<unsigned char> vchSig;
    key.Sign(hashToSign, vchSig);
    string signatureString = EncodeBase58(vchSig);

    CSignature signature(pubKeyStr, signatureString);
    signatures.push_back(signature);

    UpdateSignatures();
    return true;
}

bool CIdentifiPacket::AddSignature(CSignature signature) {
    if (signature.IsValid(GetSignedData())) {
        signatures.push_back(signature);
        UpdateSignatures();
        return true;
    }
    return false;
}

vector<pair<string, string> > CIdentifiPacket::GetAuthors() const {
    return authors;
}

vector<pair<string, string> > CIdentifiPacket::GetRecipients() const {
    return recipients;
}

vector<CSignature> CIdentifiPacket::GetSignatures() const {
    return signatures;
}

time_t CIdentifiPacket::GetTimestamp() const {
    return timestamp;
}

Value CIdentifiPacket::GetJSON() const {
    Value data;
    Object packetJSON;

    read_string(strData, data);
    packetJSON.push_back(Pair("hash", EncodeBase58(GetHash())));
    packetJSON.push_back(Pair("data", data));
    packetJSON.push_back(Pair("published", published));
    packetJSON.push_back(Pair("priority", priority));
    Array signatureDetails;
    BOOST_FOREACH(CSignature sig, signatures) {
        signatureDetails.push_back(sig.GetJSON());
    }
    packetJSON.push_back(Pair("signatureDetails", signatureDetails));

    return packetJSON;
}

void CIdentifiPacket::SetPublished() {
    published = true;
}

bool CIdentifiPacket::IsPublished() {
    return published;
}

int CIdentifiPacket::GetPriority() {
    return priority;
}

void CIdentifiPacket::SetPriority(int priority) {
    CIdentifiPacket::priority = priority;
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

string CSignature::GetSignerPubKey() const {
    return signerPubKey;
}

string CSignature::GetSignature() const {
    return signature;
}

string CSignature::GetSignerKeyID() {
    if (signerKeyID.empty()) {
        vector<unsigned char> vchPubKey;
        DecodeBase58(signerPubKey, vchPubKey);
        CPubKey key(vchPubKey);
        if (!key.IsValid())
            return "";
        CIdentifiAddress address(key.GetID());
        signerKeyID = address.ToString();
    }
    return signerKeyID;
}

bool CSignature::IsValid(string signedData) const {    
    vector<unsigned char> vchPubKey, vchSig;
    if (!DecodeBase58(signerPubKey, vchPubKey) ||
        !DecodeBase58(signature.c_str(), vchSig)) {
        return false;
    }

    CKey key;
    CPubKey pubKey(vchPubKey);
    key.SetPubKey(pubKey);

    uint256 hash = Hash(signedData.begin(), signedData.end());

    return key.Verify(hash, vchSig);
}

Object CSignature::GetJSON() {
    Object json;
    json.push_back(Pair("signerPubKey",signerPubKey));
    json.push_back(Pair("signerKeyID",GetSignerKeyID()));
    json.push_back(Pair("signature",signature));
    return json;
}