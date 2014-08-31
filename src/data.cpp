#include <string>
#include <sstream>
#include <boost/lexical_cast.hpp>
#include <algorithm>
#include "data.h"
#include "base58.h"
#include "json/json_spirit_value.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

IdentifiKey CKeyToIdentifiKey(CKey& key) {
    bool compressed = false;
    CSecret secret = key.GetSecret(compressed);
    CPubKey pubKey = key.GetPubKey();
    CIdentifiAddress address(pubKey.GetID());

    IdentifiKey identifiKey;
    identifiKey.pubKey = EncodeBase58(pubKey.Raw());
    identifiKey.keyID = address.ToString();
    identifiKey.privKey = CIdentifiSecret(secret, compressed).ToString();

    return identifiKey;
}

uint256 CIdentifiMessage::GetHash() const {
    //return Hash(strData.begin(), strData.end());
    return GetSignedDataHash();
}

string CIdentifiMessage::GetHashStr() const {
    uint256 hash = GetSignedDataHash();
    return EncodeBase58(hash);
}

uint256 CIdentifiMessage::GetSignedDataHash() const {
    string signedData = GetSignedData();
    return Hash(signedData.begin(), signedData.end());
}

string CIdentifiMessage::GetData() const {
    return strData;
}

string CIdentifiMessage::GetSignedData() const {
    Value json;
    read_string(strData, json);
    return write_string(Value(find_value(json.get_obj(), "signedData").get_obj()), false);
}

void CIdentifiMessage::UpdateSignatures() {
    mValue msg;
    mObject data, newData, signedData, signatureJSON;

    read_string(strData, msg);
    data = msg.get_obj();
    signedData = data["signedData"].get_obj();

    signatureJSON["pubKey"] = signature.GetSignerPubKey();
    signatureJSON["signature"] = signature.GetSignature();

    newData["signedData"] = signedData;
    newData["signature"] = signatureJSON;

    strData = write_string(mValue(newData), false);
}

void CIdentifiMessage::SetData(string strData, bool skipVerify) {
    mValue json;
    mObject data, signedData, sigObj;
    mArray authorsArray, recipientsArray;
    authors.clear();
    recipients.clear();

    read_string(strData, json);
    data = json.get_obj();

    if (!skipVerify) {
        if (data.size() != 2)
            throw runtime_error("Messages must contain only signature and signedData");

        if (write_string(json, false) != strData)
            throw runtime_error("Json must be in json_spirit non-pretty print format and keys alphabetically sorted");
    }

    signedData = data["signedData"].get_obj();
    sigObj = data["signature"].get_obj();
    string strSignedData = write_string(mValue(signedData), false);

    timestamp = signedData["timestamp"].get_int();
    authorsArray = signedData["author"].get_array();
    recipientsArray = signedData["recipient"].get_array();
    type = signedData["type"].get_str();

    bool hasRating = false;
    mValue val;
    val = signedData["rating"];
    if (val.type() != null_type)
        hasRating = true;

    if (hasRating) {
        rating = val.get_int();
        minRating = signedData["minRating"].get_int();
        maxRating = signedData["maxRating"].get_int();
        if (maxRating <= minRating ||
            rating > maxRating ||
            rating < minRating)
            throw runtime_error("Invalid rating");
    }

    if (authorsArray.empty())
        throw runtime_error("Messages must have at least 1 author");

    if (recipientsArray.empty())
        throw runtime_error("Messages must have at least 1 recipient");

    for (mArray::iterator it = authorsArray.begin(); it != authorsArray.end(); it++) {
        mArray author = it->get_array();
        if (!skipVerify) {
            if (author.size() != 2)
                throw runtime_error("Invalid msg author length");

            if (it+1 != authorsArray.end()) {
                mArray nextAuthor = (it+1)->get_array(); 
                if ((author[0].get_str() > nextAuthor[0].get_str()) ||
                    (author[0].get_str() == nextAuthor[0].get_str() && author[1].get_str() > nextAuthor[1].get_str()))
                    throw runtime_error("Authors must be alphabetically sorted");
            }
        }

        authors.push_back(make_pair(author[0].get_str(), author[1].get_str()));
    }

    for (mArray::iterator it = recipientsArray.begin(); it != recipientsArray.end(); it++) {
        mArray recipient = it->get_array();
        if (!skipVerify) {
            if (recipient.size() != 2)
                throw runtime_error("Invalid msg recipient length");

            if (it+1 != recipientsArray.end()) {
                mArray nextRecipient = (it+1)->get_array(); 
                if ((recipient[0].get_str() > nextRecipient[0].get_str())
                    || (recipient[0].get_str() == nextRecipient[0].get_str() && recipient[1].get_str() > nextRecipient[1].get_str()))
                    throw runtime_error("Recipients must be alphabetically sorted");
            }
        }

        recipients.push_back(make_pair(recipient[0].get_str(), recipient[1].get_str()));        
    }

    CSignature sig;

    if (sigObj["pubKey"].type() != null_type && sigObj["signature"].type() != null_type) {
        if (sigObj.size() != 2)
            throw runtime_error("Signatures must contain only pubKey and signature");
        string pubKey = sigObj["pubKey"].get_str();
        string strSignature = sigObj["signature"].get_str();
        sig = CSignature(pubKey, strSignature);
        if (!skipVerify && !sig.IsValid(strSignedData))
            throw runtime_error("Invalid signature");
    }
    signature = sig;

    CIdentifiMessage::strData = strData;
}

bool CIdentifiMessage::Sign(CKey& key) {
    string signedData = GetSignedData();
    uint256 hashToSign = Hash(signedData.begin(), signedData.end());

    vector<unsigned char> vchPubKey = key.GetPubKey().Raw();
    string pubKeyStr = EncodeBase58(vchPubKey);

    vector<unsigned char> vchSig;
    key.Sign(hashToSign, vchSig);
    string signatureString = EncodeBase58(vchSig);

    CSignature sig(pubKeyStr, signatureString);
    signature = sig;

    UpdateSignatures();
    return true;
}

bool CIdentifiMessage::AddSignature(CSignature sig) {
    if (sig.IsValid(GetSignedData())) {
        signature = sig;
        UpdateSignatures();
        return true;
    }
    return false;
}

vector<pair<string, string> > CIdentifiMessage::GetAuthors() const {
    return authors;
}

vector<pair<string, string> > CIdentifiMessage::GetRecipients() const {
    return recipients;
}

CSignature CIdentifiMessage::GetSignature() const {
    return signature;
}

time_t CIdentifiMessage::GetTimestamp() const {
    return timestamp;
}

Value CIdentifiMessage::GetJSON() {
    Value data;
    Object msgJSON;

    read_string(strData, data);
    msgJSON.push_back(Pair("hash", GetHashStr()));
    msgJSON.push_back(Pair("data", data));
    msgJSON.push_back(Pair("published", published));
    msgJSON.push_back(Pair("priority", priority));
    msgJSON.push_back(Pair("signatureDetails", signature.GetJSON()));

    return msgJSON;
}

void CIdentifiMessage::SetPublished() {
    published = true;
}

bool CIdentifiMessage::IsPublished() {
    return published;
}

int CIdentifiMessage::GetPriority() {
    return priority;
}

void CIdentifiMessage::SetPriority(int priority) {
    CIdentifiMessage::priority = priority;
}

int CIdentifiMessage::GetRating() const {
    return rating;
}

int CIdentifiMessage::GetMinRating() const {
    return minRating;
}

int CIdentifiMessage::GetMaxRating() const {
    return maxRating;
}

bool CIdentifiMessage::IsPositive() const {
    if (maxRating * minRating == 0) return false;
    return (rating > (maxRating + minRating) / 2);
}

string CIdentifiMessage::GetComment() const {
    return comment;
}

string CIdentifiMessage::GetType() const {
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

const mValue& find_value( const mObject& obj, const std::string& name ) {
    for(mObject::const_iterator i = obj.begin(); i != obj.end(); ++i ) {
        if( i->first == name )
        {
            return i->second;
        }
    }
   
    return mValue::null;
}

