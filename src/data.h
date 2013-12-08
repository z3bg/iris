#ifndef IDENTIFI_DATA_H
#define IDENTIFI_DATA_H

#include <string>
#include <vector>
#include <boost/regex.hpp>
#include "hash.h"
#include "util.h"
#include "key.h"
#include "base58.h"
#include "serialize.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

using namespace std;
using namespace boost;

class CSignature {
public:
    CSignature(string signerPubKey = "", string signature = "") : signerPubKey(signerPubKey), signature(signature) {}
    string GetSignerPubKey() const;
    string GetSignerPubKeyHash() const;
    string GetSignature() const;
    bool IsValid(string signedData) const;

private:
    string signerPubKey;
    string signature;
};

class CIdentifiPacket {
public:
    CIdentifiPacket(string strData = "") {
        if (!strData.empty())
            SetData(strData);
        published = false;
    }
    bool operator== (const CIdentifiPacket &r) const {
        return (r.GetHash() == GetHash() && r.timestamp == timestamp);
    }
    bool operator!= (const CIdentifiPacket &r) const {
        return (r.GetHash() != GetHash() || r.timestamp != timestamp);
    }
    void SetData(string strData);
    void SetPublished();
    bool IsPublished();
    bool Sign(CKey& key);
    bool AddSignature(CSignature signature);
    int GetRating() const;
    int GetMinRating() const;
    int GetMaxRating() const;
    string GetComment() const;
    string GetType() const;
    string GetData() const;
    string GetSignedData() const;
    uint256 GetSignedDataHash() const;
    uint256 GetHash() const;
    time_t GetTimestamp() const;
    vector<pair<string, string> > GetSubjects() const;
    vector<pair<string, string> > GetObjects() const;
    vector<CSignature> GetSignatures() const;
    json_spirit::Value GetJSON() const;

    IMPLEMENT_SERIALIZE
    (
        string strData;
        if (fWrite) {
            strData = GetData();
            READWRITE(strData);
        } else {
            CIdentifiPacket *packet = const_cast<CIdentifiPacket*>(this);
            READWRITE(strData);
            packet->SetData(strData);
            packet->SetPublished();
        }
    )

private:
    string strData;
    string comment;
    string type;
    int rating;
    int maxRating;
    int minRating;
    vector<pair<string, string> > subjects;
    vector<pair<string, string> > objects;
    vector<CSignature> signatures;
    time_t timestamp;
    bool published;
    void UpdateSignatures();
};

#endif // IDENTIFI_DATA_H