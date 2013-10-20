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
    CSignature(string signedHash = "", string signerPubKey = "", string signature = "") : signedHash(signedHash), signerPubKey(signerPubKey), signature(signature) {}
    string GetSignedHash() const;
    string GetSignerPubKey() const;
    string GetSignerPubKeyHash() const;
    string GetSignature() const;
    bool IsValid() const;
    json_spirit::Value GetJSON() const;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(signedHash);
        READWRITE(signerPubKey);
        READWRITE(signature);
        if (!IsValid())
            throw runtime_error("Invalid signature");
    )

private:
    string signedHash;
    string signerPubKey;
    string signature;
};

class CRelation {
public:
    CRelation(string message = "", vector<pair<string, string> > subjects = vector<pair<string, string> >(), vector<pair<string, string> > objects = vector<pair<string, string> >(), vector<CSignature> signatures = vector<CSignature>(), time_t timestamp = time(NULL), bool published = 0) : message(message), subjects(subjects), objects(objects), signatures(signatures), timestamp(timestamp), published(published) {
        data = MakeData();
    }
    bool operator== (const CRelation &r) const {
        return (r.message == message && r.timestamp == timestamp);
    }
    bool operator!= (const CRelation &r) const {
        return (r.message != message || r.timestamp != timestamp);
    }
    static string GetMessageFromData(string data);
    void SetData(string data);
    void SetPublished();
    bool IsPublished();
    bool Sign(CKey& key);
    bool AddSignature(CSignature signature);
    int GetRating() const;
    int GetMinRating() const;
    int GetMaxRating() const;
    string GetComment() const;
    string GetMessage() const;
    string GetData() const;
    uint256 GetHash() const;
    time_t GetTimestamp() const;
    vector<pair<string, string> > GetSubjects() const;
    vector<pair<string, string> > GetObjects() const;
    vector<CSignature> GetSignatures() const;
    json_spirit::Value GetJSON() const;

    IMPLEMENT_SERIALIZE
    (
        string data;
        if (fWrite) {
            data = GetData();
            READWRITE(data);
            READWRITE(signatures);
        } else {
            CRelation *rel = const_cast<CRelation*>(this);
            READWRITE(data);
            rel->SetData(data);
            rel->SetPublished();
            READWRITE(signatures);
        }
    )

private:
    string data;
    string message;
    string comment;
    string type;
    int rating;
    int maxRating;
    int minRating;
    vector<pair<string, string> > subjects;
    vector<pair<string, string> > objects;
    vector<CSignature> signatures;
    string MakeData();
    time_t timestamp;
    bool published;
};

#endif // IDENTIFI_DATA_H