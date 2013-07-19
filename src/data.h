#ifndef IDENTIFI_DATA_H
#define IDENTIFI_DATA_H

#include <string>
#include <vector>

using namespace std;

class CIdentifier {
public:
    CIdentifier(string type, string value) : type(type), value(value) {}
    ~CIdentifier();
    string GetType();
    string GetValue();
    string GetHash();
private:
    string type;
    string value;
};

class CRelation {
public:
    CRelation(string message, vector<CIdentifier> subjects, vector<CIdentifier> objects) : message(message), subjects(subjects), objects(objects) {}
    ~CRelation();
    bool Sign();
    string GetMessage();
    string GetData();
    string GetHash();
    time_t GetTimestamp();
    vector<CIdentifier> GetSubjects();
    vector<CIdentifier> GetObjects();
    vector<CIdentifier> GetSignatures();
private:
    string message;
    time_t timestamp;
    vector<CIdentifier> subjects;
    vector<CIdentifier> objects;
    vector<CIdentifier> signatures;
};

#endif // IDENTIFI_DATA_H