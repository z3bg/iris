#ifndef IDENTIFI_DATA_H
#define IDENTIFI_DATA_H

#include <string>
#include <vector>
#include <openssl/rsa.h>

using namespace std;

class CIdentifier {
public:
	CIdentifier(string type, string value) : type(type), value(value) {}
	~CIdentifier();
	string GetType();
	string GetValue();
private:
	string type;
	string value;
};

class CRelation {
public:
	CRelation(string type, string value, vector<CIdentifier> subjects, vector<CIdentifier> objects) : type(type), value(value), subjects(subjects), objects(objects) {}
	~CRelation();
	string GetType();
	string GetValue();
	time_t GetTimestamp();
	vector<CIdentifier> GetSubjects();
	vector<CIdentifier> GetObjects();
	vector<RSA> GetSignatures();
private:
	string type;
	string value;
	time_t timestamp;
	vector<CIdentifier> subjects;
	vector<CIdentifier> objects;
	vector<RSA> signatures;
};

#endif // IDENTIFI_DATA_H