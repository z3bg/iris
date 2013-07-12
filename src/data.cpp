#include <string>
#include <sstream>
#include "data.h"

using namespace std;

CIdentifier::~CIdentifier() {}

string CIdentifier::GetType() {
    return type;
}

string CIdentifier::GetValue() {
    return value;
}

string CRelation::GetMessage() {
    return message;
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