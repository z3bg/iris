#include "data.h"

using namespace std;

CIdentifier::~CIdentifier() {}

string CIdentifier::GetType() {
	return type;
}

string CIdentifier::GetValue() {
	return value;
}

string CRelation::GetType() {
	return type;
}

string CRelation::GetValue() {
	return value;
}

vector<CIdentifier> CRelation::GetSubjects() {
	return subjects;
}

vector<CIdentifier> CRelation::GetObjects() {
	return objects;
}

CRelation::~CRelation() {}