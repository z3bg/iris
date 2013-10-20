#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

#include "main.h"
#include "base58.h"
#include "util.h"
#include "identifirpc.h"

using namespace std;
using namespace json_spirit;

BOOST_AUTO_TEST_SUITE(rpc_tests)

static Array
createArgs(int nRequired, const char* address1=NULL, const char* address2=NULL)
{
    Array result;
    result.push_back(nRequired);
    Array addresses;
    if (address1) addresses.push_back(address1);
    if (address2) addresses.push_back(address2);
    result.push_back(addresses);
    return result;
}

static Value CallRPC(string args)
{
    vector<string> vArgs;
    boost::split(vArgs, args, boost::is_any_of(" \t"));
    string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    Array params = RPCConvertValues(strMethod, vArgs);

    rpcfn_type method = tableRPC[strMethod]->actor;
    try {
        Value result = (*method)(params, false);
        return result;
    }
    catch (Object& objError)
    {
        throw runtime_error(find_value(objError, "message").get_str());
    }
}

BOOST_AUTO_TEST_CASE(save_and_read_relations)
{
    Value r;

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationcount"));
    BOOST_CHECK_EQUAL(r.get_int(), 0);

    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("saverelation mbox mailto:alice@example.com mbox mailto:bob@example.com #positive"));
    BOOST_CHECK_NO_THROW(r=CallRPC("saverelation mbox mailto:bob@example.com mbox mailto:carl@example.com #positive"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationcount"));
    BOOST_CHECK_EQUAL(r.get_int(), 2);

    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 5);

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsbysubject mailto:alice@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    Object firstRelation = r.get_array().front().get_obj();
    BOOST_CHECK_NO_THROW(find_value(firstRelation, "timestamp").get_int());
    BOOST_CHECK(!find_value(firstRelation, "subjects").get_array().empty());
    BOOST_CHECK(!find_value(firstRelation, "objects").get_array().empty());
    BOOST_CHECK(find_value(firstRelation, "message").get_str().size() > 0);
    BOOST_CHECK(!find_value(firstRelation, "hashtags").get_array().empty());
    BOOST_CHECK(!find_value(firstRelation, "signatures").get_array().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsbyobject mailto:bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    firstRelation = r.get_array().front().get_obj();
    BOOST_CHECK_NO_THROW(find_value(firstRelation, "timestamp").get_int());
    BOOST_CHECK(!find_value(firstRelation, "subjects").get_array().empty());
    BOOST_CHECK(!find_value(firstRelation, "objects").get_array().empty());
    BOOST_CHECK(find_value(firstRelation, "message").get_str().size() > 0);
    BOOST_CHECK(!find_value(firstRelation, "signatures").get_array().empty());
    BOOST_CHECK(find_value(firstRelation, "hash").get_str().size() > 0);
    BOOST_CHECK_EQUAL(find_value(firstRelation, "published").get_bool(), false);

    BOOST_CHECK_NO_THROW(r=CallRPC("saverelationfromdata [1234567,[[\"mbox\",\"mailto:alice@example.com\"],[\"profile\",\"http://www.example.com/alice\"]],[[\"mbox\",\"mailto:bob@example.com\"],[\"profile\",\"http://www.example.com/bob\"]],\"#knows\"]"));
    BOOST_CHECK_EQUAL(r.get_str(), "BydAZxnCRMNeSPYWRjsNWkE1gkjeTtKLazXuDf6MH5tx");
    BOOST_CHECK_NO_THROW(CallRPC("publish BydAZxnCRMNeSPYWRjsNWkE1gkjeTtKLazXuDf6MH5tx"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 8);

    BOOST_CHECK_NO_THROW(r=CallRPC("listprivatekeys"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getpath nobody1 nobody2"));
    BOOST_CHECK(r.get_array().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mailto:alice@example.com mailto:bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mailto:alice@example.com mailto:carl@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);

    BOOST_CHECK_NO_THROW(r=CallRPC("saverelation mbox mailto:alice@example.com mbox mailto:bill@example.com #negative"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mailto:alice@example.com mailto:bill@example.com"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsbysubject http://www.example.com/alice"));
    Object relation = r.get_array().front().get_obj();
    BOOST_CHECK_EQUAL(find_value(relation, "signatures").get_array().size(), 1);

    BOOST_CHECK_THROW(r=CallRPC("addsignature BydAZxnCRMNeSPYWRjsNWkE1gkjeTtKLazXuDf6MH5tx PjP7e3W8Z1RNXjF1JbnyQWqGBqVaCgTVZUDRmLbKU3Es5GHYwN5bb6xUz8cCQ724mJ4HYUeBS7gdAwdRstbBnf2Y invalidsignature"), runtime_error);
    BOOST_CHECK_NO_THROW(r=CallRPC("addsignature BydAZxnCRMNeSPYWRjsNWkE1gkjeTtKLazXuDf6MH5tx PjP7e3W8Z1RNXjF1JbnyQWqGBqVaCgTVZUDRmLbKU3Es5GHYwN5bb6xUz8cCQ724mJ4HYUeBS7gdAwdRstbBnf2Y AN1rKpZ4mbxN4Zvc62fLDGxz5Xn9o37VLbrhLv8YZDyf9NjFnyxjt7AK9stUxJ3T6bqNc8cCQhN8v9Kpy6ZnrfYWRKi8oppaF"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsbysubject http://www.example.com/alice"));
    relation = r.get_array().front().get_obj();
    BOOST_CHECK_EQUAL(find_value(relation, "signatures").get_array().size(), 2);

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsafter 0"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 4);

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsafter 0 1"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
}

BOOST_AUTO_TEST_CASE(db_max_size)
{
    delete pidentifidb;
    pidentifidb = new CIdentifiDB(1);
    Value r;
    const char* rpcFormat = "saverelation mbox mailto:alice@example.com mbox mailto:bob@example.com %i";
    for (int i = 0; i < 1600; i++) {
        char rpc[100];
        sprintf(rpc, rpcFormat, i);
        CallRPC(rpc);
        if (i % 100 == 0) cout << i << " relations saved\n";
    }
    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationcount"));
    int relationCount = r.get_int();
    for (int i = 0; i < 300; i++) {
        char rpc[100];
        sprintf(rpc, rpcFormat, i);
        CallRPC(rpc);
        if (i % 100 == 0) cout << i << " relations saved\n";

    }
    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationcount"));
    BOOST_CHECK(relationCount - 100 < r.get_int());
}

BOOST_AUTO_TEST_SUITE_END()

/*

BOOST_AUTO_TEST_CASE(rpc_addmultisig)
{
    rpcfn_type addmultisig = tableRPC["addmultisigaddress"]->actor;

    // old, 65-byte-long:
    const char address1Hex[] = "0434e3e09f49ea168c5bbf53f877ff4206923858aab7c7e1df25bc263978107c95e35065a27ef6f1b27222db0ec97e0e895eaca603d3ee0d4c060ce3d8a00286c8";
    // new, compressed:
    const char address2Hex[] = "0388c2037017c62240b6b72ac1a2a5f94da790596ebd06177c8572752922165cb4";

    Value v;
    CIdentifiAddress address;
    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(2, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_THROW(addmultisig(createArgs(0), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(2, address1Hex), false), runtime_error);

    BOOST_CHECK_THROW(addmultisig(createArgs(1, ""), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1, "NotAValidPubkey"), false), runtime_error);

    string short1(address1Hex, address1Hex+sizeof(address1Hex)-2); // last byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short1.c_str()), false), runtime_error);

    string short2(address1Hex+1, address1Hex+sizeof(address1Hex)); // first byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short2.c_str()), false), runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    Value r;
    // input is a 1-of-2 multisig (so is output):
    string prevout =
      "[{\"txid\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
      "\"vout\":1,\"scriptPubKey\":\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
      "\"redeemScript\":\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f9216ecefca5b94d6df834e77e108f68e66f126044c052ae\"}]";
    r = CallRPC(string("createrawtransaction ")+prevout+" "+
      "{\"3HqAe9LtNBjnsfM4CyYaWTnvCaUYT7v4oZ\":11}");
    string notsigned = r.get_str();
    string privkey1 = "\"KzsXybp9jX64P5ekX1KUxRQ79Jht9uzW7LorgwE65i5rWACL6LQe\"";
    string privkey2 = "\"Kyhdf5LuKTRx4ge69ybABsiUAWjVRK4XGxAKk2FQLp2HjGMy87Z4\"";
    r = CallRPC(string("signrawtransaction ")+notsigned+" "+prevout+" "+"[]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == false);
    r = CallRPC(string("signrawtransaction ")+notsigned+" "+prevout+" "+"["+privkey1+","+privkey2+"]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == true);
}

*/
