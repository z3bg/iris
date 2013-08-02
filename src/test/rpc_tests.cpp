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
    BOOST_CHECK_EQUAL(r.get_int(), 0);

    BOOST_CHECK_NO_THROW(r=CallRPC("saverelation mbox mailto:alice@example.com mbox mailto:bob@example.com #friends"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationcount"));
    BOOST_CHECK_EQUAL(r.get_int(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 2);

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsbysubject mailto:alice@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    Object firstRelation = r.get_array().front().get_obj();
    BOOST_CHECK_NO_THROW(find_value(firstRelation, "timestamp").get_int());
    BOOST_CHECK(!find_value(firstRelation, "subjects").get_array().empty());
    BOOST_CHECK(!find_value(firstRelation, "objects").get_array().empty());
    BOOST_CHECK(find_value(firstRelation, "message").get_str().size() > 0);
    BOOST_CHECK(!find_value(firstRelation, "signatures").get_array().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsbyobject mailto:bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    firstRelation = r.get_array().front().get_obj();
    BOOST_CHECK_NO_THROW(find_value(firstRelation, "timestamp").get_int());
    BOOST_CHECK(!find_value(firstRelation, "subjects").get_array().empty());
    BOOST_CHECK(!find_value(firstRelation, "objects").get_array().empty());
    BOOST_CHECK(find_value(firstRelation, "message").get_str().size() > 0);
    BOOST_CHECK(!find_value(firstRelation, "signatures").get_array().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("saverelationfromdata '[6865346651654554112,[[\"mbox\",\"mailto:alice@example.com\"]],[[\"mbox\",\"mailto:bob@example.com\"]],\"#positive\"]'"));


/*
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier not_hex"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"), runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC("getrelationsbyidentifier"));
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier string"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier 0 string"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier 0 1 not_array"), runtime_error);
    BOOST_CHECK_NO_THROW(r=CallRPC("getrelationsbyidentifier 0 1 []"));
    BOOST_CHECK_THROW(r=CallRPC("getrelationsbyidentifier 0 1 [] extra"), runtime_error);
    BOOST_CHECK(r.get_array().empty());

    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier null null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier not_array"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier [] []"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier {} {}"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("getrelationsbyidentifier [] {}"));
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier [] {} extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier DEADBEEF"), runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(string("getrelationsbyidentifier ")+rawtx));
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "version").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "locktime").get_int(), 0);
    BOOST_CHECK_THROW(r = CallRPC(string("getrelationsbyidentifier ")+rawtx+" extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier ff00"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC(string("getrelationsbyidentifier ")+rawtx));
    BOOST_CHECK_NO_THROW(CallRPC(string("getrelationsbyidentifier ")+rawtx+" null null NONE|ANYONECANPAY"));
    BOOST_CHECK_NO_THROW(CallRPC(string("getrelationsbyidentifier ")+rawtx+" [] [] NONE|ANYONECANPAY"));
    BOOST_CHECK_THROW(CallRPC(string("getrelationsbyidentifier ")+rawtx+" null null badenum"), runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrelationsbyidentifier DEADBEEF"), runtime_error);
    BOOST_CHECK_THROW(CallRPC(string("getrelationsbyidentifier ")+rawtx+" extra"), runtime_error);
*/

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
