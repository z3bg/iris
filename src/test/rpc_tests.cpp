#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>
#include <ctime>

#include "main.h"
#include "base58.h"
#include "util.h"
#include "identifirpc.h"

using namespace std;
using namespace json_spirit;

BOOST_AUTO_TEST_SUITE(rpc_tests)

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

BOOST_AUTO_TEST_CASE(save_and_read_packets)
{
    Value r;

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketcount"));
    BOOST_CHECK_EQUAL(r.get_int(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 5);

    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket mbox mailto:alice@example.com mbox mailto:bob@example.com positive 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket mbox mailto:bob@example.com mbox mailto:carl@example.com positive 1"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketcount"));
    BOOST_CHECK_EQUAL(r.get_int(), 3);

    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 8);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor mbox mailto:alice@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    Object firstPacket, data, signedData;
    BOOST_CHECK_NO_THROW(firstPacket = r.get_array().front().get_obj());
    BOOST_CHECK_NO_THROW(data=find_value(firstPacket, "data").get_obj());
    BOOST_CHECK_NO_THROW(signedData=find_value(data, "signedData").get_obj());
    BOOST_CHECK_NO_THROW(find_value(signedData, "timestamp").get_int());
    BOOST_CHECK(!find_value(signedData, "author").get_array().empty());
    BOOST_CHECK(!find_value(signedData, "recipient").get_array().empty());
    BOOST_CHECK(find_value(signedData, "comment").get_str().size() > 0);
    BOOST_CHECK(!find_value(data, "signatures").get_array().empty());
    BOOST_CHECK_EQUAL(find_value(firstPacket, "published").get_bool(), false);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyrecipient mbox mailto:bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_NO_THROW(firstPacket = r.get_array().front().get_obj());
    BOOST_CHECK_NO_THROW(data=find_value(firstPacket, "data").get_obj());
    BOOST_CHECK_NO_THROW(signedData=find_value(data, "signedData").get_obj());
    BOOST_CHECK_NO_THROW(find_value(signedData, "timestamp").get_int());
    BOOST_CHECK(!find_value(signedData, "author").get_array().empty());
    BOOST_CHECK(!find_value(signedData, "recipient").get_array().empty());
    BOOST_CHECK(find_value(signedData, "comment").get_str().size() > 0);
    BOOST_CHECK(!find_value(data, "signatures").get_array().empty());
    BOOST_CHECK(find_value(firstPacket, "hash").get_str().size() > 0);
    BOOST_CHECK_EQUAL(find_value(firstPacket, "published").get_bool(), false);

    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1234567,\"author\":[[\"mbox\",\"mailto:alice@example.com\"],[\"profile\",\"http://www.example.com/alice\"]],\"recipient\":[[\"mbox\",\"mailto:bob@example.com\"],[\"profile\",\"http://www.example.com/bob\"]],\"type\":\"review\",\"comment\":\"thanks\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signatures\":[]}"));
    BOOST_CHECK_EQUAL(r.get_str(), "6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP");
    BOOST_CHECK_NO_THROW(CallRPC("publish 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 10);

    BOOST_CHECK_NO_THROW(r=CallRPC("getlinkedidentifier mbox mailto:alice@example.com profile"));
    BOOST_CHECK(!r.get_array().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketbyhash 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP"));
    BOOST_CHECK(!r.get_array().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketbyhash asdf"));
    BOOST_CHECK(r.get_array().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("listmykeys"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_THROW(r=CallRPC("importprivkey invalid_key"), runtime_error);
    BOOST_CHECK_NO_THROW(r=CallRPC("importprivkey 5K1T7u3NA55ypnDDBHB61MZ2hFxCoNbBeZj5dhQttPJFKo85MfR"));
    BOOST_CHECK_EQUAL(r.get_bool(), true);
    BOOST_CHECK_NO_THROW(r=CallRPC("setdefaultkey 5K1T7u3NA55ypnDDBHB61MZ2hFxCoNbBeZj5dhQttPJFKo85MfR"));
    BOOST_CHECK_EQUAL(r.get_bool(), true);
    BOOST_CHECK_NO_THROW(r=CallRPC("listmykeys"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);
    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 12);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpath p1 nobody1 p2 nobody2"));
    BOOST_CHECK(r.get_array().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mbox mailto:alice@example.com mbox mailto:bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mbox mailto:alice@example.com mbox mailto:carl@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mbox mailto:alice@example.com mbox mailto:carl@example.com 1"));
    BOOST_CHECK(r.get_array().empty());

    BOOST_CHECK_EQUAL(CallRPC("getpacketcount").get_int(), 4);
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1,\"author\":[[\"mbox\",\"mailto:alice@example.com\"]],\"recipient\":[[\"mbox\",\"mailto:dick@example.com\"]],\"type\":\"review\",\"comment\":\"thanks\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signatures\":[]} false false"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mbox mailto:alice@example.com mbox mailto:dick@example.com"));
    BOOST_CHECK(r.get_array().empty());
    BOOST_CHECK_EQUAL(CallRPC("getpacketcount").get_int(), 4);

    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket mbox mailto:alice@example.com mbox mailto:bill@example.com negative -1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mbox mailto:alice@example.com mbox mailto:bill@example.com"));
    BOOST_CHECK(r.get_array().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr trusted 5 true"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1392476848,\"author\":[[\"keyID\",\"1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr\"]],\"recipient\":[[\"email\",\"james@example.com\"]],\"type\":\"review\",\"comment\":\"trusted\",\"rating\":1,\"maxRating\":10,\"minRating\":-10},\"signatures\":[{\"pubKey\":\"RXfBZLerFkiD9k3LgreFbiGEyNFjxRc61YxAdPtHPy7HpDDxBQB62UBJLDniZwxXcf849WSra1u6TDCvUtdJxFJU\",\"signature\":\"381yXZQ5LQ2YiuPqtgUAuP3TUMCQQQR7g3gZMS5KHjChRoJoaQFZpuVZXXb6u7dW1rG5cH8AmwxXerjJdHLskgp2HJG24FqE\"}]}"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr"));
    firstPacket = r.get_array().front().get_obj();
    BOOST_CHECK_EQUAL(find_value(firstPacket, "priority").get_int(), 50);

    BOOST_CHECK_NO_THROW(r=CallRPC("gettruststep p1 nobody1 p2 nobody2"));
    BOOST_CHECK(r.get_str().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("gettruststep keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr"));
    BOOST_CHECK(!r.get_str().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("gettruststep keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As email james@example.com"));
    BOOST_CHECK(!r.get_str().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("getsavedpath p1 nobody1 p2 nobody2"));
    BOOST_CHECK(r.get_array().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("getsavedpath keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_NO_THROW(r=CallRPC("getsavedpath keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As email james@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor profile http://www.example.com/alice"));
    firstPacket = r.get_array().front().get_obj();
    data=find_value(firstPacket, "data").get_obj();
    BOOST_CHECK_EQUAL(find_value(data, "signatures").get_array().size(), 1);

    BOOST_CHECK_THROW(r=CallRPC("addsignature 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP QuFEJZLioVcvzrGjfdm2QFsV7Nrmm8vdDMCmW9X2xgpZpYPKrTkZzXjQNjcvfjuu7GrxQKGiUZjXznLkULYjet3V invalidsignature"), runtime_error);
    BOOST_CHECK_NO_THROW(r=CallRPC("addsignature 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP QuFEJZLioVcvzrGjfdm2QFsV7Nrmm8vdDMCmW9X2xgpZpYPKrTkZzXjQNjcvfjuu7GrxQKGiUZjXznLkULYjet3V AN1rKvt2BThjKHbzpNrgxrfRrssN3Fq6byGGaQL3GjjKsqnYgaCJmQqh5Pj5fDjd7UNTHTSY21Xncpe2NigZ2sZFR57brJnJZ"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor profile http://www.example.com/alice"));
    firstPacket = r.get_array().front().get_obj();
    data=find_value(firstPacket, "data").get_obj();
    BOOST_CHECK_EQUAL(find_value(data, "signatures").get_array().size(), 2);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsafter 0"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 7);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsafter 0 1"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("getlatestpackets"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 7);

    BOOST_CHECK_EQUAL(CallRPC("getpacketcount").get_int(), 7);
    BOOST_CHECK_NO_THROW(r=CallRPC("deletepacket 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP"));
    BOOST_CHECK_EQUAL(CallRPC("getpacketcount").get_int(), 6);

    BOOST_CHECK_NO_THROW(r=CallRPC("saveconnection email alice@example.com email bob@example.com email bob@example.org"));
    BOOST_CHECK_NO_THROW(r=CallRPC("refuteconnection email alice@example.com email bob@example.com email bob@example.org"));

    BOOST_CHECK_NO_THROW(r=CallRPC("search alice"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("overview mbox mailto:alice@example.com"));
    data=r.get_obj();
    BOOST_CHECK_EQUAL(find_value(data, "authoredPositive").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(data, "authoredNeutral").get_int(), 0);
    BOOST_CHECK_EQUAL(find_value(data, "authoredNegative").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(data, "receivedPositive").get_int(), 0);
    BOOST_CHECK_EQUAL(find_value(data, "receivedNeutral").get_int(), 0);
    BOOST_CHECK_EQUAL(find_value(data, "receivedNegative").get_int(), 0);

    BOOST_CHECK_NO_THROW(r=CallRPC("getconnections mbox mailto:alice@example.com"));
}

BOOST_AUTO_TEST_CASE(savepacket_performance)
{
    delete pidentifidb;
    pidentifidb = new CIdentifiDB(100);
    Value r;
    const char* rpcFormat = "savepacket mbox mailto:alice@example.com mbox mailto:bob@example.com %i 1";
    
    const int PACKET_COUNT = 5000;

    clock_t begin = clock();
    for (int i = 1; i <= PACKET_COUNT; i++) {
        char rpc[100];
        sprintf(rpc, rpcFormat, i);
        CallRPC(rpc);
        if (i % 50 == 0) {
            clock_t end = clock();
            double timeElapsed = double(end - begin) / CLOCKS_PER_SEC;
            double packetsPerSecond = i / timeElapsed;
            cout << i << " packets saved in " << timeElapsed << " seconds, ";
            cout << packetsPerSecond << " packets per second\n";
        }
    }
}

BOOST_AUTO_TEST_CASE(db_max_size)
{
    cout << "Testing DB size limit with 1 MB DB\n";
    delete pidentifidb;
    pidentifidb = new CIdentifiDB(1);
    Value r;
    const char* rpcFormat = "savepacket mbox mailto:alice@example.com mbox mailto:bob@example.com %i 1";
    for (int i = 0; i < 1600; i++) {
        char rpc[100];
        sprintf(rpc, rpcFormat, i);
        CallRPC(rpc);
        if (i % 100 == 0) cout << i << " packets saved\n";
    }
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketcount"));
    int packetCount = r.get_int();
    for (int i = 0; i < 300; i++) {
        char rpc[100];
        sprintf(rpc, rpcFormat, i);
        CallRPC(rpc);
        if (i % 100 == 0) cout << i << " packets saved\n";

    }
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketcount"));
    BOOST_CHECK(packetCount - 100 < r.get_int());
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
