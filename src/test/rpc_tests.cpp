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

int dbNumber = 0;

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

void resetDB() {
    delete pidentifidb;
    pidentifidb = new CIdentifiDB(100, GetDataDir() / to_string(dbNumber));
    dbNumber++;
}

BOOST_AUTO_TEST_CASE(save_and_read_packets)
{
    Value r;

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketcount"));
    BOOST_CHECK_EQUAL(r.get_int(), 3);

    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 8);

    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email alice@example.com email bob@example.com positive 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email bob@example.com email carl@example.com positive 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email carl@example.com email david@example.com positive 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email david@example.com email bob@example.com positive 1"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketcount"));
    BOOST_CHECK_EQUAL(r.get_int(), 7);

    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 12);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor email alice@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    Object firstPacket, data, signedData;
    BOOST_CHECK_NO_THROW(firstPacket = r.get_array().front().get_obj());
    BOOST_CHECK_NO_THROW(data=find_value(firstPacket, "data").get_obj());
    BOOST_CHECK_NO_THROW(signedData=find_value(data, "signedData").get_obj());
    BOOST_CHECK_NO_THROW(find_value(signedData, "timestamp").get_int());
    BOOST_CHECK(!find_value(signedData, "author").get_array().empty());
    BOOST_CHECK(!find_value(signedData, "recipient").get_array().empty());
    BOOST_CHECK(find_value(signedData, "comment").get_str().size() > 0);
    BOOST_CHECK(!find_value(data, "signature").get_obj().empty());
    BOOST_CHECK_EQUAL(find_value(firstPacket, "published").get_bool(), false);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyrecipient email bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);
    BOOST_CHECK_NO_THROW(firstPacket = r.get_array().front().get_obj());
    BOOST_CHECK_NO_THROW(data=find_value(firstPacket, "data").get_obj());
    BOOST_CHECK_NO_THROW(signedData=find_value(data, "signedData").get_obj());
    BOOST_CHECK_NO_THROW(find_value(signedData, "timestamp").get_int());
    BOOST_CHECK(!find_value(signedData, "author").get_array().empty());
    BOOST_CHECK(!find_value(signedData, "recipient").get_array().empty());
    BOOST_CHECK(find_value(signedData, "comment").get_str().size() > 0);
    BOOST_CHECK(!find_value(data, "signature").get_obj().empty());
    BOOST_CHECK(find_value(firstPacket, "hash").get_str().size() > 0);
    BOOST_CHECK_EQUAL(find_value(firstPacket, "published").get_bool(), false);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyrecipient email bob@example.com 20 0 email alice@example.com 3 review"));

    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1234567,\"author\":[[\"mbox\",\"mailto:alice@example.com\"],[\"profile\",\"http://www.example.com/alice\"]],\"recipient\":[[\"mbox\",\"mailto:bob@example.com\"],[\"profile\",\"http://www.example.com/bob\"]],\"type\":\"review\",\"comment\":\"thanks\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"));
    BOOST_CHECK_EQUAL(r.get_str(), "6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP");
    BOOST_CHECK_NO_THROW(CallRPC("publish 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), 16);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketbyhash 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP"));
    BOOST_CHECK(!r.get_array().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketbyhash asdf"));
    BOOST_CHECK(r.get_array().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor profile http://www.example.com/alice"));
    firstPacket = r.get_array().front().get_obj();
    data=find_value(firstPacket, "data").get_obj();
    BOOST_CHECK(!find_value(data, "signature").get_obj().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor profile http://www.example.com/alice 20 0 email alice@example.com 3 review"));

    BOOST_CHECK_THROW(r=CallRPC("addsignature 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP QuFEJZLioVcvzrGjfdm2QFsV7Nrmm8vdDMCmW9X2xgpZpYPKrTkZzXjQNjcvfjuu7GrxQKGiUZjXznLkULYjet3V invalidsignature"), runtime_error);
    BOOST_CHECK_NO_THROW(r=CallRPC("addsignature 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP QuFEJZLioVcvzrGjfdm2QFsV7Nrmm8vdDMCmW9X2xgpZpYPKrTkZzXjQNjcvfjuu7GrxQKGiUZjXznLkULYjet3V AN1rKvt2BThjKHbzpNrgxrfRrssN3Fq6byGGaQL3GjjKsqnYgaCJmQqh5Pj5fDjd7UNTHTSY21Xncpe2NigZ2sZFR57brJnJZ"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor profile http://www.example.com/alice"));
    firstPacket = r.get_array().front().get_obj();
    data=find_value(firstPacket, "data").get_obj();
    BOOST_CHECK(!find_value(data, "signature").get_obj().empty());

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsafter 0"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 8);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsafter 0 1 20 email alice@example.com 3 review"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getlatestpackets"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 8);

    BOOST_CHECK_NO_THROW(r=CallRPC("getlatestpackets 20 0 email alice@example.com 0 review"));

    BOOST_CHECK_EQUAL(CallRPC("getpacketcount").get_int(), 8);
    BOOST_CHECK_NO_THROW(r=CallRPC("deletepacket 6Q1AGhGctnjPoZn4Pen5G7ZRNfJ8WfCwsaffzze6xmRP"));
    BOOST_CHECK_EQUAL(CallRPC("getpacketcount").get_int(), 7);
}

BOOST_AUTO_TEST_CASE(connections) {
    resetDB();
    Value r;
    Object data;
    BOOST_CHECK_NO_THROW(r=CallRPC("saveconnection email bob@example.com email alice@example.com name Alice"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getname email alice@example.com"));

    BOOST_CHECK_NO_THROW(r=CallRPC("saveconnection email alice@example.com email bob@example.com email bob@example.org"));
    BOOST_CHECK_NO_THROW(r=CallRPC("refuteconnection email alice@example.com email bob@example.com email bob@example.org"));

    BOOST_CHECK_NO_THROW(r=CallRPC("search alice"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);

    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email alice@example.com email bob@example.com pos 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email alice@example.com email bob@example.com neut 0"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email alice@example.com email bob@example.com neg -1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email bob@example.com email alice@example.com pos 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email bob@example.com email alice@example.com neut 0"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email bob@example.com email alice@example.com neg -1"));

    BOOST_CHECK_NO_THROW(r=CallRPC("overview email alice@example.com"));
    data=r.get_obj();
    BOOST_CHECK_EQUAL(find_value(data, "authoredPositive").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(data, "authoredNeutral").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(data, "authoredNegative").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(data, "receivedPositive").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(data, "receivedNeutral").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(data, "receivedNegative").get_int(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("overview email alice@example.com email alice@example.com 3"));

    BOOST_CHECK_NO_THROW(r=CallRPC("getconnections email alice@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("getconnections email alice@example.com 20 0 email alice@example.com 3"));
}

BOOST_AUTO_TEST_CASE(keys_and_signatures) {
    Value r;
    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    int identifierCountBefore = r.get_int();
    BOOST_CHECK_NO_THROW(r=CallRPC("listmykeys"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_THROW(r=CallRPC("importprivkey invalid_key"), runtime_error);
    BOOST_CHECK_NO_THROW(r=CallRPC("importprivkey 5K1T7u3NA55ypnDDBHB61MZ2hFxCoNbBeZj5dhQttPJFKo85MfR"));
    BOOST_CHECK_EQUAL(r.get_bool(), true);
    BOOST_CHECK_NO_THROW(r=CallRPC("setdefaultkey 5K1T7u3NA55ypnDDBHB61MZ2hFxCoNbBeZj5dhQttPJFKo85MfR"));
    BOOST_CHECK_EQUAL(r.get_bool(), true);
    BOOST_CHECK_NO_THROW(r=CallRPC("getnewkey"));
    BOOST_CHECK_NO_THROW(r=CallRPC("listmykeys"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 3);
    BOOST_CHECK_NO_THROW(r=CallRPC("getidentifiercount"));
    BOOST_CHECK_EQUAL(r.get_int(), identifierCountBefore + 4);
}

BOOST_AUTO_TEST_CASE(trust_paths) {
    resetDB();
    Value r;
    Object firstPacket;
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email abc@example.com email def@example.com negative -1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email abc@example.com email def@example.com"));
    BOOST_CHECK(r.get_array().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email abc@example.com email def@example.com positive 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email abc@example.com email def@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);


    BOOST_CHECK_NO_THROW(r=CallRPC("setdefaultkey 5K1T7u3NA55ypnDDBHB61MZ2hFxCoNbBeZj5dhQttPJFKo85MfR"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr trusted 5 true"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1392476848,\"author\":[[\"keyID\",\"1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr\"]],\"recipient\":[[\"email\",\"james@example.com\"]],\"type\":\"review\",\"comment\":\"trusted\",\"rating\":1,\"maxRating\":10,\"minRating\":-10},\"signature\":{\"pubKey\":\"RXfBZLerFkiD9k3LgreFbiGEyNFjxRc61YxAdPtHPy7HpDDxBQB62UBJLDniZwxXcf849WSra1u6TDCvUtdJxFJU\",\"signature\":\"381yXZQ5LQ2YiuPqtgUAuP3TUMCQQQR7g3gZMS5KHjChRoJoaQFZpuVZXXb6u7dW1rG5cH8AmwxXerjJdHLskgp2HJG24FqE\"}}"));
    BOOST_CHECK_EQUAL(r.get_str(), "9EqUAJXnCnWSWiTaMGUG4j2tTMnvY77qDuhrUdcS6sy3");
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketsbyauthor keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    firstPacket = r.get_array().front().get_obj();
    BOOST_CHECK_EQUAL(find_value(firstPacket, "priority").get_int(), 50);

    // Packet by dev key
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1400788640,\"author\":[[\"keyID\",\"147cQZJ7Bd4ErnVYZahLfCaecJVkJVvqBP\"]],\"recipient\":[[\"keyID\",\"1Chdftd6Q9AbCih329udiYMNW46wpmS2nG\"]],\"type\":\"review\",\"comment\":\"test\",\"rating\":0,\"maxRating\":10,\"minRating\":-10},\"signature\":{\"pubKey\":\"PqxqDCkJ8h3Gj1ZqJp8qeWrrZGe5FuruJqj4YfBGj5BhUcSmphsuUWUc5eyoAwqP7N2WY7KAhpMtLuwCEiEbcEHV\",\"signature\":\"381yXZRZqUEtMPKFyzcTDJBsUgdMPvijTauLHK69jtZDVtAvGfKzeMfJjh5YdDKZcoLMHQQ7w3kL4JFipujc8EDE9kuJXoha\"}}"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpacketbyhash 1otjE8Sk6dFtax9V3f7jLceYxJXHJ7yFLd1btLuf82F"));
    firstPacket = r.get_array().front().get_obj();
    BOOST_CHECK_EQUAL(find_value(firstPacket, "priority").get_int(), 50);

    BOOST_CHECK_NO_THROW(r=CallRPC("gettruststep p1 nobody1 p2 nobody2"));
    BOOST_CHECK(r.get_str().empty());
    BOOST_CHECK_NO_THROW(r=CallRPC("gettruststep keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr"));
    BOOST_CHECK(!r.get_str().empty());
    
    BOOST_CHECK_NO_THROW(r=CallRPC("getsavedpath p1 nobody1 p2 nobody2"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 0);
    BOOST_CHECK_NO_THROW(r=CallRPC("getsavedpath keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As keyID 1CevLPhmqURncVPniRtGVAFzu4dM6KMwRr"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As email james@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email james@example.com keyID 1Jzbz2SsqnFpSrADASRywQEwZGZEY6y3As"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 0);

    BOOST_CHECK_NO_THROW(r=CallRPC("getpath p1 nobody1 p2 nobody2"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 0);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email alice@example.com email bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 1);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email alice@example.com email carl@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 2);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email alice@example.com email david@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 3);
    BOOST_CHECK_NO_THROW(r=CallRPC("saveconnection email james@example.com email david@example.com url http://example.com/david"));
    BOOST_CHECK_NO_THROW(r=CallRPC("saveconnection email james@example.com url http://example.com/david account user@bitcoin-otc.com"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email alice@example.com account user@bitcoin-otc.com 5"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 5);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email alice@example.com account user@bitcoin-otc.com 5"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 5);

    // Trust path should be one-way
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email david@example.com email emil@example.com pos 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacket email emil@example.com email fred@example.com pos 1"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email emil@example.com email david@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 0);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email fred@example.com email david@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 0);
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath email fred@example.com email bob@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 0);

    int i = CallRPC("getpacketcount").get_int();
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1,\"author\":[[\"mbox\",\"mailto:alice@example.com\"]],\"recipient\":[[\"mbox\",\"mailto:dick@example.com\"]],\"type\":\"review\",\"comment\":\"thanks\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}} false false"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getpath mbox mailto:alice@example.com mbox mailto:dick@example.com"));
    BOOST_CHECK_EQUAL(r.get_array().size(), 0);
    BOOST_CHECK_EQUAL(CallRPC("getpacketcount").get_int(), i);
}

BOOST_AUTO_TEST_CASE(link_confs_and_refutes)
{
    resetDB();
    Value r;
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1234567,\"author\":[[\"email\",\"alice@example.com\"],[\"profile\",\"http://www.example.com/alice\"]],\"recipient\":[[\"email\",\"bob@example.com\"],[\"nickname\",\"BobTheBuilder\"]],\"type\":\"confirm_connection\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1234568,\"author\":[[\"email\",\"alice@example.com\"],[\"profile\",\"http://www.example.com/alice\"]],\"recipient\":[[\"email\",\"bob@example.com\"],[\"nickname\",\"BobTheBuilder\"]],\"type\":\"confirm_connection\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1234567,\"author\":[[\"email\",\"john@example.com\"]],\"recipient\":[[\"email\",\"bob@example.com\"],[\"nickname\",\"BobTheBuilder\"]],\"type\":\"confirm_connection\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1234567,\"author\":[[\"email\",\"james@example.com\"]],\"recipient\":[[\"email\",\"bob@example.com\"],[\"nickname\",\"BobTheBuilder\"]],\"type\":\"refute_connection\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"));
    BOOST_CHECK_NO_THROW(r=CallRPC("savepacketfromdata {\"signedData\":{\"timestamp\":1234567,\"author\":[[\"email\",\"james@example.com\"]],\"recipient\":[[\"email\",\"bob@example.com\"],[\"nickname\",\"BobTheBuilder\"]],\"type\":\"refute_connection\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"));
    BOOST_CHECK_NO_THROW(r=CallRPC("getconnections email bob@example.com"));

    Array data = r.get_array();
    Object first = data.front().get_obj();
    BOOST_CHECK_EQUAL(find_value(first, "type").get_str(), "nickname");
    BOOST_CHECK_EQUAL(find_value(first, "value").get_str(), "BobTheBuilder");
    BOOST_CHECK_EQUAL(find_value(first, "confirmations").get_int(), 2);
    BOOST_CHECK_EQUAL(find_value(first, "refutations").get_int(), 1);

    BOOST_CHECK_NO_THROW(r=CallRPC("getconnectingpackets email bob@example.com nickname BobTheBuilder"));
    BOOST_CHECK(!r.get_array().empty()); 

    BOOST_CHECK_NO_THROW(r=CallRPC("getconnectingpackets email bob@example.com nickname BobTheBuilder 20 0 email alice@example.com 3 review"));
}

BOOST_AUTO_TEST_CASE(canonical_json)
{
    resetDB();
    Value r;
    // No whitespace
    BOOST_CHECK_THROW(r=CallRPC("savepacketfromdata {\"signedData\": {\"timestamp\":1234567,\"author\":[[\"email\",\"alice@example.com\"],[\"profile\",\"http://www.example.com/alice\"]],\"recipient\":[[\"email\",\"bob@example.com\"],[\"nickname\",\"BobTheBuilder\"]],\"type\":\"confirm_connection\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"), runtime_error);
    // No line breaks
    BOOST_CHECK_THROW(r=CallRPC("savepacketfromdata {\"signedData\": \n{\"timestamp\":1234567,\"author\":[[\"email\",\"alice@example.com\"],[\"profile\",\"http://www.example.com/alice\"]],\"recipient\":[[\"email\",\"bob@example.com\"],[\"nickname\",\"BobTheBuilder\"]],\"type\":\"confirm_connection\",\"rating\":100,\"minRating\":-100,\"maxRating\":100},\"signature\":{}}"), runtime_error);
}

BOOST_AUTO_TEST_CASE(savepacket_performance)
{
    resetDB();
    Value r;
    const char* rpcFormat = "savepacket mbox mailto:alice@example.com mbox mailto:bob@example.com %i 1";
    
    const int PACKET_COUNT = 5000;

    clock_t begin = clock();
    for (int i = 1; i <= PACKET_COUNT; i++) {
        char rpc[100];
        sprintf(rpc, rpcFormat, i);
        CallRPC(rpc);
        if (i % 200 == 0) {
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
