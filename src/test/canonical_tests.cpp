//
// Unit tests for canonical signatures

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"
#include <iostream>
#include <fstream>
#include <boost/test/unit_test.hpp>
#include <openssl/ecdsa.h>

#include "key.h"
#include "script.h"
#include "util.h"

using namespace std;
using namespace json_spirit;


Array
read_json(const std::string& filename)
{
    namespace fs = boost::filesystem;
    fs::path testFile = fs::current_path() / "test" / "data" / filename;

#ifdef TEST_DATA_DIR
    if (!fs::exists(testFile))
    {
        testFile = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
    }
#endif

    ifstream ifs(testFile.string().c_str(), ifstream::in);
    Value v;
    if (!read_stream(ifs, v))
    {
        if (ifs.fail())
            BOOST_ERROR("Cound not find/open " << filename);
        else
            BOOST_ERROR("JSON syntax error in " << filename);
        return Array();
    }
    if (v.type() != array_type)
    {
        BOOST_ERROR(filename << " does not contain a json array");
        return Array();
    }

    return v.get_array();
}

BOOST_AUTO_TEST_SUITE(canonical_tests)

// OpenSSL-based test for canonical signature (without test for hashtype byte)
bool static IsCanonicalSignature_OpenSSL_inner(const std::vector<unsigned char>& vchSig)
{
    if (vchSig.size() == 0)
        return false;
    const unsigned char *input = &vchSig[0];
    ECDSA_SIG *psig = NULL;
    d2i_ECDSA_SIG(&psig, &input, vchSig.size());
    if (psig == NULL)
        return false;
    unsigned char buf[256];
    unsigned char *pbuf = buf;
    unsigned int nLen = i2d_ECDSA_SIG(psig, NULL);
    if (nLen != vchSig.size()) {
        ECDSA_SIG_free(psig);
        return false;
    }
    nLen = i2d_ECDSA_SIG(psig, &pbuf);
    ECDSA_SIG_free(psig);
    return (memcmp(&vchSig[0], &buf[0], nLen) == 0);
}

// OpenSSL-based test for canonical signature
bool static IsCanonicalSignature_OpenSSL(const std::vector<unsigned char> &vchSignature) {
    if (vchSignature.size() < 1)
        return false;
    if (vchSignature.size() > 127)
        return false;
    if (vchSignature[vchSignature.size() - 1] & 0x7C)
        return false;

    std::vector<unsigned char> vchSig(vchSignature);
    vchSig.pop_back();
    if (!IsCanonicalSignature_OpenSSL_inner(vchSig))
        return false;
    return true;
}

BOOST_AUTO_TEST_CASE(script_canon)
{
    Array tests = read_json("sig_canonical.json");

    BOOST_FOREACH(Value &tv, tests) {
        string test = tv.get_str();
        if (IsHex(test)) {
            std::vector<unsigned char> sig = ParseHex(test);
            BOOST_CHECK_MESSAGE(IsCanonicalSignature(sig), test);
            BOOST_CHECK_MESSAGE(IsCanonicalSignature_OpenSSL(sig), test);
        }
    }
}

BOOST_AUTO_TEST_CASE(script_noncanon)
{
    Array tests = read_json("sig_noncanonical.json");

    BOOST_FOREACH(Value &tv, tests) {
        string test = tv.get_str();
        if (IsHex(test)) {
            std::vector<unsigned char> sig = ParseHex(test);
            BOOST_CHECK_MESSAGE(!IsCanonicalSignature(sig), test);
            BOOST_CHECK_MESSAGE(!IsCanonicalSignature_OpenSSL(sig), test);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
