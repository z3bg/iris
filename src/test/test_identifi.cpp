#define BOOST_TEST_MODULE Identifi Test Suite
#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>

#include "ui_interface.h"
#include "main.h"
#include "util.h"

CClientUIInterface uiInterface;

extern bool fPrintToConsole;
extern void noui_connect();

struct TestingSetup {
    boost::filesystem::path pathTemp;
    boost::thread_group threadGroup;

    TestingSetup() {
        fPrintToDebugger = true; // don't want to write to debug.log file
        noui_connect();
        pathTemp = GetTempPath() / strprintf("test_identifi_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
        boost::filesystem::create_directories(pathTemp);
        mapArgs["-datadir"] = pathTemp.string();
        pidentifidb = new CIdentifiDB();
    }
    ~TestingSetup()
    {
        threadGroup.interrupt_all();
        threadGroup.join_all();
        boost::filesystem::remove_all(pathTemp);
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

void Shutdown(void* parg)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}

