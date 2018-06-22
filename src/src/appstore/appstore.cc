#include <cstdio>
#include "appstore_core/appstore_core_main.h"
#pragma comment(lib,"appstore_core.lib")

int wmain(int argc, wchar_t* argv[]){
	AppstoreCore::AppstoreCoreMain* appstore = new AppstoreCore::AppstoreCoreMain;
	appstore->SendAuthenticate("m", "");
	appstore->SendBuy("");
	return 0;
}

