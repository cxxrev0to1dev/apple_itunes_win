#ifndef APPSTORE_CORE_APPSTORE_CORE_MAIN_H_
#define APPSTORE_CORE_APPSTORE_CORE_MAIN_H_

#include "appstore_core/dllexport.h"

namespace AppstoreCore{
	class AppstoreCoreMain {
	public:
		APPSTORE_CORE_API AppstoreCoreMain(void);
		APPSTORE_CORE_API bool SendAuthenticate(const char* username, const char* password);
		APPSTORE_CORE_API bool SendBuy(const char* appid);
	};
}

#endif