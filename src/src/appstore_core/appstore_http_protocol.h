#ifndef APPSTORE_CORE_APPSTORE_HTTP_PROTOCOL_H_
#define APPSTORE_CORE_APPSTORE_HTTP_PROTOCOL_H_

#include <string>
#include "appstore_core/dllexport.h"

namespace AppstoreCore{
	class AppstoreHTTPProtocol {
	public:
		AppstoreHTTPProtocol();
		~AppstoreHTTPProtocol();
		void reset_common_headers();
		void set_content_type(const wchar_t* default_plist);
		void set_x_apple_actionsignature(const wchar_t* x_apple_actionsignature);
		void set_cookies(const wchar_t* cookies);
	private:
		std::wstring common_headers_;
		std::wstring content_type_;
		std::wstring x_apple_actionsignature_;
		std::wstring cookies_;
	};
}

#endif