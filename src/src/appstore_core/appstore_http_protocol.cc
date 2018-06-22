#include "appstore_core/appstore_http_protocol.h"

namespace AppstoreCore{
	AppstoreHTTPProtocol::AppstoreHTTPProtocol(){
		common_headers_.resize(0);
		content_type_.resize(0);
		set_x_apple_actionsignature(nullptr);
		set_cookies(nullptr);
	}
	AppstoreHTTPProtocol::~AppstoreHTTPProtocol(){
		common_headers_.resize(0);
		content_type_.resize(0);
		set_x_apple_actionsignature(nullptr);
		set_cookies(nullptr);
	}
	void AppstoreHTTPProtocol::reset_common_headers(){
		common_headers_.resize(0);
		common_headers_.append(L"X-Apple-Client-Versions: GameCenter/2.0\r\n");
		common_headers_.append(L"Accept: */*\r\n");
		common_headers_.append(L"X-Apple-Store-Front: 143465-19,26\r\n");
		common_headers_.append(L"X-Apple-Partner: origin.0\r\n");
		common_headers_.append(L"Accept-Encoding: gzip, deflate\r\n");
		common_headers_.append(L"Accept-Language: zh-Hans\r\n");
		common_headers_.append(L"User-Agent: com.apple.Preferences/1 iOS/8.1.2 model/iPhone6,1 build/12B440 (6; dt:89)\r\n");
		common_headers_.append(L"X-Apple-Connection-Type: WiFi\r\n");
		common_headers_.append(L"Connection: keep-alive\r\n");
	}
	void AppstoreHTTPProtocol::set_content_type(const wchar_t* default_plist){
		content_type_.resize(0);
		if (default_plist == nullptr)
			content_type_.append(L"Content-Type: application/x-apple-plist\r\n");
		else{
			content_type_.append(L"Content-Type: ");
			content_type_.append(default_plist);
			content_type_.append(L"\r\n");
		}
	}
	void AppstoreHTTPProtocol::set_x_apple_actionsignature(const wchar_t* x_apple_actionsignature){
		x_apple_actionsignature_.resize(0);
		if (x_apple_actionsignature != nullptr){
			x_apple_actionsignature_.append(L"X-Apple-ActionSignature: ");
			x_apple_actionsignature_.append(x_apple_actionsignature);
			x_apple_actionsignature_.append(L"\r\n");
		}
	}
	void AppstoreHTTPProtocol::set_cookies(const wchar_t* cookies){
		cookies_.resize(0);
		if (cookies != nullptr){
			cookies_.append(L"Cookie: ");
			cookies_.append(cookies);
			cookies_.append(L"\r\n");
		}
	}
}
