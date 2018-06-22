#include "appstore_core/appstore_core_main.h"
#include "win_itunes/itunes_client_interface.h"
#include "win_itunes/windows_hardware.h"
#include "win_itunes/itunes_download_info.h"

namespace AppstoreCore{
	win_itunes::communicates *communicates = win_itunes::communicates::singleton();
	AppstoreCoreMain::AppstoreCoreMain(){
		communicates->ResetSapSetup(true);
		return;
	}
	bool AppstoreCoreMain::SendAuthenticate(const char* username, const char* password){
		win_itunes::HardwareInfo hardware;
		//"DengTao", "128dba73ccf589225c29ad2c623da34f5521b1bd"
		return communicates->Authenticate(username, password, hardware.GetMachineName().c_str(), hardware.cookie().c_str());
	}
	bool AppstoreCoreMain::SendBuy(const char* appid){
		win_itunes::HardwareInfo hardware;
		communicates->SendMessage_buyProduct(appid, hardware.GetMachineName().c_str(), hardware.cookie().c_str(), win_itunes::iTunesDownloadInfo::GetInterface(), 0, true);
		return true;
	}
}