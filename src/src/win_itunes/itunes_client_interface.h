#ifndef WIN_ITUNES_ITUNES_CLIENT_INTERFACE_H_
#define WIN_ITUNES_ITUNES_CLIENT_INTERFACE_H_
//////////////////////////////////////////////////////////////////////////
#include <cstdint>
#include "appstore_core/basictypes.h"
#include "win_itunes/itunes_download_info.h"
//////////////////////////////////////////////////////////////////////////
namespace win_itunes{
	namespace internal{
		unsigned long GetKbSyncId();
		std::string GetLoginText(const std::string& apple_id,const std::string& password);
		std::string GetKeyValue(const std::string& key,const std::string h_table);
		class GenerateAuthenticateOsGUID
		{
		public:
			explicit GenerateAuthenticateOsGUID(){
				char buffer[MAX_PATH] = {0};
				DWORD buf_len = MAX_PATH;
				GetComputerNameA(buffer,&buf_len);
				machine_name_ = buffer;
				machine_guid_ = "8EFFF7FD.86E7195C.00000000.39CF53B5.2350EAA0.C3A8E888.7FAFF8CE";
			}
			std::string machine_name() const{
				//test:2015/3/19
				//return "WIN-4GI25B3ETJE";
				return machine_name_;
			}
			std::string machine_guid() const{
				//test:2015/3/19
				//return "8EFFF7FD.86E7195C.00000000.39CF53B5.2350EAA0.C3A8E888.7FAFF8CE";
				return machine_guid_;
			}
		private:
			std::string machine_name_;
			std::string machine_guid_;
			DISALLOW_EVIL_CONSTRUCTORS(GenerateAuthenticateOsGUID);
		};
		class KbSyncIdParameter
		{
		public:
			static void Initialize();
			static DWORD GetKbsyncIDAddress();
			static const char* AllPCMd5();
			static const char* LocalPCMd5();
		};
	}
	class communicates
	{
	public:
		static communicates* singleton();
		void ResetSapSetup(bool x_act_sig);
		bool ConsolePrint(const char* file, const char* os_name = NULL, const char* os_guid = NULL);
		bool Authenticate(const char* username,const char* password,const char* os_name,const char* os_guid);
		bool SendMessage_pendingSongs(const char* os_name, const char* os_guid);
		bool SendMessageLookupPurchasesAppIdList();
		bool SendMessageLookupPurchasesAppInfo(const char* app_id);
		bool SendMessage_buyProduct(const char* product_id, const char* os_name, const char* os_guid, iTunesDownloadInfo* download_info, const int try_count = 1, bool expense = false);
		bool SongDownloadDone(const char* product_id, const char* hardware_cookie_guid, iTunesDownloadInfo* download_info);
	private:
		void SapSessionInitialize();
		void SapSetupInitialize(bool x_act_sig_flag);
		communicates(void);
		~communicates(void);
		DISALLOW_EVIL_CONSTRUCTORS(communicates);
	};
	class CalcCallback
	{
	public:
		CalcCallback();
		~CalcCallback();
		void Initialize();
		bool SapSetupInitialize(const int x_aa_sig,const char* sign_cert,char* buffer,size_t length);
		bool CalcXAppleActionSignature(char* buffer,size_t length);
		bool CalcXAppleActionSignature(const char* x_aa_sig,const size_t length);
		bool CalcXAppleActionSignature(const char* x_aa_sig,const size_t x_aa_sig_length,char* buffer,size_t length);
	private:
		DISALLOW_EVIL_CONSTRUCTORS(CalcCallback);
	};
}
//////////////////////////////////////////////////////////////////////////
#endif
