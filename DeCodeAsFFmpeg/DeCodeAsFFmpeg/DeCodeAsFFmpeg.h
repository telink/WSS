#pragma once
#define EXPORT_API extern "C" _declspec(dllexport)		// ������ʶdll���������ǰ׺����
// for int64_t print using PRId64 format.
#ifndef __STDC_FORMAT_MACROS   
#define __STDC_FORMAT_MACROS
#endif// for cpp to use c-style macro UINT64_C in libavformat
#ifndef __STDC_CONSTANT_MACROS   
#define __STDC_CONSTANT_MACROS
#endif
#if _MSC_VER
//#define snprintf _snprintf
#if defined(_MSC_VER) && _MSC_VER<1900
#  define snprintf _snprintf
#endif
#endif

typedef enum CKAirplayState
{
	CKAirplayState_MirrorVideoStart = 0X01,    //������Ƶ���ݿ���
	CKAirplayState_MirrorVideoProcessing,      //������Ƶ���ݴ�����
	CKAirplayState_MirrorVideoStop,            //������Ƶ���ݹر�
	CKAirplayState_MirrorAudioStart,           //������Ƶ���ݿ���
	CKAirplayState_MirrorAudioProcessing,      //������Ƶ���ݴ�����
	CKAirplayState_MirrorAudioStop,            //������Ƶ���ݹر�
	CKAirplayState_MirrorMediaInitaialErr,     //airplay��ʼ��ʧ��               
}state;


typedef void(__stdcall* CKVideoCallbackResult)(CKAirplayState state, int width, int height, unsigned char *buffer, int buflen, int payloadtype, double timestamp);
typedef void(__stdcall* CKAudioCallbackResult)(CKAirplayState state, int bits, int channels, int samplerate, int isaudio, unsigned char *buffer, int buflen, double timestamp, int seqnum);

//״̬���ݼ����ص�

EXPORT_API void StartAirplayService(const char* hostname, CKVideoCallbackResult vcback, CKAudioCallbackResult acback);

EXPORT_API void StopAirplayService();




