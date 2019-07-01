#pragma once
#define EXPORT_API extern "C" _declspec(dllexport)		// 用来标识dll输出函数的前缀类型
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
	CKAirplayState_MirrorVideoStart = 0X01,    //镜像视频数据开启
	CKAirplayState_MirrorVideoProcessing,      //镜像视频数据传输中
	CKAirplayState_MirrorVideoStop,            //镜像视频数据关闭
	CKAirplayState_MirrorAudioStart,           //镜像音频数据开启
	CKAirplayState_MirrorAudioProcessing,      //镜像音频数据传输中
	CKAirplayState_MirrorAudioStop,            //镜像音频数据关闭
	CKAirplayState_MirrorMediaInitaialErr,     //airplay初始化失败               
}state;


typedef void(__stdcall* CKVideoCallbackResult)(CKAirplayState state, int width, int height, unsigned char *buffer, int buflen, int payloadtype, double timestamp);
typedef void(__stdcall* CKAudioCallbackResult)(CKAirplayState state, int bits, int channels, int samplerate, int isaudio, unsigned char *buffer, int buflen, double timestamp, int seqnum);

//状态数据监听回调

EXPORT_API void StartAirplayService(const char* hostname, CKVideoCallbackResult vcback, CKAudioCallbackResult acback);

EXPORT_API void StopAirplayService();




