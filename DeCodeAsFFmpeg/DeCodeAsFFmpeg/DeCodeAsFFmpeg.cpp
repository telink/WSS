// DeCodeAsFFmpeg.cpp: 定义 DLL 应用程序的导出函数。
//
#include "stdafx.h"
#include "DeCodeAsFFmpeg.h"
#include "VideoSource.h"
#define CKNOERR 0

static VideoSource *airplayvs;
static CKVideoCallbackResult videoCallback;
static CKAudioCallbackResult audioCallback;

//视频开始
void videoBegin(int width, int height, const void *buffer, int buflen, int payloadtype, double timestamp)
{
	printf("%s", __FUNCTION__);
	if (videoCallback) {
		videoCallback(CKAirplayState_MirrorVideoStart, width, height, (unsigned char*)buffer, buflen, payloadtype, timestamp);
	}
}

//视频数据传输过程中
void videoFlushing(int width, int height, const void *buffer, int buflen, int payloadtype, double timestamp)
{
	printf("%s", __FUNCTION__);
	if (videoCallback){
		videoCallback(CKAirplayState_MirrorVideoProcessing, width, height, (unsigned char*)buffer, buflen, payloadtype, timestamp);
	}

}

//视频流被关闭
void videoStopped()
{
	printf("%s", __FUNCTION__);
	if (videoCallback)
	{
		videoCallback(CKAirplayState_MirrorVideoStop, 0, 0, NULL, 0, 0, 0.f);
	}
}
//typedef void(__stdcall* CKAudioCallbackResult)(CKAirplayState state, int bits, int channels, int samplerate, int isaudio, const void *buffer, int buflen, double timestamp, uint32_t seqnum);

//音频开始
void audioBegin(int bits, int channels, int samplerate, int isaudio)
{
	printf("%s", __FUNCTION__);
	if (audioCallback)
	{
		//CKAirplayState state, int bits, int channels, int samplerate, int isaudio, unsigned char *buffer, int buflen, double timestamp, int seqnum
		audioCallback(CKAirplayState_MirrorAudioStart, bits, channels, samplerate, isaudio, NULL, 0, 0.f, 0);
	}
}

//音频数据传输过程中
void audioFlushing(const void *buffer, int buflen, double timestamp, uint32_t seqnum)
{
	printf("%s", __FUNCTION__);
	if (audioCallback)
	{
		//CKAirplayState state, int bits, int channels, int samplerate, int isaudio, unsigned char *buffer, int buflen, double timestamp, int seqnum
		audioCallback(CKAirplayState_MirrorAudioProcessing, 0, 0, 0, 1, (unsigned char*)buffer, buflen, timestamp, seqnum);
	}
}

///音频流被关闭
void audioStopped()
{
	printf("%s", __FUNCTION__);
	if (audioCallback)
	{
		//CKAirplayState state, int bits, int channels, int samplerate, int isaudio, unsigned char *buffer, int buflen, double timestamp, int seqnum
		audioCallback(CKAirplayState_MirrorAudioStop, 0, 0, 0, 1, NULL, 0, 0.f, 0);
	}
}


void StartAirplayService(const char* hostname, CKVideoCallbackResult vcback, CKAudioCallbackResult acback)
{

	videoCallback = vcback;
	//audioCallback = acback;

	airplayvs = new VideoSource();
	strcpy(airplayvs->myhostname, hostname);
	

	airplayvs->mirrorvideoplaybegin(videoBegin);
	airplayvs->mirrorvideoplaying(videoFlushing);
	airplayvs->mirrorvideoplaystop(videoStopped);

	airplayvs->mirroraudioplaybegin(audioBegin);
	airplayvs->mirroraudioplaying(audioFlushing);
	airplayvs->mirroraudioplaystop(audioStopped);

	if (airplayvs->start_airplay() != CKNOERR)
	{
		videoCallback(CKAirplayState_MirrorMediaInitaialErr, 0, 0, NULL, 0, 0, 0.f);
		audioCallback(CKAirplayState_MirrorMediaInitaialErr, 0, 0, 0, 1, NULL, 0, 0.f, 0);
	}
}


void StopAirplayService()
{
	airplayvs->stop_airplay();
	//videoCallback = NULL;
	//audioCallback = NULL;
}
