#include <jni.h>
#include <string>
#include"valid.cpp"
#include "MD5.h"
#include "assert.h"
#include "uninstall.c"
#include "DES.c"
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
/*
#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO , TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN , TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR , TAG, __VA_ARGS__)
 */
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN , TAG, __VA_ARGS__)
extern "C"
JNIEXPORT jstring JNICALL
Java_com_ushaqi_zhuishushenqi_signture_getSignaturesSha1(
        JNIEnv *env,
        jobject,
        jobject contextObject) {

    return env->NewStringUTF(app_sha1);
}
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ushaqi_zhuishushenqi_signture_checkSha1(
        JNIEnv *env,
        jobject,
        jobject contextObject) {

    char *sha1 = getSha1(env, contextObject);

    jboolean result = checkValidity(env, sha1);

    return result;
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_ushaqi_zhuishushenqi_signture_getToken(
        JNIEnv *env,
        jobject,
        jobject contextObject,
        jstring userId) {
    char *sha1 = getSha1(env, contextObject);
    jboolean result = checkValidity(env, sha1);

    if (result) {
        return env->NewStringUTF("获取Token成功");
    } else {
        return env->NewStringUTF("获取失败，请检查valid.cpp文件配置的sha1值");
    }
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_ushaqi_zhuishushenqi_signture_getMd5(
        JNIEnv *env,
        jobject,
        jstring strText
) {
    /*
    int i;
    unsigned char encrypt[] = "admin";//21232f297a57a5a743894a0e4a801fc3
    unsigned char decrypt[16];

    MD5_CTX md5;

    MD5Init(&md5);
    MD5Update(&md5, encrypt, strlen((char *)encrypt));
    MD5Final(&md5, decrypt);

    //Md5加密后的32位结果
    printf("加密前:%s\n加密后16位:", encrypt);
    for (i = 4; i<12; i++)
    {
        printf("%02x", decrypt[i]);
    }

    //Md5加密后的32位结果
    printf("\n加密前:%s\n加密后32位:", encrypt);
    for (i = 0; i<16; i++)
    {
        printf("%02x", decrypt[i]);
    }

    getchar();
*/
    char *szText = (char *) env->GetStringUTFChars(strText, 0);

    MD5_CTX context = {0};
    MD5Init(&context);
    MD5Update(&context, (unsigned char *) szText, strlen(szText));
    unsigned char dest[16] = {0};
    MD5Final(&context, dest);
    env->ReleaseStringUTFChars(strText, szText);

    int i = 0;
    char szMd5[32] = {0};
    for (i = 0; i < 16; i++) {
        sprintf(szMd5, "%s%02x", szMd5, dest[i]);
    }

    return env->NewStringUTF(szMd5);
}
/*
* Set some test stuff up.
*
* Returns the JNI version on success, -1 on failure.
*/
extern "C"
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = NULL;
    jint result = -1;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    assert(env != NULL);
    jclass activityThread = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    //获取Application，也就是全局的Context
    jmethodID getApplication = env->GetMethodID(activityThread, "getApplication", "()Landroid/app/Application;");
    jobject context = env->CallObjectMethod(at, getApplication);
    char *sha1 = getSha1(env, context);
    if (!checkValidity(env, sha1)) {
        return JNI_VERSION_1_4;
    }
    else{
        return JNI_ERR;
    }
    /* success -- return valid version number */
    result = JNI_VERSION_1_4;

    return result;
}

extern "C"
JNIEXPORT int Java_com_ushaqi_zhuishushenqi_signture_httpConnect(JNIEnv *env, jobject thiz,
                                                                       jstring method,
                                                                       jstring host,
                                                                       jstring httppath, jstring cs,
                                                                       jint port) {

    const char *cpath = env->GetStringUTFChars(httppath, JNI_FALSE);
    const char *chost = env->GetStringUTFChars(host, JNI_FALSE);
    const char *para = env->GetStringUTFChars(cs, JNI_FALSE);
    const char *cmethod = env->GetStringUTFChars(method, JNI_FALSE);
    paraStruct *data = (paraStruct *) malloc(sizeof(paraStruct));
    data->cpath = (char *)cpath;
    data->chost =(char *)chost;
    data->para = (char *)para;
    data->cport = port;
    data->method = (char *)cmethod;
    return httpRequester(data);
}
extern "C"
JNIEXPORT int Java_com_ushaqi_zhuishushenqi_signture_uninstall(JNIEnv *env, jobject thiz,
                                                               jarray path,
                                                               jstring httppath, jstring cs,
                                                               jstring host, jint port) {
    ++start_count;
    if(start_count>2){//为什么会设置大于2不是1 我测试下来至少为2才会执行
        return 0;//说明已经执行过了监控代码
    }else{
        const char *watch_path = env->GetStringUTFChars((jstring) path, NULL);
        const char *cpath = env->GetStringUTFChars(httppath, JNI_FALSE);
        const char *chost = env->GetStringUTFChars(host, JNI_FALSE);
        const char *para = env->GetStringUTFChars(cs, JNI_FALSE);
        return commonJavaSegment(watch_path, cpath, chost, para, port);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_ushaqi_zhuishushenqi_signture_readFromAssets(JNIEnv *env, jclass type,
                                                      jobject assetManager, jstring filename_)
{
    LOGI("ReadAssets");
    AAssetManager* mgr = AAssetManager_fromJava(env, assetManager);
    if(mgr==NULL)
    {
        //LOGI(" %s","AAssetManager==NULL");
        return ;
    }
    jboolean iscopy;
    const char *mfile = env->GetStringUTFChars(filename_, &iscopy);
    AAsset* asset = AAssetManager_open(mgr, mfile,AASSET_MODE_UNKNOWN);
    env->ReleaseStringUTFChars(filename_, mfile);
    if(asset==NULL)
    {
        //LOGI(" %s","asset==NULL");
        return ;
    }
    off_t bufferSize = AAsset_getLength(asset);
    //LOGI("file size : %d\n",bufferSize);
    char *buffer=(char *)malloc(bufferSize+1);
    buffer[bufferSize]=0;
    int numBytesRead = AAsset_read(asset, buffer, bufferSize);
    //LOGI(": %s",buffer);
    LOGW(">>>>>>>>>>>>>>>>>>>assets=%s", buffer);
    LOGW(">>>>>>>>>>>>>>>>>>>assets=%d", numBytesRead);
    free(buffer);
    AAsset_close(asset);
}