// uninstall.c
// Created by Fred on 16/4/19.
//
// email:gsiner@live.com


#include <stdio.h>
#include <string.h>
#include <jni.h>
#include <android/log.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/inotify.h>
#include <stdlib.h>


#include <stdbool.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "GUNetDef.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "fred", __VA_ARGS__)

static char c_TAG[] = "onEvent";

#define BUFFER_SIZE 2

/**
 * 感谢大风提供的三个发送或处理请求的方法
 * @edited fred
 */

int Connect(int *sock, const char *address, unsigned short port) {
    int _sk = socket(AF_INET, SOCK_STREAM, 0);
    if (_sk == INVALID_SOCKET)
        return NET_SOCKET_ERROR;

    struct sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));

    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(address);
    sockAddr.sin_port = htons(port);

    if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *host = gethostbyname(address);
        if (host == NULL) {
            return NET_SOCKET_ERROR;
        }
        sockAddr.sin_addr.s_addr = ((struct in_addr *) host->h_addr)->s_addr;
    }
    fcntl(_sk, F_SETFL, O_NONBLOCK | fcntl(_sk, F_GETFL)); // 设置成非阻塞
    int ret = connect(_sk, (struct sockaddr *) &sockAddr, sizeof(struct sockaddr));

    fd_set fdset;
    struct timeval tmv;
    FD_ZERO(&fdset);
    FD_SET(_sk, &fdset);
    tmv.tv_sec = 15; // 设置超时时间
    tmv.tv_usec = 0;

    ret = select(_sk + 1, 0, &fdset, 0, &tmv);
    if (ret == 0) {
        return NET_CONNNECT_TIMEOUT;
    }
    else if (ret < 0) {
        return NET_SOCKET_ERROR;
    }
    int flags = fcntl(_sk, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    fcntl(_sk, F_SETFL, flags); // 设置成阻塞
    *sock = _sk;
    return SUCCESS;
}

int SendData(int _sk, const UInt8 *buffer, int bufferSize) {
    int ret = send(_sk, buffer, bufferSize, 0);
    if (ret != bufferSize)
        return NET_SOCKET_ERROR;

    return SUCCESS;
}


int DisConnect(int _sk) {
    if (_sk != INVALID_SOCKET) {
        close(_sk);
        _sk = INVALID_SOCKET;
    }
    return SUCCESS;
}

//    signal(SIGPIPE,SIG_IGN);//自己可以处理一些信号
void request(char *host, int port, char *reqHead) {

    int sk = INVALID_SOCKET;
    int ret = Connect(&sk, host, port);
    if (ret != SUCCESS)
        return;
    ret = SendData(sk, (UInt8 *)reqHead, strlen(reqHead));
    LOGI("SendData TRACE");
    if (ret != SUCCESS) {
        LOGI("send data error");
        return;
    }
    LOGI("send data success");
    DisConnect(sk);
    LOGI("DisConnect");
    //后续处理返回的数据即可 由于本功能不需要 so省略

}


typedef struct paraStruct {
    char *watch_path;
    char *cpath;
    char *chost;
    char *para;
    char *method;
    int cport;
} paraStruct;

int httpRequester(paraStruct *data) {
    char s[2048] = {0};
    LOGI("c-code::method=%s",data->method);
    if (strcmp(data->method, "POST") == 0) {
        sprintf(s,
                "POST %s HTTP/1.1\r\nHost: %s\r\nCache-Control: no-cache\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s",
                data->cpath, data->chost, strlen(data->para), data->para);
    }
    else if (strcmp(data->method, "GET") == 0) {
        sprintf(s,
                "GET %s HTTP/1.1\r\nHost: %s\r\nCache-Control: no-cache\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",
                data->cpath, data->chost);

    } else {
        return 1;
    }
    request(data->chost, data->cport, s);
    return 0;
}

void *threadBegin(void *arg) {
    paraStruct *data = (paraStruct *)arg;
    if (data) {
        int fileDescriptor = inotify_init();
        if (fileDescriptor < 0) {
            LOGI("inotify_init failed !!!");
            exit(1);
        }
        int watchDescriptor;
        watchDescriptor = inotify_add_watch(fileDescriptor,
                                            data->watch_path, IN_DELETE);
        if (watchDescriptor < 0) {
            LOGI("inotify_add_watch failed !!!");
            exit(1);
        }

        //分配缓存，以便读取event，缓存大小=一个struct inotify_event的大小，这样一次处理一个event
        void *p_buf = malloc(sizeof(struct inotify_event));
        if (p_buf == NULL) {
            LOGI("malloc failed !!!");
            exit(1);
        }
        //开始监听
        LOGI("start observer");
        //read会阻塞进程，b
        size_t readBytes = read(fileDescriptor, p_buf,
                                sizeof(struct inotify_event));

        //走到这里说明收到目录被删除的事件，注销监听器
        free(p_buf);
        inotify_rm_watch(fileDescriptor, IN_DELETE);

        //目录不存在log
        LOGI("uninstalled");
        //扩展：可以执行其他shell命令，am(即activity manager)，可以打开某程序、服务，broadcast intent，等等
        data->method="POST";
        httpRequester(data);
        exit(0);

    }
    return 0;
}

int commonJavaSegment(const char *watch_path,
                      const char *cpath, const char *chost,
                      const char *para, int port) {

    //初始化log
    LOGI("init OK");
    //fork子进程，以执行轮询任务
    pid_t pid;
    pid = fork();
    if (pid) {
        LOGI("pid=%d", pid);
    } else if (pid == 0) {
        //子进程注册目录监听器
        LOGI("child:: start");
        paraStruct *data = (paraStruct *) malloc(sizeof(paraStruct));
        data->watch_path = (char *) watch_path;
        data->cpath = (char *) cpath;
        data->chost = (char *) chost;
        data->para = (char *) para;
        data->cport = port;
        threadBegin(data);
    } else {
        //父进程直接退出，使子进程被init进程领养，以避免子进程僵死
        LOGI("fork failed !!!");
    }

    return 0;
}

static int start_count=0;//【当然也可以通过互斥锁来标记子进程是否正在运行】

//this jni method made by rec unistall event and feedback
/*
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
*/
/**
 * C语言的Http请求方法 【此方法备用】
 * @author fred
 */
/*
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
 */

