//
//  GUNetDef.h
//

#ifndef MyGoUDome_GUNetDef_h
#define MyGoUDome_GUNetDef_h


#define NET_Header_ID (0x7F)
#define NET_Header_VER (0x01)

#define NET_MAX_PACKET_SIZE (4096)
#define NET_NETWORK_PUBLIC (0) // 是否为公网环境


#if NET_NETWORK_PUBLIC
# define NET_AUTHSERVER_ADDR "s1.goyou.cn"
# define NET_AUTHSERVER_PORT (33880)
#else
# define NET_AUTHSERVER_ADDR "192.168.108.181"
# define NET_AUTHSERVER_PORT (33880)
#endif

#define NET_TOKEN_SIZE (16)
#define NET_UUID_SIZE (16)



typedef unsigned char UInt8;

// 数据头
typedef struct {
    UInt8 head4[4]; // index 0: NET_Header_ID; index 1: NET_Header_VER; 2:插件号 ;3:命令字
    int dataLen;
}t_net_header;

#define kMyGoUNetworkErrorDomain @"MyGoUNetworkErrorDomain"

// 通信错误码定义
#define SUCCESS 0

// socket 相关错误码
#define INVALID_SOCKET (~0)

#define NET_SOCKET_ERROR -1
#define NET_CONNNECT_TIMEOUT -100
#define NET_RECV_TIMEOUT -200
#define NET_COMMUNICATOR_ERROR -500

#endif
