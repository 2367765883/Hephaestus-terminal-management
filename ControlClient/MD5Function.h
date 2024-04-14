#pragma once

#include <iostream>
using namespace  std;
typedef unsigned int int_32;

typedef unsigned char md5byte;
typedef int_32 UWORD32;

struct MD5Context {//*MD5结构
	UWORD32 buf[4];
	UWORD32 bytes[2];
	UWORD32 in[16];
};

//--internal
static void MD5Init(struct MD5Context* context);//* 初始化MD5结构
static void MD5Update(struct MD5Context* context, md5byte const* buf, unsigned len); //* 加入要计算MD5的数据
static void MD5Final(struct MD5Context* context, unsigned char digest[16]); //* 生成最终MD5值
static void MD5Transform(UWORD32 buf[4], UWORD32 const in[16]);
static void byteSwap(UWORD32* buf, unsigned words); //* 数字转换
string EncodeByMd5(string data);
//.end internal

//* 计算并返回data对应的MD5 - 16进制字符
std::string GetDataMD5(const std::string data);
