#ifndef P08_DISPATCH_H
#define P08_DISPATCH_H
#include <stdint.h>
#include <string.h>
#include "p18_version.h"
namespace p08 {
enum { NEEDS_BACKEND=0xfe };
inline uint8_t dispatch_local(uint8_t command,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t &response_length)
{
 response_length=0;if(length>8192)return 2;
 if(command==0xfe){if(length)memcpy(response,request,length);response_length=length;return 0;}
 if(command==0x00||command==0x26){
  if(length)return 2;
  static const uint8_t version[]=P18_WIRE_VERSION;
  static const uint8_t numbers[]={P18_WIC64_MAJOR,P18_WIC64_MINOR,P18_WIC64_PATCH,P18_WIC64_REVISION};
  const uint8_t *p=command?numbers:version;response_length=command?sizeof(numbers):sizeof(version);
  memcpy(response,p,response_length);return 0;
 }
 return NEEDS_BACKEND;
}
}
#endif
