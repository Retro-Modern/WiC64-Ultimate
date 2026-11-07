/* Exact local Control Center asset admission; no network or C64 mutation.
 * GPL-3.0-or-later. The service copies accepted bytes before this owner dies.
 */
#ifndef P18_CONTROL_CENTER_H
#define P18_CONTROL_CENTER_H
#include "filemanager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wolfssl/wolfcrypt/hash.h>

namespace p18cc {
static const unsigned ASSET_BYTES=22595;
static const char ASSET_NAME[]="WIC64CC.PRG";
static const uint8_t ASSET_SHA256[32]={
 0xf4,0x32,0x2e,0xca,0x46,0x9f,0x6e,0xc4,0xca,0x7b,0x8f,0x82,0xcd,0x3a,0xb2,0x9a,
 0x87,0x95,0x95,0x90,0x58,0xba,0x2b,0xe7,0x03,0xd3,0xb6,0x2b,0x52,0x18,0xc5,0x73
};
enum Result {OK,MISSING,OPEN_ERROR,READ_ERROR,INVALID_ASSET,NO_MEMORY,HASH_ERROR};
struct Image {
 uint8_t *bytes;
 Image():bytes(0){}
 ~Image(){free(bytes);}
 Image(const Image &)=delete;
 Image &operator=(const Image &)=delete;
};
struct OpenFile {
 FileManager *manager;File *file;
 explicit OpenFile(FileManager *m):manager(m),file(0){}
 ~OpenFile(){if(file)manager->fclose(file);}
};
inline Result at(FileManager *manager,const char *directory,Image &image)
{
 OpenFile opened(manager);
 FRESULT result=manager->fopen(directory,ASSET_NAME,FA_READ,&opened.file);
 if(result!=FR_OK){
  return result==FR_NO_FILE||result==FR_NO_PATH||result==FR_NOT_READY||
         result==FR_NO_FILESYSTEM||result==FR_INVALID_DRIVE?MISSING:OPEN_ERROR;
 }
 if(!opened.file)return OPEN_ERROR;
 if(opened.file->get_size()!=ASSET_BYTES)return INVALID_ASSET;
 uint8_t *bytes=static_cast<uint8_t *>(malloc(ASSET_BYTES));
 if(!bytes)return NO_MEMORY;
 struct FreeBytes {uint8_t *p;~FreeBytes(){free(p);}}owner={bytes};
 unsigned used=0;
 while(used<ASSET_BYTES){
  uint32_t got=0;unsigned wanted=ASSET_BYTES-used;
  if(opened.file->read(bytes+used,wanted,&got)!=FR_OK||!got||got>wanted)return READ_ERROR;
  used+=got;
 }
 uint8_t extra=0;uint32_t got=0;
 if(opened.file->read(&extra,1,&got)!=FR_OK)return READ_ERROR;
 if(got||bytes[0]!=1||bytes[1]!=8)return INVALID_ASSET;
 uint8_t digest[32];
 if(wc_Sha256Hash(bytes,ASSET_BYTES,digest)!=0)return HASH_ERROR;
 if(memcmp(digest,ASSET_SHA256,sizeof(digest)))return INVALID_ASSET;
 image.bytes=bytes;owner.p=0;return OK;
}
inline Result load(FileManager *manager,const char *current,Image &image)
{
 if(!manager||image.bytes)return OPEN_ERROR;
 bool open_error=false;
 if(current&&*current){
  Result result=at(manager,current,image);
  if(result!=MISSING&&result!=OPEN_ERROR)return result;
  open_error|=result==OPEN_ERROR;
  char directory[256];
  int count=snprintf(directory,sizeof(directory),"%s/WiC64",current);
  if(count>0&&unsigned(count)<sizeof(directory)){
   result=at(manager,directory,image);
   if(result!=MISSING&&result!=OPEN_ERROR)return result;
   open_error|=result==OPEN_ERROR;
  }
 }
 static const char *const locations[]={"/USB1/WiC64","/SD/WiC64","/USB2/WiC64","/USB1","/SD","/USB2"};
 for(unsigned i=0;i<sizeof(locations)/sizeof(locations[0]);++i){
  Result result=at(manager,locations[i],image);
  if(result!=MISSING&&result!=OPEN_ERROR)return result;
  open_error|=result==OPEN_ERROR;
 }
 return open_error?OPEN_ERROR:MISSING;
}
inline const char *message(Result result)
{
 switch(result){
 case MISSING:return "Control Center not found.\nCopy WIC64CC.PRG to\n/USB1/WiC64 or /SD/WiC64.";
 case OPEN_ERROR:return "Cannot open Control Center.\nCheck the storage device.";
 case READ_ERROR:return "Cannot read Control Center.\nCopy WIC64CC.PRG again.";
 case INVALID_ASSET:return "Control Center file does not match.\nUse WIC64CC.PRG from this package.";
 case NO_MEMORY:return "Not enough memory for\nControl Center.";
 case HASH_ERROR:return "Control Center verification failed.";
 default:return "Control Center ready.";
 }
}
}
#endif
