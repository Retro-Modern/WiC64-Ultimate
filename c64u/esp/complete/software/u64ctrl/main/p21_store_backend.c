/* Two independently versioned keys. Always replace the OLDER key: the newest
 * verified generation is never the key being changed. Required because the
 * pinned SDK's chunk recovery can lose the previous version of one blob key.
 * No marker key, no erase recovery, no additional partition or capacity claim. */
#include "p21_store_backend.h"
#include "nvs.h"
#include <string.h>
#include <stdbool.h>
#include <limits.h>
static bool available;
static const char *const keys[2]={"state","state_b"};
static uint8_t records[2][P21_RECORD_MAX];
static uint32_t lengths[2],crcs[2];
static uint64_t generations[2];
static void wipe(void*p,size_t n){volatile uint8_t*b=p;while(n--)*b++=0;}
void p21_backend_ready(int ready){available=ready!=0;}
int p21_backend_available(void){return available;}
enum {MISSING=0,VALID=1,CORRUPT=2,FUTURE=3,IO_ERROR=4};
static int read_slot(nvs_handle_t h,unsigned slot,int *detail){
 size_t n=0;esp_err_t err=nvs_get_blob(h,keys[slot],NULL,&n);
 if(err==ESP_ERR_NVS_NOT_FOUND)return MISSING;
 if(err!=ESP_OK){*detail=err;return IO_ERROR;}
 if(n<P21_RECORD_HEADER||n>P21_RECORD_MAX)return CORRUPT;
 size_t got=n;uint8_t*p=records[slot];err=nvs_get_blob(h,keys[slot],p,&got);
 if(err!=ESP_OK||got!=n){*detail=err;return IO_ERROR;}
 if(!memcmp(p,"WNVS",4)&&p21_get16(p+4)!=1)return FUTURE;
 if(memcmp(p,"WNVS",4)||p21_get16(p+6)!=P21_RECORD_HEADER||p21_get32(p+24)||p21_get32(p+28)!=p21_crc32(p,28))return CORRUPT;
 uint32_t len=p21_get32(p+8),crc=p21_get32(p+20);uint64_t gen=p21_get64(p+12);
 if(!gen||len>P21_STORE_MAX||n!=P21_RECORD_HEADER+len||crc!=p21_crc32(p+P21_RECORD_HEADER,len))return CORRUPT;
 lengths[slot]=len;generations[slot]=gen;crcs[slot]=crc;return VALID;
}
static void retire(void){wipe(records,sizeof(records));wipe(lengths,sizeof(lengths));wipe(crcs,sizeof(crcs));wipe(generations,sizeof(generations));}
static int select_record(int *selected,int *detail){
 *selected=-1;*detail=0;retire();if(!available)return P21_STORE_BLOCKED;
 nvs_handle_t h=0;esp_err_t err=nvs_open("wic64_private",NVS_READONLY,&h);
 if(err==ESP_ERR_NVS_NOT_FOUND)return P21_STORE_EMPTY;
 if(err!=ESP_OK){*detail=err;return P21_STORE_BLOCKED;}
 int a=read_slot(h,0,detail),b=read_slot(h,1,detail);nvs_close(h);
 if(a==FUTURE||b==FUTURE||a==IO_ERROR||b==IO_ERROR)return P21_STORE_BLOCKED;
 if(a!=VALID&&b!=VALID)return P21_STORE_BLOCKED;
 int pick=a==VALID?0:1;
 if(a==VALID&&b==VALID){
  if(generations[0]==generations[1]&&(lengths[0]!=lengths[1]||crcs[0]!=crcs[1]||memcmp(records[0],records[1],P21_RECORD_HEADER+lengths[0])))return P21_STORE_BLOCKED;
  if(generations[1]>generations[0])pick=1;
 }
 *selected=pick;return P21_STORE_OK;
}
int p21_backend_load(uint8_t *payload,uint32_t *length,uint64_t *generation,uint32_t *crc,int *detail){
 int selected=-1;*length=0;*generation=0;*crc=0;int result=select_record(&selected,detail);
 if(result==P21_STORE_OK){*length=lengths[selected];*generation=generations[selected];*crc=crcs[selected];memcpy(payload,records[selected]+P21_RECORD_HEADER,*length);}
 retire();return result;
}
int p21_backend_commit(const uint8_t *payload,uint32_t length,uint64_t expected,uint32_t crc,int *detail){
 int selected=-1,target=0,result;*detail=0;
 if(!payload||length>P21_STORE_MAX||expected==UINT64_MAX||p21_crc32(payload,length)!=crc)return P21_STORE_BAD;
 result=select_record(&selected,detail);
 if(result!=P21_STORE_OK&&result!=P21_STORE_EMPTY)goto done;
 uint64_t previous=selected<0?0:generations[selected];
 if(previous!=expected){result=P21_STORE_CONFLICT;goto done;}
 if(selected>=0)target=1-selected;
 uint8_t*p=records[target];wipe(p,P21_RECORD_MAX);memcpy(p,"WNVS",4);p21_put16(p+4,1);p21_put16(p+6,P21_RECORD_HEADER);
 p21_put32(p+8,length);p21_put64(p+12,expected+1);p21_put32(p+20,crc);p21_put32(p+28,p21_crc32(p,28));memcpy(p+P21_RECORD_HEADER,payload,length);
 nvs_handle_t h=0;esp_err_t err=nvs_open("wic64_private",NVS_READWRITE,&h);
 if(err!=ESP_OK){*detail=err;result=P21_STORE_FAILED;goto done;}
 err=nvs_set_blob(h,keys[target],p,P21_RECORD_HEADER+length);
 if(err==ESP_OK)err=nvs_commit(h);
 nvs_close(h);
 if(err!=ESP_OK){*detail=err;result=P21_STORE_UNKNOWN;goto done;}
 /* Reopen, validate both generations, and compare the entire payload. */
 result=select_record(&selected,detail);
 if(result!=P21_STORE_OK||selected<0||lengths[selected]!=length||generations[selected]!=expected+1||crcs[selected]!=crc||memcmp(records[selected]+P21_RECORD_HEADER,payload,length))result=P21_STORE_UNKNOWN;
done:
 retire();return result;
}
