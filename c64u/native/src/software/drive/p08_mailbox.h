#ifndef P08_MAILBOX_H
#define P08_MAILBOX_H
#include <stdint.h>
#include "p64_ordering.h"
#include <string.h>
namespace p08 {
enum { D_ADDRESS=0x0340,H_ADDRESS=0x0380,RX_ADDRESS=0x0400,TX_ADDRESS=0x0500,
       HEADER_SIZE=64,MAX_RX=8192,MAX_TX=65536,
       IDLE=1,RX_WINDOW=2,REQUEST_READY=3,WAIT_DUMMY=4,TX=5,TX_WINDOW=6,DISCARD=7,FAULT=8,STOPPED=9,RX=10,
       RX_CONSUMED=1,RESPONSE_START=2,TX_CHUNK=3,STOP=4,ENDPOINT_RESET=5,LOW_READY=1,W_PRG_MINUS2=1,FINAL_RX=1 };
enum Result { OK,BUSY,BAD_STATE,BAD_PARAMETER,NO_DRIVE,BAD_MAILBOX,BAD_C64,STOP_TIMEOUT,TIMER_FAILURE,DIRECTION_NOT_READY,RESET_DETECTED,LIMIT_REACHED };
struct Snapshot {uint8_t d[64],h[64];};
struct Measurement {uint8_t pra,ddra,ddrb;bool sampled,published;uint16_t stop_ms;};
inline void barrier(){
#if defined(C64U_CORE49_FENCELESS) && C64U_CORE49_FENCELESS
    p64_ordering::mailbox_barrier();
#elif defined(__riscv)
 __asm__ volatile("fence iorw,iorw" ::: "memory");
#else
 __asm__ volatile("" ::: "memory");
#endif
}
inline uint16_t u16(const uint8_t *p){return uint16_t(p[0])|uint16_t(p[1])<<8;}
inline uint32_t u32(const uint8_t *p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
inline void put16(uint8_t *p,uint16_t v){p[0]=uint8_t(v);p[1]=uint8_t(v>>8);}
inline void put32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=uint8_t(v>>(8*i));}
inline bool nonzero(const uint8_t *p,unsigned n){uint8_t v=0;for(unsigned i=0;i<n;i++)v|=p[i];return v!=0;}
inline bool committed(const uint8_t *p,unsigned start){uint32_t s=u32(p+start);return s && !(s&1) && s==u32(p+60);}
inline bool protocol(uint8_t p){return p=='R'||p=='E'||p=='W';}
inline bool valid_drive(const uint8_t *d,const uint8_t session[8]){
 return !memcmp(d,"P8DM",4)&&d[4]==2&&d[5]>=IDLE&&d[5]<=RX&&!(d[6]&~3)&&!d[27]&&committed(d,8)&&
        !memcmp(d+12,session,8)&&u32(d+20)<=0xfffffffeu;
}
inline bool read_snapshot(volatile const uint8_t *memory,Snapshot &out){
 for(unsigned attempt=0;attempt<3;attempt++){
  uint8_t dsbytes[4],hsbytes[4];for(unsigned i=0;i<4;i++){dsbytes[i]=memory[D_ADDRESS+8+i];hsbytes[i]=memory[H_ADDRESS+i];}
  uint32_t ds=u32(dsbytes),hs=u32(hsbytes);barrier();if(!ds||(ds&1)||(hs&1))continue;
  for(unsigned i=0;i<64;i++){out.d[i]=memory[D_ADDRESS+i];out.h[i]=memory[H_ADDRESS+i];}barrier();
  bool same=ds==u32(out.d+8)&&ds==u32(out.d+60)&&hs==u32(out.h)&&hs==u32(out.h+60);
  for(unsigned i=0;i<4;i++)same=same&&memory[D_ADDRESS+8+i]==dsbytes[i]&&memory[H_ADDRESS+i]==hsbytes[i];
  if(same)return true;
 }return false;
}
inline bool snapshot(volatile const uint8_t *memory,const uint8_t session[8],Snapshot &out){return read_snapshot(memory,out)&&valid_drive(out.d,session);}
inline bool command_base(const Snapshot &s,const uint8_t session[8],uint32_t request,uint8_t opcode,uint8_t command[64]){
 if(!valid_drive(s.d,session)||!request||request!=u32(s.d+20))return false;
 uint32_t previous=u32(s.h);
 if(previous&1||previous>0xfffffffcu||u32(s.d+42)!=previous||
    (previous&&(!committed(s.h,0)||memcmp(s.h+8,session,8)||u32(s.h+16)>request)))return false;
 memset(command,0,64);put32(command,previous+2);put32(command+60,previous+2);command[4]=opcode;
 memcpy(command+8,session,8);put32(command+16,request);return true;
}
// Secret-free, individually distinguishable reasons for the generation guard.
enum { HELPER_PARALLEL_TIMEOUT=4 };
inline uint32_t helper_guard_reasons(const Snapshot &s,uint32_t sequence,uint32_t request,uint32_t drive_request){
 return (u32(s.d+8)<sequence?1u:0u)|(u32(s.d+20)<request?2u:0u)|
        (u32(s.d+20)<drive_request?4u:0u)|(s.d[5]==FAULT?8u:0u)|
        (s.d[5]==STOPPED?16u:0u)|
        // transfer_abort publishes DISCARD with this recoverable error.
        // Every other helper error, rollback and rejected grant stays fatal.
        (s.d[7]&&!(s.d[5]==DISCARD&&s.d[7]==HELPER_PARALLEL_TIMEOUT)?32u:0u)|
        (u16(s.d+56)?64u:0u);
}
inline bool prepare_endpoint_reset(const Snapshot &s,const uint8_t session[8],uint32_t request,uint8_t command[64]){
 return s.d[5]==REQUEST_READY&&s.d[24]==0x29&&(s.d[25]=='R'||s.d[25]=='W')&&
        !u32(s.d+28)&&!u32(s.d+36)&&!u16(s.d+40)&&
        command_base(s,session,request,ENDPOINT_RESET,command);
}
inline bool prepare_response(const Snapshot &s,const uint8_t session[8],uint32_t request,uint32_t total,uint16_t length,
 uint8_t status,uint8_t flags,uint32_t generation,const Measurement &m,uint8_t command[64]){
 uint8_t p=s.d[25];
 if(s.d[5]!=REQUEST_READY||!protocol(p)||u32(s.d+28)>MAX_RX||u32(s.d+36)||u16(s.d+40)||total>MAX_TX||
    (p!='E'&&total>65535)||length!=(total>256?256:total)||(flags&~W_PRG_MINUS2)||
    (flags&&(p!='W'||total<=2))||!generation||generation<=u32(s.d+46)||!m.sampled||(m.pra&4)||!(m.ddra&4)||m.ddrb||
    !command_base(s,session,request,RESPONSE_START,command))return false;
 command[5]=status;command[6]=flags;put32(command+24,total);put16(command+28,length);
 command[30]=m.pra;command[31]=m.ddra;command[32]=m.ddrb;command[33]=LOW_READY;put32(command+34,generation);return true;
}
inline bool prepare_rx(const Snapshot &s,const uint8_t session[8],uint32_t request,uint8_t command[64]){
 uint32_t off=u32(s.d+36),total=u32(s.d+28);uint16_t len=u16(s.d+40);
 if(s.d[5]!=RX_WINDOW||!protocol(s.d[25])||!len||len>256||total>MAX_RX||off>total||len>total-off||
    bool(s.d[6]&FINAL_RX)!=(off+len==total)||!command_base(s,session,request,RX_CONSUMED,command))return false;
 put32(command+20,off);put32(command+24,total);put16(command+28,len);return true;
}
inline bool prepare_tx(const Snapshot &s,const uint8_t session[8],uint32_t request,uint32_t offset,uint32_t total,
 uint8_t status,uint8_t flags,uint8_t command[64]){
 if(s.d[5]!=TX_WINDOW||!protocol(s.d[25])||u16(s.d+40)||u32(s.d+36)!=offset||u32(s.d+32)!=total||s.d[26]!=status||
    ((s.d[6]>>1)&1)!=flags||offset>=total||total>MAX_TX||(s.d[25]!='E'&&total>65535)||
    !command_base(s,session,request,TX_CHUNK,command))return false;
 command[5]=status;command[6]=flags;put32(command+20,offset);put32(command+24,total);
 put16(command+28,total-offset>256?256:uint16_t(total-offset));return true;
}
inline bool publish(volatile uint8_t *memory,const Snapshot &before,const uint8_t session[8],const uint8_t command[64],const uint8_t *payload,uint16_t length){
 Snapshot now;if(length>256||!snapshot(memory,session,now)||memcmp(&now,&before,sizeof(now)))return false;
 volatile uint8_t *h=memory+H_ADDRESS;h[0]=uint8_t(u32(command)-1);barrier();
 for(unsigned i=0;i<length;i++)memory[TX_ADDRESS+i]=payload[i];
 for(unsigned i=4;i<60;i++){h[i]=command[i];}
 barrier();
 for(unsigned i=0;i<4;i++){h[60+i]=command[60+i];}
 barrier();
 for(unsigned i=3;i;i--){h[i]=command[i];}
 h[0]=command[0];barrier();return true;
}
inline const char *result_name(Result r){static const char *n[]={"OK","BUSY","BAD_STATE","BAD_PARAMETER","NO_DRIVE","BAD_MAILBOX","BAD_C64","STOP_TIMEOUT","TIMER_FAILURE","DIRECTION_NOT_READY","RESET_DETECTED","LIMIT_REACHED"};return n[unsigned(r)<sizeof(n)/sizeof(*n)?unsigned(r):unsigned(BAD_STATE)];}
}
#endif
