/* The C64 and Drive subsystem trylocks are held by the caller. The first
   response is committed while the C64 remains stopped; never await a Drive
   acknowledgement here. No C64 application header or 6510 port is accessed. */
#include "task.h"
namespace p08 { bool native_menu_held(); bool native_c64_reset_pending(); }

/* The host MMIO test supplies the same three bus reads through its banking
   model. The firmware build always uses the volatile C64 DMA aperture. */
#ifndef P08_C64_BUS_READ
#define P08_C64_BUS_READ(address) \
    (*reinterpret_cast<volatile uint8_t *>(C64_MEMORY_BASE + (address)))
#define P08_UNDEF_C64_BUS_READ
#endif

#if defined(U64E2_CIA_VISIBLE_SAMPLE) && U64E2_CIA_VISIBLE_SAMPLE
/* Compare a hidden character-ROM view without changing the C64 mapping.
   This is the native character-ROM aperture, not another CIA bus read. */
#ifndef P08_C64_CHAR_READ
#define P08_C64_CHAR_READ(address) \
    (*reinterpret_cast<volatile uint8_t *>(U64_CHARROM_BASE + ((address)&0xfff)))
#define P08_UNDEF_C64_CHAR_READ
#endif

struct P08CiaTuple { uint8_t pra,ddra,ddrb; };

static P08CiaTuple p08_read_cia_tuple()
{
    P08CiaTuple value;
    value.pra=P08_C64_BUS_READ(0xdd00);
    value.ddra=P08_C64_BUS_READ(0xdd02);
    value.ddrb=P08_C64_BUS_READ(0xdd03);
    p08::barrier();
    return value;
}

static bool p08_raw_equal(const P08CiaTuple &a,const P08CiaTuple &b)
{
    return a.pra==b.pra && a.ddra==b.ddra && a.ddrb==b.ddrb;
}

/* Input pins may change independently. Only PRA bits configured as outputs
   establish a stable direction sample, together with both complete DDRs. */
static bool p08_cia_equal(const P08CiaTuple &a,const P08CiaTuple &b)
{
    return a.ddra==b.ddra && a.ddrb==b.ddrb &&
           !((a.pra^b.pra)&a.ddra);
}
#endif

static bool p08_read_ms(uint16_t &value)
{
    for(unsigned i=0;i<4;i++) {
        uint8_t hi=ioRead8(ITU_MS_TIMER_HI),lo=ioRead8(ITU_MS_TIMER_LO);
        if(hi==ioRead8(ITU_MS_TIMER_HI)){value=(uint16_t(hi)<<8)|lo;return true;}
    }
    return false;
}

bool U64Machine::p08_start_eligible()
{
    return available && (U64_CART_DETECT&3)==3;
}

bool U64Machine::p08_environment_safe()
{
    return available && !isFrozen && !p08::native_menu_held() && !p08::native_c64_reset_pending() && !(C64_STOP&(C64_DO_STOP|C64_HAS_STOPPED)) &&
           C64_MODE==MODE_NORMAL && !c64_reset_detect() &&
           (U64_CART_DETECT&3)==3;
}

p08::Result U64Machine::p08_measure_publish(volatile uint8_t *drive_memory,
    const p08::Snapshot &before,const uint8_t session[8],uint32_t request,
    const uint8_t *payload,uint16_t chunk_length,uint32_t total_length,
    uint8_t status,uint8_t flags,uint32_t generation,p08::Measurement &m)
{
    m.sampled=false;m.published=false;m.stop_ms=0;
    if(!drive_memory || !session || (chunk_length&&!payload) || chunk_length>256)
        return p08::BAD_PARAMETER;
    uint16_t began=0,now=0;uint8_t command[64];
    p08::Result result=p08::BAD_C64;
    portENTER_CRITICAL();
    if(!p08_environment_safe()){portEXIT_CRITICAL();return result;}
    if(!p08_read_ms(began)){portEXIT_CRITICAL();return p08::TIMER_FAILURE;}
    uint8_t saved_stop_mode=C64_STOP_MODE;
    C64_STOP_MODE=STOP_COND_RWSEQ;C64_STOP=C64_DO_STOP;
    bool stopped=false,timer_ok=true;
    for(unsigned n=0;n<65536;n++) {
        if(C64_STOP&C64_HAS_STOPPED){stopped=true;break;}
        if(!p08_read_ms(now)){timer_ok=false;break;}
        if(uint16_t(now-began)>=3)break;
    }
    if(!stopped) {
        C64_STOP=0;C64_STOP_MODE=saved_stop_mode;portEXIT_CRITICAL();
        return timer_ok?p08::STOP_TIMEOUT:p08::TIMER_FAILURE;
    }
    stop_mode=2;raster=raster_hi=vic_irq_en=vic_irq=0;
    const uint8_t saved_memonly=C64_DMA_MEMONLY,saved_serve=C64_SERVE_CONTROL;
#if defined(U64E2_CIA_VISIBLE_SAMPLE) && U64E2_CIA_VISIBLE_SAMPLE
    /* U64E2 transfer sample: never alter GAME/EXROM while the VIC runs.
       The normal DMA and direct CharROM apertures use the pinned E2 ABI.
       HAS_STOPPED inhibits new REU writes in the reference architecture,
       but does not retract an accepted write. The raw sandwich rejects a
       changing RAM view; it is not an absolute proof against an ABA race. */
    if(!isFrozen && !p08::native_menu_held() && !p08::native_c64_reset_pending() && C64_MODE==MODE_NORMAL && !c64_reset_detect() &&
       (C64_STOP&C64_HAS_STOPPED) && (U64_CART_DETECT&3)==3) {
        C64_SERVE_CONTROL=saved_serve|SERVE_WHILE_STOPPED;
        C64_DMA_MEMONLY=1;p08::barrier();
        const P08CiaTuple raw_before=p08_read_cia_tuple();
        C64_DMA_MEMONLY=0;p08::barrier();
        const P08CiaTuple normal_before=p08_read_cia_tuple();
        C64_DMA_MEMONLY=1;p08::barrier();
        const P08CiaTuple raw_after=p08_read_cia_tuple();
        C64_DMA_MEMONLY=0;p08::barrier();
        const P08CiaTuple normal_after=p08_read_cia_tuple();
        P08CiaTuple characters;
        characters.pra=P08_C64_CHAR_READ(0xdd00);
        characters.ddra=P08_C64_CHAR_READ(0xdd02);
        characters.ddrb=P08_C64_CHAR_READ(0xdd03);
        p08::barrier();

        m.pra=normal_after.pra;m.ddra=normal_after.ddra;m.ddrb=normal_after.ddrb;
        m.sampled=p08_raw_equal(raw_before,raw_after) &&
                  p08_cia_equal(normal_before,normal_after) &&
                  !p08_cia_equal(normal_after,raw_before) &&
                  !p08_cia_equal(normal_after,characters);
        result=p08::DIRECTION_NOT_READY;
    } else result=p08::RESET_DETECTED;
    C64_DMA_MEMONLY=saved_memonly;C64_SERVE_CONTROL=saved_serve;p08::barrier();

    if(!p08_read_ms(now))result=p08::TIMER_FAILURE;
    else if(uint16_t(now-began)>=3)result=p08::STOP_TIMEOUT;
    else if(isFrozen || p08::native_menu_held() || p08::native_c64_reset_pending() || C64_MODE!=MODE_NORMAL || c64_reset_detect() ||
            !(C64_STOP&C64_HAS_STOPPED) || (U64_CART_DETECT&3)!=3)
        result=p08::RESET_DETECTED;
    else if(m.sampled && !(m.pra&4) && (m.ddra&4) && !m.ddrb) {
        if(!p08::prepare_response(before,session,request,total_length,chunk_length,
                                 status,flags,generation,m,command))result=p08::BAD_MAILBOX;
        else {
            m.published=p08::publish(drive_memory,before,session,command,payload,chunk_length);
            result=m.published?p08::OK:p08::BUSY;
        }
    }
    timer_ok=p08_read_ms(now);m.stop_ms=uint16_t(now-began);
    const bool normal=!isFrozen && !p08::native_menu_held() && !p08::native_c64_reset_pending() && C64_MODE==MODE_NORMAL &&
        !c64_reset_detect() && (C64_STOP&C64_HAS_STOPPED) && (U64_CART_DETECT&3)==3;
    /* This stop belongs to this bounded sample. Generic resume() also
       writes C64_MODE, so release only our stop request, on every exit. */
    C64_STOP=0;C64_STOP_MODE=saved_stop_mode;
    if(!normal)result=p08::RESET_DETECTED;
    if(!timer_ok)result=p08::TIMER_FAILURE;
    else if(uint16_t(now-began)>=3)result=p08::STOP_TIMEOUT;
    portEXIT_CRITICAL();return result;
#else
    bool mode_lost=false,forced=false;
    if(!isFrozen && !p08::native_menu_held() && !p08::native_c64_reset_pending() && C64_MODE==MODE_NORMAL && !c64_reset_detect() &&
       (C64_STOP&C64_HAS_STOPPED) && (U64_CART_DETECT&3)==3) {
        C64_SERVE_CONTROL=saved_serve|SERVE_WHILE_STOPPED;
        C64_DMA_MEMONLY=0;
        C64_MODE=MODE_ULTIMAX;forced=true;p08::barrier();
        if(C64_MODE==MODE_ULTIMAX && !c64_reset_detect() &&
           (C64_STOP&C64_HAS_STOPPED) && (U64_CART_DETECT&3)==3) {
            m.pra=P08_C64_BUS_READ(0xdd00);
            m.ddra=P08_C64_BUS_READ(0xdd02);
            m.ddrb=P08_C64_BUS_READ(0xdd03);m.sampled=true;
            p08::barrier();
            result=p08::DIRECTION_NOT_READY;
        } else result=p08::RESET_DETECTED;
    } else result=p08::RESET_DETECTED;

    if(forced) {
        const uint8_t current_mode=C64_MODE;
        mode_lost=current_mode!=MODE_ULTIMAX;
        /* C64_MODE bits 2/3 are RESET/UNRESET write commands, not ordinary
           mode bits. Exclude both when clearing our Ultimax override, so a
           newly asserted reset remains asserted. Preserve a foreign NMI. */
        C64_MODE=current_mode&0x10;
        p08::barrier();
    }
    C64_DMA_MEMONLY=saved_memonly;C64_SERVE_CONTROL=saved_serve;p08::barrier();

    if(!p08_read_ms(now))result=p08::TIMER_FAILURE;
    else if(uint16_t(now-began)>=3)result=p08::STOP_TIMEOUT;
    else if(mode_lost || isFrozen || p08::native_menu_held() || p08::native_c64_reset_pending() || C64_MODE!=MODE_NORMAL || c64_reset_detect() ||
            !(C64_STOP&C64_HAS_STOPPED) || (U64_CART_DETECT&3)!=3)
        result=p08::RESET_DETECTED;
    else if(m.sampled && !(m.pra&4) && (m.ddra&4) && !m.ddrb) {
        if(!p08::prepare_response(before,session,request,total_length,chunk_length,
                                 status,flags,generation,m,command))result=p08::BAD_MAILBOX;
        else {
            m.published=p08::publish(drive_memory,before,session,command,payload,chunk_length);
            result=m.published?p08::OK:p08::BUSY;
        }
    }
    timer_ok=p08_read_ms(now);m.stop_ms=uint16_t(now-began);
    bool normal=!mode_lost && !isFrozen && !p08::native_menu_held() && !p08::native_c64_reset_pending() && C64_MODE==MODE_NORMAL &&
        !c64_reset_detect() && (C64_STOP&C64_HAS_STOPPED) && (U64_CART_DETECT&3)==3;
    if(normal)resume();else{C64_STOP=0;result=p08::RESET_DETECTED;}
    C64_STOP_MODE=saved_stop_mode;
    if(!timer_ok)result=p08::TIMER_FAILURE;
    else if(uint16_t(now-began)>=3)result=p08::STOP_TIMEOUT;
    portEXIT_CRITICAL();return result;
#endif
}

#ifdef P08_UNDEF_C64_CHAR_READ
#undef P08_C64_CHAR_READ
#undef P08_UNDEF_C64_CHAR_READ
#endif

#ifdef P08_UNDEF_C64_BUS_READ
#undef P08_C64_BUS_READ
#undef P08_UNDEF_C64_BUS_READ
#endif
