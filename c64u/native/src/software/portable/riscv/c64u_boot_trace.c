/* C64U internal startup/fatal capture, no heap, printf, RTOS or persistence.
 * Uses the Stock HDMI overlay display path and the existing loaded font/timing.
 * All addresses and byte values come from Stock u64.h/chargen.h/u64ii_test.cc.
 */
#include <stdint.h>
#include "c64u_boot_trace.h"
#include "u64.h"
#include "chargen.h"
#if !C64U_BOOT_TRACE || !C64U_API22_ALPHA || !P05_RAM_DIAGNOSTIC
#error Bootcheck requires the explicit RAM-only API22 diagnostic profile
#endif
_Static_assert(sizeof(unsigned)==4,"RV32 trace record requires 32-bit unsigned");
struct BootRecord {
    unsigned magic, stage, detail, sequence, active, fatal;
    unsigned cause, pc, value, sp, status, heartbeat;
};
/* .data survives BSS clear; the linker/validator must prove in-place data copy. */
volatile struct BootRecord c64u_boot_record = {
    0x42435431,0,0,0,1,0,0,0,0,0,0,0
};
/* Every frame is composed completely before publication. Volatile scalar
 * stores avoid an implicit memset dependency before constructors run. The
 * page is fully initialized on each use, including before BSS is cleared. */
static volatile uint8_t private_page[1000];
static unsigned disable_irqs(void) {
    unsigned old;
    __asm__ volatile("csrrci %0, mstatus, 8":"=r"(old)::"memory");
    return old;
}
static void restore_irqs(unsigned old) {
    if(old&8) __asm__ volatile("csrsi mstatus, 8":::"memory");
}
static void text(unsigned row,unsigned col,const char *s) {
    volatile uint8_t *p=private_page+row*40+col;
    for(unsigned i=col;*s&&i<40;++i) *p++=(uint8_t)(*s++&0x7f);
}
static void hex(unsigned row,unsigned col,unsigned value) {
    static const char digits[]="0123456789ABCDEF";
    volatile uint8_t *p=private_page+row*40+col;
    for(unsigned i=0;i<8;++i) p[i]=(uint8_t)digits[(value>>(28-4*i))&15];
}
static void configure_overlay(void) {
    volatile t_chargen_registers *regs=(volatile t_chargen_registers *)U64II_OVERLAY_BASE;
    /* Leave original LINE_CLOCKS and X/Y untouched. No write-only-reg reads. */
    regs->CHAR_WIDTH=8;regs->CHAR_HEIGHT=9;
    regs->CHARS_PER_LINE=40;regs->ACTIVE_LINES=25;
    regs->POINTER_HI=0;regs->POINTER_LO=0;regs->PERFORM_SYNC=0;
}
static void compose_page(void) {
    for(unsigned i=0;i<1000;++i) private_page[i]=0x20;
    text(0,1,"C64U WIC64 FINETUNE2");
    text(2,1,c64u_boot_record.fatal?"BOOT STOPPED - PLEASE TAKE A PHOTO":"BOOT IN PROGRESS");
    text(4,1,"STAGE");hex(4,12,c64u_boot_record.stage);
    text(5,1,"DETAIL");hex(5,12,c64u_boot_record.detail);
    text(6,1,"SEQUENCE");hex(6,12,c64u_boot_record.sequence);
    if(c64u_boot_record.fatal){
        text(8,1,"REASON");hex(8,12,c64u_boot_record.fatal);
        text(9,1,"CAUSE");hex(9,12,c64u_boot_record.cause);
        text(10,1,"PC");hex(10,12,c64u_boot_record.pc);
        text(11,1,"VALUE");hex(11,12,c64u_boot_record.value);
        text(12,1,"SP");hex(12,12,c64u_boot_record.sp);
        text(13,1,"MSTATUS");hex(13,12,c64u_boot_record.status);
    }
    text(16,1,c64u_boot_record.fatal?"RAM APPLICATION STOPPED":"RAM APPLICATION STARTING");
    text(18,1,"IF THIS STAYS: PHOTO OF WHOLE SCREEN");
    text(20,1,"USE HDMI FOR THIS DIAGNOSTIC");
    text(22,1,"POWER OFF/ON RETURNS TO STOCK");
}
static void publish_page(void) {
    volatile t_chargen_registers *regs=(volatile t_chargen_registers *)U64II_OVERLAY_BASE;
    volatile uint8_t *chars=(volatile uint8_t *)U64II_CHARGEN_SCREEN_RAM;
    volatile uint8_t *colors=(volatile uint8_t *)U64II_CHARGEN_COLOR_RAM;
    for(unsigned i=0;i<1000;++i){chars[i]=private_page[i];colors[i]=0x0f;}
    /* Stock u64ii_test.cc uses 0x80 for display without keyboard ownership. */
    regs->TRANSPARENCY=0x80;
}
static void render(void) {
    compose_page();
    publish_page();
}
void c64u_boot_stage(unsigned stage,unsigned detail) {
    unsigned old=disable_irqs();
    if(c64u_boot_record.fatal){restore_irqs(old);return;}
    c64u_boot_record.stage=stage;c64u_boot_record.detail=detail;
    ++c64u_boot_record.sequence;
#if C64U_BOOT_TRACE_DISPLAY
    if(c64u_boot_record.active&&!c64u_boot_record.fatal){
        configure_overlay();
        render();
    }
#endif
    restore_irqs(old);
}
void c64u_boot_hide(void) {
    unsigned old=disable_irqs();
    if(!c64u_boot_record.fatal){
        c64u_boot_record.active=0;
        ((volatile t_chargen_registers *)U64II_OVERLAY_BASE)->TRANSPARENCY=0;
    }
    restore_irqs(old);
}
void c64u_boot_ready(void) {
    unsigned old=disable_irqs();
    if(c64u_boot_record.fatal){restore_irqs(old);return;}
    c64u_boot_record.stage=0x70;c64u_boot_record.active=0;
    /* ultimate_main restores its exact Overlay settings immediately before. */
    ((volatile t_chargen_registers *)U64II_OVERLAY_BASE)->TRANSPARENCY=0;
    restore_irqs(old);
}
void c64u_boot_poll(void) { ++c64u_boot_record.heartbeat; }
void c64u_boot_fault(unsigned cause,unsigned pc,unsigned value,unsigned original_sp) {
    unsigned status=disable_irqs();
    if(!c64u_boot_record.fatal){
        c64u_boot_record.cause=cause;c64u_boot_record.pc=pc;
        c64u_boot_record.value=value;c64u_boot_record.sp=original_sp;
        c64u_boot_record.status=status;c64u_boot_record.fatal=1;
    }
    configure_overlay();
    for(;;) render();
}
void c64u_boot_fail(unsigned reason,unsigned detail) {
    unsigned status=disable_irqs(),sp;
    __asm__ volatile("mv %0, sp":"=r"(sp));
    if(!c64u_boot_record.fatal){
        c64u_boot_record.pc=(unsigned)__builtin_return_address(0);
        c64u_boot_record.value=detail;c64u_boot_record.sp=sp;
        c64u_boot_record.status=status;c64u_boot_record.fatal=reason;
    }
    configure_overlay();
    for(;;) render();
}
