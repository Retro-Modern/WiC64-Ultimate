; WiC64 internal drive helper. GPL-3.0-or-later.
; Current distribution, modified 2026-11-05.
!cpu 6502

VIA_PB       = $1800
VIA_PA       = $180f         ; alias without CA1/CA2 acknowledge/pulse
VIA_T2_LOW   = $1808
VIA_T2_HIGH  = $1809
VIA_DDRB     = $1802
VIA_DDRA     = $1803
VIA_ACR      = $180b
VIA_PCR      = $180c
VIA_IFR      = $180d
VIA_IER      = $180e
DISK_PB      = $1c00         ; VIA2 PB2 controls the emulated spindle motor
DISK_DDRB    = $1c02

ZP_RX        = $02
ZP_RAW_REPLY = $03
ZP_R_CMD     = $04
ZP_R_LEN_LO  = $05
ZP_R_LEN_HI  = $06
ZP_WAIT_LO   = $07
ZP_WAIT_HI   = $08
ZP_PCR_HIGH  = $09           ; manual CA2 high plus next CA1 edge polarity
ZP_INIT_ATN  = $0a           ; boot-only PB7 sample, before IEC_READY

D = $0340
H = $0380
CMD = $0200
REPLY_HEADER = $0240
RX = $0400
TX = $0500
ZP_DSEQ = $20             ; LE32 monotonic, even publication counter
ZP_HSEQ = $24
ZP_SNAP = $28
ZP_TX_PTR = $2c
ZP_HEADER_LEFT = $2e
ZP_TX_COUNT = $2f          ; LE32 physical wire bytes including header
ZP_RX_LEFT = $33           ; LE32 remaining request bytes
ZP_REQUEST = $37           ; LE32 nonwrapping request ID
ZP_GENERATION = $3b        ; initial direction sample generation
ZP_RX_OFFSET = $3f         ; LE32 first byte of current RX page
ZP_RX_USED = $43           ; LE16 0..256
ZP_TX_OFFSET = $45         ; LE32 consumed payload bytes
ZP_TX_PAGE_LEFT = $49      ; LE16 current page bytes remaining
ZP_TX_TOTAL = $4b          ; LE32 physical response body size
ZP_PROTOCOL = $4f
ZP_RX_TOTAL = $50          ; LE32 parsed request body size
ZP_RESPONSE_FLAGS = $54
ZP_DEADLINE = $57         ; LE16 Timer2 periods remaining
ZP_EXPECT_LEN = $55        ; LE16 exact page length at current offset
ZP_TRANSFER_PERIODS = $59  ; active one-shot $2D timeout, LE16 T2 periods; zero=legacy default
ZP_NEXT_PERIODS = $5b      ; pending timeout consumed by the next explicit W/R/E start
ZP_FIRST_RX_BYTE = $5d    ; retained first request byte, independent of streamed RX page reuse

S_IDLE = 1
S_RX_WINDOW = 2
S_REQUEST_READY = 3
S_WAIT_DUMMY = 4
S_TX = 5
S_TX_WINDOW = 6
S_DISCARD = 7
S_FAULT = 8
S_STOPPED = 9
S_RX = 10
OP_RX_CONSUMED = 1
OP_RESPONSE_START = 2
OP_TX_CHUNK = 3
OP_STOP = 4
OP_ENDPOINT_RESET = 5      ; input-only $29 completion, no response frame
E_SESSION_MISSING = 1
E_BAD_START = 2
E_RX_LENGTH = 3
E_PARALLEL_TIMEOUT = 4
E_OPCODE = 5
E_SESSION = 6
E_REQUEST = 7
E_DIRECTION = 8
E_TX_LENGTH = 9
E_GENERATION = 10
E_SEQUENCE_LIMIT = 11
E_REQUEST_LIMIT = 12
E_RESERVED = 13
E_STATE = 14
E_OFFSET = 15
E_METADATA = 16

!macro inc32 .p {
    inc .p
    bne +
    inc .p+1
    bne +
    inc .p+2
    bne +
    inc .p+3
+
}
!macro sat16 .p {
    lda .p
    and .p+1
    cmp #$ff
    beq +
    inc .p
    bne +
    inc .p+1
+
}

IEC_ATN_MIN_DWELL_CYCLES = 256
IEC_RELEASE_BUDGET_CYCLES = 128

MB_BASE        = $0300
MB_VERSION     = $0304
MB_STATE       = $0305
MB_ERROR       = $0306
MB_RAW_VALUE   = $0307
MB_RX_COUNT    = $0308
MB_TX_COUNT    = $030a
MB_RAW_COUNT   = $030c
MB_WIC_COUNT   = $030e
MB_ERROR_COUNT = $0310
MB_RELEASES    = $0312
MB_STROBES     = $0314
MB_LAST_RX     = $0316
MB_LAST_TX     = $0317
MB_BURST_COUNT = $0318
MB_RESYNC_COUNT = $031a

; Independent diagnostic block, sixteen bytes, published ready last.
IEC_BASE        = $0320      ; IEC1, schema=1
IEC_SCHEMA      = $0324
IEC_READY       = $0325
IEC_LAST_ATN    = $0326      ; external ATN: 0 asserted, 1 released
IEC_LAST_DDRB   = $0327      ; 0a asserted / 1a released
IEC_ASSERTS     = $0328      ; accepted assertion IRQs, LE16
IEC_RELEASES    = $032a      ; accepted release IRQs, LE16
IEC_IRQ_COUNT   = $032c      ; accepted CA1 IRQs, LE16
IEC_INIT_RETRIES = $032e     ; saturating boot resample count
IEC_ERROR       = $032f      ; reserved zero; not a pulse-width detector

STATE_IDLE       = $00
STATE_RAW_OPCODE = $01
STATE_RAW_VALUE  = $02
STATE_RAW_TURN   = $03
STATE_RAW_REPLY  = $04
STATE_R_HEADER   = $10
STATE_R_RELEASE  = $11
STATE_R_DUMMY    = $12
STATE_R_REPLY    = $13
STATE_R_DISCARD  = $14

ERROR_UNKNOWN_BYTE = $01
ERROR_RAW_OPCODE   = $02
ERROR_R_COMMAND    = $03
ERROR_R_LENGTH     = $04
ERROR_TIMEOUT      = $05

* = $c000

drive_reset:
    sei
    cld
    ldx #$ff
    txs

    ; Reset leaves VIA2 PB2 as an input, which the drive treats as motor ON.
    ; Set the inactive latch before making only the motor pin an output.
    ; Other disk pins remain inputs; the userport/IEC VIA1 is independent.
    lda #$00
    sta DISK_PB
    lda #$04
    sta DISK_DDRB

    ; Never drive the data bus until the host's turnaround is observed.
    lda #$00
    sta VIA_DDRA
    sta VIA_ACR
    lda #$ff
    sta VIA_PA
    lda #$7f
    sta VIA_IER
    lda #$0e                 ; CA2 manual output high; CB1 negative edge
    sta VIA_PCR
    lda #$7f
    sta VIA_IFR

    lda #0
    ldx #$7f
drive_clear_private:
    sta $00,x
    dex
    cpx #$1f
    bne drive_clear_private
    ldx #$7f
drive_clear_service_mailboxes:
    sta D,x                  ; boot only, before any management ownership
    dex
    bpl drive_clear_service_mailboxes

    lda #$00
    ldx #$1f
drive_clear_mailbox:
    sta MB_BASE,x
    dex
    bpl drive_clear_mailbox
    ldx #$0f
drive_clear_iec:
    sta IEC_BASE,x
    dex
    bpl drive_clear_iec
    ldx #$04
drive_write_signature:
    lda mailbox_signature,x
    sta MB_BASE,x
    dex
    bpl drive_write_signature
    ldx #$03
drive_write_iec_signature:
    lda iec_signature,x
    sta IEC_BASE,x
    dex
    bpl drive_write_iec_signature
    lda #$01
    sta IEC_SCHEMA

    ; PRB's IEC output latches stay zero permanently. DDRB1/3 are outputs,
    ; so inverted DATA-OUT and CLK-OUT are both released. ATNACK is selected
    ; through DDRB4: input -> pulled-up one; output -> latched zero. Changing
    ; DDRB has none of ORB's CB1 acknowledge side effects.
    lda #$00
    sta VIA_PB               ; BOOT ONLY: no userport traffic before READY
    lda #$0a
    sta VIA_DDRB
iec_boot_sync:
    lda VIA_PB               ; BOOT ONLY: PB7 = not external ATN
    and #$80
    sta ZP_INIT_ATN
    beq iec_boot_atn_high
    lda #$0a                 ; ATN low -> ATNACK high -> DATA released
    sta VIA_DDRB
    sta IEC_LAST_DDRB
    lda #$0e                 ; CA1 now high: next falling edge
    bne iec_boot_set_edge
iec_boot_atn_high:
    lda #$1a                 ; ATN high -> ATNACK low -> DATA released
    sta VIA_DDRB
    sta IEC_LAST_DDRB
    lda #$0f                 ; CA1 now low: next rising edge
iec_boot_set_edge:
    sta ZP_PCR_HIGH
    sta VIA_PCR
    and #$01
    sta IEC_LAST_ATN
    lda #$7f
    sta VIA_IFR              ; boot only: no pending userport work is valid
    lda VIA_PB
    and #$80
    cmp ZP_INIT_ATN
    beq iec_boot_stable
    lda IEC_INIT_RETRIES
    cmp #$ff
    beq iec_boot_sync
    inc IEC_INIT_RETRIES
    jmp iec_boot_sync
iec_boot_stable:
    lda #$82                 ; only CA1 may interrupt the helper
    sta VIA_IER
    cli
    lda #$01
    sta IEC_READY
    jmp service_initialize

drive_idle:
    lda #STATE_IDLE
    sta MB_STATE
    lda #$00
    sta VIA_DDRA
    jsr receive_byte_idle
    cmp #$ff                 ; input-only bus/presence probe: ACK and idle
    beq drive_idle
    cmp #$a5
    beq raw_command
    cmp #$52                 ; R: status + LE16 response length
    beq wic_start_protocol
    cmp #$45                 ; E: status + LE32 response length
    beq wic_start_protocol
    cmp #$57                 ; W: legacy total length and BE16 reply
    beq wic_start_protocol
    lda #E_BAD_START
    jmp service_fault

raw_command:
    lda #STATE_RAW_OPCODE
    sta MB_STATE
    jsr receive_byte_timed
    bcc raw_opcode_received
    jmp transfer_abort
raw_opcode_received:
    cmp #$01
    beq raw_get_value
    lda #ERROR_RAW_OPCODE
    jsr record_error
    jmp drive_idle

raw_get_value:
    lda #STATE_RAW_VALUE
    sta MB_STATE
    jsr receive_byte_timed
    bcc raw_value_received
    jmp transfer_abort
raw_value_received:
    sta MB_RAW_VALUE
    eor #$ff
    sta ZP_RAW_REPLY

raw_turnaround:
    lda #STATE_RAW_TURN
    sta MB_STATE
    ; This explicit dummy read is part of the raw diagnostic protocol.
    ; It must not be mistaken for WiC64's PA2 direction handshake.
    jsr wait_strobe_timed
    bcc raw_send_reply
    jmp transfer_abort

raw_send_reply:
    lda #STATE_RAW_REPLY
    sta MB_STATE
    lda ZP_RAW_REPLY
    jsr send_byte_wait_consumed
    bcc raw_reply_consumed
    jmp transfer_abort
raw_reply_consumed:
    lda #$00
    sta VIA_DDRA             ; release first, then tell host it may send
    inc MB_RAW_COUNT
    bne raw_count_done
    inc MB_RAW_COUNT+1
raw_count_done:
    jsr pulse_flag
    jmp drive_idle

wic_start_protocol:
    sta ZP_PROTOCOL
wic_command:
    lda #STATE_R_HEADER
    sta MB_STATE
    jsr start_request
wic_header_after_start:
    lda #STATE_R_HEADER
    sta MB_STATE
    lda ZP_PROTOCOL
    cmp #$57
    beq wic_legacy_header
    jsr receive_byte_timed
    bcc +
    jmp wic_header_timeout
+
    sta ZP_R_CMD
    ldx #0
wic_length_loop:
    jsr receive_byte_timed
    bcc +
    jmp wic_header_timeout
+
    sta ZP_RX_TOTAL,x
    inx
    cpx #2
    bne wic_length_check_extended
    lda ZP_PROTOCOL
    cmp #$45
    bne wic_validate_length
wic_length_check_extended:
    cpx #4
    bne wic_length_loop
    beq wic_validate_length
wic_legacy_header:
    jsr receive_byte_timed
    bcc +
    jmp wic_header_timeout
+
    sta ZP_RX_TOTAL
    jsr receive_byte_timed
    bcc +
    jmp wic_header_timeout
+
    sta ZP_RX_TOTAL+1
    jsr receive_byte_timed
    bcc +
    jmp wic_header_timeout
+
    sta ZP_R_CMD
    lda ZP_RX_TOTAL
    sec
    sbc #4
    sta ZP_RX_TOTAL
    lda ZP_RX_TOTAL+1
    sbc #0
    sta ZP_RX_TOTAL+1
    bcs +
    jmp wic_bad_length        ; total includes four header bytes
+
wic_validate_length:
    lda ZP_RX_TOTAL+2
    ora ZP_RX_TOTAL+3
    bne wic_bad_length_jump
    lda ZP_RX_TOTAL+1
    cmp #$20                 ; request cache is bounded to 8192 bytes
    bcc wic_length_valid
    bne wic_bad_length_jump
    lda ZP_RX_TOTAL
    beq wic_length_valid
wic_bad_length_jump:
    jmp wic_bad_length
wic_length_valid:
    ldx #3
wic_rx_left_copy:
    lda ZP_RX_TOTAL,x
    sta ZP_RX_LEFT,x
    dex
    bpl wic_rx_left_copy
    jsr begin_publication
    lda ZP_R_CMD
    sta D+24
    lda ZP_PROTOCOL
    sta D+25
    ldx #3
wic_rx_total_publish:
    lda ZP_RX_TOTAL,x
    sta D+28,x
    dex
    bpl wic_rx_total_publish
    lda #S_RX
    sta D+5
    jsr end_publication
wic_payload_loop:
    lda ZP_RX_LEFT
    ora ZP_RX_LEFT+1
    ora ZP_RX_LEFT+2
    ora ZP_RX_LEFT+3
    bne +
    jmp wic_request_ready
+
    jsr wait_strobe_timed
    bcc +
    jmp wic_header_timeout
+
    jsr receive_sample_no_ack
    ldx ZP_RX_USED
    sta RX,x                 ; page is never larger than 256 bytes
    cpx #0
    bne wic_rx_first_saved
    lda ZP_RX_OFFSET
    ora ZP_RX_OFFSET+1
    ora ZP_RX_OFFSET+2
    ora ZP_RX_OFFSET+3
    bne wic_rx_first_saved
    lda RX
    sta ZP_FIRST_RX_BYTE
wic_rx_first_saved:
    inc ZP_RX_USED
    bne wic_rx_used_ready
    inc ZP_RX_USED+1
wic_rx_used_ready:
    ldx #0
wic_rx_subtract_one:
    lda ZP_RX_LEFT,x
    bne wic_rx_decrement
    dec ZP_RX_LEFT,x
    inx
    bne wic_rx_subtract_one
wic_rx_decrement:
    dec ZP_RX_LEFT,x
    lda ZP_RX_USED+1
    bne wic_rx_page_ready
    lda ZP_RX_LEFT
    ora ZP_RX_LEFT+1
    ora ZP_RX_LEFT+2
    ora ZP_RX_LEFT+3
    beq wic_rx_page_ready
    jsr pulse_flag
    jmp wic_payload_loop
wic_header_timeout:
    jmp transfer_abort
wic_bad_length:
    lda #E_RX_LENGTH
    jmp service_fault
wic_rx_page_ready:
    ; The last incoming byte is already in RX, but its FLAG is withheld.
    ; Thus the original host waits with stable output while management copies.
    jsr begin_publication
    ldx #3
wic_rx_offset_publish:
    lda ZP_RX_OFFSET,x
    sta D+36,x
    dex
    bpl wic_rx_offset_publish
    lda ZP_RX_USED
    sta D+40
    lda ZP_RX_USED+1
    sta D+41
    lda #0
    sta D+6
    lda ZP_RX_LEFT
    ora ZP_RX_LEFT+1
    ora ZP_RX_LEFT+2
    ora ZP_RX_LEFT+3
    bne wic_rx_not_final
    lda #1
    sta D+6
wic_rx_not_final:
    lda #S_RX_WINDOW
    sta D+5
    jsr end_publication
rx_window_published:
    jsr wait_mailbox
    ; poll_command has published RX (not the stale pending window) and ACK.
    ; It is now safe to reuse RX, then acknowledge the withheld last byte.
    clc
    lda ZP_RX_OFFSET
    adc ZP_RX_USED
    sta ZP_RX_OFFSET
    lda ZP_RX_OFFSET+1
    adc ZP_RX_USED+1
    sta ZP_RX_OFFSET+1
    lda ZP_RX_OFFSET+2
    adc #0
    sta ZP_RX_OFFSET+2
    lda ZP_RX_OFFSET+3
    adc #0
    sta ZP_RX_OFFSET+3
    lda #0
    sta ZP_RX_USED
    sta ZP_RX_USED+1
    jsr pulse_flag
    jmp wic_payload_loop
wic_request_ready:
    jsr begin_publication
    lda #0
    sta D+6
    ldx #5
wic_clear_window:
    sta D+36,x
    dex
    bpl wic_clear_window
    lda #S_REQUEST_READY
    sta D+5
    +sat16 D+58
    jsr end_publication
request_published:
    lda #STATE_R_RELEASE
    sta MB_STATE
    jsr wait_mailbox
response_accepted:
    lda #STATE_R_DUMMY
    sta MB_STATE
    jsr pulse_flag           ; one direction-ready FLAG per response
    jsr wait_strobe_timed    ; original host's direction dummy read
    bcs +
    jmp wic_begin_reply
+
    jmp transfer_abort

; VIA1 T2 is unused by parallel/IEC. ACR=0 selects its Phi2 one-shot.
; $ffff underflows after 65536 Phi2 ticks (+synchronizer/event phase).
; Repeated periods provide an input-only backend wait of at least65 seconds,
; and a roughly3-second RX/TX window deadline, independent of poll path cost.
wait_mailbox:
    lda #46
    sta ZP_DEADLINE
    lda #0
    sta ZP_DEADLINE+1
    lda D+5
    cmp #S_REQUEST_READY
    beq wait_mailbox_backend
    lda ZP_TRANSFER_PERIODS
    ora ZP_TRANSFER_PERIODS+1
    beq wait_mailbox_timer_start
    lda ZP_TRANSFER_PERIODS
    sta ZP_DEADLINE
    lda ZP_TRANSFER_PERIODS+1
    sta ZP_DEADLINE+1
    jmp wait_mailbox_timer_start
wait_mailbox_backend:
    lda #<1008               ; nominal66.06s, permits max60s backend
    sta ZP_DEADLINE
    lda #>1008
    sta ZP_DEADLINE+1
wait_mailbox_timer_start:
    jsr deadline_reload
wait_mailbox_loop:
    lda VIA_IFR
    and #$10
    beq wait_mailbox_poll
    lda D+5
    cmp #S_TX_WINDOW
    beq wait_mailbox_unpaced
    cmp #S_REQUEST_READY
    beq wait_mailbox_new_start
    cmp #S_RX_WINDOW
    bne wait_mailbox_poll
wait_mailbox_new_start:
    ; An explicit new W/R/E start cancels a still-input old request. Clear
    ; before sampling so a subsequently held start cannot be lost.
    lda #$10
    sta VIA_IFR
    lda VIA_PA
    cmp #$52
    beq wait_mailbox_restart
    cmp #$45
    beq wait_mailbox_restart
    cmp #$57
    bne wait_mailbox_poll
wait_mailbox_restart:
    sta ZP_PROTOCOL
    pla
    pla                      ; unwind this main wait only; no nested parser
    jsr start_request         ; invalidate old ID before acknowledging start
    jsr receive_sample_and_ack
    jmp wic_header_after_start
wait_mailbox_unpaced:
    pla
    pla
    jmp wic_unpaced_read
wait_mailbox_poll:
    jsr poll_command
    bcc wait_mailbox_done
    lda VIA_IFR
    and #$20                 ; inspect T2 only; never acknowledge CB1/CA1
    beq wait_mailbox_loop
    lda ZP_DEADLINE
    bne wait_deadline_low
    dec ZP_DEADLINE+1
wait_deadline_low:
    dec ZP_DEADLINE
    lda ZP_DEADLINE
    ora ZP_DEADLINE+1
    beq wait_mailbox_timeout
    jsr deadline_reload      ; writing T2 high clears only its own IFR flag
    jmp wait_mailbox_loop
wait_mailbox_timeout:
    pla
    pla
    jmp transfer_abort
wait_mailbox_done:
    rts
deadline_reload:
    lda #$ff
    sta VIA_T2_LOW
    sta VIA_T2_HIGH
    rts

wic_begin_reply:
    lda #STATE_R_REPLY
    sta MB_STATE
    jsr begin_publication
    lda #S_TX
    sta D+5
    jsr end_publication
    lda ZP_PROTOCOL
    cmp #$57
    beq wic_make_legacy_reply
    lda D+26
    sta REPLY_HEADER
    ldx #3
wic_copy_reply_length:
    lda ZP_TX_TOTAL,x
    sta REPLY_HEADER+1,x
    dex
    bpl wic_copy_reply_length
    lda #3
    ldx ZP_PROTOCOL
    cpx #$45
    bne wic_header_prepared
    lda #5
    bne wic_header_prepared
wic_make_legacy_reply:
    lda ZP_TX_TOTAL
    sta REPLY_HEADER+1
    lda ZP_TX_TOTAL+1
    sta REPLY_HEADER
    lda ZP_RESPONSE_FLAGS
    beq wic_legacy_length_ready
    lda REPLY_HEADER+1
    sec
    sbc #2
    sta REPLY_HEADER+1
    lda REPLY_HEADER
    sbc #0
    sta REPLY_HEADER
wic_legacy_length_ready:
    lda #2
wic_header_prepared:
    sta ZP_HEADER_LEFT
    lda #<REPLY_HEADER
    sta ZP_TX_PTR
    lda #>REPLY_HEADER
    sta ZP_TX_PTR+1
    ldy #0
wic_send_loop:
    ; Preserve the proven P06A/P07 four-cycle post-FLAG causal test.
    php
    sei
    lda (ZP_TX_PTR),y
    sta VIA_PA
    sta MB_LAST_TX
    lda #$ff
    sta VIA_DDRA
    lda VIA_IFR
    and #$10
    beq +
    jmp wic_unpaced_read_masked
+
    lda ZP_PCR_HIGH
    eor #$02
    sta VIA_PCR
    lda VIA_IFR                ; exactly four drive cycles after STA PCR
    and #$10
    beq +
    jmp wic_unpaced_read_masked
+
    lda ZP_PCR_HIGH
    sta VIA_PCR
    plp
    jsr wait_strobe_timed
    bcc wic_was_consumed
    jmp transfer_abort
wic_was_consumed:
    inc MB_TX_COUNT
    bne wic_byte_consumed
    inc MB_TX_COUNT+1
wic_byte_consumed:
    +inc32 ZP_TX_COUNT
    lda ZP_HEADER_LEFT
    beq wic_payload_consumed
    dec ZP_HEADER_LEFT
    bne wic_advance_pointer
    lda ZP_TX_TOTAL
    ora ZP_TX_TOTAL+1
    ora ZP_TX_TOTAL+2
    ora ZP_TX_TOTAL+3
    beq wic_reply_complete
    jmp wic_start_payload
wic_payload_consumed:
    +inc32 ZP_TX_OFFSET
    lda ZP_TX_PAGE_LEFT
    bne wic_page_left_low
    dec ZP_TX_PAGE_LEFT+1
wic_page_left_low:
    dec ZP_TX_PAGE_LEFT
    ldx #3
wic_check_all_consumed:
    lda ZP_TX_OFFSET,x
    cmp ZP_TX_TOTAL,x
    bne wic_payload_more
    dex
    bpl wic_check_all_consumed
    jmp wic_reply_complete
wic_payload_more:
    lda ZP_TX_PAGE_LEFT
    ora ZP_TX_PAGE_LEFT+1
    beq wic_need_page
wic_advance_pointer:
    inc ZP_TX_PTR
    beq wic_advance_high
    jmp wic_send_loop
wic_advance_high:
    inc ZP_TX_PTR+1
    jmp wic_send_loop
wic_start_payload:
    lda #<TX
    sta ZP_TX_PTR
    lda #>TX
    sta ZP_TX_PTR+1
    jmp wic_send_loop
wic_need_page:
    ; strobe_seen already released DDRA and consumed the preceding PC2.
    ; A refill neither sends another header nor a direction-ready FLAG.
    jsr begin_publication
    ldx #3
wic_tx_offset_publish:
    lda ZP_TX_OFFSET,x
    sta D+36,x
    dex
    bpl wic_tx_offset_publish
    lda #0
    sta D+40
    sta D+41
    lda #S_TX_WINDOW
    sta D+5
    jsr end_publication
tx_window_published:
    jsr wait_mailbox
    jmp wic_start_payload
wic_reply_complete:
    lda #0
    sta VIA_DDRA
    sta ZP_TRANSFER_PERIODS
    sta ZP_TRANSFER_PERIODS+1
    inc MB_WIC_COUNT
    bne wic_count_done
    inc MB_WIC_COUNT+1
wic_count_done:
    jsr begin_publication
    lda #S_IDLE
    sta D+5
    ldx #3
wic_final_offset:
    lda ZP_TX_OFFSET,x
    sta D+36,x
    dex
    bpl wic_final_offset
    +sat16 D+52
    jsr end_publication
    jmp drive_idle

; Experimental resynchronisation after an actually observed unpaced read.
; Do not count collapsed PC2 edges; discard input-only reads without FLAG2.
wic_unpaced_read_masked:
    lda ZP_PCR_HIGH
    sta VIA_PCR
    lda #$00
    sta VIA_DDRA
    plp                        ; release bus BEFORE a delayed ATN IRQ
wic_unpaced_read:
    inc MB_BURST_COUNT
    bne wic_burst_counted
    inc MB_BURST_COUNT+1
wic_burst_counted:
    jsr begin_publication
    lda #S_DISCARD
    sta D+5
    +sat16 D+54
wic_discard_counted:
    jsr end_publication
    lda #STATE_R_DISCARD
    sta MB_STATE
wic_discard_wait:
    jsr poll_command          ; STOP/reject only; never drives in DISCARD
    lda VIA_IFR
    and #$10
    beq wic_discard_wait
    ; Clear before sampling: if the host writes R after this clear it
    ; sets a fresh flag; if it wrote R before, R remains held until ACK.
    ; Sampling FF and only then clearing could lose a new R in between.
    lda #$10
    sta VIA_IFR
    lda VIA_PA
    cmp #$ff
    bne wic_resync_start
    jmp wic_discard_wait
wic_resync_start:
    cmp #$52
    beq wic_resync_r
    cmp #$45
    beq wic_resync_r
    cmp #$57
    beq wic_resync_r
    ; Explicit W/R/E restart only. Unknown input is ignored
    ; without inventing a reply; this is not general abort recovery.
    jmp wic_discard_wait
wic_resync_r:
    ; receive_sample_and_ack rereads the stable request byte and accounts it.
    lda #$10
    sta VIA_IFR
    inc MB_STROBES
    bne wic_resync_strobe_counted
    inc MB_STROBES+1
wic_resync_strobe_counted:
    inc MB_RESYNC_COUNT
    bne wic_resync_counted
    inc MB_RESYNC_COUNT+1
wic_resync_counted:
    jsr receive_sample_and_ack
    sta ZP_PROTOCOL
    jmp wic_command

; A transfer that the host abandons must not leave the parallel bus driven.
; The last error is sticky until reset; successful transfers do not erase it.
transfer_abort:
    lda #$00
    sta VIA_DDRA
    sta ZP_TRANSFER_PERIODS
    sta ZP_TRANSFER_PERIODS+1
    jsr flag_high
    lda #$10
    sta VIA_IFR
    lda #E_PARALLEL_TIMEOUT
    jsr record_error
    jsr begin_publication
    lda #S_DISCARD
    sta D+5
    lda #E_PARALLEL_TIMEOUT
    sta D+7
    jsr end_publication
    lda #STATE_R_DISCARD
    sta MB_STATE
    jmp wic_discard_wait

service_initialize:
    ldx #3
service_magic_loop:
    lda service_magic,x
    sta D,x
    dex
    bpl service_magic_loop
    lda #2
    sta D+4
    ldx #7
service_copy_session:
    lda helper_session,x
    sta D+12,x
    dex
    bpl service_copy_session
    lda #0
    ldx #7
service_session_nonzero:
    ora helper_session,x
    dex
    bpl service_session_nonzero
    cmp #0
    bne service_session_valid
    lda #E_SESSION_MISSING
    jmp service_fault
service_session_valid:
    jsr begin_publication
    lda #S_IDLE
    sta D+5
    jsr end_publication
    jmp drive_idle

start_request:
    ; A configured server transfer timeout applies once, including the next
    ; frame's header/payload, its turnaround and response/refill waits. Backend
    ; execution retains its separate >=65-second budget. Never persist $2D.
    lda ZP_NEXT_PERIODS
    sta ZP_TRANSFER_PERIODS
    lda ZP_NEXT_PERIODS+1
    sta ZP_TRANSFER_PERIODS+1
    lda #0
    sta ZP_NEXT_PERIODS
    sta ZP_NEXT_PERIODS+1
    ; FFFFFFFE is the final allowed request ID; a new request cannot wrap.
    lda ZP_REQUEST+3
    and ZP_REQUEST+2
    and ZP_REQUEST+1
    cmp #$ff
    bne request_limit_ok
    lda ZP_REQUEST
    cmp #$fe
    bcc request_limit_ok
    lda #E_REQUEST_LIMIT
    jmp service_fault
request_limit_ok:
    +inc32 ZP_REQUEST
    lda #0
    ldx #3
request_clear_private:
    sta ZP_RX_TOTAL,x
    sta ZP_RX_OFFSET,x
    sta ZP_TX_OFFSET,x
    sta ZP_TX_TOTAL,x
    sta ZP_TX_COUNT,x
    dex
    bpl request_clear_private
    sta ZP_RX_USED
    sta ZP_RX_USED+1
    sta ZP_RESPONSE_FLAGS
    sta ZP_FIRST_RX_BYTE
    jsr begin_publication
    ldx #3
request_id_copy:
    lda ZP_REQUEST,x
    sta D+20,x
    dex
    bpl request_id_copy
    lda #0
    ldx #17
request_clear_metadata:
    sta D+24,x
    dex
    bpl request_clear_metadata
    sta D+6
    sta D+7
    lda #S_IDLE              ; invalidate prior READY before touching RX
    sta D+5
    jsr end_publication
    rts

; Consume only stable, newer H commits. No simultaneous writer to CMD.
poll_command:
    lda H
    and #1
    bne command_not_ready_jump
    ldx #3
    lda #0
command_capture_start:
    lda H,x
    sta ZP_SNAP,x
    dex
    bpl command_capture_start
    lda ZP_SNAP
    ora ZP_SNAP+1
    ora ZP_SNAP+2
    ora ZP_SNAP+3
    beq command_not_ready_jump
    ldx #3
command_compare_sequence:
    lda ZP_SNAP,x
    cmp ZP_HSEQ,x
    bcc command_not_ready_jump
    bne command_copy
    dex
    bpl command_compare_sequence
command_not_ready_jump:
    sec
    rts
command_copy:
    ldx #63
command_copy_loop:
    lda H,x
    sta CMD,x
    dex
    bpl command_copy_loop
    ldx #3
command_recheck_start:
    lda H,x
    cmp ZP_SNAP,x
    bne command_not_ready_jump
    cmp CMD,x
    bne command_not_ready_jump
    cmp CMD+60,x
    bne command_not_ready_jump
    dex
    bpl command_recheck_start
    ldx #3
command_remember_sequence:
    lda ZP_SNAP,x
    sta ZP_HSEQ,x
    dex
    bpl command_remember_sequence
    ldx #7
command_session_loop:
    lda CMD+8,x
    cmp D+12,x
    bne command_wrong_session
    dex
    bpl command_session_loop
    ldx #3
command_request_loop:
    lda CMD+16,x
    cmp ZP_REQUEST,x
    bcc command_old_request
    bne command_wrong_request
    dex
    bpl command_request_loop
    jmp command_current_request
command_old_request:
    ; A canceled frame can leave a previously committed H command pending.
    ; Same-session older IDs are consumed without error or state/output change.
    jsr begin_publication
    jsr publish_h_ack
    jsr end_publication
    sec
    rts
command_current_request:
    lda CMD+7
    bne command_reserved_bad_jump
    ldx #59
command_common_reserved:
    lda CMD,x
    bne command_reserved_bad_jump
    dex
    cpx #37
    bne command_common_reserved
    lda CMD+4
    cmp #OP_STOP
    beq command_stop_jump
    cmp #OP_RX_CONSUMED
    beq command_rx_jump
    cmp #OP_RESPONSE_START
    beq command_response_jump
    cmp #OP_TX_CHUNK
    beq command_chunk_jump
    cmp #OP_ENDPOINT_RESET
    beq command_endpoint_reset_jump
    lda #E_OPCODE
    jmp reject_command
command_wrong_session:
    lda #E_SESSION
    jmp reject_command
command_wrong_request:
    lda #E_REQUEST
    jmp reject_command
command_reserved_bad_jump:
    lda #E_RESERVED
    jmp reject_command
command_stop_jump:
    jmp command_stop
command_rx_jump:
    jmp command_rx_consumed
command_response_jump:
    jmp command_response_start
command_chunk_jump:
    jmp command_tx_chunk
command_endpoint_reset_jump:
    jmp command_endpoint_reset

command_rx_consumed:
    lda D+5
    cmp #S_RX_WINDOW
    bne command_state_bad_jump
    lda CMD+5
    ora CMD+6
    bne command_reserved_bad_jump
    ldx #7
command_rx_echo:
    lda CMD+20,x
    cpx #4
    bcc command_rx_offset
    cmp D+24,x              ; Htotal24..27 = DrequestTotal28..31
    bne command_metadata_bad_jump
    jmp command_rx_next
command_rx_offset:
    cmp D+36,x
    bne command_offset_bad_jump
command_rx_next:
    dex
    bpl command_rx_echo
    lda CMD+28
    cmp ZP_RX_USED
    bne command_length_bad_jump
    lda CMD+29
    cmp ZP_RX_USED+1
    bne command_length_bad_jump
    jsr validate_zero_sample
    bcs command_reserved_bad_jump
    jsr begin_publication
    jsr publish_h_ack
    lda #0
    sta D+6
    lda #S_RX
    sta D+5
    jsr end_publication
    clc
    rts
command_state_bad_jump:
    lda #E_STATE
    jmp reject_command
command_metadata_bad_jump:
    lda #E_METADATA
    jmp reject_command
command_offset_bad_jump:
    lda #E_OFFSET
    jmp reject_command
command_length_bad_jump:
    lda #E_TX_LENGTH
    jmp reject_command

command_response_start:
    lda D+5
    cmp #S_REQUEST_READY
    bne command_state_bad_jump
    ldx #3
command_initial_offset:
    lda CMD+20,x
    bne command_offset_bad_jump
    dex
    bpl command_initial_offset
    ; E permits exactly 00010000 (65536); W/R at most 0000ffff.
    lda CMD+27
    bne command_length_bad_jump
    lda CMD+26
    beq command_total_valid
    cmp #1
    bne command_length_bad_jump
    lda ZP_PROTOCOL
    cmp #$45
    bne command_length_bad_jump
    lda CMD+24
    ora CMD+25
    bne command_length_bad_jump
command_total_valid:
    lda CMD+6
    and #$fe
    bne command_reserved_bad_far
    lda CMD+6
    beq command_flags_valid
    lda ZP_PROTOCOL
    cmp #$57
    bne command_reserved_bad_far
    lda CMD+25
    bne command_flags_valid
    lda CMD+24
    cmp #3                  ; upstream W PRG lie applies only body >2
    bcc command_length_bad_far
command_flags_valid:
    jsr expected_first_length
    jsr validate_chunk_length
    bcs command_length_bad_far
    lda CMD+31
    and #4
    beq command_direction_bad
    lda CMD+30
    and #4
    bne command_direction_bad
    lda CMD+32
    bne command_direction_bad
    lda CMD+33
    cmp #1
    bne command_direction_bad
    ldx #3
command_generation_loop:
    lda CMD+34,x
    cmp ZP_GENERATION,x
    bcc command_generation_bad
    bne command_generation_ok
    dex
    bpl command_generation_loop
command_generation_bad:
    lda #E_GENERATION
    jmp reject_command
command_direction_bad:
    lda #E_DIRECTION
    jmp reject_command
command_reserved_bad_far:
    lda #E_RESERVED
    jmp reject_command
command_length_bad_far:
    lda #E_TX_LENGTH
    jmp reject_command
command_generation_ok:
    ; The native dispatcher accepted $2D. Keep the requested timeout pending
    ; until a distinct request starts; this command's own response uses its
    ; previous active setting. Upstream reads only the first request byte;
    ; retain it separately because later RX pages overwrite the stream window.
    lda CMD+5
    bne command_timeout_checked
    lda ZP_R_CMD
    cmp #$2d
    bne command_timeout_checked
    lda ZP_PROTOCOL
    cmp #$45
    beq command_timeout_checked
    lda ZP_RX_TOTAL
    ora ZP_RX_TOTAL+1
    ora ZP_RX_TOTAL+2
    ora ZP_RX_TOTAL+3
    beq command_timeout_checked
    ldx ZP_FIRST_RX_BYTE
    beq command_timeout_checked
    lda transfer_periods_low,x
    sta ZP_NEXT_PERIODS
    lda transfer_periods_high,x
    sta ZP_NEXT_PERIODS+1
command_timeout_checked:
    jsr begin_publication
    jsr publish_h_ack
    lda CMD+5
    sta D+26
    lda CMD+6
    sta ZP_RESPONSE_FLAGS
    asl
    sta D+6
    ldx #3
command_initial_metadata:
    lda CMD+24,x
    sta ZP_TX_TOTAL,x
    sta D+32,x
    lda CMD+34,x
    sta ZP_GENERATION,x
    sta D+46,x
    dex
    bpl command_initial_metadata
    jsr copy_chunk_length
    +sat16 D+50
    lda #S_WAIT_DUMMY
    sta D+5
    jsr end_publication
response_committed:
    clc
    rts

command_tx_chunk:
    lda D+5
    cmp #S_TX_WINDOW
    beq command_chunk_state_valid
    lda #E_STATE
    jmp reject_command
command_chunk_state_valid:
    lda CMD+5
    cmp D+26
    bne command_chunk_metadata_bad
    lda CMD+6
    cmp ZP_RESPONSE_FLAGS
    bne command_chunk_metadata_bad
    ldx #3
command_chunk_metadata_loop:
    lda CMD+24,x
    cmp ZP_TX_TOTAL,x
    bne command_chunk_metadata_bad
    lda CMD+20,x
    cmp ZP_TX_OFFSET,x
    bne command_chunk_offset_bad
    dex
    bpl command_chunk_metadata_loop
    jsr validate_zero_sample
    bcs command_chunk_reserved_bad
    ; total-offset >0; get exact remaining length min(256,remaining).
    lda ZP_TX_TOTAL
    sec
    sbc ZP_TX_OFFSET
    sta ZP_EXPECT_LEN
    lda ZP_TX_TOTAL+1
    sbc ZP_TX_OFFSET+1
    sta ZP_EXPECT_LEN+1
    lda ZP_TX_TOTAL+2
    sbc ZP_TX_OFFSET+2
    ora ZP_EXPECT_LEN+1
    beq command_chunk_expected
    lda #0
    sta ZP_EXPECT_LEN
    lda #1
    sta ZP_EXPECT_LEN+1
command_chunk_expected:
    jsr validate_chunk_length
    bcs command_chunk_length_bad
    jsr begin_publication
    jsr publish_h_ack
    jsr copy_chunk_length
    lda #S_TX
    sta D+5
    jsr end_publication
chunk_committed:
    clc
    rts
command_chunk_metadata_bad:
    lda #E_METADATA
    jmp reject_command
command_chunk_offset_bad:
    lda #E_OFFSET
    jmp reject_command
command_chunk_reserved_bad:
    lda #E_RESERVED
    jmp reject_command
command_chunk_length_bad:
    lda #E_TX_LENGTH
    jmp reject_command

expected_first_length:
    lda CMD+24
    sta ZP_EXPECT_LEN
    lda CMD+25
    ora CMD+26
    beq expected_first_small
    lda #0
    sta ZP_EXPECT_LEN
    lda #1
expected_first_small:
    sta ZP_EXPECT_LEN+1
    rts
validate_chunk_length:
    lda CMD+28
    cmp ZP_EXPECT_LEN
    bne chunk_length_invalid
    lda CMD+29
    cmp ZP_EXPECT_LEN+1
    bne chunk_length_invalid
    clc
    rts
chunk_length_invalid:
    sec
    rts
validate_zero_sample:
    ldx #7
zero_sample_loop:
    lda CMD+30,x
    bne zero_sample_invalid
    dex
    bpl zero_sample_loop
    clc
    rts
zero_sample_invalid:
    sec
    rts
copy_chunk_length:
    lda CMD+28
    sta ZP_TX_PAGE_LEFT
    sta D+40
    lda CMD+29
    sta ZP_TX_PAGE_LEFT+1
    sta D+41
    rts

; The service has reset its transient endpoint state. $29 never hands the
; parallel data bus to the helper, never emits a response header and never
; reboots the Ultimate. A single completion FLAG means ready for new input.
command_endpoint_reset:
    lda D+5
    cmp #S_REQUEST_READY
    bne endpoint_reset_state_bad
    lda ZP_R_CMD
    cmp #$29
    bne endpoint_reset_state_bad
    lda ZP_PROTOCOL
    cmp #$45
    beq endpoint_reset_state_bad
    lda ZP_RX_TOTAL
    ora ZP_RX_TOTAL+1
    ora ZP_RX_TOTAL+2
    ora ZP_RX_TOTAL+3
    bne endpoint_reset_state_bad
    lda CMD+5
    ora CMD+6
    bne endpoint_reset_reserved_bad
    ldx #39
endpoint_reset_reserved:
    lda CMD+20,x
    bne endpoint_reset_reserved_bad
    dex
    bpl endpoint_reset_reserved
    lda #0
    sta VIA_DDRA
    sta ZP_TRANSFER_PERIODS
    sta ZP_TRANSFER_PERIODS+1
    sta ZP_NEXT_PERIODS
    sta ZP_NEXT_PERIODS+1
    jsr begin_publication
    jsr publish_h_ack
    lda #0
    sta D+26
    lda #S_IDLE
    sta D+5
    +sat16 D+50
    +sat16 D+52
    jsr end_publication
    jsr pulse_flag
    pla
    pla                       ; abandon poll_command in the backend wait
    pla
    pla                       ; abandon wait_mailbox, no normal response
    jmp drive_idle
endpoint_reset_state_bad:
    lda #E_STATE
    jmp reject_command
endpoint_reset_reserved_bad:
    lda #E_RESERVED
    jmp reject_command

command_stop:
    ldx #39
command_stop_reserved:
    lda CMD+20,x
    bne command_stop_bad
    dex
    bpl command_stop_reserved
    lda CMD+5
    ora CMD+6
    bne command_stop_bad
    lda #0
    sta VIA_DDRA
    jsr flag_high
    jsr begin_publication
    jsr publish_h_ack
    lda #S_STOPPED
    sta D+5
    jsr end_publication
    jmp terminal_wait
command_stop_bad:
    lda #E_RESERVED
    jmp reject_command

reject_command:
    pha
    jsr begin_publication
    pla
    sta D+7
    jsr publish_h_ack
    +sat16 D+56
    jsr end_publication
command_rejected:
    sec
    rts
publish_h_ack:
    ldx #3
publish_h_ack_loop:
    lda ZP_HSEQ,x
    sta D+42,x
    dex
    bpl publish_h_ack_loop
    rts

begin_publication:
    lda ZP_DSEQ+3
    and ZP_DSEQ+2
    and ZP_DSEQ+1
    cmp #$ff
    bne publication_has_room
    lda ZP_DSEQ
    cmp #$fc
    bcs publication_exhausted
publication_has_room:
    lda ZP_DSEQ
    ora #1
    sta D+8                  ; invalidate LOW first, even at carry
    rts
end_publication:
    inc ZP_DSEQ
    +inc32 ZP_DSEQ
    ldx #3
publication_end_loop:
    lda ZP_DSEQ,x
    sta D+60,x
    dex
    bpl publication_end_loop
    ldx #3
publication_high_loop:
    lda ZP_DSEQ,x
    sta D+8,x
    dex
    bne publication_high_loop
    lda ZP_DSEQ
    sta D+8                  ; commit LOW last
    rts
publication_exhausted:
    lda #0
    sta VIA_DDRA
    jsr flag_high
    lda ZP_DSEQ
    ora #1
    sta D+8
    lda #S_FAULT
    sta D+5
    lda #E_SEQUENCE_LIMIT
    sta D+7
    lda ZP_DSEQ
    cmp #$fc
    bne terminal_wait
    jsr end_publication      ; final stable FFFFFFFE fault, never wrap
    jmp terminal_wait
service_fault:
    pha
    lda #0
    sta VIA_DDRA
    jsr flag_high
    jsr begin_publication
    pla
    sta D+7
    jsr record_error
    lda #S_FAULT
    sta D+5
    jsr end_publication
terminal_wait:
    jmp terminal_wait        ; IEC CA1 handler remains active

receive_byte_idle:
    jsr wait_strobe_idle
    jmp receive_sample_and_ack

receive_byte_timed:
    jsr wait_strobe_timed
    bcc receive_sample_and_ack
    rts                      ; C=1, no ACK on timeout

receive_sample_and_ack:
    jsr receive_sample_no_ack
    jsr pulse_flag
    lda ZP_RX
    clc
    rts
receive_sample_no_ack:
    lda VIA_PA
    sta ZP_RX
    sta MB_LAST_RX
    inc MB_RX_COUNT
    bne receive_count_done
    inc MB_RX_COUNT+1
receive_count_done:
    lda ZP_RX
    clc
    rts

; In: A=data. Out: C=0 after the host read it; C=1 after bounded timeout.
; The caller must release DDRA after the last byte or on error.
send_byte_wait_consumed:
    sta VIA_PA
    sta MB_LAST_TX
    lda #$ff
    sta VIA_DDRA
    jsr pulse_flag
    jsr wait_strobe_timed
    bcc send_byte_consumed
    rts
send_byte_consumed:
    inc MB_TX_COUNT
    bne send_count_done
    inc MB_TX_COUNT+1
send_count_done:
    clc
    rts

; Poll CB1's falling-edge flag. Reading PA does NOT acknowledge this flag.
; Clear it explicitly before issuing a FLAG2 pulse. Idle has no timeout.
wait_strobe_idle:
    jsr poll_command          ; no response accepted in IDLE; STOP may park
    lda VIA_IFR
    and #$10
    beq wait_strobe_idle
    jmp strobe_seen

wait_strobe_timed:
    lda ZP_TRANSFER_PERIODS
    ora ZP_TRANSFER_PERIODS+1
    bne wait_strobe_custom
    lda #$00
    sta ZP_WAIT_LO
    sta ZP_WAIT_HI
wait_strobe_poll:
    lda VIA_IFR
    and #$10
    bne strobe_seen
    dec ZP_WAIT_LO
    bne wait_strobe_poll
    dec ZP_WAIT_HI
    bne wait_strobe_poll
    sec
    rts

wait_strobe_custom:
    ; ceil(seconds * 1,000,000 / 65,536) periods: no early expiry at
    ; nominal1MHz. At most one T2 period rounding, including255-second input.
    lda ZP_TRANSFER_PERIODS
    sta ZP_WAIT_LO
    lda ZP_TRANSFER_PERIODS+1
    sta ZP_WAIT_HI
    jsr deadline_reload
wait_strobe_custom_poll:
    lda VIA_IFR
    and #$10
    bne strobe_seen
    lda VIA_IFR
    and #$20
    beq wait_strobe_custom_poll
    lda ZP_WAIT_LO
    bne wait_strobe_custom_low
    dec ZP_WAIT_HI
wait_strobe_custom_low:
    dec ZP_WAIT_LO
    lda ZP_WAIT_LO
    ora ZP_WAIT_HI
    beq wait_strobe_custom_timeout
    jsr deadline_reload
    jmp wait_strobe_custom_poll
wait_strobe_custom_timeout:
    sec
    rts

strobe_seen:
    ; At a genuine PC2 access the old response byte has been consumed. Make
    ; the bus input before clearing its evidence, without an intervening IRQ.
    ; This is harmless in the receive/dummy paths, where DDRA already is zero.
    php
    sei
    lda #$00
    sta VIA_DDRA
    lda #$10
    sta VIA_IFR
    plp
    inc MB_STROBES
    bne strobe_count_done
    inc MB_STROBES+1
strobe_count_done:
    clc
    rts

pulse_flag:
    ; A real manual pulse avoids acknowledging CA1. Block IRQs until CA2 is
    ; high again, so the IRQ's PCR polarity update cannot create another FLAG.
    php
    sei
    lda ZP_PCR_HIGH
    eor #$02
    sta VIA_PCR
    lda ZP_PCR_HIGH
    sta VIA_PCR
    plp
    rts

flag_high:
    php
    sei
    lda ZP_PCR_HIGH
    sta VIA_PCR
    plp
    rts

record_error:
    sta MB_ERROR
    inc MB_ERROR_COUNT
    bne record_error_done
    inc MB_ERROR_COUNT+1
record_error_done:
    rts

; CA1 is not external ATN itself: the drive wiring supplies not ATN.
; Arm the opposite CA1 edge after every accepted edge. This is bounded
; software acknowledgement, with the documented minimum level dwell time.
; There is deliberately no ORB read/write here and no CB1-IFR clear.
; A PC2 already pending means a driven byte was read: release it early but
; leave CB1 pending for the original state machine to consume and account.
drive_nmi:
    rti
drive_irq:
    pha
    lda VIA_IFR
    and #$10
    beq iec_irq_check_ca1
    lda #$00
    sta VIA_DDRA
iec_irq_check_ca1:
    lda VIA_IFR
    and #$02
    beq iec_irq_done
    lda #$02
    sta VIA_IFR
    lda ZP_PCR_HIGH
    eor #$01
    sta ZP_PCR_HIGH
    sta VIA_PCR               ; rearm opposite edge BEFORE any counters
    and #$01
    beq iec_irq_atn_asserted
    lda #$1a
    sta VIA_DDRB
    sta IEC_LAST_DDRB
    lda #$01
    sta IEC_LAST_ATN
    inc IEC_RELEASES
    bne iec_irq_rearm
    inc IEC_RELEASES+1
    jmp iec_irq_rearm
iec_irq_atn_asserted:
    lda #$0a
    sta VIA_DDRB
    sta IEC_LAST_DDRB
    lda #$00
    sta IEC_LAST_ATN
    inc IEC_ASSERTS
    bne iec_irq_rearm
    inc IEC_ASSERTS+1
iec_irq_rearm:
    ; A strobe may have arrived since IRQ entry. A second check bounds how
    ; long the helper keeps a consumed byte driven during this ATN handler.
    lda VIA_IFR
    and #$10
    beq iec_irq_count
    lda #$00
    sta VIA_DDRA
iec_irq_count:
    inc IEC_IRQ_COUNT
    bne iec_irq_done
    inc IEC_IRQ_COUNT+1
iec_irq_done:
    pla
    rti

mailbox_signature:
    !text "WPAR"
    !byte $08

iec_signature:
    !text "IEC1"

service_magic:
    !text "P8DM"
transfer_periods_low:
    !for .seconds,0,255 { !byte <((.seconds * 1000000 + 65535) / 65536) }
transfer_periods_high:
    !for .seconds,0,255 { !byte >((.seconds * 1000000 + 65535) / 65536) }
helper_session:
    !fill 8,0

drive_code_end:
    !if * > $fffa { !error "Drive probe overlaps CPU vectors" }
    !fill $fffa-*, $ff
    !word drive_nmi, drive_reset, drive_irq
    ; ACME 0.96.4 wraps the logical PC to zero after $FFFF.
    !if (* & $ffff) != $0000 { !error "Drive probe vectors must end at $FFFF" }
