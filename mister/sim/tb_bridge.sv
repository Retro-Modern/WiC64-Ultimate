// Testbank fuer wic64_bridge: C64-Seite wie wic64.asm (WiC64-Bibliothek),
// Linux-Seite als UART-Modell, das ECHO ($fe) beantwortet.
`timescale 1ns/1ps
module tb;

localparam real CLK_NS = 31.718;     // 31,527954 MHz (PAL)
localparam real BIT_NS = 640.0;      // 1 562 500 Baud

reg clk = 0;
always #(CLK_NS/2) clk = ~clk;

reg        reset = 1;
reg  [7:0] prb = 8'hFF, ddrb = 0;
wire [7:0] pb_o = prb | ~ddrb;
wire [7:0] pb_i;
reg        pa2 = 1;
reg        pc2_n = 1;
wire       flag2_n;
reg        hps_tx = 1;              // HPS -> FPGA
wire       hps_rx;                  // FPGA -> HPS
reg        dtr = 0;

wic64_bridge dut(
	.clk(clk), .reset(reset), .baud_inc(24'd831465),
	.pb_o(pb_o), .pb_i(pb_i), .pa2_o(pa2), .pc2_n(pc2_n), .flag2_n(flag2_n),
	.uart_rx(hps_tx), .uart_tx(hps_rx), .uart_flush(dtr)
);

// ------------------------------------------------------------ C64-Modell
// FLAG2-Flanke setzt ICR-Bit 4 wie die CIA; Lesen loescht es.
reg icr_flag = 0;
reg clr_flag = 0;
always @(negedge flag2_n or posedge clr_flag)
	if(clr_flag) icr_flag <= 0; else icr_flag <= 1;

integer errors = 0;
integer timeouts = 0;

task cpu(input integer cycles); #(cycles*1015); endtask   // PAL-Takt

task pc2_pulse; begin
	@(posedge clk); #1 pc2_n = 0; repeat(32) @(posedge clk); #1 pc2_n = 1;
end endtask

// wic64_wait_for_handshake: bit $dd0d in einer Schleife, Zeitlimit
task wait_hs; integer t; begin
	t = 0;
	while(!icr_flag && t < 5000) begin cpu(8); t = t + 1; end
	if(!icr_flag) begin $display("%t ZEITLIMIT beim Warten auf FLAG2", $time); timeouts = timeouts + 1; end
	clr_flag = 1; #1 clr_flag = 0;
end endtask

task c64_put(input [7:0] b); begin  // sta $dd01 + wait
	prb = b; pc2_pulse; wait_hs; cpu(6);
end endtask

task c64_get(output [7:0] b); begin // wait + lda $dd01
	wait_hs; cpu(4); b = pb_i; pc2_pulse; cpu(6);
end endtask

reg [7:0] req[0:2047];
reg [7:0] resp[0:2047];
integer   resp_len;
reg [7:0] status;

task c64_request(input integer len); integer i; reg [7:0] d; begin
	// wic64_initialize + send_header
	clr_flag = 1; #1 clr_flag = 0;
	pa2 = 1; cpu(6); ddrb = 8'hFF; cpu(6);
	for(i = 0; i < len; i = i + 1) c64_put(req[i]);
	// receive_header
	ddrb = 0; cpu(4); pa2 = 0;
	wait_hs;                         // Antwort bereit
	cpu(4); pc2_pulse;               // lda $dd01 (blind)
	c64_get(status);
	c64_get(d); resp_len = d;
	c64_get(d); resp_len = resp_len | (d << 8);
	for(i = 0; i < resp_len; i = i + 1) c64_get(resp[i]);
	// finalize
	ddrb = 0;
	clr_flag = 1; #1 clr_flag = 0;
end endtask

// ------------------------------------------------------ Linux-Modell (UART)
reg [7:0] tx_q[0:65535];
integer   tx_w = 0, tx_r = 0;
integer   sent = 0, credit = 0;      // Kreditrechnung wie wic64d.py
reg       wait04 = 0;
integer   snap;

task hps_send_byte(input [7:0] b); integer i; begin
	hps_tx = 0; #(BIT_NS);
	for(i = 0; i < 8; i = i + 1) begin hps_tx = b[i]; #(BIT_NS); end
	hps_tx = 1; #(BIT_NS);
end endtask

// Sender: nicht mehr als 3840 Bytes unterwegs
always begin
	wait(tx_r < tx_w && sent - credit*256 < 3840 && !wait04);
	snap = tx_r;
	hps_send_byte(tx_q[snap]);
	if(tx_r == snap) tx_r = snap + 1;  // nicht weiterzaehlen, wenn verworfen wurde
	sent = sent + 1;
end

task q(input [7:0] b); begin tx_q[tx_w] = b; tx_w = tx_w + 1; end endtask

// Empfaenger
reg [7:0] ev_a, ev_b;
reg       ev_have = 0;
task hps_recv_byte(output [7:0] b); integer i; begin
	@(negedge hps_rx); #(BIT_NS*1.5);
	for(i = 0; i < 8; i = i + 1) begin b[i] = hps_rx; #(BIT_NS); end
	if(!hps_rx) begin $display("%t Rahmenfehler", $time); errors = errors + 1; end
end endtask

reg [7:0]  lreq[0:65535];
integer    lpos = 0, llen = 0, lneed = 4;
integer    pongs = 0, resets = 0, flushes = 0, marks = 0;
integer    open_resp = 0;              // Antwort ohne Marke im FPGA

task respond; integer i, n, k; begin
	if($time > 57000000) $display("%t Antwort %0d Bytes", $time, llen);
	// Antwort auf ECHO: Status 0, Laenge, Nutzdaten = Anfrage-Nutzdaten
	n = llen;
	q(8'h11);                        // HS: Antwort bereit
	// Kopf (3 Bytes) und Nutzdaten in DATA-Rahmen zu hoechstens 256 Bytes
	q(8'h10); q(8'h03); q(8'h00); q(n & 255); q(n >> 8);
	i = 0;
	while(i < n) begin
		k = (n - i > 256) ? 256 : n - i;
		q(8'h10); q(k & 255);
		repeat(k) begin q(lreq[4 + i]); i = i + 1; end
	end
	q(8'h14);                        // MARKE
	open_resp = 1;
end endtask

reg flush_req = 0;
always begin
	wait(flush_req);
	tx_r = tx_w;                     // Ungesendetes weg
	wait04 = 1;                      // Sender haelt an
	#(BIT_NS*12);                    // laufendes Byte zu Ende
	dtr = ~dtr;
	open_resp = 0;
	flush_req = 0;
end

always begin
	hps_recv_byte(ev_a);
	hps_recv_byte(ev_b);
	if($time > 57000000 && ev_a != 1) $display("%t Ereignis %h %h  tx %0d/%0d wait04 %0d", $time, ev_a, ev_b, tx_r, tx_w, wait04);
	case(ev_a)
		8'h01: begin
			lreq[lpos] = ev_b; lpos = lpos + 1;
			if(lpos == 4) begin llen = lreq[2] | (lreq[3] << 8); lneed = 4 + llen; end
			if(lpos == lneed) begin respond; lpos = 0; lneed = 4; end
		end
		8'h02: if(ev_b == 1) begin
			lpos = 0; lneed = 4;
			if(open_resp) flush_req = 1;
		end
		8'h03: if(!wait04) credit = credit + 1;
		8'h04: begin flushes = flushes + 1; wait04 = 0; sent = 0; credit = 0; end
		8'h05: resets = resets + 1;
		8'h06: pongs = pongs + 1;
		8'h07: begin marks = marks + 1; open_resp = 0; end
		default: begin $display("%t unbekanntes Ereignis %h %h", $time, ev_a, ev_b); errors = errors + 1; end
	endcase
end

// ------------------------------------------------------------- Ablauf
integer i, n, rep;
initial begin

	#2000 reset = 0;
	#20000;
	q(8'h12);                         // PING
	#40000;
	if(pongs != 1 || resets != 1) begin $display("PING/Reset fehlt: %0d %0d", pongs, resets); errors = errors + 1; end

	for(rep = 0; rep < 4; rep = rep + 1) begin
		n = (rep == 0) ? 5 : (rep == 1) ? 0 : (rep == 2) ? 300 : 1500;
		req[0] = "R"; req[1] = 8'hfe; req[2] = n & 255; req[3] = n >> 8;
		for(i = 0; i < n; i = i + 1) req[4+i] = (i * 7 + rep) & 255;
		c64_request(4 + n);
		if(status !== 0 || resp_len !== n) begin
			$display("ECHO %0d: Status %h Laenge %0d", n, status, resp_len); errors = errors + 1;
		end
		for(i = 0; i < n; i = i + 1)
			if(resp[i] !== req[4+i]) begin
				if(errors < 10) $display("ECHO %0d: Byte %0d ist %h statt %h", n, i, resp[i], req[4+i]);
				errors = errors + 1;
			end
		#20000;
		if(marks != rep + 1) begin $display("MARKE fehlt"); errors = errors + 1; end
		$display("%t ECHO mit %0d Bytes fertig", $time, n);
	end

	// Abbruch: C64 laesst eine grosse Antwort liegen und fragt neu
	n = 600;
	req[0] = "R"; req[1] = 8'hfe; req[2] = n & 255; req[3] = n >> 8;
	for(i = 0; i < n; i = i + 1) req[4+i] = i & 255;
	clr_flag = 1; #1 clr_flag = 0;
	pa2 = 1; cpu(6); ddrb = 8'hFF; cpu(6);
	for(i = 0; i < 4 + n; i = i + 1) c64_put(req[i]);
	$display("%t Abbruch: Anfrage gesendet", $time);
	ddrb = 0; cpu(4); pa2 = 0;
	wait_hs;                         // Antwort bereit, dann aufgeben
	$display("%t Abbruch: Antwort bereit", $time);
	#3000000;
	for(rep = 0; rep < 3; rep = rep + 1) begin
		n = 5 + rep;
		req[0] = "R"; req[1] = 8'hfe; req[2] = n; req[3] = 0;
		for(i = 0; i < n; i = i + 1) req[4+i] = 8'hA0 + i + rep;
		c64_request(4 + n);
		if(status !== 0 || resp_len !== n) begin
			$display("nach Abbruch %0d: Status %h Laenge %0d", rep, status, resp_len); errors = errors + 1;
		end
		for(i = 0; i < n; i = i + 1)
			if(resp[i] !== req[4+i]) begin $display("nach Abbruch: Byte %0d falsch", i); errors = errors + 1; end
	end
	if(flushes != 1) begin $display("Verwerfen: %0d statt 1", flushes); errors = errors + 1; end
	q(8'h12); #40000;
	if(pongs != 2) begin $display("PING nach Abbruch fehlt"); errors = errors + 1; end
	$display("%t Abbruch und Neuanfang fertig, Marken %0d", $time, marks);

	$display("Fehler: %0d, Zeitlimits: %0d, Kredite: %0d", errors, timeouts, credit);
	if(errors == 0 && timeouts == 0) $display("BESTANDEN"); else $display("DURCHGEFALLEN");
	$finish;
end

endmodule
