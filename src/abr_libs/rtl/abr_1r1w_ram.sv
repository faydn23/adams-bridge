// SPDX-License-Identifier: Apache-2.0

`include "abr_sva.svh"

module abr_1r1w_ram #(
     parameter int DEPTH      = 64,
     parameter int DATA_WIDTH = 32,
     parameter int ADDR_WIDTH = $clog2(DEPTH)
)(
    input  logic                     clk_i,

    input  logic                     we_i,
    input  logic [ADDR_WIDTH-1:0]    waddr_i,
    input  logic [DATA_WIDTH-1:0]    wdata_i,

    input  logic                     re_i,
    input  logic [ADDR_WIDTH-1:0]    raddr_i,
    output logic [DATA_WIDTH-1:0]    rdata_o
);

    // ✅ CRITICAL: doğru memory form
    (* ram_style = "block" *)
    logic [DATA_WIDTH-1:0] ram [0:DEPTH-1];

    // ✅ write
    always_ff @(posedge clk_i) begin
        if (we_i)
            ram[waddr_i] <= wdata_i;
    end

    // ✅ BRAM-friendly read (NO ELSE!)
    always_ff @(posedge clk_i) begin
        if (re_i)
            rdata_o <= ram[raddr_i];
    end

`ABR_ASSERT_NEVER(ABR_MEM_RD_GT_DEPTH, raddr_i >= DEPTH, clk_i, 0, re_i)
`ABR_ASSERT_NEVER(ABR_MEM_WR_GT_DEPTH, waddr_i >= DEPTH, clk_i, 0, we_i)

endmodule