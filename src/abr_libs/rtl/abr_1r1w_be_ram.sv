// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

`include "abr_sva.svh"

module abr_1r1w_be_ram #(
     parameter int DEPTH         = 64,
     parameter int DATA_WIDTH    = 32,
     parameter int STROBE_WIDTH  = 8,
     localparam int ADDR_WIDTH   = $clog2(DEPTH),
     localparam int NUM_BYTES    = DATA_WIDTH / STROBE_WIDTH
)(
    input  logic                                   clk_i,

    input  logic                                   we_i,
    input  logic [NUM_BYTES-1:0]                   wstrobe_i,
    input  logic [ADDR_WIDTH-1:0]                  waddr_i,
    input  logic [NUM_BYTES-1:0][STROBE_WIDTH-1:0] wdata_i,

    input  logic                                   re_i,
    input  logic [ADDR_WIDTH-1:0]                  raddr_i,
    output logic [DATA_WIDTH-1:0]                  rdata_o
);

    // BRAM-friendly flat memory declaration
    (* ram_style = "block" *) logic [DATA_WIDTH-1:0] ram [0:DEPTH-1];

    always_ff @(posedge clk_i) begin
        if (we_i) begin
            for (int i = 0; i < NUM_BYTES; i++) begin
                if (wstrobe_i[i]) begin
                    ram[waddr_i][i*STROBE_WIDTH +: STROBE_WIDTH] <= wdata_i[i];
                end
            end
        end

        if (re_i) begin
            rdata_o <= ram[raddr_i];
        end
    end

`ABR_ASSERT_NEVER(ABR_MEM_RD_GT_DEPTH, raddr_i >= DEPTH, clk_i, 0, re_i)
`ABR_ASSERT_NEVER(ABR_MEM_WR_GT_DEPTH, waddr_i >= DEPTH, clk_i, 0, we_i)

endmodule