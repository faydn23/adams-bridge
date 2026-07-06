// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//Sequencer for ABR
//ML-DSA functions
//  Keygen
//  Signing
//  Verify
//ML-KEM functions
//  Keygen

module abr_seq
  import abr_ctrl_pkg::*;
  (
  input logic clk,

  input  logic en_i,
  input  logic [ABR_PROG_ADDR_W-1 : 0] addr_i,
  output abr_seq_instr_t data_o
  );


`ifdef RV_FPGA_OPTIMIZE
    (*rom_style = "block" *) abr_seq_instr_t data_o_rom;
`else 
    abr_seq_instr_t data_o_rom;
`endif
    assign data_o = data_o_rom;

  //----------------------------------------------------------------
  // ROM content
  //----------------------------------------------------------------
 
  always_ff @(posedge clk) begin
        if (en_i) begin
            unique case(addr_i)
                //RESET
                ABR_RESET        : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};

                //ZEROIZE
                ABR_ZEROIZE      : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};

                //KEYGEN
                //rnd_seed=Keccak(entropy||counter)
                MLDSA_KG_S       : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:ABR_ENTROPY_ID, operand2:ABR_NOP, operand3:ABR_NOP};                
                MLDSA_KG_S+ 1   : data_o_rom <= '{opcode:ABR_UOP_SHAKE256,    imm:'h0000, length:'d08, operand1:ABR_CNT_ID,     operand2:ABR_NOP, operand3:ABR_DEST_LFSR_SEED_REG_ID};
                MLDSA_KG_S+ 2   : data_o_rom <= '{opcode:ABR_UOP_LFSR,        imm:'h0000, length:'d00, operand1:ABR_NOP,        operand2:ABR_NOP, operand3:ABR_NOP};
                //(p,p',K)=Keccak(seed)
                //                                //SHAKE256 operation                              //SRC                 //SRC2            //DEST
                MLDSA_KG_S+ 3   : data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0708, length:'d34, operand1:MLDSA_SEED_ID, operand2:ABR_NOP, operand3:MLDSA_DEST_K_RHO_REG_ID};
                //s1=expandS
                //                                //Rej Bounded op      //SRC imm              //SRC1                 //SRC2            //DEST
                MLDSA_KG_S+ 4   : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0000, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S1_0_BASE};
                MLDSA_KG_S+ 5   : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0001, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S1_1_BASE};
                MLDSA_KG_S+ 6   : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0002, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S1_2_BASE};
                MLDSA_KG_S+ 7   : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0003, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S1_3_BASE};
                MLDSA_KG_S+ 8   : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0004, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S1_4_BASE};
                MLDSA_KG_S+ 9   : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0005, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S1_5_BASE};
                MLDSA_KG_S+ 10  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0006, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S1_6_BASE};
                //s2=expandS
                MLDSA_KG_S+ 11  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0007, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_0_BASE};
                MLDSA_KG_S+ 12  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0008, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_1_BASE};
                MLDSA_KG_S+ 13  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h0009, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_2_BASE};
                MLDSA_KG_S+ 14  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h000A, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_3_BASE};
                MLDSA_KG_S+ 15  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h000B, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_4_BASE};
                MLDSA_KG_S+ 16  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h000C, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_5_BASE};
                MLDSA_KG_S+ 17  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h000D, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_6_BASE};
                MLDSA_KG_S+ 18  : data_o_rom <= '{opcode:ABR_UOP_MASKED_REJB, imm:'h000E, length:'d66, operand1:MLDSA_RHO_P_ID, operand2:ABR_NOP, operand3:MLDSA_S2_7_BASE};
                //NTT(s1)
                MLDSA_KG_S+ 19  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0000, length:'d00, operand1:MLDSA_S1_0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_0_NTT_BASE};
                MLDSA_KG_S+ 20  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0000, length:'d00, operand1:MLDSA_S1_1_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_1_NTT_BASE};
                MLDSA_KG_S+ 21  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0000, length:'d00, operand1:MLDSA_S1_2_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_2_NTT_BASE};
                MLDSA_KG_S+ 22  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0000, length:'d00, operand1:MLDSA_S1_3_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_3_NTT_BASE};
                MLDSA_KG_S+ 23  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0000, length:'d00, operand1:MLDSA_S1_4_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_4_NTT_BASE};
                MLDSA_KG_S+ 24  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0000, length:'d00, operand1:MLDSA_S1_5_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_5_NTT_BASE};
                MLDSA_KG_S+ 25  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0000, length:'d00, operand1:MLDSA_S1_6_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_6_NTT_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 26  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0000, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 27  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0001, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 28  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0002, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 29  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0003, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 30  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0004, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 31  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0005, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 32  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0006, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+ 33  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+ 34  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_0_BASE, operand3:MLDSA_T0_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 35  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0100, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 36  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0101, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 37  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0102, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 38  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0103, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 39  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0104, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 40  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0105, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 41  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0106, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+ 42  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+ 43  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_1_BASE, operand3:MLDSA_T1_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 44  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0200, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 45  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0201, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 46  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0202, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 47  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0203, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 48  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0204, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 49  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0205, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 50  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0206, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+ 51  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+ 52  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_2_BASE, operand3:MLDSA_T2_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 53  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0300, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 54  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0301, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 55  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0302, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 56  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0303, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 57  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0304, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 58  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0305, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 59  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0306, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+ 60  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+ 61  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_3_BASE, operand3:MLDSA_T3_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 62  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0400, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 63  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0401, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 64  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0402, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 65  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0403, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 66  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0404, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 67  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0405, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 68  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0406, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+ 69  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+ 70  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_4_BASE, operand3:MLDSA_T4_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 71  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0500, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 72  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0501, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 73  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0502, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 74  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0503, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 75  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0504, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 76  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0505, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 77  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0506, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+ 78  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+ 79  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_5_BASE, operand3:MLDSA_T5_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 80  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0600, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 81  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0601, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 82  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0602, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 83  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0603, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 84  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0604, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 85  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0605, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 86  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0606, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+ 87  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+ 88  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_6_BASE, operand3:MLDSA_T6_BASE};
                //ExpandA(?) AND A? NTT(s1)
                MLDSA_KG_S+ 89  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0700, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_0_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 90  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0701, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_1_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 91  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0702, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_2_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+ 92  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0703, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_3_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+  93 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0704, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_4_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+  94 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0705, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_5_NTT_BASE, operand3:MLDSA_AS0_BASE};
                MLDSA_KG_S+  95 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0706, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_S1_6_NTT_BASE, operand3:MLDSA_AS0_BASE};
                //NTT-1(A? ?NTT(s1))
                MLDSA_KG_S+  96 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'d01, length:'d00, operand1:MLDSA_AS0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_AS0_INTT_BASE};
                //t ?NTT-1(A? ?NTT(s1))+s2
                MLDSA_KG_S+  97 : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'d00, length:'d00, operand1:MLDSA_AS0_INTT_BASE, operand2:MLDSA_S2_7_BASE, operand3:MLDSA_T7_BASE};
                //(t1,t0)?Power2Round(t,d) AND pk ?pkEncode(?,t1)
                MLDSA_KG_S+  98 : data_o_rom <= '{opcode:ABR_UOP_PWR2RND_R, imm:'h0000, length:'d00, operand1:MLDSA_T0_BASE, operand2:ABR_NOP, operand3:MLDSA_SK_T0_OFFSET};
                //tr ?H(BytesToBits(pk),512)
                MLDSA_KG_S+  99 : data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:PUBKEY_NUM_BYTES, operand1:MLDSA_PK_REG_ID, operand2:ABR_NOP, operand3:MLDSA_DEST_TR_REG_ID};
                //sk ?skEncode(?,K,tr,s1,s2,t0) - s1 recombined on read via SKENCODE_R
                MLDSA_KG_S+ 100 : data_o_rom <= '{opcode:ABR_UOP_SKENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_S1_0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_KG_JUMP_SIGN : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                //KG end
                MLDSA_KG_E       : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};

                //rnd_seed=Keccak(entropy||counter)
                MLDSA_SIGN_S            : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:ABR_ENTROPY_ID, operand2:ABR_NOP, operand3:ABR_NOP};                
                MLDSA_SIGN_S+ 1         : data_o_rom <= '{opcode:ABR_UOP_SHAKE256,    imm:'h0000, length:'d08, operand1:ABR_CNT_ID,     operand2:ABR_NOP, operand3:ABR_DEST_LFSR_SEED_REG_ID};
                MLDSA_SIGN_S+ 2         : data_o_rom <= '{opcode:ABR_UOP_LFSR,        imm:'h0000, length:'d00, operand1:ABR_NOP,        operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_CHECK_MODE   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                //? ?H(tr||M,512)
                MLDSA_SIGN_H_MU         : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:MLDSA_TR_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_H_MU + 1     : data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:'d66, operand1:MLDSA_MSG_ID, operand2:ABR_NOP, operand3:MLDSA_DEST_MU_REG_ID};
                //??=Keccak(K||rnd|| ?)
                MLDSA_SIGN_H_RHO_P      : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d32, operand1:MLDSA_K_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_H_RHO_P+ 1   : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d32, operand1:MLDSA_SIGN_RND_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_H_RHO_P+ 2   : data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:'d64, operand1:MLDSA_MU_ID, operand2:ABR_NOP, operand3:MLDSA_DEST_RHO_P_REG_ID};
       
                //Signing initial steps start
                MLDSA_SIGN_INIT_S   : data_o_rom <= '{opcode:ABR_UOP_MASKED_SKDECODE, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:MLDSA_S1_0_BASE};
                //NTT(t0)
                MLDSA_SIGN_INIT_S+1 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T0_BASE};
                MLDSA_SIGN_INIT_S+2 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T1_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T1_BASE};
                MLDSA_SIGN_INIT_S+3 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T2_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T2_BASE};
                MLDSA_SIGN_INIT_S+4 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T3_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T3_BASE};
                MLDSA_SIGN_INIT_S+5 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T4_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T4_BASE};
                MLDSA_SIGN_INIT_S+6 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T5_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T5_BASE};
                MLDSA_SIGN_INIT_S+7 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T6_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T6_BASE};
                MLDSA_SIGN_INIT_S+8 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T7_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T7_BASE};
                //NTT(s1)
                MLDSA_SIGN_INIT_S+9 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S1_0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_0_BASE};
                MLDSA_SIGN_INIT_S+10 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S1_1_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_1_BASE};
                MLDSA_SIGN_INIT_S+11: data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S1_2_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_2_BASE};
                MLDSA_SIGN_INIT_S+12: data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S1_3_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_3_BASE};
                MLDSA_SIGN_INIT_S+13: data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S1_4_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_4_BASE};
                MLDSA_SIGN_INIT_S+14: data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S1_5_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_5_BASE};
                MLDSA_SIGN_INIT_S+15: data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S1_6_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S1_6_BASE};
                //NTT(s2)
                MLDSA_SIGN_INIT_S+16: data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_0_BASE};
                MLDSA_SIGN_INIT_S+17: data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_1_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_1_BASE};
                MLDSA_SIGN_INIT_S+18 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_2_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_2_BASE};
                MLDSA_SIGN_INIT_S+19 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_3_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_3_BASE};
                MLDSA_SIGN_INIT_S+20 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_4_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_4_BASE};
                MLDSA_SIGN_INIT_S+21 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_5_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_5_BASE};
                MLDSA_SIGN_INIT_S+22 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_6_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_6_BASE};
                MLDSA_SIGN_INIT_S+23 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLDSA_S2_7_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_S2_7_BASE};

                //lfsr_seed=Keccak(re_entropy||counter)
                MLDSA_SIGN_LFSR_S       : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:ABR_ENTROPY_ID, operand2:ABR_NOP, operand3:ABR_NOP};                
                MLDSA_SIGN_LFSR_S+ 1    : data_o_rom <= '{opcode:ABR_UOP_SHAKE256,    imm:'h0000, length:'d08, operand1:ABR_CNT_ID,     operand2:ABR_NOP, operand3:ABR_DEST_LFSR_SEED_REG_ID};
                MLDSA_SIGN_LFSR_S+ 2    : data_o_rom <= '{opcode:ABR_UOP_LFSR,        imm:'h0000, length:'d00, operand1:ABR_NOP,        operand2:ABR_NOP, operand3:ABR_NOP};
                //y=ExpandMask(?' ,?)
                MLDSA_SIGN_MAKE_Y_S     : data_o_rom <= '{opcode:ABR_UOP_MASKED_EXP_MASK, imm:'h0000, length:'d66, operand1:MLDSA_RHO_P_KAPPA_ID, operand2:ABR_NOP, operand3:MLDSA_Y_0_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 1  : data_o_rom <= '{opcode:ABR_UOP_MASKED_EXP_MASK, imm:'h0001, length:'d66, operand1:MLDSA_RHO_P_KAPPA_ID, operand2:ABR_NOP, operand3:MLDSA_Y_1_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 2  : data_o_rom <= '{opcode:ABR_UOP_MASKED_EXP_MASK, imm:'h0002, length:'d66, operand1:MLDSA_RHO_P_KAPPA_ID, operand2:ABR_NOP, operand3:MLDSA_Y_2_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 3  : data_o_rom <= '{opcode:ABR_UOP_MASKED_EXP_MASK, imm:'h0003, length:'d66, operand1:MLDSA_RHO_P_KAPPA_ID, operand2:ABR_NOP, operand3:MLDSA_Y_3_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 4  : data_o_rom <= '{opcode:ABR_UOP_MASKED_EXP_MASK, imm:'h0004, length:'d66, operand1:MLDSA_RHO_P_KAPPA_ID, operand2:ABR_NOP, operand3:MLDSA_Y_4_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 5  : data_o_rom <= '{opcode:ABR_UOP_MASKED_EXP_MASK, imm:'h0005, length:'d66, operand1:MLDSA_RHO_P_KAPPA_ID, operand2:ABR_NOP, operand3:MLDSA_Y_5_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 6  : data_o_rom <= '{opcode:ABR_UOP_MASKED_EXP_MASK, imm:'h0006, length:'d66, operand1:MLDSA_RHO_P_KAPPA_ID, operand2:ABR_NOP, operand3:MLDSA_Y_6_BASE};
                //NTT(Y)
                MLDSA_SIGN_MAKE_Y_S+ 7  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0001, length:'d00, operand1:MLDSA_Y_0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_Y_0_NTT_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 8  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0001, length:'d00, operand1:MLDSA_Y_1_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_Y_1_NTT_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 9  : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0001, length:'d00, operand1:MLDSA_Y_2_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_Y_2_NTT_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 10 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0001, length:'d00, operand1:MLDSA_Y_3_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_Y_3_NTT_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 11 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0001, length:'d00, operand1:MLDSA_Y_4_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_Y_4_NTT_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 12 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0001, length:'d00, operand1:MLDSA_Y_5_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_Y_5_NTT_BASE};
                MLDSA_SIGN_MAKE_Y_S+ 13 : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT,  imm:'h0001, length:'d00, operand1:MLDSA_Y_6_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_Y_6_NTT_BASE};
                //A? ?ExpandA(?) AND A? ?NTT(y)
                MLDSA_SIGN_MAKE_W_S     : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0000, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 1  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0001, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 2  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0002, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 3  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0003, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 4  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0004, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 5  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0005, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 6  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0006, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 7  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 8  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0100, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 9  : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0101, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 10 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0102, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 11 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0103, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 12 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0104, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 13 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0105, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 14 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0106, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 15 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_1_BASE};
                
                MLDSA_SIGN_MAKE_W_S+ 16 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0200, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 17 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0201, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 18 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0202, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 19 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0203, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 20 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0204, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 21 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0205, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 22 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0206, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 23 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_2_BASE};

                MLDSA_SIGN_MAKE_W_S+ 24 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0300, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 25 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0301, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 26 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0302, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 27 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0303, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 28 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0304, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 29 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0305, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 30 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0306, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 31 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_3_BASE};

                MLDSA_SIGN_MAKE_W_S+ 32 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0400, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 33 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0401, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 34 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0402, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 35 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0403, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 36 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0404, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 37 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0405, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 38 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0406, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 39 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_4_BASE};
    
                MLDSA_SIGN_MAKE_W_S+ 40 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0500, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 41 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0501, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 42 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0502, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 43 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0503, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 44 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0504, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 45 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0505, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 46 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0506, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 47 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_5_BASE};
                
                MLDSA_SIGN_MAKE_W_S+ 48 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0600, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 49 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0601, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 50 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0602, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 51 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0603, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 52 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0604, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 53 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0605, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 54 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0606, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 55 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_6_BASE};
                
                MLDSA_SIGN_MAKE_W_S+ 56 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWM,  imm:'h0700, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_0_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 57 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0701, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_1_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 58 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0702, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_2_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 59 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0703, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_3_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 60 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0704, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_4_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 61 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0705, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_5_NTT_BASE, operand3:MLDSA_AY0_BASE};
                MLDSA_SIGN_MAKE_W_S+ 62 : data_o_rom <= '{opcode:ABR_UOP_REJS_MASKED_PWMA, imm:'h0706, length:'d34, operand1:MLDSA_CONSTANT_RHO /*MLDSA_RHO_ID*/, operand2:MLDSA_Y_6_NTT_BASE, operand3:MLDSA_AY0_BASE};

                MLDSA_SIGN_MAKE_W_S+ 63 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT,  imm:'h0001, length:'d00, operand1:MLDSA_AY0_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_W0_7_BASE};
                
                //(w1,w0) ?Decompose(w) AND c??H(?||w1Encode(w1),2?)
                // DECOMPOSE_R absorbs W0_0..W0_7 recombine into its read pipeline.
                MLDSA_SIGN_MAKE_W_S+ 64 : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:MLDSA_MU_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_MAKE_W       : data_o_rom <= '{opcode:ABR_UOP_DECOMPOSE_R, imm:'h0000, length:'d00, operand1:MLDSA_W0_0_BASE, operand2:ABR_NOP, operand3:MLDSA_W0_0_BASE}; 

                MLDSA_SIGN_MAKE_C       : data_o_rom <= '{opcode:ABR_UOP_RUN_SHAKE256, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:MLDSA_DEST_SIG_C_REG_ID};
                MLDSA_SIGN_MAKE_C+ 1    : data_o_rom <= '{opcode:ABR_UOP_SIB, imm:'h0000, length:'d64, operand1: MLDSA_CONSTANT_C /* MLDSA_SIG_C_REG_ID*/, operand2:ABR_NOP, operand3:ABR_NOP};

                //NTT(C) - MASKED_NTT_NOSHUF: both NTTs produce identical C_NTT
                //at identical addresses (no shuffling divergence since c is public)
                MLDSA_SIGN_VALID_S     : data_o_rom <= '{opcode:ABR_UOP_MASKED_NTT_NOSHUF, imm:'h0000, length:'d00, operand1:MLDSA_C_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_C_NTT_BASE};

		//Compute Z and perform norm check
                MLDSA_SIGN_VALID_S+1      : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S1_0_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+2      : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS1_BASE};
                MLDSA_SIGN_VALID_S+3      : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'h0000, length:'d00, operand1:MLDSA_CS1_BASE, operand2:MLDSA_Y_0_BASE, operand3:MLDSA_Z_BASE};
                MLDSA_SIGN_VALID_S+4      : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+5      : data_o_rom <= '{opcode:ABR_UOP_SIGENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:15'h000};

                // 30 NOPs
                MLDSA_SIGN_VALID_S+6       : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+7       : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+8       : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+9       : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+10     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+11     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+12     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+13     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+14     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+15     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+16     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+17     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+18     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+19     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+20     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+21     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+22     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+23     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+24     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+25     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+26     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+27     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+28     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+29     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+30     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+31     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+32     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+33     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+34     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+35     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
         

  
                MLDSA_SIGN_VALID_S+36   : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM,  imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S1_1_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+37   : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS1_BASE};
                MLDSA_SIGN_VALID_S+38   : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA,  imm:'h0000, length:'d00, operand1:MLDSA_CS1_BASE, operand2:MLDSA_Y_1_BASE, operand3:MLDSA_Z_BASE};
                MLDSA_SIGN_VALID_S+39   : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R,   imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+40   : data_o_rom <= '{opcode:ABR_UOP_SIGENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:15'h040};
                
                // 30 NOPs
             	MLDSA_SIGN_VALID_S+41   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+42   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+43   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+44   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+45   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+46   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+47   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+48   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+49   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+50   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+51   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+52   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+53   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+54   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+55   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+56   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+57   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+58   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+59   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+60   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+61   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+62   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+63   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+64   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+65   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+66   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+67   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+68   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+69   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+70   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                
                MLDSA_SIGN_VALID_S+71   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+72   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+73   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+74   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+75   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+76   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+77   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+78   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+79   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+80   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+81   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+82   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+83   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+84   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+85   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+86   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+87   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+88   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+89   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                
 
                MLDSA_SIGN_VALID_S+90   : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S1_2_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+91   : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS1_BASE};
                MLDSA_SIGN_VALID_S+92   : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'h0000, length:'d00, operand1:MLDSA_CS1_BASE, operand2:MLDSA_Y_2_BASE, operand3:MLDSA_Z_BASE};
                MLDSA_SIGN_VALID_S+93   : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+94   : data_o_rom <= '{opcode:ABR_UOP_SIGENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:15'h080};


 		// 100 NOPs
             	MLDSA_SIGN_VALID_S+95   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+96   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+97   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+98   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+99   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+100   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+101   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+102   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+103   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+104   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+105   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+106   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+107   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+108   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+109   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+110   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+111   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+112   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+113   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+114   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+115   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+116   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+117   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+118   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+119   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+120   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+121   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+122   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+123   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+124   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+125   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+126   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+127   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+128   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+129   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+130   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+131   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+132   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+133   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+134   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+135   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+136   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+137   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+138   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+139   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+140   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+141   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+142   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+143   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+144   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+145   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+146   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+147   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+148   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+149   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+150   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+151   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+152   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+153   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+154   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+155   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+156   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+157   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+158   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+159   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+160   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+161   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+162   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+163   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+164   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+165   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+166   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+167   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+168   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+169   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+170   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+171   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+172   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+173   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+174   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+175   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+176   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+177   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+178   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+179   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+180   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+181   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+182   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+183   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+184   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+185   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+186   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+187   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+188   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+189   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+190   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+191   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+192   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+193   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+194   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
               
                

                MLDSA_SIGN_VALID_S+195  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S1_3_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+196  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS1_BASE};
                MLDSA_SIGN_VALID_S+197  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'h0000, length:'d00, operand1:MLDSA_CS1_BASE, operand2:MLDSA_Y_3_BASE, operand3:MLDSA_Z_BASE};
		MLDSA_SIGN_VALID_S+198  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+199  : data_o_rom <= '{opcode:ABR_UOP_SIGENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:15'h0C0};                


		// 100 NOPs
             	MLDSA_SIGN_VALID_S+200   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+201   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+202   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+203   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+204   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+205   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+206   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+207   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+208   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+209   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+210   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+211   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+212   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+213   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+214   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+215   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+216   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+217   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+218   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+219   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+220   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+221   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+222   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+223   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+224   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+225   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+226   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+227   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+228   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+229   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+230   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+231   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+232   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+233   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+234   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+235   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+236   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+237   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+238   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+239   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+240   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+241   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+242   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+243   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+244   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+245   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+246   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+247   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+248   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+249   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+250   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+251   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+252   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+253   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+254   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+255   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+256   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+257   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+258   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+259   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+260   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+261   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+262   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+263   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+264   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+265   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+266   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+267   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+268   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+269   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+270   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+271   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+272   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+273   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+274   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+275   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+276   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+277   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+278   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+279   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+280   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+281   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+282   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+283   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+284   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+285   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+286   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+287   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+288   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+289   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+290   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+291   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+292   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+293   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+294   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+295   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+296   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+297   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+298   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+299   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};

		MLDSA_SIGN_VALID_S+300  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S1_4_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+301  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS1_BASE};
                MLDSA_SIGN_VALID_S+302  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'h0000, length:'d00, operand1:MLDSA_CS1_BASE, operand2:MLDSA_Y_4_BASE, operand3:MLDSA_Z_BASE};
		MLDSA_SIGN_VALID_S+303  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+304  : data_o_rom <= '{opcode:ABR_UOP_SIGENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:15'h100};

		// 100 NOPs
             	MLDSA_SIGN_VALID_S+305   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+306   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+307   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+308   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+309   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+310   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+311   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+312   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+313   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+314   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+315   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+316   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+317   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+318   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+319   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+320   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+321   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+322   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+323   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+324   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+325   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+326   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+327   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+328   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+329   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+330   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+331   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+332   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+333   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+334   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+335   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+336   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+337   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+338   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+339   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+340   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+341   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+342   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+343   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+344   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+345   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+346   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+347   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+348   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+349   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+350   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+351   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+352   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+353   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+354   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+355   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+356   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+357   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+358   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+359   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+360   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+361   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+362   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+363   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+364   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+365   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+366   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+367   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+368   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+369   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+370   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+371   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+372   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+373   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+374   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+375   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+376   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+377   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+378   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+379   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+380   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+381   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+382   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+383   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+384   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+385   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+386   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+387   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+388   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+389   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+390   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+391   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+392   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+393   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+394   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+395   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+396   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+397   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+398   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+399   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+400   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+401   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+402   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+403   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+404   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
               
		MLDSA_SIGN_VALID_S+405  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S1_5_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+406  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS1_BASE};
                MLDSA_SIGN_VALID_S+407  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'h0000, length:'d00, operand1:MLDSA_CS1_BASE, operand2:MLDSA_Y_5_BASE, operand3:MLDSA_Z_BASE};
		MLDSA_SIGN_VALID_S+408  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+409  : data_o_rom <= '{opcode:ABR_UOP_SIGENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:15'h140};


		// 100 NOPs
             	MLDSA_SIGN_VALID_S+410   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+411   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+412   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+413   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+414   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+415   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+416   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+417   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+418   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+419   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+420   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+421   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+422   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+423   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+424   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+425   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+426   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+427   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+428   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+429   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+430   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+431   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+432   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+433   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+434   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+435   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+436   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+437   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+438   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+439   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+440   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+441   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+442   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+443   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+444   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+445   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+446   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+447   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+448   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+449   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+450   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+451   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+452   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+453   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+454   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+455   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+456   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+457   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+458   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+459   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+460   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+461   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+462   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+463   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+464   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+465   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+466   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+467   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+468   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+469   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+470   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+471   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+472   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+473   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+474   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+475   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+476   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+477   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+478   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+479   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+480   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+481   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+482   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+483   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+484   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+485   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+486   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+487   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+488   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+489   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+490   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+491   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+492   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+493   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+494   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+495   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+496   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+497   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+498   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+499   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+500   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+501   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+502   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+503   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+504   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+505   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+506   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+507   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+508   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+509   : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
              
		MLDSA_SIGN_VALID_S+510  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S1_6_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+511  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS1_BASE};
                MLDSA_SIGN_VALID_S+512  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWA, imm:'h0000, length:'d00, operand1:MLDSA_CS1_BASE, operand2:MLDSA_Y_6_BASE, operand3:MLDSA_Z_BASE};
                MLDSA_SIGN_VALID_S+513  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+514  : data_o_rom <= '{opcode:ABR_UOP_SIGENCODE_R, imm:'h0000, length:'d00, operand1:MLDSA_Z_BASE, operand2:ABR_NOP, operand3:15'h180};


                MLDSA_SIGN_VALID_S+515  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T0_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+516  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_0_BASE};
                MLDSA_SIGN_VALID_S+517  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T1_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+518  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_1_BASE};
                MLDSA_SIGN_VALID_S+519  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T2_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+520  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_2_BASE};
                MLDSA_SIGN_VALID_S+521  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T3_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+522  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_3_BASE};
                MLDSA_SIGN_VALID_S+523  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T4_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+524  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_4_BASE};
                MLDSA_SIGN_VALID_S+525  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T5_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+526  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_5_BASE};
                MLDSA_SIGN_VALID_S+527  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T6_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+528  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_6_BASE};
                MLDSA_SIGN_VALID_S+529  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T7_BASE, operand3:MLDSA_CT_NTT_BASE};
                MLDSA_SIGN_VALID_S+530  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CT_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CT_7_BASE};
                //Make R0, CT0 and Hint_r
                MLDSA_SIGN_VALID_S+531  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_0_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+532  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+533  : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_0_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+534  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+535  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+536  : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_0_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_0_BASE};

                MLDSA_SIGN_VALID_S+537  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_1_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+538  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+539  : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_1_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+540  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+541  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_1_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+542  : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_1_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_1_BASE};

                MLDSA_SIGN_VALID_S+543  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_2_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+544  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+545  : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_2_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+546  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+547  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_2_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+548  : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_2_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_2_BASE};

                MLDSA_SIGN_VALID_S+549  : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_3_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+550  : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+551  : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_3_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+552  : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+553 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_3_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+554 : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_3_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_3_BASE};

                MLDSA_SIGN_VALID_S+555 : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_4_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+556 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+557 : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_4_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+558 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+559 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_4_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+560 : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_4_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_4_BASE};

                MLDSA_SIGN_VALID_S+561 : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_5_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+562 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+563 : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_5_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+564 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+565 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_5_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+566 : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_5_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_5_BASE};

                MLDSA_SIGN_VALID_S+567 : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_6_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+568 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+569 : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_6_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+570 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+571 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_6_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+572 : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_6_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_6_BASE};

                MLDSA_SIGN_VALID_S+573 : data_o_rom <= '{opcode:ABR_UOP_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_S2_7_BASE, operand3:MLDSA_CS_NTT_BASE};
                MLDSA_SIGN_VALID_S+574 : data_o_rom <= '{opcode:ABR_UOP_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLDSA_CS_NTT_BASE, operand2:MLDSA_TEMP2_BASE, operand3:MLDSA_CS2_BASE};
                MLDSA_SIGN_VALID_S+575 : data_o_rom <= '{opcode:ABR_UOP_PWS_R, imm:'h0000, length:'d00, operand1:MLDSA_CS2_BASE, operand2:MLDSA_W0_7_BASE, operand3:MLDSA_R0_BASE};
                MLDSA_SIGN_VALID_S+576 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_R0, length:'d00, operand1:MLDSA_R0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+577 : data_o_rom <= '{opcode:ABR_UOP_NORMCHK_R, imm:MLDSA_NORMCHK_CT0, length:'d00, operand1:MLDSA_CT_7_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_VALID_S+578 : data_o_rom <= '{opcode:ABR_UOP_PWA_R, imm:'h0000, length:'d00, operand1:MLDSA_CT_7_BASE, operand2:MLDSA_R0_BASE, operand3:MLDSA_HINT_R_7_BASE};

                MLDSA_SIGN_VALID_S+579 : data_o_rom <= '{opcode:ABR_UOP_MAKEHINT, imm:'h0000, length:'d00, operand1:MLDSA_HINT_R_0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};


                MLDSA_SIGN_CHL_E        : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_SIGN_E            : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};

                //Verify flow
                //(?,t1)?pkDecode(pk)
                MLDSA_VERIFY_S          : data_o_rom <= '{opcode:ABR_UOP_PKDECODE, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:MLDSA_T0_BASE};
                //(c?,z,h)?sigDecode(?) 
                MLDSA_VERIFY_S+ 1       : data_o_rom <= '{opcode:ABR_UOP_SIGDEC_Z, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:MLDSA_Z_0_BASE};
                //||z||? ? ?1 -?
                MLDSA_VERIFY_S+ 2       : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_0_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_S+ 3       : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_1_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_S+ 4       : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_2_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_S+ 5       : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_3_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_S+ 6       : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_4_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_S+ 7       : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_5_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_S+ 8       : data_o_rom <= '{opcode:ABR_UOP_NORMCHK, imm:MLDSA_NORMCHK_Z, length:'d00, operand1:MLDSA_Z_6_BASE, operand2:ABR_NOP, operand3:ABR_NOP};
                //tr ?H(pk,512)
                MLDSA_VERIFY_H_TR           : data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:PUBKEY_NUM_BYTES, operand1:MLDSA_PK_REG_ID, operand2:ABR_NOP, operand3:MLDSA_DEST_TR_REG_ID};
                MLDSA_VERIFY_CHECK_MODE     : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                //? ?H(tr||M,512)
                MLDSA_VERIFY_H_MU           : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:MLDSA_TR_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_H_MU+ 1        : data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:'d66, operand1:MLDSA_MSG_ID, operand2:ABR_NOP, operand3:MLDSA_DEST_MU_REG_ID};
                //c ?SampleInBall(c?1)
                MLDSA_VERIFY_MAKE_C         : data_o_rom <= '{opcode:ABR_UOP_SIB, imm:'h0000, length:'d64, operand1:MLDSA_SIG_C_REG_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                //c? ?NTT(c)
                MLDSA_VERIFY_NTT_C          : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_C_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_C_NTT_BASE};
                //t1 ?NTT(t1)
                MLDSA_VERIFY_NTT_T1          : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T0_BASE};
                MLDSA_VERIFY_NTT_T1+ 1       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T1_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T1_BASE};
                MLDSA_VERIFY_NTT_T1+ 2       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T2_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T2_BASE};
                MLDSA_VERIFY_NTT_T1+ 3       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T3_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T3_BASE};
                MLDSA_VERIFY_NTT_T1+ 4       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T4_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T4_BASE};
                MLDSA_VERIFY_NTT_T1+ 5       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T5_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T5_BASE};
                MLDSA_VERIFY_NTT_T1+ 6       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T6_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T6_BASE};
                MLDSA_VERIFY_NTT_T1+ 7       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_T7_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_T7_BASE};

                //z ?NTT(z)
                MLDSA_VERIFY_NTT_Z          : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_Z_0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_Z_NTT_0_BASE};
                MLDSA_VERIFY_NTT_Z+ 1       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_Z_1_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_Z_NTT_1_BASE};
                MLDSA_VERIFY_NTT_Z+ 2       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_Z_2_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_Z_NTT_2_BASE};
                MLDSA_VERIFY_NTT_Z+ 3       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_Z_3_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_Z_NTT_3_BASE};
                MLDSA_VERIFY_NTT_Z+ 4       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_Z_4_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_Z_NTT_4_BASE};
                MLDSA_VERIFY_NTT_Z+ 5       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_Z_5_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_Z_NTT_5_BASE};
                MLDSA_VERIFY_NTT_Z+ 6       : data_o_rom <= '{opcode:ABR_UOP_NTT, imm:'h0000, length:'d00, operand1:MLDSA_Z_6_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_Z_NTT_6_BASE};
                //A? ?ExpandA(?) AND A? ?NTT(z)
                MLDSA_VERIFY_EXP_A+ 0       : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0000, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 1       : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0001, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 2       : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0002, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 3       : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0003, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 4       : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0004, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 5       : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0005, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 6       : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0006, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 7       : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T0_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 8       : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 9        : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_0_BASE};
                
                MLDSA_VERIFY_EXP_A+ 10      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0100, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 11      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0101, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 12      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0102, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 13      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0103, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 14      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0104, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 15      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0105, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 16      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0106, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 17      : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T1_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 18      : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 19      : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_1_BASE};
                
                MLDSA_VERIFY_EXP_A+ 20      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0200, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 21      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0201, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 22      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0202, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 23      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0203, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 24      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0204, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 25      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0205, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 26      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0206, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 27      : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T2_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 28      : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 29      : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_2_BASE};
                
                MLDSA_VERIFY_EXP_A+ 30      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0300, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 31      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0301, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 32      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0302, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 33      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0303, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 34      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0304, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 35      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0305, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 36      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0306, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 37      : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T3_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 38      : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 39      : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_3_BASE};
        
                MLDSA_VERIFY_EXP_A+ 40      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0400, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 41      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0401, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 42      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0402, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 43      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0403, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 44      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0404, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 45      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0405, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 46      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0406, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 47      : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T4_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 48      : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 49      : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_4_BASE};
        
                MLDSA_VERIFY_EXP_A+ 50      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0500, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 51      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0501, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 52      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0502, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 53      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0503, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 54      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0504, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 55      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0505, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 56      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0506, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 57      : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T5_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 58      : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 59      : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_5_BASE};
                
                MLDSA_VERIFY_EXP_A+ 60      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0600, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 61      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0601, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 62      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0602, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 63      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0603, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 64      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0604, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 65      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0605, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 66      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0606, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 67      : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T6_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 68      : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 69      : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_6_BASE};
            
                MLDSA_VERIFY_EXP_A+ 70      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWM,  imm:'h0700, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 71      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0701, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_1_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 72      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0702, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_2_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 73      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0703, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_3_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 74      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0704, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_4_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 75      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0705, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_5_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 76      : data_o_rom <= '{opcode:ABR_UOP_REJS_PWMA, imm:'h0706, length:'d34, operand1:MLDSA_RHO_ID, operand2:MLDSA_Z_NTT_6_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 77      : data_o_rom <= '{opcode:ABR_UOP_PWM, imm:'h0000, length:'d00, operand1:MLDSA_C_NTT_BASE, operand2:MLDSA_T7_BASE, operand3:MLDSA_CT_BASE};
                MLDSA_VERIFY_EXP_A+ 78      : data_o_rom <= '{opcode:ABR_UOP_PWS, imm:'h0000, length:'d00, operand1:MLDSA_CT_BASE, operand2:MLDSA_AZ0_BASE, operand3:MLDSA_AZ0_BASE};
                MLDSA_VERIFY_EXP_A+ 79      : data_o_rom <= '{opcode:ABR_UOP_INTT, imm:'h0000, length:'d00, operand1:MLDSA_AZ0_BASE, operand2:MLDSA_TEMP0_BASE, operand3:MLDSA_W0_7_BASE};
     
                MLDSA_VERIFY_RES+ 0         : data_o_rom <= '{opcode:ABR_UOP_SIGDEC_H, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:MLDSA_HINT_R_BASE};
                MLDSA_VERIFY_RES+ 1         : data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:MLDSA_MU_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLDSA_VERIFY_RES+ 2         : data_o_rom <= '{opcode:ABR_UOP_USEHINT, imm:'h0000, length:'d00, operand1:MLDSA_W0_0_BASE, operand2:MLDSA_HINT_R_BASE, operand3:ABR_NOP};
                MLDSA_VERIFY_RES+ 3         : data_o_rom <= '{opcode:ABR_UOP_RUN_SHAKE256, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:MLDSA_DEST_VERIFY_RES_REG_ID};
                MLDSA_VERIFY_E              : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};

                //MLKEM Keygen
                //rnd_seed=Keccak(entropy||counter)
                MLKEM_KG_S   + 0: data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:ABR_ENTROPY_ID, operand2:ABR_NOP, operand3:ABR_NOP};                
                MLKEM_KG_S   + 1: data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:'d08, operand1:ABR_CNT_ID, operand2:ABR_NOP, operand3:ABR_DEST_LFSR_SEED_REG_ID};
                MLKEM_KG_S   + 2: data_o_rom <= '{opcode:ABR_UOP_LFSR, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLKEM_KG_S   + 3: data_o_rom <= '{opcode:ABR_UOP_SHA512, imm:'h0004, length:'d33, operand1:MLKEM_SEED_D_ID, operand2:ABR_NOP, operand3:MLKEM_DEST_RHO_SIGMA_REG_ID};
                MLKEM_KG_S   + 4: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0000, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_S0_BASE};
                MLKEM_KG_S   + 5: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0001, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_S1_BASE};
                MLKEM_KG_S   + 6: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0002, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_S2_BASE};
                MLKEM_KG_S   + 7: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0003, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_S3_BASE};
                MLKEM_KG_S   + 8: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0004, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_E0_BASE};
                MLKEM_KG_S   + 9: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0005, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_E1_BASE};
                MLKEM_KG_S  + 10: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0006, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_E2_BASE};
                MLKEM_KG_S  + 11: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0007, length:'d33, operand1:MLKEM_SIGMA_ID, operand2:ABR_NOP, operand3:MLKEM_E3_BASE};
                MLKEM_KG_S  + 12: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_S0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_S0_BASE};
                MLKEM_KG_S  + 13: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_S1_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_S1_BASE};
                MLKEM_KG_S  + 14: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_S2_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_S2_BASE};
                MLKEM_KG_S  + 15: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_S3_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_S3_BASE};
                MLKEM_KG_S  + 16: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_E0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_E0_BASE};
                MLKEM_KG_S  + 17: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_E1_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_E1_BASE};
                MLKEM_KG_S  + 18: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_E2_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_E2_BASE};
                MLKEM_KG_S  + 19: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_E3_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_E3_BASE};
                MLKEM_KG_S  + 20: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM , imm:'h0000, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S0_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 21: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0001, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S1_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 22: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0002, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S2_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 23: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0003, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S3_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 24: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWA,       imm:'h0000, length:'d00, operand1:MLKEM_AS0_BASE, operand2:MLKEM_E0_BASE, operand3:MLKEM_T0_BASE};
                MLKEM_KG_S  + 25: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM , imm:'h0100, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S0_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 26: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0101, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S1_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 27: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0102, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S2_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 28: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0103, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S3_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 29: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWA,       imm:'h0000, length:'d00, operand1:MLKEM_AS0_BASE, operand2:MLKEM_E1_BASE, operand3:MLKEM_T1_BASE};
                MLKEM_KG_S  + 30: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM , imm:'h0200, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S0_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 31: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0201, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S1_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 32: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0202, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S2_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 33: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0203, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S3_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 34: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWA,       imm:'h0000, length:'d00, operand1:MLKEM_AS0_BASE, operand2:MLKEM_E2_BASE, operand3:MLKEM_T2_BASE};
                MLKEM_KG_S  + 35: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM , imm:'h0300, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S0_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 36: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0301, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S1_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 37: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0302, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S2_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 38: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0303, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_S3_BASE, operand3:MLKEM_AS0_BASE};
                MLKEM_KG_S  + 39: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWA,       imm:'h0000, length:'d00, operand1:MLKEM_AS0_BASE, operand2:MLKEM_E3_BASE, operand3:MLKEM_T3_BASE};
                MLKEM_KG_S  + 40: data_o_rom <= '{opcode:ABR_UOP_COMPRESS_R, imm:'h0403, length:'d00, operand1:MLKEM_T0_BASE, operand2:ABR_NOP, operand3:MLKEM_DEST_EK_MEM_OFFSET};
                MLKEM_KG_S  + 41: data_o_rom <= '{opcode:ABR_UOP_COMPRESS_R, imm:'h0403, length:'d00, operand1:MLKEM_S0_BASE, operand2:ABR_NOP, operand3:MLKEM_DEST_DK_MEM_OFFSET};
                MLKEM_KG_S  + 42: data_o_rom <= '{opcode:ABR_UOP_SHA256, imm:'h0000, length:EK_NUM_BYTES, operand1:MLKEM_EK_REG_ID, operand2:ABR_NOP, operand3:MLKEM_DEST_TR_REG_ID};
                MLKEM_KG_E : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                //MLKEM Decaps
                //rnd_seed=Keccak(entropy||counter)
                MLKEM_DECAPS_S   + 0: data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:ABR_ENTROPY_ID, operand2:ABR_NOP, operand3:ABR_NOP};                
                MLKEM_DECAPS_S   + 1: data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:'d08, operand1:ABR_CNT_ID, operand2:ABR_NOP, operand3:ABR_DEST_LFSR_SEED_REG_ID};
                MLKEM_DECAPS_S   + 2: data_o_rom <= '{opcode:ABR_UOP_LFSR, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLKEM_DECAPS_S   + 3: data_o_rom <= '{opcode:ABR_UOP_SHA256, imm:'h0000, length:EK_NUM_BYTES, operand1:MLKEM_EK_REG_ID, operand2:ABR_NOP, operand3:MLKEM_DEST_TR_REG_ID};
                MLKEM_DECAPS_S   + 4: data_o_rom <= '{opcode:ABR_UOP_MASKED_DECOMPRESS, imm:'h0403, length:'d00, operand1:MLKEM_SRC_DK_MEM_OFFSET, operand2:ABR_NOP, operand3:MLKEM_S0_BASE};
                MLKEM_DECAPS_S   + 5: data_o_rom <= '{opcode:ABR_UOP_DECOMPRESS, imm:'h0402, length:'d00, operand1:MLKEM_SRC_C1_MEM_OFFSET, operand2:ABR_NOP, operand3:MLKEM_U0_BASE};
                MLKEM_DECAPS_S   + 6: data_o_rom <= '{opcode:ABR_UOP_DECOMPRESS, imm:'h0101, length:'d00, operand1:MLKEM_SRC_C2_MEM_OFFSET, operand2:ABR_NOP, operand3:MLKEM_V_BASE};
                MLKEM_DECAPS_S   + 7: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_U0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP0_BASE};
                MLKEM_DECAPS_S   + 8: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_U1_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP1_BASE};
                MLKEM_DECAPS_S   + 9: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_U2_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP2_BASE};
                MLKEM_DECAPS_S  + 10: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_U3_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP3_BASE};
                MLKEM_DECAPS_S  + 11: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLKEM_S0_BASE, operand2:MLKEM_UP0_BASE, operand3:MLKEM_SU_MASKED_BASE};
                MLKEM_DECAPS_S  + 12: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWMA, imm:'h0000, length:'d00, operand1:MLKEM_S1_BASE, operand2:MLKEM_UP1_BASE, operand3:MLKEM_SU_MASKED_BASE};
                MLKEM_DECAPS_S  + 13: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWMA, imm:'h0000, length:'d00, operand1:MLKEM_S2_BASE, operand2:MLKEM_UP2_BASE, operand3:MLKEM_SU_MASKED_BASE};
                MLKEM_DECAPS_S  + 14: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWMA, imm:'h0000, length:'d00, operand1:MLKEM_S3_BASE, operand2:MLKEM_UP3_BASE, operand3:MLKEM_SU_MASKED_BASE};
                MLKEM_DECAPS_S  + 15: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLKEM_SU_MASKED_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_SU_BASE};
                // Fused PWS_R - absorbs the prior RECOMBINE into PWS's pwm_b read.
                MLKEM_DECAPS_S  + 16: data_o_rom <= '{opcode:ABR_UOP_MLKEM_PWS_R, imm:'h0000, length:'d00, operand1:MLKEM_SU_BASE, operand2:MLKEM_V_BASE, operand3:MLKEM_V_BASE};
                MLKEM_DECAPS_S  + 17: data_o_rom <= '{opcode:ABR_UOP_COMPRESS, imm:'h0100, length:'d00, operand1:MLKEM_V_BASE, operand2:ABR_NOP, operand3:MLKEM_DEST_MSG_MEM_OFFSET};
                //MLKEM Encaps
                //rnd_seed=Keccak(entropy||counter)
                MLKEM_ENCAPS_S   + 0: data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256, imm:'h0000, length:'d64, operand1:ABR_ENTROPY_ID, operand2:ABR_NOP, operand3:ABR_NOP};                
                MLKEM_ENCAPS_S   + 1: data_o_rom <= '{opcode:ABR_UOP_SHAKE256, imm:'h0000, length:'d08, operand1:ABR_CNT_ID, operand2:ABR_NOP, operand3:ABR_DEST_LFSR_SEED_REG_ID};
                MLKEM_ENCAPS_S   + 2: data_o_rom <= '{opcode:ABR_UOP_LFSR, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLKEM_ENCAPS_S   + 3: data_o_rom <= '{opcode:ABR_UOP_DECOMPRESS, imm:'h0403, length:'d00, operand1:MLKEM_SRC_EK_MEM_OFFSET, operand2:ABR_NOP, operand3:MLKEM_T0_BASE};
                MLKEM_ENCAPS_S   + 4: data_o_rom <= '{opcode:ABR_UOP_COMPRESS, imm:'h0413, length:'d00, operand1:MLKEM_T0_BASE, operand2:ABR_NOP, operand3:MLKEM_DEST_EK_MEM_OFFSET};
                MLKEM_ENCAPS_S   + 5: data_o_rom <= '{opcode:ABR_UOP_SHA256, imm:'h0000, length:EK_NUM_BYTES, operand1:MLKEM_EK_REG_ID, operand2:ABR_NOP, operand3:MLKEM_DEST_TR_REG_ID};
                MLKEM_ENCAPS_S   + 6: data_o_rom <= '{opcode:ABR_UOP_LD_SHA512, imm:'h0000, length:'d32, operand1:MLKEM_MSG_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLKEM_ENCAPS_S   + 7: data_o_rom <= '{opcode:ABR_UOP_SHA512, imm:'h0000, length:'d32, operand1:MLKEM_TR_ID, operand2:ABR_NOP, operand3:MLKEM_DEST_K_R_REG_ID};
                MLKEM_ENCAPS_S   + 8: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0000, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_Y0_BASE};
                MLKEM_ENCAPS_S   + 9: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0001, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_Y1_BASE};
                MLKEM_ENCAPS_S  + 10: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0002, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_Y2_BASE};
                MLKEM_ENCAPS_S  + 11: data_o_rom <= '{opcode:ABR_UOP_MASKED_CBD, imm:'h0003, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_Y3_BASE};
                MLKEM_ENCAPS_S  + 12: data_o_rom <= '{opcode:ABR_UOP_CBD, imm:'h0004, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_E0_BASE};
                MLKEM_ENCAPS_S  + 13: data_o_rom <= '{opcode:ABR_UOP_CBD, imm:'h0005, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_E1_BASE};
                MLKEM_ENCAPS_S  + 14: data_o_rom <= '{opcode:ABR_UOP_CBD, imm:'h0006, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_E2_BASE};
                MLKEM_ENCAPS_S  + 15: data_o_rom <= '{opcode:ABR_UOP_CBD, imm:'h0007, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_E3_BASE};
                MLKEM_ENCAPS_S  + 16: data_o_rom <= '{opcode:ABR_UOP_CBD, imm:'h0008, length:'d33, operand1:MLKEM_R_ID, operand2:ABR_NOP, operand3:MLKEM_E_2_BASE};
                MLKEM_ENCAPS_S  + 17: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_Y0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_Y0_BASE};
                MLKEM_ENCAPS_S  + 18: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_Y1_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_Y1_BASE};
                MLKEM_ENCAPS_S  + 19: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_Y2_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_Y2_BASE};
                MLKEM_ENCAPS_S  + 20: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_NTT, imm:'h0000, length:'d00, operand1:MLKEM_Y3_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_Y3_BASE};
                MLKEM_ENCAPS_S  + 21: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM, imm:'h0000, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y0_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 22: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0100, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y1_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 23: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0200, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y2_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 24: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0300, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y3_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 25: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLKEM_AY0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP0_BASE};
                MLKEM_ENCAPS_S  + 26: data_o_rom <= '{opcode:ABR_UOP_MLKEM_PWA, imm:'h0000, length:'d00, operand1:MLKEM_UP0_BASE, operand2:MLKEM_E0_BASE, operand3:MLKEM_UP0_BASE};
                // RECOMBINE(UP0) absorbed into COMPRESS_R at +53.
                MLKEM_ENCAPS_S  + 27: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM, imm:'h0001, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y0_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 28: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0101, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y1_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 29: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0201, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y2_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 30: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0301, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y3_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 31: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLKEM_AY0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP1_BASE};
                MLKEM_ENCAPS_S  + 32: data_o_rom <= '{opcode:ABR_UOP_MLKEM_PWA, imm:'h0000, length:'d00, operand1:MLKEM_UP1_BASE, operand2:MLKEM_E1_BASE, operand3:MLKEM_UP1_BASE};
                MLKEM_ENCAPS_S  + 33: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM, imm:'h0002, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y0_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 34: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0102, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y1_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 35: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0202, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y2_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 36: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0302, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y3_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 37: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLKEM_AY0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP2_BASE};
                MLKEM_ENCAPS_S  + 38: data_o_rom <= '{opcode:ABR_UOP_MLKEM_PWA, imm:'h0000, length:'d00, operand1:MLKEM_UP2_BASE, operand2:MLKEM_E2_BASE, operand3:MLKEM_UP2_BASE};
                MLKEM_ENCAPS_S  + 39: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWM, imm:'h0003, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y0_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 40: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0103, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y1_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 41: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0203, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y2_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 42: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_REJS_PWMA, imm:'h0303, length:'d34, operand1:MLKEM_RHO_ID, operand2:MLKEM_Y3_BASE, operand3:MLKEM_AY0_BASE};
                MLKEM_ENCAPS_S  + 43: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLKEM_AY0_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_UP3_BASE};
                MLKEM_ENCAPS_S  + 44: data_o_rom <= '{opcode:ABR_UOP_MLKEM_PWA, imm:'h0000, length:'d00, operand1:MLKEM_UP3_BASE, operand2:MLKEM_E3_BASE, operand3:MLKEM_UP3_BASE};
                MLKEM_ENCAPS_S  + 45: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWM, imm:'h0000, length:'d00, operand1:MLKEM_T0_BASE, operand2:MLKEM_Y0_BASE, operand3:MLKEM_TY_MASKED_BASE};
                MLKEM_ENCAPS_S  + 46: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWMA, imm:'h0000, length:'d00, operand1:MLKEM_T1_BASE, operand2:MLKEM_Y1_BASE, operand3:MLKEM_TY_MASKED_BASE};
                MLKEM_ENCAPS_S  + 47: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWMA, imm:'h0000, length:'d00, operand1:MLKEM_T2_BASE, operand2:MLKEM_Y2_BASE, operand3:MLKEM_TY_MASKED_BASE};
                MLKEM_ENCAPS_S  + 48: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_PWMA, imm:'h0000, length:'d00, operand1:MLKEM_T3_BASE, operand2:MLKEM_Y3_BASE, operand3:MLKEM_TY_MASKED_BASE};
                MLKEM_ENCAPS_S  + 49: data_o_rom <= '{opcode:ABR_UOP_MLKEM_MASKED_INTT, imm:'h0000, length:'d00, operand1:MLKEM_TY_MASKED_BASE, operand2:ABR_TEMP0_BASE, operand3:MLKEM_V_BASE};
                MLKEM_ENCAPS_S  + 50: data_o_rom <= '{opcode:ABR_UOP_MLKEM_PWA, imm:'h0000, length:'d00, operand1:MLKEM_V_BASE, operand2:MLKEM_E_2_BASE, operand3:MLKEM_V_BASE};
                MLKEM_ENCAPS_S  + 51: data_o_rom <= '{opcode:ABR_UOP_DECOMPRESS, imm:'h0100, length:'d00, operand1:MLKEM_SRC_MSG_MEM_OFFSET, operand2:ABR_NOP, operand3:MLKEM_MU_BASE};
                MLKEM_ENCAPS_S  + 52: data_o_rom <= '{opcode:ABR_UOP_MLKEM_PWA, imm:'h0000, length:'d00, operand1:MLKEM_V_BASE, operand2:MLKEM_MU_BASE, operand3:MLKEM_V_BASE};
                MLKEM_ENCAPS_S  + 53: data_o_rom <= '{opcode:ABR_UOP_COMPRESS_R, imm:'h0422, length:'d00, operand1:MLKEM_UP0_BASE, operand2:ABR_NOP, operand3:MLKEM_DEST_C1_MEM_OFFSET};
                MLKEM_ENCAPS_S  + 54: data_o_rom <= '{opcode:ABR_UOP_COMPRESS_R, imm:'h0121, length:'d00, operand1:MLKEM_V_BASE, operand2:ABR_NOP, operand3:MLKEM_DEST_C2_MEM_OFFSET};
                MLKEM_ENCAPS_E + 0 : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
                MLKEM_DECAPS_CHK + 0: data_o_rom <= '{opcode:ABR_UOP_LD_SHAKE256,  imm:'h0000, length:'d32, operand1:MLKEM_SEED_Z_ID, operand2:ABR_NOP, operand3:ABR_NOP};
                MLKEM_DECAPS_CHK + 1: data_o_rom <= '{opcode:ABR_UOP_SHAKE256,  imm:'h0000, length:CT_NUM_BYTES, operand1:MLKEM_CIPHERTEXT_ID, operand2:ABR_NOP, operand3:MLKEM_DEST_K_REG_ID};
                MLKEM_DECAPS_E + 0 : data_o_rom <= '{opcode:ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};

                default :              data_o_rom <= '{opcode: ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
            endcase 
    end
    else begin
        data_o_rom <= '{opcode: ABR_UOP_NOP, imm:'h0000, length:'d00, operand1:ABR_NOP, operand2:ABR_NOP, operand3:ABR_NOP};
    end
end

endmodule
