module Trivium(
  output keystream,
  input clk,
  input rst);

  reg [287:0] r = 288'b0;
  reg temp = 0;
  wire t1 = 0;
  wire t2 = 0;
  wire t3 = 0;

  assign keystream = 0;

  always @(posedge clk, posedge rst)
  begin
    if (rst)
    begin
      keystream = 4'b0;
    end
    else
      t1 <= r[65] ^ r[92];
      t2 <= r[161] ^ r[176];
      t3 <= r[242] ^ r[287];
      temp <= t1 ^ t2 ^ t3;
      t1 <= t1 ^ r[90] & r[91] ^ r[170];
      t2 <= t2 ^ r[174] & r[175] ^ r[263];
      t3 <= t3 ^ r[285] & r[286] ^ r[68];
      r <= {r[0],r[287:1]};
      r[0] <= t3;
      r[93] <= t1;
      r[177] <= t2;
  end
endmodule