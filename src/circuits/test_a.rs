use binius_core::Word;
use binius_frontend::{Circuit, CircuitBuilder, Wire};



pub fn a()->Circuit{
    //新建电路
    let builder:CircuitBuilder = CircuitBuilder::new();
    //私有输入
    let p1 :Wire= builder.add_witness();
    //公开输入
    let p2:Wire = builder.add_inout();
    //输出比对
    let o3:Wire=builder.add_inout();
    //输入相乘
    let (high,low) =builder.imul(p1, p2);
    //约束高64位为零
    builder.assert_false("A",high);
    //约束计算结果与输出相等
    builder.assert_eq("B",o3,low);
    //构建电路
    builder.build()
}