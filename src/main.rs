use std::time::Instant;
use crate::circuits::battleship::init_chessboard;
use crate::zk_manger::battleship::{init_chessboard_prove, init_chessboard_verify, InitChessboardProof, InitChessboardPublic};

mod circuits;
mod zk_manger;

fn main() {
    init_chessboard();

    let t0 = Instant::now();
    let pieces:[u8;8]=[1,0,0,0,0,0,0,0];
    let proof:InitChessboardProof;
    match init_chessboard_prove(1,25,&pieces) {
        Ok(p)=>{
            proof=p;
            println!("证明成功！");
        },
        Err(e)=>{
            println!("证明失败{}", e);
            let t1 = Instant::now();
            println!(" 证明速度: {:?}", t1 - t0);
            return;
        }
    }
    let t1 = Instant::now();
    println!(" 证明速度: {:?}", t1 - t0);

    match InitChessboardPublic::from_public_words(&proof) {
        Some(public)=>{
            println!("公开值：{},{}",public.cont,public.size);
        }
        _ => {}
    }
    let t2 = Instant::now();
    println!("  转换公开值速度: {:?}", t2 - t1);


    match init_chessboard_verify(&proof) {
        Ok(_)=>{
            println!("验证成功！")
        },
        Err(e)=>{
            println!("{}",e)
        }
    }
    let t3 = Instant::now();
    println!("  验证速度: {:?}", t3 - t2);

}
