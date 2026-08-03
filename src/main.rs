use std::time::Instant;
use battleship_zkp::circuits::battleship::{attack, init_chessboard};
use battleship_zkp::zk_manger::battleship::{attack_prove, attack_verify, init_chessboard_prove, init_chessboard_verify, AttackCircuitPublic, InitChessboardProof, InitChessboardPublic, OutsideError};


/// 仅作为测试
/// 
fn main() {
    init_chessboard();
    attack();

    let t0 = Instant::now();
    let pieces:[u8;8]=[2,5,0,0,0,0,0,0];
    let proof:InitChessboardProof;
    let nonce;
    let cont:u64 = 2;
    let size:u64 = 25;
    let attack_piece = 1;
    match init_chessboard_prove(cont,size,&pieces) {
        Ok(p)=>{
            proof=p.0;
            nonce=p.1;
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
            println!("公开值：{},{}", public.count, public.size);
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

    let a_prove;


    // 攻击证明
    match attack_prove(&cont, &size, &pieces, &nonce, &attack_piece) {
        Ok(p)=>{
            a_prove=p;
            match AttackCircuitPublic::from_public_words(&a_prove) {
                Some(a)=>{
                    if a.out_attack_result==0 {
                        println!("攻击结果已证明：未命中");
                    }else {
                        println!("攻击结果已证明：命中");
                    }
                    println!("攻击坐标：{}",a.attack_piece);
                }

                _ => {println!("攻击结果已证明：公开值读取失败");}
            }

        },
        Err(e) => {
            if e.downcast_ref::<OutsideError>().is_some() {
                eprintln!("证明失败: 攻击超出范围");
            } else {
                eprintln!("证明失败: {}", e);
            }
            return;
        }
    }
    let t4 = Instant::now();
    println!("  攻击证明速度: {:?}", t4 - t3);
    // 攻击验证
    match attack_verify(&a_prove) {
        Ok(_)=>{
            println!("攻击验证成功")
        },
        Err(e)=>{
            println!("{}", e);
        }
    }

    let t5 = Instant::now();
    println!("  攻击验证速度: {:?}", t5 - t4);

}
