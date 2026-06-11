
use std::sync::OnceLock;
use binius_circuits::bytes::swap_bytes_32;
use binius_circuits::sha256::sha256_fixed;
use binius_frontend::{Circuit, CircuitBuilder, Wire};

/// 静态缓存
static CHESSBOARD: OnceLock<ChessboardCircuit> = OnceLock::new();
// 传出电路与传输线的结构体
pub struct ChessboardCircuit {
    pub circuit: Circuit,
    pub cont: Wire,
    pub size: Wire,
    pub piece: [Wire; 1],
    pub nonce: [Wire; 4],
    pub out_hash: [Wire; 4],
}

/// 棋盘初始化证明与存证哈希
pub fn init_chessboard()->&'static ChessboardCircuit{
    CHESSBOARD.get_or_init(|| {
        let builder:CircuitBuilder = CircuitBuilder::new();

        // 随机数
        let nonce:[_; 4] = core::array::from_fn(|_| builder.add_witness());
        // 棋子数量
        let cont = builder.add_inout();
        // 棋盘大小
        let size = builder.add_inout();
        // 多个棋子坐标，每个棋子使用一个字节
        let piece:[_; 1] = core::array::from_fn(|_| builder.add_witness());


        // 棋子坐标+nonce的哈希
        let out_hash:[_; 4] = core::array::from_fn(|_| builder.add_inout());

        // 计算
        // 消息拼接 坐标+nonce
        let message: Vec<_> = piece.into_iter().chain(nonce).collect();

        // 坐标拆分
        let piece_list: Vec<Wire> = (0..8)
            .map(|j| builder.extract_byte(piece[0], j))
            .collect();

        // 约束
        // 棋子数量小于9
        builder.assert_true("A",
                            builder.icmp_ult(
                                cont,
                                builder.add_constant_64(9)
                            )
        );
        // 棋子数量不为0
        builder.assert_non_zero("count_non_zero",cont);
        // 棋盘大小不超过256
        builder.assert_true("B",
                            builder.icmp_ult(
                                size,
                                builder.add_constant_64(257)
                            )
        );
        // 棋盘大小不小于棋子数量
        builder.assert_true("C",
                            builder.icmp_ule(cont,size)
        );



        // 棋子位置+nonce的sha256哈希正确
        // let sha256 = Sha256::new(&builder,builder.add_constant_64(40),out_hash, message);
        assert_sha256(&builder,&message,out_hash);
        // 棋盘检查
        chessboard_check(&builder,&piece_list,cont,size);

        let circuit = builder.build();

        ChessboardCircuit {
                circuit,
                cont,
                size,
                piece,
                nonce,
                out_hash,
        }
    })
}

// 棋盘检查
// 棋子格子没有冲突，没有超出棋盘大小
fn chessboard_check(builder: &CircuitBuilder,piece:&Vec<Wire>,cont:Wire,size:Wire){

    for i in 0..piece.len() {

        // 有限棋子不超过范围
        builder.assert_false("D",
            // 属于棋子范围并且小于棋盘范围 1 band 0 == 0
            // 属于棋子范围并且大于等于棋盘范围 1 band 1 == 1
            // 不属于棋子范围并且小于棋盘范围 0 band 0 == 0
            // 不属于棋子范围并且大于等于棋盘范围 0 band 1 == 0
            builder.band(
                // 判断属于棋子范围，属于为1，不属于为0
                builder.icmp_ult(builder.add_constant_64(i as u64),cont),
                // 判断棋子小于棋盘范围，大于等于为1，小于为0
                builder.icmp_uge(piece[i],size)
            )
        );


        // 检查是否存在重复位置
        for j in (i + 1)..piece.len() {
            // 判断有限数量内没有重复的棋子
            builder.assert_false("E",
                 // 棋子属于范围且位置不同 1 band 0 == 0
                 // 棋子属于范围且位置相同 1 band 1 == 1
                 // 棋子不属于范围且位置不同 0 band 0 == 0
                 // 棋子不属于范围且位置相同 0 band 1 == 0
                 builder.band(
                     // 判断两个元素同时属于棋子范围，同时属于范围内为 1
                     builder.band(
                         builder.icmp_ult(builder.add_constant_64(i as u64),cont),
                         builder.icmp_ult(builder.add_constant_64(j as u64),cont)
                     ),
                     // 判断两个棋子位置是否相同，相同为1
                     builder.icmp_eq(
                         piece[i],
                         piece[j]
                     )
                 )
            )

        }
    }
}
/// SHA256 电路约束：验证 `message` 的自然序哈希等于 `hash`。
///
/// # 数据格式
/// - message: 每线 8 字节，小端序打包（自然序）
/// - hash: [Wire; 4]，64 位大端序字
///
/// # 原理
/// 内部用 `swap_bytes_32` 将自然序转为大端序，传给 `sha256_fixed`。
/// 所有转换均为门约束，自动推导中间值，不依赖外部填充。
/// 摘要从 8×32 位自动拼装为 4×64 位与 hash 比对。
pub fn assert_sha256(builder: &CircuitBuilder, message: &[Wire], hash: [Wire; 4]) {
    // ① 端序转换：自然序 → 大端序 32 位字
    let mut msg32 = Vec::with_capacity(message.len() * 2);
    for &w in message {
        let s = swap_bytes_32(builder, w);
        let mask = builder.add_constant_64(0xFFFF_FFFF);
        msg32.push(builder.band(s, mask));            // 低 32 位
        msg32.push(builder.band(builder.shr(s, 32), mask)); // 高 32 位（原本在低 32 的大端序值）
    }

    // ② 电路内 SHA256
    let digest = sha256_fixed(builder, &msg32, message.len() * 8);

    // ③ 摘要比对：8×32位 → 4×64位
    for i in 0..4 {
        let hi = builder.band(digest[i * 2],     builder.add_constant_64(0xFFFF_FFFF));
        let lo = builder.band(digest[i * 2 + 1], builder.add_constant_64(0xFFFF_FFFF));
        let word = builder.bxor(lo, builder.shl(hi, 32));
        builder.assert_eq("digest", hash[i], word);
    }
}
