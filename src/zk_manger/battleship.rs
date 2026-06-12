use std::fmt;
use crate::circuits::battleship;
use binius_core::Word;
use rand::random;
use sha2::{Digest, Sha256};
use binius_core::verify::verify_constraints;
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128, Prover};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{Verifier, config::StdChallenger};
use serde::{Deserialize, Serialize};

//出界错误
#[derive(Debug)]
pub struct OutsideError{
    details: String,
}

impl OutsideError {
    fn new(msg: &str) -> Self {
        OutsideError { details: msg.to_string() }
    }
}
impl fmt::Display for OutsideError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}
impl std::error::Error for OutsideError {}


/// 棋盘证明的公开数据
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitChessboardPublic {
    pub cont: u64,
    pub size: u64,
    pub out_hash: [u64; 4],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitChessboardProof{
    pub public_words: Vec<u64>,
    pub proof: Vec<u8>,
}

/// 攻击证明的公开数据
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackCircuitPublic {
    pub cont: u64,
    pub size: u64,
    pub out_hash: [u64; 4],
    pub attack_piece: u64,
    pub out_attack_result: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackCircuitProof{
    pub public_words: Vec<u64>,
    pub proof: Vec<u8>,
}

impl InitChessboardPublic {
    /// 从 public_words 提取（顺序由电路 init_chessboard 保证）
    pub fn from_public_words(proof: &InitChessboardProof) -> Option<Self> {
        let chess = battleship::init_chessboard();

        let cont = *proof.public_words.get(chess.circuit.witness_index(chess.cont).0 as usize)?;
        let size = *proof.public_words.get(chess.circuit.witness_index(chess.size).0 as usize)?;
        let mut out_hash = [0u64; 4];
        for i in 0..4 {
            out_hash[i] = *proof.public_words.get(chess.circuit.witness_index(chess.out_hash[i]).0 as usize)?;
        }
        Some(Self { cont, size, out_hash })
    }
}

impl AttackCircuitPublic {
    /// 从 public_words 提取（顺序由电路 init_chessboard 保证）
    pub fn from_public_words(proof: &AttackCircuitProof) -> Option<Self> {
        let chess = battleship::attack();

        let cont = *proof.public_words.get(chess.circuit.witness_index(chess.cont).0 as usize)?;
        let size = *proof.public_words.get(chess.circuit.witness_index(chess.size).0 as usize)?;
        let mut out_hash = [0u64; 4];
        for i in 0..4 {
            out_hash[i] = *proof.public_words.get(chess.circuit.witness_index(chess.out_hash[i]).0 as usize)?;
        }
        let attack_piece = *proof.public_words.get(chess.circuit.witness_index(chess.attack_piece).0 as usize)?;
        let out_attack_result = *proof.public_words.get(chess.circuit.witness_index(chess.out_attack_result).0 as usize)?;
        Some(Self { cont, size, out_hash,attack_piece,out_attack_result })
    }
}


//证明棋盘的初始化状态
pub fn init_chessboard_prove(cont:u64, size:u64, pieces:&[u8]) ->  Result<(InitChessboardProof,[u8;32]), Box<dyn std::error::Error>>  {
    // 电路信息
    let chessboard_circuit = battleship::init_chessboard();
    // 证明信息传输器
    let mut witness = chessboard_circuit.circuit.new_witness_filler();

    witness[chessboard_circuit.cont]=Word(cont);
    witness[chessboard_circuit.size]=Word(size);

    // 打包 8 个坐标（每坐标 1 字节）进 1 个 wire
    let mut packed = 0u64;
    for (i, &coord) in pieces.iter().take(8).enumerate() {
        packed |= (coord as u64) << (i * 8);
    }
    witness[chessboard_circuit.piece[0]] = Word(packed);

    //生成随机数
    let nonce:[u8;32] =random();
    // nonce（4 wires × 8 字节 = 32 字节）
    for i in 0..4 {
        let bytes = std::array::from_fn::<u8, 8, _>(|j| nonce[i * 8 + j]);
        witness[chessboard_circuit.nonce[i]] = Word(u64::from_le_bytes(bytes));
    }


    // 计算 SHA256(pieces || nonce)，填入 out_hash
    let mut msg = [0u8; 40];
    msg[..8].copy_from_slice(&pieces[..8]);
    msg[8..].copy_from_slice(&nonce);
    let digest: [u8; 32] = Sha256::digest(msg).into();
    for i in 0..4 {
        let bytes = std::array::from_fn::<u8, 8, _>(|j| digest[i * 8 + j]);
        witness[chessboard_circuit.out_hash[i]] = Word(u64::from_be_bytes(bytes));
    }


    // 电路评估 + 断言检查
    if let Err(e) = chessboard_circuit.circuit.populate_wire_witness(&mut witness) {
        return Err(e.into());
    }

    let cs = chessboard_circuit.circuit.constraint_system();    // &ConstraintSystem
    let witness_vec = witness.into_value_vec();                  // 消耗 witness
    verify_constraints(cs, &witness_vec)?;                       // 调试

    // 填写公开值
    let public_words: Vec<u64> = witness_vec.public().iter()
        .map(|w| w.as_u64())
        .collect();

    let verifier = Verifier::<StdHashSuite>::setup(cs.clone(), 1)?;
    let prover = Prover::<OptimalPackedB128, StdHashSuite>::setup(verifier.clone())?;

    let mut pt = ProverTranscript::new(StdChallenger::default());
    prover.prove(witness_vec, &mut pt)?;                         // 消耗 witness_vec
    let proof = pt.finalize();                                   // Vec<u8>



    Ok((InitChessboardProof{public_words,proof},nonce))
}

pub fn init_chessboard_verify(
    proof: &InitChessboardProof,
) -> Result<(), Box<dyn std::error::Error>> {
    // 电路验证
    let chess = battleship::init_chessboard();
    let cs = chess.circuit.constraint_system().clone();
    let verifier = Verifier::<StdHashSuite>::setup(cs, 1)?;

    let public_words: Vec<Word> = proof.public_words.iter()
        .map(|&x| Word(x))
        .collect();

    let mut vt = VerifierTranscript::new(StdChallenger::default(), proof.proof.clone());
    verifier.verify(&public_words, &mut vt).map_err(|e| {
        e
    })?;
    vt.finalize()?;
    Ok(())
}


pub fn attack_prove(cont:&u64, size:&u64, pieces:&[u8;8],nonce:&[u8;32],attack_piece:&u64) ->  Result<AttackCircuitProof, Box<dyn std::error::Error>>  {
    // 电路信息
    let circuit = battleship::attack();
    // 证明信息传输器
    let mut witness = circuit.circuit.new_witness_filler();

    witness[circuit.cont]=Word(cont.clone());
    witness[circuit.size]=Word(size.clone());

    // 打包 8 个坐标（每坐标 1 字节）进 1 个 wire
    let mut packed = 0u64;
    for (i, &coord) in pieces.iter().take(8).enumerate() {
        packed |= (coord as u64) << (i * 8);
    }
    witness[circuit.piece[0]] = Word(packed);

    // nonce（4 wires × 8 字节 = 32 字节）
    for i in 0..4 {
        let bytes = std::array::from_fn::<u8, 8, _>(|j| nonce[i * 8 + j]);
        witness[circuit.nonce[i]] = Word(u64::from_le_bytes(bytes));
    }


    // 计算 SHA256(pieces || nonce)，填入 out_hash
    let mut msg = [0u8; 40];
    msg[..8].copy_from_slice(&pieces[..8]);
    msg[8..].copy_from_slice(nonce);
    let digest: [u8; 32] = Sha256::digest(msg).into();
    for i in 0..4 {
        let bytes = std::array::from_fn::<u8, 8, _>(|j| digest[i * 8 + j]);
        witness[circuit.out_hash[i]] = Word(u64::from_be_bytes(bytes));
    }

    // 计算攻击是否出界
    if attack_piece.clone() >= size.clone() || attack_piece.clone() >= 256u64 {
        return Err(OutsideError::new("攻击超出界限").into());
    }

    // 计算攻击是否成功
    let mut attack_result:u64 = 0;
    for i in pieces.iter(){
        let ii = i.clone() as u64;
        if attack_piece.eq(&ii){
            attack_result=1;
        }
    }
    witness[circuit.out_attack_result] = Word(attack_result);

    // 电路评估 + 断言检查
    if let Err(e) = circuit.circuit.populate_wire_witness(&mut witness) {
        return Err(e.into());
    }

    let cs = circuit.circuit.constraint_system();    // &ConstraintSystem
    let witness_vec = witness.into_value_vec();                  // 消耗 witness
    verify_constraints(cs, &witness_vec)?;                       // 调试

    // 填写公开值
    let public_words: Vec<u64> = witness_vec.public().iter()
        .map(|w| w.as_u64())
        .collect();

    let verifier = Verifier::<StdHashSuite>::setup(cs.clone(), 1)?;
    let prover = Prover::<OptimalPackedB128, StdHashSuite>::setup(verifier.clone())?;

    let mut pt = ProverTranscript::new(StdChallenger::default());
    prover.prove(witness_vec, &mut pt)?;                         // 消耗 witness_vec
    let proof = pt.finalize();                                   // Vec<u8>



    Ok((AttackCircuitProof{public_words,proof}))
}

pub fn attack_verify(
    proof: &AttackCircuitProof,
) -> Result<(), Box<dyn std::error::Error>> {
    // 电路验证
    let chess = battleship::attack();
    let cs = chess.circuit.constraint_system().clone();
    let verifier = Verifier::<StdHashSuite>::setup(cs, 1)?;

    let public_words: Vec<Word> = proof.public_words.iter()
        .map(|&x| Word(x))
        .collect();

    let mut vt = VerifierTranscript::new(StdChallenger::default(), proof.proof.clone());
    verifier.verify(&public_words, &mut vt).map_err(|e| {
        e
    })?;
    vt.finalize()?;
    Ok(())
}