use ark_bn254::G1Affine;
use ark_bn254::G2Affine;
use ark_serialize::CanonicalDeserialize;
use hex::FromHex;
use near_bigint::U256;
use near_groth16_verifier::G1Point;
use near_groth16_verifier::G2Point;
use near_groth16_verifier::Proof;
use near_sdk::json_types::Base64VecU8;
use near_sdk::json_types::U128;
use near_sdk::{Gas, NearToken};
use near_workspaces::{Account, Contract, DevNetwork, Worker};
use risc0_groth16::Seal;
use risc0_zkvm::serde::from_slice;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use serde_json::json;
use serde_json::Value;

const VERIFIER_DATA: &str =
    include_str!("../../../plonky2-reputation/reputation_proof.verify.json");
const PROOF: &str = include_str!("../../../plonky2-reputation/reputation_proof.json");

#[derive(Serialize, Deserialize)]
struct VerificationData {
    pub common: String,
    pub verifier: String,
}

pub fn verification_data() -> (Base64VecU8, Base64VecU8) {
    let data: VerificationData = serde_json::from_str(VERIFIER_DATA).unwrap();
    let common = Base64VecU8(near_sdk::base64::decode(data.common).unwrap());
    let verifier = Base64VecU8(near_sdk::base64::decode(data.verifier).unwrap());

    return (common, verifier);
}

fn split_digest(digest: Digest) -> (U256, U256) {
    let (a, b) = risc0_groth16::split_digest(digest).unwrap();
    (U256(a.0 .0), U256(b.0 .0))
}

pub const BN254_CONTROL_ID: &str =
    "10ff834dbef62ccbba201ecd26a772e3036a075aacbaf47200679a11dcdcf10d";
pub const ALLOWED_IDS_ROOT: &str =
    "88c1f749250aba181168c33839d7a351671e7a5b7f3e746dde91ef6c6e9ef344";

#[test]
fn test_digest() {
    let d = Digest::from_hex(ALLOWED_IDS_ROOT).unwrap();
    let (a, b) = split_digest(d);
    let (a1, b1) = risc0_groth16::split_digest(d).unwrap();

    assert_eq!(a.to_string(), a1.0.to_string());
    assert_eq!(b.to_string(), b1.0.to_string());

    let id_p254_hash = U256::from_str_radix(BN254_CONTROL_ID, 16).unwrap();
    let id_p254_hash1 = risc0_groth16::fr_from_hex_string(BN254_CONTROL_ID).unwrap();
    assert_eq!(id_p254_hash.to_string(), id_p254_hash1.0.to_string());
}

async fn init(
    worker: &Worker<impl DevNetwork>,
    initial_balance: U128,
    arguments: serde_json::Value,
) -> anyhow::Result<(Contract, Account)> {
    let contract = worker
        .dev_deploy(
            &include_bytes!("../../../target/near/testing_contract/testing_contract.wasm").to_vec(),
        )
        .await?;

    let res = contract
        .call("new")
        .args_json(arguments)
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    println!("{:?}", res.logs());

    let alice = contract
        .as_account()
        .create_subaccount("alice")
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await?
        .into_result()?;

    return Ok((contract, alice));
}

#[tokio::test]
async fn test_plonky() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (common, verifier) = verification_data();

    let (contract, alice) = init(
        &worker,
        NearToken::from_near(10).as_yoctonear().into(),
        json!({
            "common": common,
            "verifier": verifier,
        }),
    )
    .await
    .unwrap();

    println!("{:?}", Gas::from_tgas(300));
    let res = contract
        .call("verify_proof")
        .args_json(json!({
            "proof": PROOF,
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    println!("{:?}", res.logs());
    assert!(res.is_success(), "{:?}", res);
    Ok(())
}

fn g1_from_bytes(elem: &[Vec<u8>]) -> G1Point {
    G1Point {
        x: U256::from_big_endian(&elem[0]),
        y: U256::from_big_endian(&elem[1]),
    }
}

// Deserialize an element over the G2 group from bytes in big-endian format
fn g2_from_bytes(elem: &Vec<Vec<Vec<u8>>>) -> G2Point {
    G2Point {
        x: [
            U256::from_big_endian(&elem[0][1]),
            U256::from_big_endian(&elem[0][0]),
        ],
        y: [
            U256::from_big_endian(&elem[1][1]),
            U256::from_big_endian(&elem[1][0]),
        ],
    }
}

const ALPHA_X: &str =
    "20491192805390485299153009773594534940189261866228447918068658471970481763042";
const ALPHA_Y: &str =
    "9383485363053290200918347156157836566562967994039712273449902621266178545958";
const BETA_X1: &str =
    "4252822878758300859123897981450591353533073413197771768651442665752259397132";
const BETA_X2: &str =
    "6375614351688725206403948262868962793625744043794305715222011528459656738731";
const BETA_Y1: &str =
    "21847035105528745403288232691147584728191162732299865338377159692350059136679";
const BETA_Y2: &str =
    "10505242626370262277552901082094356697409835680220590971873171140371331206856";
const GAMMA_X1: &str =
    "11559732032986387107991004021392285783925812861821192530917403151452391805634";
const GAMMA_X2: &str =
    "10857046999023057135944570762232829481370756359578518086990519993285655852781";
const GAMMA_Y1: &str =
    "4082367875863433681332203403145435568316851327593401208105741076214120093531";
const GAMMA_Y2: &str =
    "8495653923123431417604973247489272438418190587263600148770280649306958101930";
const DELTA_X1: &str =
    "17459137677540232029121579111806194201335604911445641118023073971023969565095";
const DELTA_X2: &str =
    "16850927772192893321067430466725055468022063819919435552018169508037555801891";
const DELTA_Y1: &str =
    "16440269342816906375775882524040730637133399248560416660251195197654028701204";
const DELTA_Y2: &str =
    "20318668496029522144912607185068507665315850570859328375503723843595483973858";
const IC0_X: &str = "8446592859352799428420270221449902464741693648963397251242447530457567083492";
const IC0_Y: &str = "1064796367193003797175961162477173481551615790032213185848276823815288302804";
const IC1_X: &str = "3179835575189816632597428042194253779818690147323192973511715175294048485951";
const IC1_Y: &str = "20895841676865356752879376687052266198216014795822152491318012491767775979074";
const IC2_X: &str = "5332723250224941161709478398807683311971555792614491788690328996478511465287";
const IC2_Y: &str = "21199491073419440416471372042641226693637837098357067793586556692319371762571";
const IC3_X: &str = "12457994489566736295787256452575216703923664299075106359829199968023158780583";
const IC3_Y: &str = "19706766271952591897761291684837117091856807401404423804318744964752784280790";
const IC4_X: &str = "19617808913178163826953378459323299110911217259216006187355745713323154132237";
const IC4_Y: &str = "21663537384585072695701846972542344484111393047775983928357046779215877070466";
const IC5_X: &str = "6834578911681792552110317589222010969491336870276623105249474534788043166867";
const IC5_Y: &str = "15060583660288623605191393599883223885678013570733629274538391874953353488393";

#[tokio::test]
async fn test_risc0() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    #[derive(Deserialize)]
    struct Dg {
        digest: Digest,
    }
    let digest: Dg =
        serde_json::from_str(include_str!("../../../risc0-reputation/digest")).unwrap();
    let verifier_key = risc0_groth16::verifier::prepared_verifying_key().unwrap();
    let p = verifier_key.vk.alpha_g1.clone();
    let p =  
    let alpha1 = G1Point {
        x: U256(verifier_key.vk.alpha_g1.x.0 .0),
        y: U256(verifier_key.vk.alpha_g1.y.0 .0),
    };
    print(&alpha1);
    let beta2 = G2Point {
        x: [
            U256::from_dec_str(&BETA_X2).unwrap(),
            U256::from_dec_str(&BETA_X1).unwrap(),
        ],
        y: [
            U256::from_dec_str(&BETA_Y2).unwrap(),
            U256::from_dec_str(&BETA_Y1).unwrap(),
        ],
    };
    let gamma2 = G2Point {
        x: [
            U256::from_dec_str(&GAMMA_X2).unwrap(),
            U256::from_dec_str(&GAMMA_X1).unwrap(),
        ],
        y: [
            U256::from_dec_str(&GAMMA_Y2).unwrap(),
            U256::from_dec_str(&GAMMA_Y1).unwrap(),
        ],
    };
    let delta2 = G2Point {
        x: [
            U256::from_dec_str(&DELTA_X2).unwrap(),
            U256::from_dec_str(&DELTA_X1).unwrap(),
        ],
        y: [
            U256::from_dec_str(&DELTA_Y2).unwrap(),
            U256::from_dec_str(&DELTA_Y1).unwrap(),
        ],
    };
    print1(&beta2);
    print1(&gamma2);
    print1(&delta2);

    let ic = [
        IC0_X, IC0_Y, IC1_X, IC1_Y, IC2_X, IC2_Y, IC3_X, IC3_Y, IC4_X, IC4_Y, IC5_X, IC5_Y,
    ]
    .chunks(2)
    .map(|(a)| G1Point {
        x: U256::from_dec_str(a[0]).unwrap(),
        y: U256::from_dec_str(a[1]).unwrap(),
    })
    .collect::<Vec<_>>();
    ic.iter().for_each(print);

    let (a0, a1) = split_digest(Digest::from_hex(ALLOWED_IDS_ROOT).unwrap());
    let id_p254_hash = U256::from_dec_str(
        &risc0_groth16::fr_from_hex_string(BN254_CONTROL_ID)
            .unwrap()
            .0
            .to_string(),
    )
    .unwrap();
    let (contract, alice) = init(
        &worker,
        NearToken::from_near(10).as_yoctonear().into(),
        json!({
            "alfa1": alpha1,
            "beta2": beta2,
            "gamma2": gamma2,
            "delta2": delta2,
            "ic": ic,
            "a_public": [a0, a1],
            "id_p254_hash_public": id_p254_hash,
            "digest": digest.digest,
        }),
    )
    .await
    .unwrap();

    println!("{:?}", Gas::from_tgas(300));
    #[derive(Deserialize)]
    struct Pf {
        proof: Receipt,
    }
    let proof = include_str!("../../../risc0-reputation/proof");
    let value: Pf = serde_json::from_str(proof).unwrap();
    let value = value.proof;
    let compact = value.inner.compact().unwrap();

    value.verify(digest.digest).unwrap();
    println!("{:?}", compact);

    let seal = Seal::from_vec(&compact.seal).unwrap();
    let a = g1_from_bytes(&seal.a);
    let b = g2_from_bytes(&seal.b);
    let c = g1_from_bytes(&seal.c);
    let proof = Proof { a, b, c };

    print(&proof.a);
    print1(&proof.b);
    print(&proof.c);

    let res = contract
        .call("verify_proof")
        .args_json(json!({
            "proof": proof,
            "claim": compact.claim,
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    println!("{:?}", res.logs());
    println!("{:?}", res.receipt_failures());
    assert!(res.is_success(), "{:?}", res);
    Ok(())
}

fn print(point: &G1Point) {
    println!("________________________-");
    println!("{}", &hex::encode(point.x.to_le_bytes()));
    println!("{}", &hex::encode(point.y.to_le_bytes()));
    println!("________________________-");
}

fn print1(point: &G2Point) {
    println!("________________________-");
    println!("{:?}", hex::encode(point.x[0].to_le_bytes()));
    println!("{:?}", hex::encode(point.x[1].to_le_bytes()));
    println!("{:?}", hex::encode(point.y[0].to_le_bytes()));
    println!("{:?}", hex::encode(point.y[1].to_le_bytes()));
    println!("________________________-");
}
