// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{log, near_bindgen};

// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Contract {}

// Define the default, which automatically initializes the contract
impl Default for Contract {
    fn default() -> Self {
        Self {}
    }
}

// Implement the contract structure
#[near_bindgen]
impl Contract {
    // Public method - returns the greeting saved, defaulting to DEFAULT_GREETIN
}

#[cfg(test)]
mod test {
    use near_bigint::U256;
    use near_groth16_verifier::{hash_to_field, CommitmentKey, G1Point, G2Point};

    fn parse_g1_point(point_data: &serde_json::Value) -> G1Point {
        G1Point {
            x: U256::from_dec_str(point_data["X"].as_str().unwrap()).unwrap(),
            y: U256::from_dec_str(point_data["Y"].as_str().unwrap()).unwrap(),
        }
    }

    fn parse_g2_point(point_data: &serde_json::Value) -> G2Point {
        G2Point {
            x: [
                U256::from_dec_str(point_data["X"]["A0"].as_str().unwrap()).unwrap(),
                U256::from_dec_str(point_data["X"]["A1"].as_str().unwrap()).unwrap(),
            ],
            y: [
                U256::from_dec_str(point_data["Y"]["A0"].as_str().unwrap()).unwrap(),
                U256::from_dec_str(point_data["Y"]["A1"].as_str().unwrap()).unwrap(),
            ],
        }
    }

    #[test]
    fn test() {
        use near_groth16_verifier::{Proof, Verifier};

        let vk_json: &str = include_str!("../../../gnark-plonky2-verifier/verification_key.json");
        let vk_data: serde_json::Value =
            serde_json::from_str(vk_json).expect("Failed to parse vk.json");
        let alfa1 = parse_g1_point(&vk_data["G1"]["Alpha"]);
        let beta2 = parse_g2_point(&vk_data["G2"]["Beta"]);
        let gamma2 = parse_g2_point(&vk_data["G2"]["Gamma"]);
        let delta2 = parse_g2_point(&vk_data["G2"]["Delta"]);

        let ic: Vec<G1Point> = vk_data["G1"]["K"]
            .as_array()
            .unwrap()
            .iter()
            .map(parse_g1_point)
            .collect();

        let public_and_commitment_commited: Vec<Vec<U256>> = vk_data
            ["PublicAndCommitmentCommitted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|array| {
                array
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| U256::from_dec_str(x.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect();

        let key = CommitmentKey {
            a: beta2.clone(),
            b: beta2.clone(),
        };

        let verifier = Verifier::new(
            alfa1,
            beta2,
            gamma2,
            delta2,
            ic,
            public_and_commitment_commited,
            key,
        );

        let proof_json = include_str!("../../../gnark-plonky2-verifier/proof.json");
        let proof_data: serde_json::Value =
            serde_json::from_str(proof_json).expect("Failed to parse proof.json");

        let a = parse_g1_point(&proof_data["Ar"]);
        let b = parse_g2_point(&proof_data["Bs"]);
        let c = parse_g1_point(&proof_data["Krs"]);

        let commitments = proof_data["Commitments"]
            .as_array()
            .unwrap()
            .iter()
            .map(parse_g1_point)
            .collect();
        let commitments_pok = parse_g1_point(&proof_data["CommitmentPok"]);

        let proof = Proof {
            a,
            b,
            c,
            commitments,
            commitments_pok,
        };

        let witness_json = include_str!("../../../gnark-plonky2-verifier/pubwitness.json");
        let witness_data: serde_json::Value =
            serde_json::from_str(witness_json).expect("Failed to parse witness.json");
        let public_inputs: Vec<_> = witness_data["PublicInputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| {
                if input["Limb"].is_string() {
                    input["Limb"].as_str().unwrap().to_string()
                } else {
                    input["Limb"].as_u64().unwrap().to_string()
                }
            })
            .map(|x| U256::from_dec_str(x.as_str()).unwrap())
            .collect();

        println!("{:?}", public_inputs);

        assert!(verifier.verify(public_inputs, proof));
    }
}
