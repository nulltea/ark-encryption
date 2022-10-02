use ark_std::test_rng;
use ark_bls12_381::{Bls12_381 as ProjectiveEngine};
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar as CurveVar, EdwardsProjective as Curve, Fq,
};
use ark_ff::Field;
use ark_groth16::Groth16;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_encryption::{EncryptCircuit, Parameters, poseidon};

type Circuit = EncryptCircuit::<Curve, CurveVar>;

fn main() {
    let mut rng = test_rng();
    let bytes = [1, 2, 3];
    let msg = vec![Fq::from_random_bytes(&bytes).unwrap()];

    let params = Parameters::<Curve> {
        n: 1,
        poseidon: poseidon::get_poseidon_params::<Curve>(2),
    };
    let (_, pub_key) = Circuit::keygen(&mut rng).unwrap();

    let circuit = Circuit::new(
        pub_key.clone(),
        msg.clone().into(),
        params.clone(),
        &mut rng,
    ).unwrap();

    let (pk, vk) = Groth16::<ProjectiveEngine>::setup(circuit, &mut rng).unwrap();

    let circuit = Circuit::new(pub_key, msg.clone().into(), params.clone(), &mut rng).unwrap();
    let enc = circuit.resulted_ciphertext.clone();
    let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

    let public_inputs = Circuit::get_public_inputs::<ProjectiveEngine>(&enc, &params);
    let valid_proof = Groth16::<ProjectiveEngine>::verify(&vk, &public_inputs, &proof).unwrap();
    assert!(valid_proof);
}
