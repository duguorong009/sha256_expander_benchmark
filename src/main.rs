use arith::SimdField;
use circuit_std_rs::sha256::gf2::SHA256GF2;
use expander_compiler::frontend::*;
use expander_transcript::BytesHashTranscript;
use gkr_engine::Transcript;
use gkr_hashers::SHA256hasher;
use rand::RngCore;
use sha2::{Digest, Sha256};

// ref: https://github.com/PolyhedraZK/ExpanderCompilerCollection/blob/master/circuit-std-rs/tests/sha256_gf2.rs#L89-L137
const INPUT_LEN: usize = 100 * 8; // input size in bits, must be a multiple of 8
const OUTPUT_LEN: usize = 256; // FIXED 256

declare_circuit!(SHA256Circuit {
    input: [Variable; INPUT_LEN],
    output: [Variable; OUTPUT_LEN],
});

impl Define<GF2Config> for SHA256Circuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let mut hasher = SHA256GF2::new();
        hasher.update(&self.input);
        let output = hasher.finalize(api);
        (0..OUTPUT_LEN).for_each(|i| api.assert_is_equal(output[i], self.output[i]));
    }
}

fn main() {
    assert!(INPUT_LEN % 8 == 0);
    let n_witnesses = SIMDField::<GF2Config>::PACK_SIZE;

    // prepare data
    let mut rng = rand::rng();
    let data = [rng.next_u32() as u8; INPUT_LEN / 8];
    let mut hash = Sha256::new();
    hash.update(data);
    let output = hash.finalize();

    // compile the circuit
    let compile_result =
        compile_cross_layer(&SHA256Circuit::default(), CompileOptions::default()).unwrap();

    // prepare assignment
    let mut assignment = SHA256Circuit::default();
    for i in 0..INPUT_LEN / 8 {
        for j in 0..8 {
            assignment.input[i * 8 + j] = (((data[i] >> (7 - j)) & 1) as u32).into();
        }
    }
    for i in 0..OUTPUT_LEN / 8 {
        for j in 0..8 {
            assignment.output[i * 8 + j] = (((output[i] >> (7 - j) as u32) & 1) as u32).into();
        }
    }

    let assignments = vec![assignment; n_witnesses];
    // solve witness
    let witness = compile_result
        .witness_solver
        .solve_witnesses(&assignments)
        .unwrap();

    // run/verify the circuit
    let output = compile_result.layered_circuit.run(&witness);
    for x in output.iter() {
        assert!(*x);
    }

    // ref: https://github.com/PolyhedraZK/ExpanderCompilerCollection/blob/master/expander_compiler/tests/keccak_gf2_full_crosslayer.rs#L274-L306
    let expander_circuit = compile_result.layered_circuit
        .export_to_expander::<gkr_engine::GF2ExtConfig>()
        .flatten();

    let (simd_input, simd_public_input) = witness.to_simd::<gf2::GF2x8>();
    println!("{} {}", simd_input.len(), simd_public_input.len());
    assert_eq!(simd_public_input.len(), 0); // public input is not supported in current virgo++

    let mut transcript = BytesHashTranscript::<
        <gkr_engine::GF2ExtConfig as gkr_engine::FieldEngine>::ChallengeField,
        SHA256hasher,
    >::new();
    
    let connections = crosslayer_prototype::CrossLayerConnections::parse_circuit(&expander_circuit);
    
    let start_time = std::time::Instant::now();
    let evals = expander_circuit.evaluate(&simd_input);
    let mut sp = crosslayer_prototype::CrossLayerProverScratchPad::<gkr_engine::GF2ExtConfig>::new(
        expander_circuit.layers.len(),
        expander_circuit.max_num_input_var(),
        expander_circuit.max_num_output_var(),
        1,
    );
    let (_output_claim, _input_challenge, _input_claim) = crosslayer_prototype::prove_gkr(
        &expander_circuit,
        &evals,
        &connections,
        &mut transcript,
        &mut sp,
    );
    let stop_time = std::time::Instant::now();
    let duration = stop_time.duration_since(start_time);
    println!("Time elapsed {} ms for proving", duration.as_millis());
}
