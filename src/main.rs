use arith::SimdField;
// use circuit_std_rs::sha256::gf2::SHA256GF2;
use expander_compiler::frontend::*;
use rand::RngCore;
use serdes::ExpSerde;
use sha2::{Digest, Sha256};

// ref: https://github.com/PolyhedraZK/ExpanderCompilerCollection/blob/master/circuit-std-rs/tests/sha256_gf2.rs#L89-L137
const INPUT_LEN: usize = 64 * 8; // input size in bits, must be a multiple of 8
const OUTPUT_LEN: usize = 256; // FIXED 256
const N_HASHES: usize = 32;

declare_circuit!(SHA256Circuit {
    input: [[Variable; INPUT_LEN]; N_HASHES],
    output: [[Variable; OUTPUT_LEN]; N_HASHES], // TODO: use public inputs
});

impl Define<GF2Config> for SHA256Circuit<Variable> {
    fn define(&self, api: &mut API<GF2Config>) {
        for j in 0..N_HASHES {
            let out = compute_sha256(api, &self.input[j].to_vec());
            for i in 0..256 {
                api.assert_is_equal(out[i].clone(), self.output[j][i].clone());
            }
        }
    }
}


fn compute_sha256<C: Config>(api: &mut API<C>, input: &Vec<Variable>) -> Vec<Variable> {
    let h32: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let mut h: Vec<Vec<Variable>> = (0..8).map(|x| int2bit(api, h32[x])).collect(); 

    let k32: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c48, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
//    let k: Vec<Vec<Variable>> = (0..64).map(|x| int2bit(api, k32[x])).collect(); 

    let mut w = vec![vec![api.constant(0); 32]; 64];
    for i in 0..16 {
        w[i] = input[(i * 32)..((i + 1) * 32) as usize].to_vec();
    }
    for i in 16..64 {
        let tmp = xor(api, rotate_right(&w[i - 15], 7), rotate_right(&w[i - 15], 18));
        let shft = shift_right(api, w[i - 15].clone(), 3);
        let s0 = xor(api, tmp, shft);
        let tmp = xor(api, rotate_right(&w[i - 2], 17), rotate_right(&w[i - 2], 19));
        let shft = shift_right(api, w[i - 2].clone(), 10);
        let s1 = xor(api, tmp, shft);
        let s0 = add(api, w[i - 16].clone(), s0);
        let s1 = add(api, w[i - 7].clone(), s1);
        let s1 = add_const(api, s1, k32[i]);
        w[i] = add(api, s0, s1);
    }

    for i in 0..64 {
        let s1 = sigma1(api, h[4].clone());
        let c = ch(api, h[4].clone(), h[5].clone(), h[6].clone());
        w[i] = add(api, w[i].clone(), h[7].clone());
        let c = add_const(api, c, k32[i].clone());
        let s1 = add(api, s1, w[i].clone());
        let s1 = add(api, s1, c);
        let s0 = sigma0(api, h[0].clone());
        let m = maj(api, h[0].clone(), h[1].clone(), h[2].clone());
        let s0 = add(api, s0, m);

        h[7] = h[6].clone();
        h[6] = h[5].clone();
        h[5] = h[4].clone();
        h[4] = add(api, h[3].clone(), s1.clone());
        h[3] = h[2].clone();
        h[2] = h[1].clone();
        h[1] = h[0].clone();
        h[0] = add(api, s1, s0);
    }


    let mut result = add_const(api, h[0].clone(), h32[0].clone());
    for i in 1..8 {
        result.append(&mut add_const(api, h[i].clone(), h32[i].clone()));
    }

    result
}


pub fn int2bit<C: Config>(api: &mut API<C>, value: u32) -> Vec<Variable> {
    return (0..32).map(|x| api.constant(((value >> x) & 1) as u32)).collect();
}

pub fn rotate_right(bits: &Vec<Variable>, k: usize) -> Vec<Variable> {
    let n = bits.len();
    let s = k & (n - 1);
    let mut new_bits = bits[s as usize..].to_vec();
    new_bits.append(&mut bits[0..s as usize].to_vec());
    new_bits
}

pub fn shift_right<C: Config>(api: &mut API<C>, bits: Vec<Variable>, k: usize) -> Vec<Variable> {
    let n = bits.len();
    let s = k & (n - 1);
    let mut new_bits = bits[s as usize..].to_vec();
    new_bits.append(&mut vec![api.constant(0); s]);
    new_bits
}

// Ch function: (x AND y) XOR (NOT x AND z)
pub fn ch<C: Config>(api: &mut API<C>, x: Vec<Variable>, y: Vec<Variable>, z: Vec<Variable>) -> Vec<Variable> {
    let xy = and(api, x.clone(), y.clone());
    let not_x = not(api, x.clone());
    let not_xz = and(api, not_x, z.clone());
    
    xor(api, xy, not_xz)
}


// Maj function: (x AND y) XOR (x AND z) XOR (y AND z)
pub fn maj<C: Config>(api: &mut API<C>, x: Vec<Variable>, y: Vec<Variable>, z: Vec<Variable>) -> Vec<Variable> {
    let xy = and(api, x.clone(), y.clone());
    let xz = and(api, x.clone(), z.clone());
    let yz = and(api, y.clone(), z.clone());
    let tmp = xor(api, xy, xz);

    xor(api, tmp, yz)
}

// Sigma0 function: ROTR(x, 2) XOR ROTR(x, 13) XOR ROTR(x, 22)
pub fn sigma0<C: Config>(api: &mut API<C>, x: Vec<Variable>) -> Vec<Variable> {
    let rot2 = rotate_right(&x, 2);
    let rot13 = rotate_right(&x, 13);
    let rot22 = rotate_right(&x, 22);
    let tmp = xor(api, rot2, rot13);

    xor(api, tmp, rot22)
}

// Sigma1 function: ROTR(x, 6) XOR ROTR(x, 11) XOR ROTR(x, 25)
pub fn sigma1<C: Config>(api: &mut API<C>, x: Vec<Variable>) -> Vec<Variable> {
    let rot6 = rotate_right(&x, 6);
    let rot11 = rotate_right(&x, 11);
    let rot25 = rotate_right(&x, 25);
    let tmp = xor(api, rot6, rot11);

    xor(api, tmp, rot25)
}

pub fn add_const<C: Config>(api: &mut API<C>, a: Vec<Variable>, b: u32) -> Vec<Variable> {
    let n = a.len();
    let mut c = a.clone();
    let mut ci = api.constant(0);
    for i in 0..n {

        if b >> i & 1 == 1 {
            let p = api.add(a[i].clone(), 1);
            c[i] = api.add(p.clone(), ci.clone());

            ci = api.mul(ci, p);
            ci = api.add(ci, a[i].clone());
        } else {
            c[i] = api.add(c[i], ci.clone());
            ci = api.mul(ci, a[i].clone());
        }
    }
    c
}

fn add_brentkung<C: Config>(api: &mut API<C>, a: &Vec<Variable>, b: &Vec<Variable>) -> Vec<Variable> {
    let mut c = vec![api.constant(0); 32];
    let ci = api.constant(0);

    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;

        let (sum, ci) = brent_kung_adder_4_bits(api, &a[start..end].to_vec(), &b[start..end].to_vec(), ci);

        c[start..end].copy_from_slice(&sum);
    }

    c
}

fn brent_kung_adder_4_bits<C: Config>(api: &mut API<C>, a: &Vec<Variable>, b: &Vec<Variable>, carry_in: Variable) -> ([Variable; 4], Variable) {
    let mut g = [api.constant(0); 4];
    let mut p = [api.constant(0); 4];

    // Step 1: Generate and propagate
    for i in 0..4 {
        g[i] = api.mul(a[i], b[i]);
        p[i] = api.add(a[i], b[i]);
    }

    // Step 2: Prefix computation
    let p1g0 = api.mul(p[1], g[0]);
    let p0p1 = api.mul(p[0], p[1]);
    let p2p3 = api.mul(p[2], p[3]);

    let g10 = api.add(g[1], p1g0);
    let g20 = api.mul(p[2], g10);
    let g20 = api.add(g[2], g20);
    let g30 = api.mul(p[3], g20);
    let g30 = api.add(g[3], g30);

    // Step 3: Calculate carries
    let mut c = [api.constant(0); 5];
    c[0] = carry_in;
    let tmp = api.mul(p[0], c[0]);
    c[1] = api.add(g[0], tmp);
    let tmp = api.mul(p0p1, c[0]);
    c[2] = api.add(g10, tmp);
    let tmp = api.mul(p[2], c[0]);
    let tmp = api.mul(p0p1, tmp);
    c[3] = api.add(g20, tmp);
    let tmp = api.mul(p0p1, p2p3);
    let tmp = api.mul(tmp, c[0]);
    c[4] = api.add(g30, tmp);

    // Step 4: Calculate sum
    let mut sum = [api.constant(0); 4];
    for i in 0..4 {
        sum[i] = api.add(p[i], c[i]);
    }

    (sum, c[4])
}

pub fn add<C: Config>(api: &mut API<C>, a: Vec<Variable>, b: Vec<Variable>) -> Vec<Variable> {
    add_brentkung(api, &a, &b)
}


pub fn xor<C: Config>(api: &mut API<C>, a: Vec<Variable>, b: Vec<Variable>) -> Vec<Variable> {
    let nbits = a.len();
    let mut bits_res = vec![api.constant(0); nbits];
    for i in 0..nbits {
        bits_res[i] = api.add(a[i].clone(), b[i].clone());
    }
    bits_res
}

pub fn and<C: Config>(api: &mut API<C>, a: Vec<Variable>, b: Vec<Variable>) -> Vec<Variable> {
    let nbits = a.len();
    let mut bits_res = vec![api.constant(0); nbits];
    for i in 0..nbits {
        bits_res[i] = api.mul(a[i].clone(), b[i].clone());
    }
    bits_res
}

pub fn not<C: Config>(api: &mut API<C>, a: Vec<Variable>) -> Vec<Variable> {
    let mut bits_res = vec![api.constant(0); a.len()];
    for i in 0..a.len() {
        bits_res[i] = api.sub(1, a[i].clone());
    }
    bits_res
}


fn main() {
    assert!(INPUT_LEN % 8 == 0);
    let n_witnesses = SIMDField::<GF2Config>::PACK_SIZE;

    // prepare data
    let mut rng = rand::rng();
    let mut inputs = vec![];
    let mut outputs = vec![];

    for _ in 0..N_HASHES {
        let data = [rng.next_u32() as u8; INPUT_LEN / 8];
        let mut hash = Sha256::new();
        hash.update(data);
        let output = hash.finalize();
        inputs.push(data);
        outputs.push(output);
    }

    // compile the circuit
    let compile_result = compile(&SHA256Circuit::default(), CompileOptions::default()).unwrap();

    // prepare assignment
    let mut assignment = SHA256Circuit::default();
    for k in 0..N_HASHES {
        for i in 0..INPUT_LEN / 8 {
            for j in 0..8 {
                assignment.input[k][i * 8 + j] = (((inputs[k][i] >> (7 - j)) & 1) as u32).into();
            }
        }
        for i in 0..OUTPUT_LEN / 8 {
            for j in 0..8 {
                assignment.output[k][i * 8 + j] = (((outputs[k][i] >> (7 - j) as u32) & 1) as u32).into();
            }
        }
    }
    
    let mut assignments: Vec<SHA256Circuit<GF2>> = vec![SHA256Circuit::default(); n_witnesses];
    assignments[0] = assignment;

    // solve witness
    let witness = compile_result
        .witness_solver
        .solve_witnesses(&assignments)
        .unwrap();

    // run/verify the circuit
    let output = compile_result.layered_circuit.run(&witness);
    assert!(output[0]);

    // create "circuit.txt"
    let file = std::fs::File::create("build/circuit.txt").unwrap();
    let writer = std::io::BufWriter::new(file);
    compile_result
        .layered_circuit
        .serialize_into(writer)
        .unwrap();

    // create "witness.txt"
    let file = std::fs::File::create("build/witness.txt").unwrap();
    let writer = std::io::BufWriter::new(file);
    witness.serialize_into(writer).unwrap();
}
