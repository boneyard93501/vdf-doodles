use blake3;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use rand;
use std::time::{Duration, Instant};
// use rand::{CryptoRng, RngCore};
use vdf::{InvalidProof, PietrzakVDFParams, VDFParams, WesolowskiVDFParams, VDF};

fn keypair() -> Keypair {
    let mut csprng = rand::rngs::OsRng {};
    Keypair::generate(&mut csprng)
}

fn data(nonce: &[u8], data_size: usize) -> Vec<u8> {
    nonce.iter().cycle().cloned().take(data_size).collect()
}

fn data_hash(data: Vec<u8>) -> Vec<u8> {
    blake3::hash(&data).as_bytes().to_vec()
}

fn main() {
    // The length of the prime numbers generated, in bits.
    // we should change that often, just like K in rX. maybe figure ut a way to generate that from some blocknumbers, e.g., use
    // randomx -like K approach and then take the last 4 digits of target block
    let num_bits: u16 = 2024; // * 8;

    // here we generate a data blog, hash it, sign the hash  and use it
    // as the challenge for the VDF
    // heck, we might also consider add or insert the signature, maybe of a nonce, to the data that way we could use
    // the same data for multiple providers ... something to playbwith.
    // ideally, the data blob get's created with an updated nonce after every vdf output, e.g., signed hash of vdf out plus previous nonce

    //let data_size = 512; // 1024 * 1024 * 1024 * 1024 * 16 // 16 GB
    let data_size = 1024 * 1024 * 1024 * 16; // 16 GB

    // need nonce. maybe like K also
    let nonce = b"iamanonce"; // could use the hash of output from previous run and the submission batch requires order.

    let data = data(nonce, data_size);
    let data_hash = data_hash(data);

    let keypair = keypair();
    let challenge = &keypair.sign(&data_hash).to_bytes();

    // let challenge = b"iamasignednonce";
    let difficulty = 1_000_000; // 1_000_000;

    // An instance of the VDF.  Instances can be used arbitrarily many times.
    let start_prover = Instant::now();
    let pietrzak_vdf = PietrzakVDFParams(num_bits).new();
    let result = pietrzak_vdf.solve(challenge, difficulty).unwrap();
    let prover_duration = start_prover.elapsed();
    println!(
        "time to proof for difficulty; {}, challenge: {:?}: {} seconds",
        difficulty,
        challenge[0..10].to_vec(),
        prover_duration.as_secs()
    );

    // this is what we need to do on-chain. sadly, it seems slow
    let start_verifier = Instant::now();
    let init_vdf = Instant::now();
    let pietrzak_vdf = PietrzakVDFParams(num_bits).new();
    let init_vdf_duration = init_vdf.elapsed();
    let valid_proof = pietrzak_vdf.verify(challenge, difficulty, &result).is_ok();
    let verifier_duration = start_verifier.elapsed();

    // println!("init vdf duration: {} seconds", init_vdf_duration.as_secs());
    println!("time to verify: {} millis", verifier_duration.as_millis());
    println!("this is a valid proof: {}", valid_proof);

    /*
    // bad prime bits -- cheater wants a lower number -- no go
    // ideally that's independently verifiable. eg.., derive from blocknumber
    let pietrzak_vdf = PietrzakVDFParams(num_bits - 1).new();
    let invalid_proof = if pietrzak_vdf.verify(challenge, difficulty, &result).is_ok() {
        false
    } else {
        true
    };
    println!("this is a not a valid proof: {}", invalid_proof);
    */
}
