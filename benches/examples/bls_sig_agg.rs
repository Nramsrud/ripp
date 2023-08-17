use ark_bls12_381::{
    Bls12_381, 
    G1Projective,
    G2Projective,
    Fr,
    FrParameters,
    G1Affine,
};
use ark_dh_commitments::{
    afgho16::{AFGHOCommitmentG1, AFGHOCommitmentG2},
    identity::IdentityCommitment,
    pedersen::PedersenCommitment,
    DoublyHomomorphicCommitment,
    random_generators,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve, group::Group};
use ark_ff::{UniformRand, to_bytes, Field, PrimeField};
use ark_inner_products::{
    ExtensionFieldElement, InnerProduct, MultiexponentiationInnerProduct, PairingInnerProduct,
};
use ark_ip_proofs::gipa::GIPA;
use ark_ip_proofs::tipa::{
    structured_scalar_message::{structured_scalar_power, TIPAWithSSM},
    TIPACompatibleSetup, TIPA,
};
use ark_sipp::rng::FiatShamirRng;

use ark_std::One;

use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use blake2::Blake2b;
use digest::Digest;

use std::{ops::MulAssign, time::Instant};

// Utility function to print the type of a value
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

fn batchpairingcheck(
    len: usize, 
    aggpk: &[<Bls12_381 as PairingEngine>::G1Projective], 
    hmlist: &[<Bls12_381 as PairingEngine>::G2Projective], 
    g1list: &[<Bls12_381 as PairingEngine>::G1Projective], 
    aggsig: &[<Bls12_381 as PairingEngine>::G2Projective]) {

    type GC1 = AFGHOCommitmentG1<Bls12_381>;
    type GC2 = AFGHOCommitmentG2<Bls12_381>;
    type IP = PairingInnerProduct<Bls12_381>;
    type IPC =
        IdentityCommitment<ExtensionFieldElement<Bls12_381>, <Bls12_381 as PairingEngine>::Fr>;
    type PairingTIPA = TIPA<IP, GC1, GC2, IPC, Bls12_381, Blake2b>;


    println!("\tGenerating Proof for IPA <pk_agg,H(m)>");
    let mut start = Instant::now();

    let mut rng = StdRng::seed_from_u64(0u64);
    let (srs, ck_t) = PairingTIPA::setup(&mut rng, len).unwrap();
    let (ck_a, ck_b) = srs.get_commitment_keys();
    let v_srs = srs.get_verifier_key();
    let com_a = GC1::commit(&ck_a, &aggpk).unwrap();
    let com_b = GC2::commit(&ck_b, &hmlist).unwrap();
    let t = vec![IP::inner_product(&aggpk, &hmlist).unwrap()];
    let com_t = IPC::commit(&vec![ck_t.clone()], &t).unwrap();

    let mut bench = start.elapsed().as_millis();
    println!("\t\t setup time: {} ms", bench);

    let ipp_l = t;

    let mut start = Instant::now();
    let proof = PairingTIPA::prove(&srs, (&aggpk, &hmlist), (&ck_a, &ck_b, &ck_t)).unwrap();
    let mut bench = start.elapsed().as_millis();
    println!("\t \tproving time: {} ms", bench);

    start = Instant::now();
    assert!(PairingTIPA::verify(&v_srs, &ck_t, (&com_a, &com_b, &com_t), &proof).unwrap());
    bench = start.elapsed().as_millis();
    println!("\t \tverification time: {} ms\n", bench);

    println!("\tGenerating Proof for IPA <g1,sig_agg>");
    let mut start = Instant::now();

    let mut rng = StdRng::seed_from_u64(0u64);
    let (srs, ck_t) = PairingTIPA::setup(&mut rng, len).unwrap();
    let (ck_a, ck_b) = srs.get_commitment_keys();
    let v_srs = srs.get_verifier_key();
    let com_a = GC1::commit(&ck_a, &g1list).unwrap();
    let com_b = GC2::commit(&ck_b, &aggsig).unwrap();
    let t = vec![IP::inner_product(&g1list, &aggsig).unwrap()];
    let com_t = IPC::commit(&vec![ck_t.clone()], &t).unwrap();

    let mut bench = start.elapsed().as_millis();
    println!("\t\t setup time: {} ms", bench);

    let ipp_r = t;

    let mut start = Instant::now();
    let proof = PairingTIPA::prove(&srs, (&g1list, &aggsig), (&ck_a, &ck_b, &ck_t)).unwrap();
    let mut bench = start.elapsed().as_millis();
    println!("\t \tproving time: {} ms", bench);

    start = Instant::now();
    assert!(PairingTIPA::verify(&v_srs, &ck_t, (&com_a, &com_b, &com_t), &proof).unwrap());
    bench = start.elapsed().as_millis();
    println!("\t \tverification time: {} ms\n", bench);

    println!("Checking equality of IPP for batch signature pairing check");
    assert_eq!(ipp_l,ipp_r);
    println!("All signatures verified for {} committees", len);


    //==================================================
    // println!("\tTesting: Generating Proof for IPA of random linear combo of <pk_agg+g1^r,H(m)+sig_agg^r>");

    // let r = StdRng::seed_from_u64(0u64);
    // let generator = <Bls12_381 as PairingEngine>::G1Affine::prime_subgroup_generator();
    // let r_g1 = generator.mul(r.into_repr());
    // let generator2 = <Bls12_381 as PairingEngine>::G2Affine::prime_subgroup_generator();
    // let r_g2 = generator2.mul(r.into_repr());
    // let aggsig_r = aggsig.mul(r.into_repr());

    // //let rlc_l = &aggpk + r_g1;
    // //let rlc_r = &hmlist + aggsig_r;
    
    // let rlc_l = &aggpk + &g1list;
    // let rlc_r = &hmlist + &aggsig


}

fn main() {
    const LEN: usize = 512; //set size per committee
    const LEN2: usize = 64; //number of committees
    type GC1 = AFGHOCommitmentG1<Bls12_381>;
    type GC2 = AFGHOCommitmentG2<Bls12_381>;
    type SC1 = PedersenCommitment<<Bls12_381 as PairingEngine>::G1Projective>;
    type IP = MultiexponentiationInnerProduct<<Bls12_381 as PairingEngine>::G1Projective>;
    type IPg2 = MultiexponentiationInnerProduct<<Bls12_381 as PairingEngine>::G2Projective>;
    type IPC = IdentityCommitment<
        <Bls12_381 as PairingEngine>::G1Projective,
        <Bls12_381 as PairingEngine>::Fr,
    >;
    type MultiExpTIPA = TIPA<IP, GC1, SC1, IPC, Bls12_381, Blake2b>;
    
    let mut rng = StdRng::seed_from_u64(0u64);


    //to do:
    // - ** generate vec of scalars for secret keys - check
    // - ** create vec of G1 pubkeys from scalar vec - check
    // - create hash of message to G2
    // - ** create vec of signatures from scalar vec * H(m) - check
    // - ** create aggregate pubkey via point addition - check
    // - ** create aggregate signature via point addition -check
    // - ** do 2 pairing check <pkagg,H(m)> = <g1,sigagg> - check
    // - output size of setup
    // - how to make the setup trustless
    // - batch verify IPP proofs
    // - random linear combo batch verify of pairing check
    // - format for folding

    
    //=========================================================
    // Setting up all the key values for signing
    
    //let hm = <Bls12_381 as PairingEngine>::G2Projective::hash_to_curve(b"One key to rule them all", &[], &[]); // idk what dst/aug are, passing empty here only useable in 0.4
    let hm = <Bls12_381 as PairingEngine>::G2Projective::rand(&mut rng);
    let hm_aff = hm.into_affine();
    let sk = Fr::rand(&mut rng);
    let generator = <Bls12_381 as PairingEngine>::G1Affine::prime_subgroup_generator();
    let pk = generator.mul(sk.into_repr());
    let sig = hm_aff.mul(sk.into_repr());

    let mut sklist = Vec::new();
    let mut pklist = Vec::new();
    let mut siglist = Vec::new();
    let mut pbits = Vec::new();
    
    for i in 0..LEN {
        sklist.push(Fr::rand(&mut rng));
        pklist.push(generator.mul(sklist[i].into_repr()));
        siglist.push(hm_aff.mul(sklist[i].into_repr()));
        //pbits.push(1); //need to be not bits but Fr elements of 1
        pbits.push(Fr::one());
    }

    // sanity check on pairing check
    let leftpairing = Bls12_381::pairing(pklist[0], hm_aff);
    let rightpairing = Bls12_381::pairing(generator, siglist[0]);
    assert_eq!(leftpairing, rightpairing, "Testing pairing equality for BLS sig check with {:?} and {:?}", leftpairing, rightpairing);


//====================================================================
    //MIPP_u for proof of aggregate signature
    println!("\n\nBeginning proof of aggregate public keys of committee of size {}\n", LEN);
    println!("\tGenerating Proof of aggregate pubkeys");
    let mut start = Instant::now();

    let (srs, ck_t) = MultiExpTIPA::setup(&mut rng, LEN).unwrap();
    let (ck_a, ck_b) = srs.get_commitment_keys();
    let v_srs = srs.get_verifier_key();

    let com_a = GC1::commit(&ck_a, &pklist).unwrap();
    let com_b = SC1::commit(&ck_b, &pbits).unwrap();
    let t = vec![IP::inner_product(&pklist, &pbits).unwrap()];
    let com_t = IPC::commit(&vec![ck_t.clone()], &t).unwrap();  
    let mut bench = start.elapsed().as_millis();
    println!("\t\t setup time: {} ms", bench);



    let mut start = Instant::now();
    let proof = MultiExpTIPA::prove(&srs, (&pklist, &pbits), (&ck_a, &ck_b, &ck_t)).unwrap();
    let mut bench = start.elapsed().as_millis();
    println!("\t \tproving time: {} ms", bench);

    start = Instant::now();
    assert!(MultiExpTIPA::verify(&v_srs, &ck_t, (&com_a, &com_b, &com_t), &proof).unwrap());
    bench = start.elapsed().as_millis();
    println!("\t \tverification time: {} ms", bench);

//===================================================================    

    // aggregating sigs and pks
    let mut aggpk = pklist[0];
    let mut aggsig = siglist[0];

    for i in 1..LEN {
        aggpk = aggpk + pklist[i];
        aggsig = aggsig + siglist[i];
    }

    // sanity check on pairing check
    let aggleftpairing = Bls12_381::pairing(aggpk, hm_aff);
    let aggrightpairing = Bls12_381::pairing(generator, aggsig);
    assert_eq!(aggleftpairing, aggrightpairing, "Testing pairing equality for BLS sig check with {:?} and {:?}", aggleftpairing, aggrightpairing);    

//===================================================================


    //TIPA proof for inner pairing product
    println!("\nBeginning batch signature verification Inner Pairing Product proof for {} number committees\n", LEN2);

    let mut aggpklist = Vec::new();
    let mut aggsiglist = Vec::new();
    let mut hmlist = Vec::new();
    let mut generatorlist = Vec::new();


    for _ in 0..LEN2 {
        aggpklist.push(aggpk);
        aggsiglist.push(aggsig);
        hmlist.push(hm);
        generatorlist.push(<Bls12_381 as PairingEngine>::G1Projective::prime_subgroup_generator());
    }

    batchpairingcheck(LEN2, &aggpklist, &hmlist, &generatorlist, &aggsiglist);


}