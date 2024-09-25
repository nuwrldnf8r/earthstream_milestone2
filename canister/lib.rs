use std::cell::RefCell;
use sha2::{Digest, Sha256};
use libsecp256k1::*;
//const PACKET_TYPE_ENVIRONMENT:u8 = 4; 
use std::vec::Vec;
use ic_cdk::api::time;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use candid::{CandidType, Deserialize};


#[allow(dead_code)]
#[derive(CandidType, Deserialize)]
struct Packet{
    id: u64,
    ts: u64,
    owner: [u8; 32],
    slices: Vec<Slice>,
}

#[allow(dead_code)]
#[derive(Clone,CandidType, Deserialize)]
struct Slice{
    elapsed_time: u16,
    peak_freq: f32,
    peak_vol: f32,
    spec_ent: f32,
    harmonics: [u8; 2],
}

#[allow(dead_code)]
struct SliceScore {
    freq: f32,
    score: f32,
}

#[derive(PartialEq, CandidType, Deserialize)]
#[allow(dead_code)]
struct PacketScore {
    id: u64,
    score: f32,
}

#[allow(dead_code)]
#[derive(CandidType, Deserialize)]
struct Range{
    low: f32,
    high: f32,
}

#[allow(dead_code)]
#[derive(CandidType, Deserialize)]
struct Species {
    species: String,
    samples: u64,
    freq_range: Range,
    spec_ent_avg: f32,
    score: f32,
}
#[derive(CandidType, Deserialize)]
struct SpeciesWithId {
    species: String,
    score: f32,
    id: u64,
}


#[derive(CandidType, Deserialize, Clone)]
struct Weight{
    freq_compare_c: f32,
    freq_spec_compare_c: f32,
    freq_range_compare_c: f32,
    matching_freq: f32,
    matching_freq_harmonic: f32,
    matching_freq_spec_ent: f32,
    freq_range: f32,
    loudest_freq: f32,
    loudest_harmonic: f32,
    loudest_spec_ent: f32,
    matching_freq_score: f32,
    freq_range_score: f32,
    loudest_score: f32,
}

impl Default for Weight {
    fn default() -> Self {
        Weight {
            freq_compare_c: 100.0,
            freq_spec_compare_c: 0.3,
            freq_range_compare_c: 200.0,
            matching_freq: 2.0,
            matching_freq_harmonic: 1.0,
            matching_freq_spec_ent: 0.2,
            freq_range: 0.7,
            loudest_freq: 1.2,
            loudest_harmonic: 1.0,
            loudest_spec_ent: 0.2,
            matching_freq_score: 1.0,
            freq_range_score: 0.7,
            loudest_score: 0.7,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct OrdF32(f32);

impl PartialEq for OrdF32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for OrdF32 {}

impl Hash for OrdF32 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

thread_local! {
    static BIRDSOUND_MAP: RefCell<BTreeMap<u64, Vec<u8>>> = RefCell::new(BTreeMap::new());
    static BIRDSONG_OWNER_MAP: RefCell<HashMap<[u8; 32], Vec<u64>>> = RefCell::new(HashMap::new());
    static BIRDSONG_SENSOR_MAP: RefCell<HashMap<u64, Vec<u8>>> = RefCell::new(HashMap::new());
    static DATA_MAP: RefCell<BTreeMap<u64, u64>> = RefCell::new(BTreeMap::new());
    static FREQ_INDEX: RefCell<HashMap<u32, Vec<u64>>> = RefCell::new(HashMap::new());
    static LABELLED_DATA: RefCell<BTreeMap<u64, String>> = RefCell::new(BTreeMap::new());
    static WEIGHT: RefCell<Weight> = RefCell::new(Weight::default());
}

//util functions
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    let hex = hex.to_lowercase(); // Convert to lowercase to handle any upper case letters
    if hex.len() % 2 != 0 {
        return Err("Hex string has an odd length");
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "Invalid hex character"))
        .collect()
}

fn is_valid(data: Vec<u8>) -> bool {
    if data.len() < 128 {
        return false; // Ensure data length is sufficient
    }
    let pubkey = &data[1..65]; // Get the public key
    let signature = &data[data.len() - 64..];
    let data = &data[0..data.len() - 64];
    
    // Hash data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_result = hasher.finalize();
    let message = hash_result.to_vec();
    
    // Check signature
    check_sig(pubkey, signature, &message)

}

fn check_sig(_public_key: &[u8], _signature: &[u8], _data: &[u8]) -> bool {
    let mut pub_key = [0u8; 65];
    pub_key[0] = 0x04;
    let mut msg: [u8; 32] = [0; 32];
    let mut sig: [u8; 64] = [0; 64];
    pub_key[1..].copy_from_slice(_public_key);
    msg.copy_from_slice(_data);
    sig.copy_from_slice(_signature);
    let pubkey: PublicKey = PublicKey::parse(&pub_key).unwrap();
    let message: Message = Message::parse(&msg);
    let sig: Signature = Signature::parse_standard(&sig).unwrap();
    libsecp256k1::verify(&message, &sig, &pubkey)
}

fn bytes_to_float(bytes: &[u8]) -> f32 {
    let mut array = [0u8; 4];
    array.copy_from_slice(bytes);
    f32::from_le_bytes(array)
}

fn public_key_hash(pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.finalize().into()
}

/////////// Working with the data //////////////

fn parse_slices(data: Vec<u8>) -> Vec<Slice> {
    let mut slices = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let elapsed_time = u16::from_be_bytes([data[i], data[i + 1]]); //2
        let peak_freq = bytes_to_float(&data[i + 2..i + 6]); //4
        let peak_vol = bytes_to_float(&data[i + 6..i + 10]); //4
        let spec_ent = bytes_to_float(&data[i + 10..i + 14]); //4
        let mut harmonics: [u8; 2] = [0, 0];
        harmonics[0] = data[i + 14];
        harmonics[1] = data[i + 15];
       
        slices.push(Slice {
            elapsed_time,
            peak_freq,
            peak_vol,
            spec_ent,
            harmonics,
        });
        i += 16;
    }
    slices
}


fn add_to_birdsong_map(id: u64, data: Vec<u8>) {
    BIRDSOUND_MAP.with(|map| {
        map.borrow_mut().insert(id, data);
        ic_cdk::println!("BIRDSOUND_MAP size after insert: {}", map.borrow().len());
    });
}  

fn add_to_owner_map(owner: [u8; 32], id: u64) {
    BIRDSONG_OWNER_MAP.with(|map| {
        let mut map_mut = map.borrow_mut();
        let owner_data = map_mut.entry(owner).or_insert(Vec::new());
        owner_data.push(id);
    }); 
}

fn add_to_sensor_map(id: u64, data: Vec<u8>) {
    BIRDSONG_SENSOR_MAP.with(|map| {
        map.borrow_mut().insert(id, data);
    });
}

fn add_to_map(ts: u64, id: u64) {
    DATA_MAP.with(|map| {
        map.borrow_mut().insert(ts, id);
    });
}

fn add_to_freq_index(freq: u32, id: u64) {
    FREQ_INDEX.with(|map| {
        let mut map_mut = map.borrow_mut();
        let freq_data = map_mut.entry(freq).or_insert(Vec::new());
        freq_data.push(id); 
    });
}

fn quantize_freq(freq: f32, division: f32) -> u32 {
    ((freq / division).round() * division) as u32
}


fn index_data(id: u64, slices: Vec<Slice>) {
    //index by peak frequency
    //go through slices - quantize and store the quantized value in an array if it's not already there
    //array to hold the quantized values
    let mut freqs: Vec<u32> = Vec::new();

    for slice in slices {
        let quantized_freq = quantize_freq(slice.peak_freq, 150.0);
        if !freqs.contains(&quantized_freq) {
            freqs.push(quantized_freq);
        }
    }
    
    //loop through freqs and add_to_freq_index
    for freq in freqs {
        add_to_freq_index(freq, id);
    }
}

fn add_packet(bird_data: Vec<u8>) {
    //get public key
    let pubkey = bird_data[1..65].to_vec();
    //65-69 is the length
    let data = bird_data[69..bird_data.len() - 64].to_vec();
    let id = u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
    let ts = time();

    ic_cdk::println!("Inserting data into BIRDSOUND_MAP with ID: {}", id);

    //add ts to front of data
    let mut ts_bytes = ts.to_be_bytes().to_vec();
    ts_bytes.extend(data.clone());
    let data = ts_bytes;

    let owner = public_key_hash(&pubkey);
    let slices = parse_slices(data.clone());

    add_to_sensor_map(id, pubkey.clone());
    add_to_birdsong_map(id, data);
    add_to_owner_map(owner, id);
    add_to_map(ts, id);
    index_data(id, slices);

}

fn parse_data(data: Vec<u8>) -> Packet {
    let ts = u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
    let id = u64::from_be_bytes([data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]]);
    let owner = data[16..48].try_into().unwrap();
    let slices = parse_data_into_slices(data[48..].to_vec());
    Packet {
        id,
        ts,
        owner,
        slices,
    }
}

fn parse_data_into_slices(data: Vec<u8>) -> Vec<Slice> {
    let mut slices = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let elapsed_time = u16::from_be_bytes([data[i], data[i + 1]]);
        let peak_freq = bytes_to_float(&data[i + 2..i + 6]);
        let peak_vol = bytes_to_float(&data[i + 6..i + 10]);
        let spec_ent = bytes_to_float(&data[i + 10..i + 14]);
        let mut harmonics: [u8; 2] = [0, 0];
        harmonics[0] = data[i + 14];
        harmonics[1] = data[i + 15];

        slices.push(Slice {
            elapsed_time,
            peak_freq,
            peak_vol,
            spec_ent,
            harmonics,
        });
        i += 16;
    }
    slices
}

fn get_score(f1: f32, f2: f32, c: f32) -> f32 {
     let diff = (f1 - f2).abs();
     if diff < c {
         1.0 - (diff / c).powi(2)  
     } else {
         0.0  
     }
}

fn get_harmonics_score(h1: [u8; 2], h2: [u8; 2]) -> f32 {
    let mut score = 0.0;
    for i in 0..2 {
        //iterate over each bit in the byte and compare
        for j in 0..8 {
            let mask = 1 << j;
            if (h1[i] & mask) == (h2[i] & mask) {
                score += 1.0;
            }
        }
    }
    score / 16.0
}


fn compare_slices(mut slices1: Vec<Slice>, mut slices2: Vec<Slice>) -> f32 {  
    let w = WEIGHT.with(|w| (*w.borrow()).clone());

    let matching_freq_div = w.matching_freq + w.matching_freq_harmonic + w.matching_freq_spec_ent;
    let loudest_div = w.loudest_freq + w.loudest_harmonic + w.loudest_spec_ent;

    // Sort both arrays by frequency
    slices1.sort_by(|a, b| a.peak_freq.partial_cmp(&b.peak_freq).unwrap());
    slices2.sort_by(|a, b| a.peak_freq.partial_cmp(&b.peak_freq).unwrap());

    let mut total_score = 0.0;
    let mut idx2 = 0;
    let mut score_cnt: f32 = 0.0;

    //compare slices to find matching frequencies - and compare harmonics and spectral entropy
    for slice1 in &slices1 {
        // Iterate through slices2 until you find the closest match
        while idx2 < slices2.len() && slices2[idx2].peak_freq < slice1.peak_freq {
            idx2 += 1;
        }

        if idx2 < slices2.len() {
            // Calculate the score for the closest match in slices2
            let slice2 = &slices2[idx2];
            let freq_score = get_score(slice1.peak_freq, slice2.peak_freq, w.freq_compare_c);
            if freq_score > 0.0 {
                let harmonic_score = get_harmonics_score(slice1.harmonics, slice2.harmonics);
                let freq_spec_score = get_score(slice1.spec_ent, slice2.spec_ent, w.freq_spec_compare_c);
                let score = (freq_score * w.matching_freq + harmonic_score * w.matching_freq_harmonic + freq_spec_score * w.matching_freq_spec_ent) / matching_freq_div;
                total_score += score;
                score_cnt += 1.0;
            }
        }
    }
    if score_cnt==0.0 {
        return 0.0;
    }
    let total_score = total_score / score_cnt;

    //get frequency ranges and score the distance between highs and lows
    let freq_range1 = (slices1[0].peak_freq, slices1[slices1.len() - 1].peak_freq);
    let freq_range2 = (slices2[0].peak_freq, slices2[slices2.len() - 1].peak_freq);
    let freq_range_score = (get_score(freq_range1.0, freq_range2.0, w.freq_range_compare_c) + get_score(freq_range1.1, freq_range2.1, w.freq_range_compare_c))/2.0;

    //get loudest frequency in each slice and compare distance, harmonic and spectral entropy
        //sort slices by peak volume with highest value first
    slices1.sort_by(|a, b| a.peak_vol.partial_cmp(&b.peak_vol).unwrap());
    slices2.sort_by(|a, b| a.peak_vol.partial_cmp(&b.peak_vol).unwrap());
    //compare slices1[0].peak_freq to slices2[0].peak_freq
    let loudest_freq_score = get_score(slices1[0].peak_freq, slices2[0].peak_freq, w.freq_compare_c);
    let loudest_harmonic_score = get_harmonics_score(slices1[0].harmonics, slices2[0].harmonics);
    let loudest_spec_score = get_score(slices1[0].spec_ent, slices2[0].spec_ent, w.freq_spec_compare_c);
    let loudest_score = (loudest_freq_score * w.loudest_freq + loudest_harmonic_score * w.loudest_harmonic + loudest_spec_score * w.loudest_spec_ent) / loudest_div;

    let score_div = w.matching_freq_score + w.freq_range_score + w.loudest_score;
    let total_score = (total_score*w.matching_freq_score + freq_range_score * w.freq_range_score + loudest_score * loudest_score)/score_div;
    total_score
}

fn compare_internal(slices1: Vec<Slice>, id2: u64) -> f32 {
    let bird_data2 = BIRDSOUND_MAP.with(|map| {
        map.borrow().get(&id2).unwrap().clone()
    });
    let packet2 = parse_data(bird_data2);
    let slices2 = packet2.slices;
    compare_slices(slices1, slices2)
}   

fn find_similar(bird_data_id: u64, slices: Vec<Slice>) -> Vec<PacketScore> {
    let mut similar: Vec<PacketScore> = Vec::new();
    for slice in &slices {
        let freq = quantize_freq(slice.peak_freq, 200.0);
        
        let freq_data = FREQ_INDEX.with(|map| {
            map.borrow().get(&freq).unwrap_or(&Vec::new()).clone()
        });
        for id in freq_data {
            if id != bird_data_id {
                let score = compare_internal(slices.clone(), id);
                if score > 0.5 {
                    let packet_score = PacketScore{id, score};
                    if !similar.contains(&packet_score) {
                        similar.push(packet_score);
                    }
                }
            }
        }
    }
    similar
}

#[ic_cdk::update]
fn receive_bird_data(bird_data: String) {
    let bird_data = hex_to_bytes(&bird_data).unwrap();
    if !is_valid(bird_data.clone()) {
        panic!("Invalid data");
    }
    add_packet(bird_data);
} 

#[ic_cdk::update]
fn receive_training_data(bird_data: String, label: String) {
    let bird_data = hex_to_bytes(&bird_data).unwrap();
    if !is_valid(bird_data.clone()) {
        panic!("Invalid data");
    }
    let id = get_id_internal(bird_data.clone());
    add_packet(bird_data);
    label_bird_data(id, label);
} 

#[ic_cdk::query]
fn compare(id1: u64, id2: u64) -> f32 {
    let bird_data1 = BIRDSOUND_MAP.with(|map| {
        map.borrow().get(&id1).expect("Bird data not found for id1").clone()
    });
    let bird_data2 = BIRDSOUND_MAP.with(|map| {
        map.borrow().get(&id2).expect("Bird data not found for id2").clone()
    });
    let packet1 = parse_data(bird_data1);
    let packet2 = parse_data(bird_data2);
    compare_slices(packet1.slices, packet2.slices)
}


#[ic_cdk::query]
fn get_similar(bird_data_id: u64) -> Vec<PacketScore> {
    let bird_data = BIRDSOUND_MAP.with(|map| {
        map.borrow().get(&bird_data_id).unwrap().clone()
    });
    let packet = parse_data(bird_data);
    let slices = packet.slices;
    find_similar(bird_data_id, slices)
}

#[ic_cdk::query]
fn find_species(bird_data_id: u64) -> Species {
    let mut species = get_label(bird_data_id.clone());
    if species != "" {
        return Species {
            species,
            samples: 1,
            freq_range: Range{low:0.0, high: 0.0},
            spec_ent_avg: 0.0,
            score: 1.0,
        };
    }

    let bird_data = BIRDSOUND_MAP.with(|map| {
        map.borrow().get(&bird_data_id).unwrap().clone()
    });
    let packet = parse_data(bird_data);
    let slices = packet.slices;
    let similar = find_similar(bird_data_id, slices.clone());

    
    let mut max_score = 0.0;
    let mut avg_score = 0.0;

    for packet_score in &similar { // Iterate over references to the elements in the similar vector
        if packet_score.score > max_score {
            let mut _species = get_label(packet_score.id);
            if _species != "" {
                let s = find_species(packet_score.id);
                _species = s.species;
                if _species == "Unknown" {
                    continue;
                }
                max_score = packet_score.score;
                species =  _species;
            }
            avg_score += packet_score.score;
        }
    }

    if similar.len() == 0 {
        return Species {
            species: "Unknown".to_string(),
            samples: 1,
            freq_range: Range{low:0.0, high: 0.0},
            spec_ent_avg: 0.0,
            score: 0.0,
        };
    }

    avg_score /= similar.len() as f32;

    // Set the final score here
    let score = if species == "" {
        species = "Unknown".to_string();
        avg_score
    } else {
        max_score
    };

    let samples = similar.len() as u64;
    let freq_low = slices.iter().map(|s| s.peak_freq).min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
    let freq_high = slices.iter().map(|s| s.peak_freq).max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
    let freq_range = Range{low:freq_low, high: freq_high};
    let spec_ent_avg = slices.iter().map(|s| s.spec_ent).sum::<f32>() / slices.len() as f32;

    Species {
        species,
        samples,
        freq_range,
        spec_ent_avg,
        score, // Use the final score here
    }
}


#[ic_cdk::query]
fn get_all_data() -> Vec<u64> {
    DATA_MAP.with(|map| {
        map.borrow().values().cloned().collect()
    })
}

fn get_data(from: u64, mut to: u64) -> Vec<u64> {
    if to<from {
        to = time();
    }
    
    DATA_MAP.with(|map| {
        map.borrow().range(from..to).map(|(_, id)| *id).collect()
    })
}

#[ic_cdk::query]
fn get_data_past_hour() -> Vec<SpeciesWithId> {
    let now = time();
    let hour_ago = now - 3600000000000;
    let data = get_data(hour_ago, now);
    let mut species = Vec::new();
    for id in data {
        let s = find_species(id);
        species.push(SpeciesWithId{species: s.species, score: s.score, id});
    }
    species
}

#[ic_cdk::query]
fn get_data_past_5min() -> Vec<SpeciesWithId> {
    let now = time();
    let hour_ago = now - 300000000000;
    let data = get_data(hour_ago, now);
    let mut species = Vec::new();
    for id in data {
        let s = find_species(id);
        species.push(SpeciesWithId{species: s.species, score: s.score, id});
    }
    species
}

#[ic_cdk::query]
fn get_owner(id: u64) -> String {
    BIRDSONG_SENSOR_MAP.with(|map| {
        let sensor_data = map.borrow().get(&id).unwrap().clone();
        hex::encode(sensor_data)
    })
}

/*
#[ic_cdk::query]
fn get_data_by_owner(owner: String, from: u64, mut to: u64) -> Vec<u64> {
    //get public key from hex string owner
    let owner = hex_to_bytes(&owner).unwrap();
    //get owner id from public key
    let owner = public_key_hash(&owner);
    if to<from {
        to = time();
    }
    BIRDSONG_OWNER_MAP.with(|map| {
        match map.borrow().get(&owner) {
            //iterate over map, get the data, get ts from the front of the data (u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]])) and check if it's in range
            Some(data) => data.iter().filter(|id| {
                let bird_data = BIRDSOUND_MAP.with(|map| {
                    map.borrow().get(id).unwrap().clone()
                });
                let ts = u64::from_be_bytes([bird_data[0], bird_data[1], bird_data[2], bird_data[3], bird_data[4], bird_data[5], bird_data[6], bird_data[7]]);
                ts >= from && ts <= to
            }).cloned().collect(),
            None => Vec::new(),
        }
    })
}
*/

#[ic_cdk::query]
fn get_id(bird_data: String) -> u64{
    let bird_data = hex_to_bytes(&bird_data).unwrap();
    let data = bird_data[69..bird_data.len() - 64].to_vec();
    let id = u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
    id
}

fn get_id_internal(bird_data: Vec<u8>) -> u64{
    let data = bird_data[69..bird_data.len() - 64].to_vec();
    let id = u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
    id
}

//#[ic_cdk::query]
fn get_label(id: u64) -> String {
    LABELLED_DATA.with(|map| {
        match map.borrow().get(&id) {
            Some(label) => label.clone(),
            None => "".to_string(),
        }
    })
}

#[ic_cdk::update]
fn label_bird_data(id: u64, new_label: String) {
    // Retrieve the current label for the bird data (if any)
    let current_label = get_label(id);

    // If no label exists, find the species
    if current_label.is_empty() {
        let species_info = find_species(id);  // Predict species and get the confidence score
        let predicted_species = species_info.species; // The predicted species
        let prediction_score = species_info.score; // The confidence score returned by `find_species`

        // Check if the predicted species matches the new label
        let correct = predicted_species == new_label;

        // Adjust weights based on whether the prediction was correct
        WEIGHT.with(|w| {
            let mut weights = w.borrow_mut();
            adjust_weights(correct, prediction_score, &mut weights);  // Use the confidence score instead of a hardcoded value
        });

        // Log the result of the comparison
        if correct {
            ic_cdk::println!("Correct prediction from `find_species`: Adjusted weights positively.");
        } else {
            ic_cdk::println!("Incorrect prediction from `find_species`: Adjusted weights negatively.");
        }
    } else {
        // If the current label exists, we compare it with the new label as usual
        let correct = current_label == new_label;

        // Adjust weights based on whether the label was correct
        WEIGHT.with(|w| {
            let mut weights = w.borrow_mut();
            let score = 1.0; 
            adjust_weights(correct, score, &mut weights);
        });

        // Log the result
        if correct {
            ic_cdk::println!("Correct previous label: Adjusted weights positively.");
        } else {
            ic_cdk::println!("Incorrect previous label: Adjusted weights negatively.");
        }
    }

    // Now, assign the new label
    LABELLED_DATA.with(|map| {
        map.borrow_mut().insert(id, new_label);
    });
}

fn adjust_weights(correct: bool, score: f32, w: &mut Weight) {
    let learning_rate = 0.1;  // Small factor to control how much to adjust the weights

    if correct {
        // If the prediction was correct, increase the weights slightly to reinforce the decision
        w.matching_freq += learning_rate * score;
        w.matching_freq_harmonic += learning_rate * score;
        w.matching_freq_spec_ent += learning_rate * score;
    } else {
        // If the prediction was incorrect, decrease the weights slightly
        w.matching_freq -= learning_rate * score;
        w.matching_freq_harmonic -= learning_rate * score;
        w.matching_freq_spec_ent -= learning_rate * score;
    }

    // Ensure weights stay above zero to prevent them from becoming invalid
    w.matching_freq = w.matching_freq.max(0.1);
    w.matching_freq_harmonic = w.matching_freq_harmonic.max(0.1);
    w.matching_freq_spec_ent = w.matching_freq_spec_ent.max(0.1);
}


#[ic_cdk::query]
fn get_weights() -> Weight {
    WEIGHT.with(|w| (*w.borrow()).clone())
}

#[ic_cdk::update]
fn set_weights(freq_compare_c: f32, freq_spec_compare_c: f32, freq_range_compare_c: f32, matching_freq: f32, 
    matching_freq_harmonic: f32, matching_freq_spec_ent: f32, freq_range: f32, loudest_freq: f32, loudest_harmonic: f32, 
    loudest_spec_ent: f32, matching_freq_score: f32, freq_range_score: f32, loudest_score: f32) {
    let w = Weight {
        freq_compare_c,
        freq_spec_compare_c,
        freq_range_compare_c,
        matching_freq,
        matching_freq_harmonic,
        matching_freq_spec_ent,
        freq_range,
        loudest_freq,
        loudest_harmonic,
        loudest_spec_ent,
        matching_freq_score,
        freq_range_score,
        loudest_score,
    };
    WEIGHT.with(|weights| {
        *weights.borrow_mut() = w;
    });
}

#[ic_cdk::query]
fn get_packets(id1: u64, id2: u64) -> Vec<Packet> {
    let bird_data1 = BIRDSOUND_MAP.with(|map| {
        map.borrow().get(&id1).unwrap().clone()
    });
    let bird_data2 = BIRDSOUND_MAP.with(|map| {
        map.borrow().get(&id2).unwrap().clone()
    });
    let packet1 = parse_data(bird_data1);
    let packet2 = parse_data(bird_data2);
    vec![packet1, packet2]

}
