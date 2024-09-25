# EarthStream Milestone 2

## Preamble

Monitoring biodiversity has become increasingly critical as ecosystems face unprecedented changes. Traditional biodiversity assessment methods often rely on labor-intensive fieldwork and invasive techniques, limiting the scope and frequency of data collection. To address these challenges, we have developed a bioacoustic sensor network that autonomously monitors environmental conditions and soundscapes, offering continuous, non-invasive, and scalable data collection.

## Introduction

Milestone 1 code can be found in the following repository: [https://github.com/nuwrldnf8r/esp32_dfinity_agent](https://github.com/nuwrldnf8r/esp32_dfinity_agent)

Since Milestone 1, our sensors have been upgraded to focus on birdsong detection. Data is transmitted via LoRa to a gateway, where it utilizes the Dfinity agent (developed in Milestone 1) to upload the data to the backend canister for storage and indexing.

In this milestone, our primary focus has been on bird recognition, so other aspects such as weather data have been temporarily excluded. These components will be integrated in the next milestone.

The current sensors use an ESP32 microcontroller, equipped with two MEMS microphones (with built-in ADCs), a LoRa module, and an SD card reader. Additional sensors for temperature, humidity, and GPS are also available. The system is powered by a LiPo battery, which is recharged via a solar panel. The sensors monitor battery strength, and light levels are inferred from the solar panel’s voltage. For this demonstration, light sensing, temperature, humidity, and GPS functionalities have been disabled to focus solely on bird identification.

## Challenges and Lessons Learned

We considered several approaches:
- Record audio data and upload it to the canister for birdsong detection.
- Record audio to an SD card, retrieve it in the field, and process it similarly.

However, these methods have significant downsides. Wi-Fi is not viable over long distances and consumes too much power. Manually retrieving SD cards would disrupt real-time data collection and negatively impact the environment.

Moreover, there is a fine line between monitoring and surveillance, making the storage of actual audio data undesirable.

Next, we explored edge detection. While this is feasible on the ESP32 for small groups of bird species, it requires highly localized labeled datasets and lacks real-time training capacity in the field.

To balance these challenges, we explored pre-processing the data in a way that is feasible within the constraints of LoRa transmission. Initially, we considered MFCCs (Mel Frequency Cepstral Coefficients), but the ESP32’s processing capacity and the resulting large datasets proved limiting. We needed an alternative solution.

## Solutions

MFCCs are a standard approach in both speech and birdsong recognition. However, they push the ESP32's memory capacity to its limits, and the resulting datasets are too large for LoRa’s bandwidth.

Our current solution, which is the focus of this milestone, is inspired by the MIDI protocol. We designed a protocol that transmits slices of frequency data, timing, and volume. Given that birdsong has relatively low spectral entropy and a high number of harmonics, we included that information as well.

The sensor monitors frequencies between 1000 Hz and 8000 Hz, where most birdsong occurs. When a sound slice falls within this range, has spectral entropy below a certain threshold, and an SNR (signal-to-noise ratio) above a defined level, a sound event is triggered. The sensor then compiles an array of slices containing peak frequency, peak volume, spectral entropy, harmonics, and the time elapsed since the previous sound.

After a maximum of three seconds or when silence surpasses a certain threshold, the data is transmitted via LoRa to the gateway. The gateway validates the data (ensuring signature match, checksum integrity, etc.) before uploading it to the canister.

The sensor code has been left out of this public repo for now.

## Backend code

Backend code can be found in `/canister`.
There is also some minimal traning data 

## Field Pilot Learnings

- Weightings and thresholds need dynamic adjustments based on environmental noise.
- The current packet transfer protocol requires refinement, especially for handling multiple sensors.
- We are collaborating with an acoustics expert to improve sensor housing to reduce noise interference.

## Future Exploration

- Investigating GPRS modules to upload data via GSM.
