# Keystream reuse in deployed LoRaWAN traffic

Code and results for the paper "Keystream reuse in deployed LoRaWAN traffic: a passive audit of five city captures with a calibrated
ciphertext test" by Kofi Sarpong Adu-Manu and Stephen Kwaku Azongo (Department of Computer Science, University of Ghana), submitted to
Computer Networks.

Cite as: see `CITATION.cff`. Licence: MIT for the code; CC BY 4.0 for the results and figures (see `LICENSE`).

## In brief

LoRaWAN 1.0.x encrypts the application payload with a keystream computed from the session key, the device address (DevAddr) and the
frame counter (FCnt), so a device that repeats a counter under one key reuses its keystream. The code measures how often this happens in
passive captures. A counter test flags (DevAddr, FCnt, PHY size) triples seen at least 10 minutes apart; a ciphertext test confirms
keystream reuse when two such ciphertexts differ in fewer bits than chance allows (binomial lower tail below 1e-6) or are identical at least
6 hours apart. Controls (placebo pairs from different addresses, pairs with different counters) and validation (detection power, a
synthetic fleet with known truth, Brno devices whose message integrity codes verify under a published default key, and a mutation test of
the pipeline) bound what the test can get wrong.

Main results: 236 of 8,528 LoED addresses (London, 2019 to 2020) confirmed; 2 of 252 in Liege, 58 of 1,023 in Brno, and 7 of 1,983 in
Vienna (2022 to 2023); 0 related placebo pairs; on 11,762 Brno triples with certain reuse, 11,753 confirmed and none wrongly.

## Data (not included)

Both source datasets are public and are not redistributed here, because they hold other parties' traffic:
- LoED, the LoRaWAN at the Edge Dataset: https://doi.org/10.5281/zenodo.4121430 (file `LoED_full.zip`).
- LoRaWAN Traffic Analysis Dataset of Povalac and Kral: https://doi.org/10.5281/zenodo.8090619 (files `log.zip` and `pcap.zip`),
  saved to `data/raw/povalac_lorawan/`.

No script prints or stores a payload in clear, and no result file holds a device address; `paper_tools/scan_addresses.py` checks the
published files against every address in the captures. The derived files that scripts write under `data/derived/` hold ciphertexts and
addresses and stay local. `.gitignore` is an allow-list: only the files named in it are published.

## Layout

| Path | Contents |
|---|---|
| `src/scoping/audit_common.py` | All detector rules in one place: frames from receptions (60 s chaining, gateway-aware merge), counter test, pairs, the relatedness rule, placebo, reset count |
| `src/data/collect_loed.py` | LoED data uplinks from the raw zip (pass 1: every reception; pass 2: FRMPayload of triples seen at least 60 s apart) |
| `src/data/parse_povalac.py` | Data uplinks and join requests from the Povalac and Kral sniffer logs |
| `src/scoping/e14` to `e26` | One script per result file in `results/` (see the table below) |
| `src/figures/fig_data.py`, `paper_tools/make_figs.py` | Figure data and Figures 1 to 7 (`draft/figs/`) |
| `verification/jobD/` | Mutation test of the pipeline: planted errors, the LoED and Vienna test beds, and `out_summary_after_fix.txt` |
| `results/` | Every number in the paper, as written by the scripts |

| Result file | Script | Paper |
|---|---|---|
| `e14_counter_reuse_census.txt` | `e14_counter_reuse_census.py` | Table 1, counter test |
| `e15b_reuse_analysis.txt` | `e15b_reuse_analysis.py` | Table 2, LoED prevalence |
| `e15c_controls.txt` | `e15c_controls.py` | Table 3, concentration |
| `e16_join_census.log`, `e16b_join_analysis.txt` | `e16_join_census.py`, `e16b_join_analysis.py` | Section 4.8 |
| `e17_exposure.txt` | `e17_exposure.py` | Section 4.6 |
| `e18_mechanism_gates.txt`, `e18_devices.csv` | `e18_mechanism_gates.py` | Sections 4.5 and 4.7, Fig. 7 |
| `e19_power_and_replication.txt` | `e19_power_and_replication.py` | Section 4.3, Table B.1, split halves |
| `e20_*.txt`, `e25_*.txt` | `e20_ground_truth_sim.py`, `e25_mutation_sim.py` | Synthetic fleet and its mutation test |
| `e21_threshold_sensitivity.txt` | `e21_threshold_sensitivity.py` | Table 5 |
| `e23_povalac_audit.txt`, `e24_testdevices.txt` | `e23_povalac_audit.py`, `e24_testdevices.py` | City captures |
| `e26_default_key_mic.txt` | `e26_default_key_mic.py` | Table 4, default-key ground truth |
| `fig_*.csv`, `fig_*.txt` | `fig_data.py`, `make_figs.py` | Figures 3 to 7 |

## Reproduce

Python 3.13 with `pip install -r requirements.txt`; about 4 GB of memory is enough if the steps run one at a time. From the repository root:

```
python -I src/data/collect_loed.py <path>/LoED_full.zip both
python -I src/data/parse_povalac.py data/raw/povalac_lorawan/log.zip 02_Liege.log 04_Graz.log 07_Brno.log 05_Wien.log
python -I src/scoping/e14_counter_reuse_census.py > results/e14_counter_reuse_census.txt
python -I src/scoping/e15b_reuse_analysis.py > results/e15b_reuse_analysis.txt
python -I src/scoping/e15c_controls.py > results/e15c_controls.txt
python -I src/scoping/e16_join_census.py <path>/LoED_full.zip > results/e16_join_census.log
python -I src/scoping/e16b_join_analysis.py > results/e16b_join_analysis.txt
python -I src/scoping/e17_exposure.py > results/e17_exposure.txt
python -I src/scoping/e18_mechanism_gates.py > results/e18_mechanism_gates.txt
python -I src/scoping/e19_power_and_replication.py > results/e19_power_and_replication.txt
python -I src/scoping/e20_ground_truth_sim.py > results/e20_ground_truth_sim.txt
python -I src/scoping/e20_ground_truth_sim.py 21 0.25 0.72 > results/e20_seed21.txt
python -I src/scoping/e20_ground_truth_sim.py 22 0.25 0.72 > results/e20_seed22.txt
python -I src/scoping/e21_threshold_sensitivity.py > results/e21_threshold_sensitivity.txt
python -I src/scoping/e23_povalac_audit.py liege graz brno wien > results/e23_povalac_audit.txt
python -I src/scoping/e24_testdevices.py data/raw/povalac_lorawan/pcap.zip > results/e24_testdevices.txt
python -I src/scoping/e25_mutation_sim.py
python -I src/scoping/e26_default_key_mic.py data/raw/povalac_lorawan/log.zip 07_Brno.log 05_Wien.log > results/e26_default_key_mic.txt
python -I src/figures/fig_data.py
python -I paper_tools/make_figs.py
python -I verification/jobD/run_mutants.py loed all
python -I verification/jobD/run_mutants.py povalac all 05_Wien.log
python -I verification/jobD/summarise.py > verification/jobD/out_summary_after_fix.txt
```

Each script states its inputs, rules and outputs in its header. The ciphertext test needs no key; the default-key check (`e26`) computes
only 4-byte message integrity codes with keys the device vendors published, and decrypts nothing.
