Execute the following 5 scripts in sequence:

```bash
python3 1.parse_auditbeat_e3.py     # Parse logs to generate node.csv and edge.csv in malicious_data folder
python3 2.word_embedding.py              # Perform node information embedding
python3 3.word_embedding_hashcode.py     # Generate node indexes
python3 4.word_embedding_deldup.py       # Perform node deduplication
python3 5.generate_data.py               # Generate training/testing data needed for global provenance analysis
```

All intermediate files and final generated data files are in the data folder (included in Deliverable 2 under the opensmtpd directory for endpoint monitoring). This data will first be used for rule-based detection at the endpoint to produce the `nodes_with_encode_reduce_index_deldup_anomaly.csv` file. Subsequently, `train.txt` can be generated in the data folder of benign logs for training; in the anomaly log folder, `test.txt` and `ground_truth.txt` containing real anomaly node information will be generated for testing. After moving the generated files to their corresponding positions in the training/testing dataset (included in Deliverable 3 under the data directory for global provenance analysis), the training and testing code can be run.
