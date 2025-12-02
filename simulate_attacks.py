from utils import generate_advanced_flow

df = generate_advanced_flow(500)   # generate new advanced logs
df.to_csv("sample_logs.csv", index=False)

print("New sample_logs.csv generated with all required columns.")
