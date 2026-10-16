import os

# 1. Get the file path dynamically from the user
file_path = input("Enter the full path to the file: ").strip()

# 2. Verify that the file actually exists before trying to open it
if os.path.isfile(file_path):
    try:
        # 3. Open the file efficiently in read mode
        # 'errors="ignore"' ensures the script won't crash on non-text/binary characters
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            line_count = sum(1 for line in file)
            
        print(f"Total number of lines: {line_count}")
        
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
else:
    print("Error: The path you entered is not a valid file.")
