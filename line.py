import os, time, sys

file_path = sys.argv[1] if len(sys.argv) > 1 else "input.txt"

with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
    # .strip() removes whitespace and newlines; evaluates to False if the line is empty
    line_count = sum(1 for line in file if line.strip())