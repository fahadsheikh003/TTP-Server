import sys

if len(sys.argv) != 4:
    print("Invalid Input")

try:
    print(pow(int(sys.argv[1], 0), int(sys.argv[2], 0), int(sys.argv[3], 0)))
except:
    print("Invalid Input")
