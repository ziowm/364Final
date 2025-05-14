"""
Moiz Uddin
364 Final Project
Basic Malware Detector
"""

import os
import hashlib

#suspicious file extensions
BAD_EXTENSIONS = [".exe", ".bat", ".scr", ".vbs", ".js"]

#suspicious file hashes to look for
BAD_HASHES = [
    "326577fbe6d73973bd67437829bf9301",#= 'virus'
    "f3f0c6e992b7562598d9865b6fe8b3a6",#= 'malware'
    "f4abe4bbba17c813595195fffa5fe601"#= 'spyware'
]

def get_file_hash(filepath):
    """_summary_
    calculate MD5 hash of the file

    Args:
        filepath: the filepath of the folder that the user inputs

    Returns:
        hashlib: the MD5 hash of the file
    """
    try:
        with open(filepath, "rb") as file: #opens file in binary mode
            file_contents = file.read() #reads the entire content of the file and loads it into memory at once
            return hashlib.md5(file_contents).hexdigest() #returns the MD5 hash of the file
    except:
        return None #if file cant be read return None

def scan_folder(folder):
    """_summary_
    loop through the folder that the user provides and read and analyze each file and determine if it is suspicious or not

    Args:
        folder: folder that the user inputs at the end of the filepath

    Returns:
        list: list of suspicious_files in order
    """
    #empty list of suspicious files
    suspicious_files = []
    
    #loops through each filename in the folder
    for filename in os.listdir(folder):
        filepath = os.path.join(folder, filename)
        
        if not os.path.isfile(filepath):
            #if it is not a file, skip it
            continue
            
        #extract file extension
        ext = os.path.splitext(filename)[1].lower()
        if ext in BAD_EXTENSIONS:
            #read the file extension and if it is one of the BAD_EXTENSIONS, then add it
            suspicious_files.append((filepath, f"Bad extension: {ext}"))
            continue
            
        #read file
        file_hash = get_file_hash(filepath)
        if file_hash in BAD_HASHES:
            #read the file and see if it has one of the BAD_HASHES
            suspicious_files.append((filepath, f"Bad hash: {file_hash}"))
            
    #return list of suspicious_files in order
    return suspicious_files

def main():
    """
    main function - user interface
    """
    print("Welcome to the Suspicious File Scanner by Moiz Uddin") #welcome message
    while True: #repeats forever until user decides to quit
        folder = input("\nEnter folder to scan (or type 'quit' to exit): ").strip()
        
        #if user types quit then break loop and quit program
        if folder.lower() == 'quit':
            print("Exiting the scanner. Goodbye!")
            break

        #if folder does not exist, print message and restart while loop
        if not os.path.exists(folder):
            print("Folder does not exist!")
            continue

        results = scan_folder(folder)

        if not results: #if no suspicious files are found
            print("No suspicious files found!")
        else: #there are suspicious files
            print("\nFound suspicious files:")
            #prints files in numbered list and gives reason as to why the file was flagged as suspicious
            for i, (filepath, reason) in enumerate(results, 1):
                print(f"{i}. {filepath} - {reason}")

if __name__ == "__main__":
    main()