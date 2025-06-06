# 364Final
364 Final Project: Features the Python Script for the Malicious File Scanner and the HTML code used to program the Static Website hosted on Amazon Web Services.

Static Website hosted on Amazon Web Services: http://antivirus364.s3-website-us-east-1.amazonaws.com/

GitHub Repository Link with all code files used: https://github.com/ziowm/364Final

1. Project Overview
	
The cybersecurity issue that my project addresses is the issue of malware. Malware, in particular, can include files such as viruses, trojans, or worms. These files are often unnoticed by unsuspecting users and can easily find their way onto people's devices. My project comes in the form of a Python script that, when run, scans an entire folder and detects suspicious files. The goal here is to help users identify and then remove potentially dangerous files from their devices.
	I chose this topic because malware is one of the most common threats that everyday computer users face today. Many users do not even realize that they have malicious files being stored on their devices. By programming a very basic prototype that can detect some types of malicious files by reading file extensions or MD5 hashes within the files, I wanted to better understand both the technical and human factors in malware detection and response.


2. Description of the Prototype
	
The prototype is in two parts: the actual website hosted on an Amazon Web Services S3 Bucket as well as the Python script. The source code for both can be found on the GitHub repository I put at the top. I also included a test folder full of malicious files and some clean ones to test the program with.
	The program prototype is a simple command-line Python program that scans a provided folder for any suspicious files. The suspicious files getting flagged are ones with known dangerous extensions like .exe, .js, or .bat. It also reads through files and checks their MD5 hash, and compares them with a small sample of known malware signatures. It then tells the user the list of suspicious files and gives a reason why they were flagged.
	The website prototype is an HTML website hosted on Amazon Web Services. The website allows users to download the Python program directly from there. The website also explains in depth the overview, how the program works, the code of the program, an example output, and how to run it.
	The features that I implemented are: scanning for suspicious file extensions, comparing files to known threat signatures, and listing flagged files and reasons for flagging. I also implemented a fully functioning website that allows the general public to go and download the program with all the code and an explanation on how to use the script. The code is also very heavily commented, and anyone can go check the source code for both the Python program and the website on the GitHub repository.


3. Human Interaction
	
A real user would go to the website and read about the Python program and how to use it. The code is accessible from the website, so they can see everything directly without having to commit to a download. If they want to, they can download the program and then use it. A user would then run the program from the command line or terminal, enter the directory they want to scan, and then review the feedback that the program provides. This interaction simulates a real-world scenario where users must make decisions about unknown files.
	The goal of this project is to simulate a typical user experience with downloading antivirus software from a website and using it. The users will have to make well-educated decisions after reviewing flagged threats to keep their device safe. The project is designed to influence users to be cautious about files they do not recognize or are unsure about.


4. Framework Application
	
Human factors - Mental models: The design aligns with users’ preconceived notions of how security software works, making the interface predictable and understandable. By having a clean website with in-depth explanations of the code and the process used, it can align with user expectations. This helps reduce confusion and increases the likelihood of correct usage.
Usability - Bounded rationality: Users typically make decisions with limited knowledge. The prototype provides clear reasoning as to why a file was flagged in a way that is easy for even users with lesser knowledge to understand. This helps users make efficient, reasonably safe choices, even without deep expertise. The design is not complicated and only provides important information that supports effective decision-making.


5. Predicted User Behavior
	
Users will likely first go to the website and read through it. They will look over the code and then download the program. The users will then run the program as intended and select a folder to be scanned. Most users will either trust the program and then remove all the flagged files, or they will occasionally hesitate or manually review flagged files if they are unsure, possibly leaving some files untouched out of caution.
	An error or bias they might show would be over-reliance. Some users might blindly follow the program's recommendations and delete all the files, even files that could be safe and important. Another bias would be caution bias, where some users, who fear false positives, do not delete as much and leave malware on their machines. There might also be a misunderstanding between users where they do not understand certain file types or MD5 hashes, even though the website offers explanations for both.


6. Reflections
	
With time, I would implement more advanced malware detection using heuristics or AI/ML. I would add a GUI for better usability and to align better with commercial antivirus software. I would also add a function where, instead of deleting files, users could move them to a temporary location just in case they need to be restored. I would also add detailed explanations for less technical users.
	Making this project showed me how important human experience is when working with cybersecurity tools. The software has to be effective in explaining and communicating so that users can learn and apply the guidelines. Even a basic tool like the one I made must be carefully designed. The human factors of trust in a product and comprehension are just as important to a product as making it technically accurate.
