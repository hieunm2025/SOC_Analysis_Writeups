**John the Ripper (JtR) Overview**

* **Purpose:**
  Open-source password cracking tool used for penetration testing. The "jumbo" variant is recommended for better performance and broader hash support.

* **Cracking Modes:**

  * **Single Crack Mode:**
    Uses user info (username, home directory) to generate likely passwords.

    * Command: `john --single passwd`
  * **Wordlist Mode:**
    Attempts passwords from a dictionary against hashes. Custom rules can modify the words.

    * Command: `john --wordlist=<file> <hash_file>`
  * **Incremental Mode:**
    Brute-force method generating all character combinations.

    * Command: `john --incremental <hash_file>`

* **Hash Identification:**
  Use `hashid` to identify hash formats.

  * Command: `hashid -j <hash_value>`

* **Supported Hash Formats:**
  Includes MD5, SHA1, NTLM, MySQL, RAR, ZIP, and more.

* **Cracking Files:**
  Use tools like `pdf2john`, `rar2john`, `zip2john` to convert and crack encrypted files.
question 1:

passwd
r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash 
john --single passwd
=> password
question 2:
![alt text](image.png)
**Hashcat Overview**

* **What is Hashcat?**
  Hashcat is an open-source password cracking tool that supports various hash types and attack modes. It uses GPU acceleration to crack hashes efficiently. Hashcat supports modes like dictionary, mask, and combinator for password cracking.

* **Hashcat Syntax:**

  ```bash
  hashcat -a <attack_mode> -m <hash_type> <hash_file> [additional_arguments]
  ```

  * `-a`: Specifies the attack mode (e.g., dictionary, mask).
  * `-m`: Specifies the hash type (e.g., MD5, SHA1).
  * `<hash_file>`: File containing the hash to crack.
  * `[additional_arguments]`: Additional options like wordlists, rules, and masks.

* **Hash Types:**
  Hashcat supports hundreds of hash types, each assigned a mode number, like:

  * MD5: `-m 0`
  * SHA1: `-m 100`
  * RIPEMD-128: `-m 600`

  Use `hashcat --help` or `hashid` for hash identification.

* **Attack Modes:**

  1. **Dictionary Attack** (`-a 0`):
     Tries each word from a wordlist against the hash.
     Example:

     ```bash
     hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt
     ```

  2. **Mask Attack** (`-a 3`):
     Brute-force with a custom mask defining the password structure (e.g., `?u?l?l?l?d?s` for an uppercase letter, four lowercase letters, a digit, and a symbol).
     Example:

     ```bash
     hashcat -a 3 -m 0 <hash> '?u?l?l?l?d?s'
     ```

* **Rules:**
  You can use rules to modify words from the wordlist, applying transformations like leetspeak.
  Example:

  ```bash
  hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
  ```
**Practice:**
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'

**Cracking Protected Files Overview**

* **File Encryption Usage:**
  Encryption is often neglected in private and professional contexts, leaving sensitive data vulnerable. Symmetric encryption (e.g., AES-256) uses the same key for encryption and decryption, while asymmetric encryption uses a public and private key pair for secure transmission.

* **Hunting for Encrypted Files:**
  Files with specific extensions (e.g., `.xls`, `.pdf`, `.docx`) are commonly encrypted. You can use the following command to search for encrypted files on Linux:

  ```bash
  find / -name "*.xls" -or -name "*.pdf" -or -name "*.docx" 2>/dev/null
  ```

* **Hunting for SSH Keys:**
  SSH keys may not have standard extensions but can be identified by their headers like `-----BEGIN RSA PRIVATE KEY-----`. Use `grep` to search for these:

  ```bash
  grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
  ```

* **Cracking Encrypted SSH Keys:**
  Some SSH keys are encrypted with a passphrase. Use **John the Ripper (JtR)** to crack these by first converting them to hash format with tools like `ssh2john.py`, then using JtR:

  ```bash
  ssh2john.py SSH.private > ssh.hash
  john --wordlist=rockyou.txt ssh.hash
  ```

* **Cracking Password-Protected Documents:**

  * **Office Documents:** Use `office2john.py` to extract password hashes from Office files, then crack with JtR:

    ```bash
    office2john.py Protected.docx > protected-docx.hash
    john --wordlist=rockyou.txt protected-docx.hash
    ```
  * **PDF Files:** Use `pdf2john.py` to extract password hashes from PDF files and crack them similarly:

    ```bash
    pdf2john.py PDF.pdf > pdf.hash
    john --wordlist=rockyou.txt pdf.hash
    ```

* **Challenges:**
  Cracking encrypted files becomes harder as passwords get longer and more complex. Standard wordlists are often ineffective against these more secure files.

**Summary:**
Encrypted files, including SSH keys, PDFs, and Office documents, can be cracked using tools like JtR. The process involves extracting password hashes with specific scripts and then performing a dictionary attack using wordlists or masks.
Practice
wget https://academy.hackthebox.com/storage/modules/147/cracking-protected-files.zip
unzip cracking-protected-files.zip
john --wordlist=/usr/share/wordlists/rockyou.txt excel.hash

