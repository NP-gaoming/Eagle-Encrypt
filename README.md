Eagle encryption is a completely original symmetric encryption algorithm. The core of this algorithm is to provide a completely different encryption principle, breaking the security concept of traditional symmetric encryption algorithms. The core feature of this principle is that for any group of plaintext-ciphertext pairs, any key in the key space can actually be matched. That is, for the plaintext in a known plaintext-ciphertext pair, any key can be used to encrypted it and obtain the ciphertext in the known plaintext-ciphertext pair. This also theoretically guarantees that the encryption algorithm can resist all forms of linear attacks and differential attacks. For details of the algorithm principle, please refer to the paper "A proof of P != NP (New symmetric encryption algorithm against any linear attacks and differential attacks)" whose link is [https://arxiv.org/abs/2203.05022](https://arxiv.org/abs/2203.05022.).

# **Test method** #
## 1. Compile (you can skip this step directly) ##
Compilation language: golang

Compilation: go build main.go

## 2. Run (run in command line mode) ##
Since main.exe is an executable file, to prevent Trojan viruses, please confirm the md5 value of the file (b954e0282781e0d33a10f043e469a791) before running.

**2.1 Encrypt with text**
> main.exe enc --type=text --key=abcda1234f10568e --src=abef1efadfafafdaafeaba

> succ: ciphertext = 0000000b73093244b9e26f99ba323efeac714e21f2d0c3366335f98f43b1510bf73962d8

Note: type has two modes, --type=text or --type=file. --type=text means it encrypt or decrypt with a given text, --key is the key text. --src is the plain text. All of the text is given in hex format.
The output ciphertext is also expressed in hex format.

Since the Eagle encryption algorithm will supplement the insufficient bits of the plaintext according to the length of the key, the first four bytes of the ciphertext (such as 0000000b) indicate the length of the plaintext, and the following is the official text of the ciphertext.

**2.2 Decrypt with text** 
> main.exe dec --type=text --key=abcda1234f10568e --src=0000000b73093244b9e26f99ba323efeac714e21f2d0c3366335f98f43b1510bf73962d8

> succ: plaintext = abef1efadfafafdaafeaba

Note: During the decryption process, --src is the ciphertext text, which is given in hex format.

**2.3 Encrypt with file**
> main.exe enc --type=file --key=abcda1234f10568e --src=test\test.txt

Note: --src is the source file before encryption. Since this test code has not been optimized for engineering, it is not recommended to encrypt large files. The output file is in the same directory as the source file, and the filename is named with the suffix .cipher.

**2.4 Decrypt with file**
> main.exe dec --type=file --key=abcda1234f10568e --src=test\test.txt.cipher

Note: --src is the source file before decryption. The output file after decryption is in the same directory as the source file, and the filename is named with the .plain suffix.

## 3. Test process parameter interpretation ##
3.1 Each time the same text is encrypted with the same key, the ciphertext is completely different and randomly distributed.

3.2 For example, if the key takes two bytes and the plaintext takes one byte, through repeatedly testing, we will find that the ciphertext can take all values in the space.

## 4. Related statements ##
1 Since this algorithm is completely original, the correctness and security of the algorithm itself have not been widely recognized. At present, the open source code is only used for academic research and testing. Before this algorithm is widely recognized, it is not recommended to use it in real engineering scenarios. 


2 Since this algorithm is a basic innovation in the field of algorithms and mathematics, no one is allowed to use this source code anywhere to do anything illegal.


3 Since this algorithm can completely resist all forms of linear attacks and differential attacks at the theoretical level, it has extremely important academic research value. We warmly welcome experts and engineers in the fields of cryptography, computer algorithms, and number theory to actively participate in the construction of the project.
