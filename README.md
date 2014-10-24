Create a rainbow table and use it to “break” hash functions. You will write a program to generate a rainbow, a program to invert hashes using the rainbow table.

We will use the following system to hash 𝑛-bit password: We will left-pad the password with 0s until it 
is 128-bits long, calling the result 𝑃. Then we will compute AES-128 using 𝑃 as a key on plaintext block of all zeros 

			𝐻(𝑃) = 𝐴𝐸𝑆𝑃(0)

Thus, for the 12-bit password 𝑃 =0xABC, the result should be

	𝐻(𝑃) = 0x970fc16e71b75463abafb3f8be939d1c
