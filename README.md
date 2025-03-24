# Custom Merkle–Damgård Hash Function

This project showcases two Java implementations of a custom Merkle–Damgård-style hash function. 
It highlights core cryptographic concepts such as compression functions, diffusion analysis, and the use of Initialization Vectors (IVs). 
The implementations demonstrate both string-based and file-based hashing with basic diffusion visualization.

## Features

- Custom Merkle–Damgård hash construction
- Two implementations:
  - `HashApp.java`: Hashes binary strings and visualizes diffusion
  - `HashFileApp.java`: Hashes file content with SHA-1-like block and digest size (160 bits)
- Compression function combining:
  - Bitwise rotation
  - XOR operation
  - Byte addition
- Random IV generation using `SecureRandom`
- Diffusion analysis: bitwise comparison of similar inputs and their resulting digests

## Project Structure

```
src/
├── es/usj/crypto/
├── HashApp.java       # Binary-string input hash test with diffusion metrics
└── HashFileApp.java   # File-based hashing with a 160-bit custom function
```

## Requirements

- Java 17 or higher
- No external dependencies

## How to Run

1. Compile the classes

   ```bash
   javac es/usj/crypto/*.java
   ```

2. Run HashApp

   ```bash
   java es.usj.crypto.HashApp
   ```

3. Run HashFileApp (file-based hashing)

   > Update the `inputFile` variable in `HashFileApp.java` to point to a valid file on your machine before compiling.

   ```java
   private static final String inputFile = "/path/to/your/file.pdf";
   ```

   Then:

   ```bash
   java es.usj.crypto.HashFileApp
   ```

## Educational Goals

This project is ideal for teaching and understanding:

- The structure and flow of iterative hash functions
- The role of padding and message length encoding
- Importance of bit-level diffusion in cryptographic security
- Simple cryptographic operations in Java without external libraries