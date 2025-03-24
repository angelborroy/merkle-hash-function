package es.usj.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * Sample algorithm implementing Merkle–Damgård hash function
 *
 * By default, this uses message blocks of 160 bits to produce an 160 bits digest
 *
 * Compression function uses byte rotation, XOR, and addition operations with 3 rounds
 * Initialization Vector is generated using SecureRandom
 * Includes diffusion measurement capabilities
 *
 */
public class HashFileApp {
    // Digest length is 160 bits (like SHA-1)
    private static final int DIGEST_LENGTH_IN_BYTES = 160 / 8;
    // Block length is 160 bits
    private static final int BLOCK_LENGTH_IN_BYTES = 160 / 8;
    // Compression Function number of rounds
    private static final int ROUNDS = 3;
    // Sample file to apply the Hash Function
    private static final String inputFile = "/path/to/your/file.pdf";

    public static void main(String... args) throws Exception {
        // Create hash function instance
        HashFunction hashFunction = new HashFunction();

        // Display the initialization vector
        System.out.println("Initialization Vector: " + toHex(hashFunction.getState()));

        // Apply compression function to every input file message block in chunks of BLOCK_LENGTH
        try (InputStream in = new FileInputStream(inputFile)) {
            byte[] block = new byte[BLOCK_LENGTH_IN_BYTES];

            // Read first block
            if (in.read(block) != -1) {
                hashFunction.getDigest(block);

                // Read remaining blocks
                while (in.read(block) != -1) {
                    hashFunction.getDigest(block);
                }
            }
        }

        // Add final block with the length of the input file
        byte[] finalBlock = ByteBuffer.allocate(BLOCK_LENGTH_IN_BYTES).putLong(0, new File(inputFile).length()).array();
        byte[] digest = hashFunction.getDigest(finalBlock);

        // 160 bit digest expressed as hexadecimal string
        System.out.println("Digest: " + toHex(digest));

        // Demonstrate diffusion by hashing a slightly modified file length
        byte[] modifiedFinalBlock = ByteBuffer.allocate(BLOCK_LENGTH_IN_BYTES).putLong(0, new File(inputFile).length() + 1).array();
        HashFunction hashFunction2 = new HashFunction();
        hashFunction2.setState(hashFunction.getInitialState());
        byte[] modifiedDigest = hashFunction2.getDigest(modifiedFinalBlock);

        System.out.println("Modified Digest: " + toHex(modifiedDigest));

        // Measure diffusion between original and modified digests
        System.out.println("\nDiffusion Analysis (changing only file length by 1 byte):");
        measureDiffusion(digest, modifiedDigest);
    }

    /**
     * Convert byte[] to hexadecimal string representation
     */
    public static String toHex(byte[] bytes) {
        BigInteger bigInteger = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "x", bigInteger);
    }

    /**
     * Measure diffusion between two byte arrays by comparing bits
     * @param array1 First byte array
     * @param array2 Second byte array
     */
    private static void measureDiffusion(byte[] array1, byte[] array2) {
        // Convert both arrays to binary strings
        String binary1 = bytesToBinaryString(array1);
        String binary2 = bytesToBinaryString(array2);

        // Ensure same length by padding the shorter one
        int maxLength = Math.max(binary1.length(), binary2.length());

        // Count different bits
        int differentBits = 0;
        for (int i = 0; i < maxLength; i++) {
            if (binary1.charAt(i) != binary2.charAt(i)) {
                differentBits++;
            }
        }

        // Calculate percentage
        double percentage = (double) differentBits / maxLength * 100;

        // Print results
        System.out.println("Total bits compared: " + maxLength);
        System.out.println("Different bits: " + differentBits);
        System.out.println("Diffusion percentage: " + String.format("%.2f%%", percentage));
    }

    /**
     * Convert byte array to binary string
     */
    private static String bytesToBinaryString(byte[] bytes) {
        StringBuilder binary = new StringBuilder();
        for (byte b : bytes) {
            String bits = Integer.toBinaryString(b & 0xFF);
            // Pad to 8 bits
            while (bits.length() < 8) {
                bits = "0" + bits;
            }
            binary.append(bits);
        }
        return binary.toString();
    }

    /**
     * Improved Hash Function with better diffusion properties
     */
    static class HashFunction {
        // State holds the current digest value (160 bits / 20 bytes)
        private byte[] state;
        // Keep initial state for comparison purposes
        private byte[] initialState;

        /**
         * Initialize hash function with SecureRandom IV
         */
        public HashFunction() {
            SecureRandom secureRandom = new SecureRandom();
            state = new byte[DIGEST_LENGTH_IN_BYTES];
            secureRandom.nextBytes(state);
            // Store initial state
            initialState = state.clone();
        }

        /**
         * Get the current state
         */
        public byte[] getState() {
            return state;
        }

        /**
         * Set the state (used for diffusion testing)
         */
        public void setState(byte[] newState) {
            state = newState.clone();
        }

        /**
         * Get initial state (for diffusion testing)
         */
        public byte[] getInitialState() {
            return initialState;
        }

        /**
         * Apply compression operation to state (digest) and message block a number of rounds
         */
        public byte[] getDigest(byte[] block) {
            IntStream.range(0, ROUNDS).forEach(r -> {
                state = compressionFunction(state, block);
            });
            return state;
        }

        /**
         * Improved compression function that combines rotation, XOR and addition
         * to create a stronger mixing of bits between the block and digest
         */
        private byte[] compressionFunction(byte[] digest, byte[] block) {
            byte[] result = new byte[digest.length];

            // Copy the current digest as our starting point
            System.arraycopy(digest, 0, result, 0, digest.length);

            // For each byte in the block
            for (int i = 0; i < block.length; i++) {
                // Determine which position in the digest to modify (using modulo if block is larger)
                int position = i % digest.length;

                // Step 1: Rotate the bits of the digest byte right by 3 positions
                byte rotated = rotateRight(result[position], 3);

                // Step 2: XOR with the current block byte
                byte xored = (byte) (rotated ^ block[i]);

                // Step 3: Add the original digest byte (with overflow, which is fine for hashing)
                result[position] = (byte) (xored + digest[position]);
            }

            return result;
        }

        /**
         * Helper method to rotate the bits in a byte to the right
         * @param b The byte to rotate
         * @param positions Number of positions to rotate right
         * @return The rotated byte
         */
        private byte rotateRight(byte b, int positions) {
            // Ensure positions is within 0-7 range
            positions = positions % 8;

            // Convert to int to avoid sign issues during bit manipulation
            int value = b & 0xFF;

            // Perform the rotation
            return (byte) ((value >>> positions) | (value << (8 - positions)) & 0xFF);
        }
    }
}