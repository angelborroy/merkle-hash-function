package es.usj.crypto;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Sample algorithm implementing Merkle–Damgård hash function using byte arrays
 *
 * By default, this uses message blocks of 2 bytes to produce a 1 byte digest
 *
 * Compression function uses byte rotation, XOR, and addition operations with 3 rounds
 * Initialization Vector is generated using SecureRandom
 * Input is taken as a binary string and converted to bytes internally
 * Includes diffusion measurement to compare hash results
 *
 */
public class HashApp {

    // Digest length 1 byte
    private static byte[] initializationVector;
    // Block length 2 bytes
    private static final int BLOCK_LENGTH = 2;
    // Compression Function number of rounds
    private static final int ROUNDS = 3;

    public static void main(String... args) {
        // Generate random IV using SecureRandom
        generateRandomIV();
        System.out.print("IV:      ");
        printBytes(initializationVector);

        // Input message as binary string
        String binaryMessage1 = "01111010011111110100101111111011";
        System.out.println("Message1: " + binaryMessage1);

        // Convert binary string to bytes
        byte[] message1 = binaryStringToBytes(binaryMessage1);
        byte[] digest1 = hashMessage(message1);

        System.out.print("Digest1:  ");
        printBytes(digest1);

        // Slightly different message (just one bit changed)
        String binaryMessage2 = "11111010011111110100101111111011";
        System.out.println("Message2: " + binaryMessage2);

        byte[] message2 = binaryStringToBytes(binaryMessage2);
        byte[] digest2 = hashMessage(message2);

        System.out.print("Digest2:  ");
        printBytes(digest2);

        // Compare messages
        System.out.println("\nComparing input messages:");
        measureDiffusion(message1, message2);

        // Compare digests to see diffusion effect
        System.out.println("\nComparing output digests:");
        measureDiffusion(digest1, digest2);
    }

    /**
     * Hash a message and return the digest
     */
    private static byte[] hashMessage(byte[] message) {
        // Initial input for the compression function is the Initialization Vector
        byte[] digest = initializationVector.clone();

        // Apply compression function to every message block
        for (byte[] block : messageBlocks(message)) {
            // Apply compression function for a message block a number of rounds
            for (int i = 0; i < ROUNDS; i++) {
                digest = compressionFunction(block, digest);
            }
        }

        return digest;
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
        binary1 = padBinaryString(binary1, maxLength);
        binary2 = padBinaryString(binary2, maxLength);

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

        // Print visual representation of differences
        System.out.println("Bit differences (^ marks different bits):");
        System.out.println("1: " + binary1);
        System.out.println("2: " + binary2);
        StringBuilder diff = new StringBuilder();
        for (int i = 0; i < maxLength; i++) {
            diff.append(binary1.charAt(i) != binary2.charAt(i) ? '^' : ' ');
        }
        System.out.println("   " + diff);
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
     * Pad binary string to specified length
     */
    private static String padBinaryString(String binary, int length) {
        if (binary.length() >= length) {
            return binary;
        }
        StringBuilder padded = new StringBuilder(binary);
        while (padded.length() < length) {
            padded.append('0');
        }
        return padded.toString();
    }

    /**
     * Generate a random initialization vector using SecureRandom
     */
    private static void generateRandomIV() {
        SecureRandom secureRandom = new SecureRandom();
        initializationVector = new byte[1]; // 1 byte digest
        secureRandom.nextBytes(initializationVector);
    }

    /**
     * Convert a binary string to byte array
     * @param binaryString String of 0s and 1s
     * @return byte array
     */
    private static byte[] binaryStringToBytes(String binaryString) {
        int length = binaryString.length();
        int byteCount = (length + 7) / 8; // Calculate number of bytes needed
        byte[] bytes = new byte[byteCount];

        // Pad the binary string to a multiple of 8 if needed
        StringBuilder paddedBinary = new StringBuilder(binaryString);
        while (paddedBinary.length() % 8 != 0) {
            paddedBinary.append('0');
        }

        // Convert each 8-bit section to a byte
        for (int i = 0; i < byteCount; i++) {
            int startIndex = i * 8;
            String byteStr = paddedBinary.substring(startIndex, startIndex + 8);
            bytes[i] = (byte) Integer.parseInt(byteStr, 2);
        }

        return bytes;
    }

    /**
     * Helper method to print bytes in binary format
     */
    private static void printBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            // Convert byte to binary string and ensure it has 8 bits
            String binary = Integer.toBinaryString(b & 0xFF);
            while (binary.length() < 8) {
                binary = "0" + binary;
            }
            sb.append(binary);
        }
        System.out.println(sb.toString());
    }

    /**
     * Split message in blocks of BLOCK_LENGTH size.
     * Add length of the message at the end of the last block.
     * Padding applied when required.
     * @param message Byte array message
     * @return List of byte array blocks
     */
    private static List<byte[]> messageBlocks(byte[] message) {
        // Split the message into blocks of BLOCK_LENGTH size
        List<byte[]> blocks = new ArrayList<>();
        int messageLength = message.length;

        for (int i = 0; i < messageLength; i += BLOCK_LENGTH) {
            int blockSize = Math.min(BLOCK_LENGTH, messageLength - i);
            byte[] block = new byte[blockSize];
            System.arraycopy(message, i, block, 0, blockSize);
            blocks.add(block);
        }

        // Get the last block
        byte[] lastBlock = blocks.get(blocks.size() - 1);

        // We need to add message length as an additional byte
        byte lengthByte = (byte) messageLength;

        // If last block is already full, pad it to BLOCK_LENGTH and add a new block with the length
        if (lastBlock.length == BLOCK_LENGTH) {
            byte[] lengthBlock = new byte[BLOCK_LENGTH];
            lengthBlock[0] = lengthByte;
            // Pad remaining bytes with zeros
            for (int i = 1; i < BLOCK_LENGTH; i++) {
                lengthBlock[i] = 0;
            }
            blocks.add(lengthBlock);
        } else {
            // If last block has space, add the length byte to it and pad if needed
            byte[] paddedLastBlock = new byte[BLOCK_LENGTH];
            System.arraycopy(lastBlock, 0, paddedLastBlock, 0, lastBlock.length);
            paddedLastBlock[lastBlock.length] = lengthByte;
            // Pad remaining bytes with zeros if needed
            for (int i = lastBlock.length + 1; i < BLOCK_LENGTH; i++) {
                paddedLastBlock[i] = 0;
            }
            blocks.set(blocks.size() - 1, paddedLastBlock);
        }

        return blocks;
    }

    /**
     * Improved compression function that combines rotation, XOR and addition
     * to create a stronger mixing of bits between the block and digest
     */
    private static byte[] compressionFunction(byte[] block, byte[] digest) {
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
    private static byte rotateRight(byte b, int positions) {
        // Ensure positions is within 0-7 range
        positions = positions % 8;

        // Convert to int to avoid sign issues during bit manipulation
        int value = b & 0xFF;

        // Perform the rotation
        return (byte) ((value >>> positions) | (value << (8 - positions)) & 0xFF);
    }
}