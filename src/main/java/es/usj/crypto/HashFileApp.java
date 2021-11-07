package es.usj.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.stream.IntStream;

/**
 * Sample algorithm implementing Merkle–Damgård hash function
 *
 * By default, this uses message blocks of 160 bits to produce an 160 bits digest
 *
 * Compression function is XOR operation on block and digest bits using 3 rounds
 *
 * This algorithm is intended only for teaching purposes, since diffusion is not covered at all.
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
    private static final String inputFile = "/Users/aborroy/Downloads/script.txt";

    public static void main(String... args) {

        HashFunction hashFunction = new HashFunction();

        // Initialize block message buffer and digest buffer
        byte[] digest = new byte[DIGEST_LENGTH_IN_BYTES];
        byte[] block = new byte[BLOCK_LENGTH_IN_BYTES];

        // Apply compression function to every input file message block in chunks of BLOCK_LENGTH
        try (InputStream in = new FileInputStream(inputFile)) {
            in.read(block);
            hashFunction.getDigest(block);
            while (in.read(block) != -1) {
                hashFunction.getDigest(block);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Add final block with the length of the input file
        block = ByteBuffer.allocate(BLOCK_LENGTH_IN_BYTES).putLong(0, new File(inputFile).length()).array();
        digest = hashFunction.getDigest(block);

        // 160 bit digest expressed as hexadecimal string
        System.out.println(toHex(digest));

    }

    /**
     * Convert byte[] to hexadecimal string representation
     */
    public static String toHex(byte[] bytes) {
        BigInteger bigInteger = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "x", bigInteger);
    }

    /**
     * Simple Hash Function, applying XOR to state (digest) and message blocks
     */
    static class HashFunction {

        // Initialization vector: 160 bits / 20 bytes
        // Populated with random numbers
        private byte[] state = new byte[] {
            (byte) 0xa7, (byte) 0xe5, (byte) 0xd9, (byte) 0x42, (byte) 0x83,
            (byte) 0x70, (byte) 0x1a, (byte) 0x4e, (byte) 0xb6, (byte) 0x9e,
            (byte) 0xc0, (byte) 0x25, (byte) 0x3c, (byte) 0xb5, (byte) 0x54,
            (byte) 0x0b, (byte) 0xf5, (byte) 0x83, (byte) 0x65, (byte) 0x34
        };

        /**
         * Apply compression operation to state (digest) and message block a number of rounds
         */
        public byte[] getDigest(byte[] block) {
            IntStream.range(0, ROUNDS).forEach(r -> {
                state = Xor(state, block);
            });
            return state;
        }

        /**
         * XOR bit operation for byte[] operands
         */
        public static byte[] Xor(byte[] left, byte[] right)
        {
            byte[] val = new byte[left.length];
            for (int i = 0; i < left.length; i++)
                val[i] = (byte)(left[i] ^ right[i]);
            return val;
        }

    }

}
