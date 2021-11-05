package es.usj.crypto;

import java.util.ArrayList;
import java.util.List;

/**
 * Sample algorithm implementing Merkle–Damgård hash function
 *
 * By default, this uses message blocks of 16 bits to produce an 8 bits digest
 *
 * Compression function is XOR operation on block and digest bits using 3 rounds
 *
 */
public class HashApp {

    // Digest length 8 bits
    private static final String INITIALIZATION_VECTOR = "01101010";
    // Block length 16 bits
    private static final int BLOCK_LENGTH = 16;
    // Compression Function number of rounds
    private static final int ROUNDS = 3;

    public static void main(String... args) {

        String message = "01111010011111110100101111111011";
        System.out.println("Message: " + message);

        // Initial input for the compression function is the Initialization Vector
        String digest = INITIALIZATION_VECTOR;

        // Apply compression function to every message block
        for (String block : messageBlocks(message)) {
            // Apply compression function for a message block a number of rounds
            for (int i = 0; i < ROUNDS; i++) {
                digest = compressionFunction(block, digest);
            }
        }
        System.out.println("Digest:  " + digest);

    }

    /**
     * Split message in blocks of BLOCK_LENGTH size.
     * Add length of the message at the end of the last block.
     * Padding applied when required.
     * @param message Bit String message
     * @return List of Bit String blocks
     */
    private static List<String> messageBlocks(String message) {

        // Split the message into blocks of BLOCK_LENGTH size
        List<String> blocks = new ArrayList<>();
        int length = message.length();
        for (int i = 0; i < length; i += BLOCK_LENGTH) {
            blocks.add(message.substring(i, Math.min(length, i + BLOCK_LENGTH)));
        }

        // Preparation to add the length of the message to the last block
        String lastBlock = blocks.get(blocks.size() - 1);
        String lengthBinary = Integer.toBinaryString(length);

        // When last block doesn't have enough space to add the length of the message,
        // right padding is added to the last block to complete the BLOCK_LENGTH and
        // a new message block is created with the length of the message left padded
        // to complete the BLOCK_LENGTH
        if (lastBlock.length() + lengthBinary.length() > BLOCK_LENGTH) {
            lastBlock = rightPadding(lastBlock, BLOCK_LENGTH);
            blocks.set(blocks.size() - 1, lastBlock);
            lengthBinary = leftPadding(lengthBinary, BLOCK_LENGTH);
            blocks.add(lengthBinary);
        } else {
            // When last block has space to add the length of the message,
            // last block is modified padding in the middle of last block and message length
            // to complete the BLOCK_LENGTH
            lastBlock = lastBlock + leftPadding(lengthBinary, BLOCK_LENGTH - lastBlock.length());
            blocks.set(blocks.size() - 1, lastBlock);
        }

        return blocks;

    }

    /**
     * Add zeroes to the left till complete length
     */
    private static String leftPadding(String text, int length) {
        return String.format("%1$" + length + "s", text).replace(' ', '0');
    }

    /**
     * Add zeroes to the right till complete length
     */
    private static String rightPadding(String text, int length) {
        return String.format("%1$-" + length + "s", text).replace(' ', '0');
    }

    /**
     * Compressing block bits input into digest length bits as output
     * Apply XOR operation modulo digest length
     */
    private static String compressionFunction(String block, String digest) {

        StringBuilder xor = new StringBuilder();
        for (int i = 0; i < block.length(); i++) {
            // When block char position is less or equals to digest length, apply xor
            if (i < digest.length()) {
                xor.append((block.charAt(i) - '0') ^ (digest.charAt(i) - '0'));
            } else {
                // When block char position is greater than digest length, apply xor modulo digest length
                xor.setCharAt(
                    i % digest.length(),
                    Character.forDigit((block.charAt(i) - '0') ^ (digest.charAt(i % digest.length()) - '0'), 10));
            }
        }
        return xor.toString();
    }

}
