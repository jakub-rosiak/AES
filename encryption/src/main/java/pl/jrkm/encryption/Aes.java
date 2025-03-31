package pl.jrkm.encryption;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Aes {

    private static final int[][] sbox = {
        { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },
        { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },
        { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },
        { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },
        { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },
        { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF },
        { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },
        { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },
        { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },
        { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },
        { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },
        { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },
        { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },
        { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },
        { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },
        { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }
    };

    private static final int[][] inv_sbox = {
        { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },
        { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },
        { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },
        { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },
        { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },
        { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },
        { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },
        { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },
        { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },
        { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },
        { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },
        { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },
        { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },
        { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },
        { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },
        { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }
    };

    private static final int[][] mix_columns_matrix = {
        { 0x02, 0x03, 0x01, 0x01 },
        { 0x01, 0x02, 0x03, 0x01 },
        { 0x01, 0x01, 0x02, 0x03 },
        { 0x03, 0x01, 0x01, 0x02 },
    };

    private static final int[][] inv_mix_columns_matrix = {
        {0x0E, 0x0B, 0x0D, 0x09},
        {0x09, 0x0E, 0x0B, 0x0D},
        {0x0D, 0x09, 0x0E, 0x0B},
        {0x0B, 0x0D, 0x09, 0x0E}
    };

    private static final int[] rcon = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    public static String decrypt(String encrypted, String key) {
        int[] keyInts = stringToHexArray(key);
        int[] encryptedInts = stringToHexArray(encrypted);
        List<int[][]> blocks = new ArrayList<>();
        List<int[][]> decryptedBlocks = new ArrayList<>();

        int counter = 0;
        while (counter < encryptedInts.length) {
            int[][] block = new int[4][4];

            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    block[row][col] = encryptedInts[counter];
                    counter++;
                }
            }
            blocks.add(block);
        }
        int rounds;
        switch (keyInts.length) {
            case 16 -> rounds = 9;
            case 24 -> rounds = 11;
            case 32 -> rounds = 13;
            default -> throw new IllegalArgumentException();
        }

        blocks.forEach(block -> {
            List<int[]> roundKeys = expandKey(keyInts);
            int[][] roundKey = new int[4][4];
            for (int i = 3; i >= 0; i--) {
                roundKey[i] = roundKeys.removeLast();
            }
            block = addRoundKey(block, roundKey);

            for(int i = 0; i < rounds; i++) {
                block = invShiftRows(block);
                block = invSubBytes(block);
                for (int j = 3; j >= 0; j--) {
                    roundKey[j] = roundKeys.removeLast();
                }
                block = addRoundKey(block, roundKey);
                block = invMixColumns(block);
            }

            block = invShiftRows(block);
            block = invSubBytes(block);
            for (int i = 3; i >= 0; i--) {
                roundKey[i] = roundKeys.removeLast();
            }
            block = addRoundKey(block, roundKey);
            decryptedBlocks.add(block);
        });

        return toUtf8String(decryptedBlocks);
    }

    public static String encrypt(String plainText, String key) {
        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
        int[] keyInts = stringToHexArray(key);
        int[] plainTextInts = new int[plainTextBytes.length];
        List<int[][]> blocks = new ArrayList<>();
        List<int[][]> encryptedBlocks = new ArrayList<>();


        for (int i = 0; i < plainTextBytes.length; i++) {
            plainTextInts[i] = plainTextBytes[i] & 0xFF;
        }

        int counter = 0;
        while (counter < plainTextInts.length) {
            int[][] block = new int[4][4];

            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    if (counter < plainTextInts.length) {
                        block[row][col] = plainTextInts[counter];
                        counter++;
                    } else {
                        block[row][col] = 0;
                    }
                }
            }
            blocks.add(block);
        }


        int rounds;
        switch (keyInts.length) {
            case 16 -> rounds = 9;
            case 24 -> rounds = 11;
            case 32 -> rounds = 13;
            default -> throw new IllegalArgumentException();
        }

        blocks.forEach(block -> {
            List<int[]> roundKeys = expandKey(keyInts);
            int[][] roundKey = new int[4][4];
            for (int i = 0; i < 4; i++) {
                roundKey[i] = roundKeys.getFirst();
                roundKeys.removeFirst();
            }
            block = addRoundKey(block, roundKey);

            for(int i = 0; i < rounds; i++) {
                block = subBytes(block);
                block = shiftRows(block);
                block = mixColumns(block);

                for (int j = 0; j < 4; j++) {
                    roundKey[j] = roundKeys.getFirst();
                    roundKeys.removeFirst();
                }
                block = addRoundKey(block, roundKey);
            }

            block = subBytes(block);
            block = shiftRows(block);
            for (int i = 0; i < 4; i++) {
                roundKey[i] = roundKeys.getFirst();
                roundKeys.removeFirst();
            }
            block = addRoundKey(block, roundKey);
            encryptedBlocks.add(block);
        });

        return hexToString(encryptedBlocks);
    }

    static String hexToString(List<int[][]> blocks) {
        StringBuilder sb = new StringBuilder();

        for (int[][] matrix : blocks) {
            for (int[] row : matrix) {
                for(int val: row) {
                    sb.append(String.format("%02X", val));
                }
            }
        }
        return sb.toString();
    }

    static int[] stringToHexArray(String hex) {
        int[] intArray = new int[hex.length() / 2];
        for (int i = 0; i < hex.length(); i+=2) {
            intArray[i/2] = Integer.parseInt(hex.substring(i, i+2), 16);
        }
        return intArray;
    }

    static String toUtf8String(List<int[][]> intArray) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        for (int[][] block : intArray) {
            for (int[] row : block) {
                for (int val : row) {
                    System.out.printf("%02X", val);
                    baos.write(val & 0xFF);
                }
            }
        }

        byte[] rawBytes = baos.toByteArray();

        if (rawBytes.length > 0) {
            int paddingLength = rawBytes[rawBytes.length - 1] & 0xFF;

            if (paddingLength > 0 && paddingLength <= 16) {
                boolean validPadding = true;
                for (int i = rawBytes.length - paddingLength; i < rawBytes.length; i++) {
                    if ((rawBytes[i] & 0xFF) != paddingLength) {
                        validPadding = false;
                        break;
                    }
                }

                if (validPadding) {
                    rawBytes = Arrays.copyOfRange(rawBytes, 0, rawBytes.length - paddingLength);
                }
            }
        }

        try {
            return new String(rawBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert decrypted data to UTF-8 string", e);
        }
    }

    public static List<int[]> expandKey(int[] key) {
        int numberofKeys;
        int numberOfWords;
        List<int[]> roundKeyWords = new ArrayList<>();
        switch (key.length) {
            case 16 -> {
                numberofKeys = 11;
                numberOfWords = 4;
            }
            case 24 -> {
                numberofKeys = 13;
                numberOfWords = 6;
            }
            case 32 -> {
                numberofKeys = 15;
                numberOfWords = 8;
            }
            default -> throw new IllegalArgumentException("The key length must be 16, 24 or 32 bytes");
        }
        int counter = 0;
        while (counter < key.length) {
            int[] word = new int[4];
            for (int i = 0; i < 4; i++) {
                word[i] = key[counter];
                counter++;
            }
            roundKeyWords.add(word);
        }

        for (int i = numberOfWords; i < numberofKeys * 4; i++) {
            int[] tempWord = roundKeyWords.getLast().clone();
            if(i % numberOfWords == 0) {
                tempWord = rotWord(tempWord);
                tempWord = subWord(tempWord);
                tempWord[0] ^= getRcon(i / numberOfWords);
            }

            for (int j = 0; j < 4; j++) {
                tempWord[j] ^= roundKeyWords.get(i - numberOfWords)[j];
            }

            roundKeyWords.add(tempWord);
        }

        return roundKeyWords;

    }

    static int[] rotWord(int[] word) {
        int[] rotatedWord = new int[4];
        rotatedWord[0] = word[1];
        rotatedWord[1] = word[2];
        rotatedWord[2] = word[3];
        rotatedWord[3] = word[0];
        return rotatedWord;
    }

    static int[] subWord(int[] word) {
        int[] substitutedWord = new int[4];
        for (int i = 0; i < 4; i++) {
            int value = word[i] & 0xFF;
            int row = (value >> 4) & 0xF;
            int col = value & 0xF;

            substitutedWord[i] = sbox[row][col];
        }
        return substitutedWord;
    }

    static int getRcon(int round) {
        return rcon[round - 1];
    }

    static int[][] subBytes(int[][] state) {
        int[][] newState = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int value = state[i][j];
                int row = (value & 0xF0) >> 4;
                int col = value & 0x0F;

                newState[i][j] = sbox[row][col];
            }
        }
        return newState;
    }

    static int[][] invSubBytes(int[][] state) {
        int[][] newState = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int value = state[i][j];
                int row = (value & 0xF0) >> 4;
                int col = value & 0x0F;

                newState[i][j] = inv_sbox[row][col];
            }
        }
        return newState;
    }

    static int[][] shiftRows(int[][] state) {
        int[][] newState = new int[4][4];

        System.arraycopy(state[0], 0, newState[0], 0, 4);

        for (int j = 0; j < 4; j++) {
            newState[1][j] = state[1][(j + 1) % 4];
        }

        for (int j = 0; j < 4; j++) {
            newState[2][j] = state[2][(j + 2) % 4];
        }

        for (int j = 0; j < 4; j++) {
            newState[3][j] = state[3][(j + 3) % 4];
        }

        return newState;
    }

    static int[][] invShiftRows(int[][] state) {
        int[][] newState = new int[4][4];

        System.arraycopy(state[0], 0, newState[0], 0, 4);

        for (int j = 0; j < 4; j++) {
            newState[1][j] = state[1][(j - 1 + 4) % 4];
        }

        for (int j = 0; j < 4; j++) {
            newState[2][j] = state[2][(j - 2 + 4) % 4];
        }

        for (int j = 0; j < 4; j++) {
            newState[3][j] = state[3][(j - 3 + 4) % 4];
        }

        return newState;
    }


    static int[][] mixColumns(int[][] state) {
        int[][] newState = new int[4][4];

        for (int c = 0; c < 4; c++) {
            int[] column = new int[4];
            for (int r = 0; r < 4; r++) {
                column[r] = state[r][c];
            }

            for (int r = 0; r < 4; r++) {
                int newValue = 0;
                for (int k = 0; k < 4; k++) {
                    newValue ^= gmul(mix_columns_matrix[r][k], column[k]);
                }
                newState[r][c] = newValue;
            }
        }

        return newState;
    }

    static int[][] invMixColumns(int[][] state) {
        int[][] newState = new int[4][4];

        for (int c = 0; c < 4; c++) {
            int[] column = new int[4];
            for (int r = 0; r < 4; r++) {
                column[r] = state[r][c];
            }

            for (int r = 0; r < 4; r++) {
                int newValue = 0;
                for (int k = 0; k < 4; k++) {
                    newValue ^= gmul(inv_mix_columns_matrix[r][k], column[k]);
                }
                newState[r][c] = newValue;
            }
        }

        return newState;
    }

    private static int gmul(int a, int b) {
        int p = 0;
        int counter;
        for (counter = 0; counter < 8; counter++) {
            if ((b & 1) == 1) {
                p ^= a;
            }
            boolean highBitSet = (a & 0x80) == 0x80;
            a <<= 1;
            if (highBitSet) {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return p & 0xFF;
    }

    static int[][] addRoundKey(int[][] state, int[][] roundKey) {
        int[][] newState = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[i][j] = state[i][j] ^ roundKey[i][j];
            }
        }
        return newState;
    }

    
}
