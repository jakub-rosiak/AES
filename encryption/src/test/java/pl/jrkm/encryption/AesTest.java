package pl.jrkm.encryption;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AesTest {
    @Test
    public void testSubBytes() {
        int[][] state = {
                {0xCF, 0xB1, 0x2A, 0x1A},
                {0x4E, 0x7F, 0x52, 0x27},
                {0xBC, 0x45, 0x81, 0x97},
                {0x9F, 0x41, 0xE2, 0xAB}
        };
        int[][] expectedState = {
                {0x8A, 0xC8, 0xE5, 0xA2},
                {0x2F, 0xD2, 0x00, 0xCC},
                {0x65, 0x6E, 0x0C, 0x88},
                {0xDB, 0x83, 0x98, 0x62}
        };
        state = Aes.subBytes(state);
        assertArrayEquals(expectedState, state);
    }

    @Test
    public void testInvSubBytes() {
        int[][] expectedState = {
                {0xCF, 0xB1, 0x2A, 0x1A},
                {0x4E, 0x7F, 0x52, 0x27},
                {0xBC, 0x45, 0x81, 0x97},
                {0x9F, 0x41, 0xE2, 0xAB}
        };
        int[][] state = {
                {0x8A, 0xC8, 0xE5, 0xA2},
                {0x2F, 0xD2, 0x00, 0xCC},
                {0x65, 0x6E, 0x0C, 0x88},
                {0xDB, 0x83, 0x98, 0x62}
        };
        state = Aes.invSubBytes(state);
        assertArrayEquals(expectedState, state);
    }

    @Test
    public void testShiftRows() {
        int[][] state = {
                {0x63, 0xeb, 0x9f, 0xa0},
                {0xc0, 0x2f, 0x93, 0x92},
                {0xab, 0x30, 0xaf, 0xc7},
                {0x20, 0xcb, 0x2b, 0xa2}
        };
        int[][] expectedState = {
                {0x63, 0xeb, 0x9f, 0xa0},
                {0x2f, 0x93, 0x92, 0xc0},
                {0xaf, 0xc7, 0xab, 0x30},
                {0xa2, 0x20, 0xcb, 0x2b}
        };
        state = Aes.shiftRows(state);
        System.out.println(Arrays.deepToString(state));
        assertArrayEquals(expectedState, state);
    }

    @Test
    public void testInvShiftRows() {
        int[][] expectedState = {
                {0x63, 0xeb, 0x9f, 0xa0},
                {0xc0, 0x2f, 0x93, 0x92},
                {0xab, 0x30, 0xaf, 0xc7},
                {0x20, 0xcb, 0x2b, 0xa2}
        };
        int[][] state = {
                {0x63, 0xeb, 0x9f, 0xa0},
                {0x2f, 0x93, 0x92, 0xc0},
                {0xaf, 0xc7, 0xab, 0x30},
                {0xa2, 0x20, 0xcb, 0x2b}
        };
        state = Aes.invShiftRows(state);
        System.out.println(Arrays.deepToString(state));
        assertArrayEquals(expectedState, state);
    }

    @Test
    public void testMixColumns() {
        int[][] state = {
                {0x8A, 0xC8, 0xE5, 0xA2},
                {0xD2, 0x00, 0xCC, 0x2F},
                {0x0C, 0x88, 0x65, 0x6E},
                {0x62, 0xDB, 0x83, 0x98}
        };
        int[][] expectedState = {
                {0x0C, 0xD8, 0x78, 0xD8},
                {0x43, 0x90, 0x4A, 0xD6},
                {0xE6, 0xB5, 0x7D, 0xE2},
                {0x9F, 0x66, 0x80, 0x97}
        };
        state = Aes.mixColumns(state);
        assertArrayEquals(expectedState, state);
    }

    @Test
    public void testInvMixColumns() {
        int[][] expectedState = {
                {0x8A, 0xC8, 0xE5, 0xA2},
                {0xD2, 0x00, 0xCC, 0x2F},
                {0x0C, 0x88, 0x65, 0x6E},
                {0x62, 0xDB, 0x83, 0x98}
        };
        int[][] state = {
                {0x0C, 0xD8, 0x78, 0xD8},
                {0x43, 0x90, 0x4A, 0xD6},
                {0xE6, 0xB5, 0x7D, 0xE2},
                {0x9F, 0x66, 0x80, 0x97}
        };
        state = Aes.invMixColumns(state);
        assertArrayEquals(expectedState, state);
    }

    @Test
    public void testAddRoundKey() {
        int[][] state = {
                {0x04, 0x66, 0x81, 0xe5},
                {0xe0, 0xcb, 0x19, 0x9a},
                {0x48, 0xf8, 0xd3, 0x7a},
                {0x28, 0x06, 0x26, 0x4c}
        };
        int[][] roundKey = {
                {0xa0, 0x88, 0x23, 0x2a},
                {0xfa, 0x54, 0xa3, 0x6c},
                {0xfe, 0x2c, 0x39, 0x76},
                {0x17, 0xb1, 0x39, 0x05}
        };
        int[][] expectedState = {
                {0xa4, 0xee, 0xa2, 0xcf},
                {0x1a, 0x9f, 0xba, 0xf6},
                {0xb6, 0xd4, 0xea, 0x0c},
                {0x3f, 0xb7, 0x1f, 0x49}
        };
        state = Aes.addRoundKey(state, roundKey);
        assertArrayEquals(expectedState, state);
    }

    @Test
    public void testKeyExpansion128Bit() {
        // Test vector for 128-bit key (4x4 matrix, one byte per element)
        int[] key128 = {
                0x2b, 0x28, 0xab, 0x09,
                0x7e, 0xae, 0xf7, 0xcf,
                0x15, 0xd2, 0x15, 0x4f,
                0x16, 0xa6, 0x88, 0x3c
        };

        // Expected round keys for 128-bit key (10+1 round keys, each as 4x4 matrix)
        int[][] expected128 = {
                // Initial round key (round 0) - same as the input key
                {0x2b, 0x28, 0xab, 0x09},
                {0x7e, 0xae, 0xf7, 0xcf},
                {0x15, 0xd2, 0x15, 0x4f},
                {0x16, 0xa6, 0x88, 0x3c},

                // Round 1
                {0x0e, 0xec, 0x40, 0x4e},
                {0x70, 0x42, 0xb7, 0x81},
                {0x65, 0x90, 0xa2, 0xce},
                {0x73, 0x36, 0x2a, 0xf2},

                // Round 2
                {0x09, 0x09, 0xc9, 0xc1},
                {0x79, 0x4b, 0x7e, 0x40},
                {0x1c, 0xdb, 0xdc, 0x8e},
                {0x6f, 0xed, 0xf6, 0x7c},

                // Round 3
                {0x58, 0x4b, 0xd9, 0x69},
                {0x21, 0x00, 0xa7, 0x29},
                {0x3d, 0xdb, 0x7b, 0xa7},
                {0x52, 0x36, 0x8d, 0xdb},

                // Round 4
                {0x55, 0x16, 0x60, 0x69},
                {0x74, 0x16, 0xc7, 0x40},
                {0x49, 0xcd, 0xbc, 0xe7},
                {0x1b, 0xfb, 0x31, 0x3c},

                // Round 5
                {0x4a, 0xd1, 0x8b, 0xc6},
                {0x3e, 0xc7, 0x4c, 0x86},
                {0x77, 0x0a, 0xf0, 0x61},
                {0x6c, 0xf1, 0xc1, 0x5d},

                // Round 6
                {0xcb, 0xa9, 0xc7, 0x96},
                {0xf5, 0x6e, 0x8b, 0x10},
                {0x82, 0x64, 0x7b, 0x71},
                {0xee, 0x95, 0xba, 0x2c},

                // Round 7
                {0xa1, 0x5d, 0xb6, 0xbe},
                {0x54, 0x33, 0x3d, 0xae},
                {0xd6, 0x57, 0x46, 0xdf},
                {0x38, 0xc2, 0xfc, 0xf3},

                // Round 8
                {0x04, 0xed, 0xbb, 0xb9},
                {0x50, 0xde, 0x86, 0x17},
                {0x86, 0x89, 0xc0, 0xc8},
                {0xbe, 0x4b, 0x3c, 0x3b},

                // Round 9
                {0xac, 0x06, 0x59, 0x17},
                {0xfc, 0xd8, 0xdf, 0x00},
                {0x7a, 0x51, 0x1f, 0xc8},
                {0xc4, 0x1a, 0x23, 0xf3},

                // Round 10
                {0x38, 0x20, 0x54, 0x0b},
                {0xc4, 0xf8, 0x8b, 0x0b},
                {0xbe, 0xa9, 0x94, 0xc3},
                {0x7a, 0xb3, 0xb7, 0x30},
        };


        List<int[]> result128 = Aes.expandKey(key128);

        // Check number of round keys
        assertEquals(44, result128.size(), "Number of round keys for 128-bit key should be 11");

        // Verify each round key matches the expected value
        for(int i = 0; i < result128.size(); i++) {
            assertArrayEquals(expected128[i], result128.get(i), "Round key at index " + i);
        }
    }

    @Test
    public void testKeyExpansion192Bit() {
        // Test vector for 192-bit key (6x4 matrix)
        // We'll represent it as a 4x6 matrix for consistency with AES column-major operations
        int[] key192 = {
                0x8e, 0xc8, 0x80, 0x1f, 0x3b, 0x2d,
                0x73, 0x10, 0x90, 0x35, 0x61, 0x98,
                0xb0, 0xf3, 0x79, 0x2c, 0x08, 0x10,
                0xf7, 0x2b, 0xe5, 0x07, 0xd7, 0xa3
        };

        // Expected round keys for 192-bit key (12+1 round keys)
        // We'll check just the first few and last round key for brevity
        int[][] expectedFirstKey = {
                {0x8e, 0xc8, 0x80, 0x1f},
                {0x3b, 0x2d, 0x73, 0x10},
                {0x90, 0x35, 0x61, 0x98},
                {0xb0, 0xf3, 0x79, 0x2c}
        };


        int[][] expectedSecondKey = {
                {0x08, 0x10, 0xf7, 0x2b},
                {0xe5, 0x07, 0xd7, 0xa3},
                {0x4a, 0xc6, 0x8a, 0xc6},
                {0x71, 0xeb, 0xf9, 0xd6}
        };

        int[][] expectedTenthKey = {
                {0x72, 0xb4, 0x2e, 0xc3},
                {0xcc, 0xc1, 0xe1, 0x8d},
                {0x1a, 0xd7, 0xe8, 0x98},
                {0x3a, 0xb7, 0x53, 0xef}
        };




        List<int[]> result192 = Aes.expandKey(key192);

        // Check number of round keys
        assertEquals( 52, result192.size(), "Number of round keys for 192-bit key should be 13");

        // Verify the first and last round keys match the expected values
        int[][] firstKey = new int[4][4];
        int[][] secondKey = new int[4][4];
        int[][] tenthKey = new int[4][4];
        for(int i = 0; i < 4; i++) {
            firstKey[i] = result192.get(i);
            secondKey[i] = result192.get(i + 4);
            tenthKey[i] = result192.get(i + 40);
        }


        // Check first round key
        assertArrayEquals(expectedFirstKey, firstKey);
        assertArrayEquals(expectedSecondKey, secondKey);
        assertArrayEquals(expectedTenthKey, tenthKey);

    }

    @Test
    public void testInvalidKeyDimensions() {
        // Invalid key dimensions (not 4x4, 4x6, or 4x8)
        int[] invalidKey = {
                0x01, 0x02,
                0x03, 0x04,
                0x05, 0x06,
                0x07, 0x08
        }; // 4x2 matrix, invalid dimensions

        assertThrows(IllegalArgumentException.class, () -> Aes.expandKey(invalidKey));
    }

    @Test
    public void testRotWord() {
        int[] word = {
                0x01, 0x02, 0x03, 0x04
        };

        int[] expectedWord = {
                0x02, 0x03, 0x04, 0x01
        };

        word = Aes.rotWord(word);

        assertArrayEquals(expectedWord, word);
    }

    @Test
    public void testSubWord() {
        int[] word = {
                0xB9, 0xC4, 0x93, 0x1A
        };
        int[] expectedWord = {
                0x56, 0x1C, 0xDC, 0xA2
        };
        word = Aes.subWord(word);
        assertArrayEquals(expectedWord, word);
    }
}
