using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.ObjectModel;

using Word = System.UInt32;

namespace Serpentify
{
    class CSerpent
    {
        #region Variablen
        private Word[] roundKeys;
        private const uint GoldenRatio = 0x9e3779b9;

        #region S-Box
        // S-Box für Verschlüsselung
        public static byte[][] SBox = 
        { 
            new byte[] { 3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12 }, 
            new byte[] { 15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4 }, 
            new byte[] { 8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2 }, 
            new byte[] { 0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14 }, 
            new byte[] { 1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13 }, 
            new byte[] { 15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1 }, 
            new byte[] { 7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0 }, 
            new byte[] { 1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6 } 
        };

        // S-Box für Entschlüsselng
        public static byte[][] InvSBox =
        {
            new byte[] { 13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2 }, 
            new byte[] { 5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0 }, 
            new byte[] { 12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7 }, 
            new byte[] { 0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1 }, 
            new byte[] { 5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1 }, 
            new byte[] { 8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0 }, 
            new byte[] { 15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11 }, 
            new byte[] { 3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2 }
        };
        #endregion

        #endregion

        #region Methoden

        // Verschlüsselung
        public Word[] Encrypt(Word[] input, Word[] key) {

            Word[] Words;
            /* if keysize is smaller than 256 bits, then its going to be filled up */
            if (key.Length < 8)
            {
                /* to do so, we add a one and the rest is going to be filled with zeros */
                Words = new Word[8];
                Array.Copy(key, Words, key.Length);
                Words[key.Length] = 1;
                key = Words;
            }

            else
            {
                Words = new Word[8];
                Array.Copy(key, Words, 8);
                key = Words;
            }

            /* expand the eight 32-Bit Words to 132 32-bit prekeys */
            Word[] prekeys = new Word[140];
            Array.Copy(key, prekeys, 8);
            for (Word i = 8; i < prekeys.Length; i++)
            {
                /* with this formula we evenly distribute the key even though it had  a lot of zeros in it (because of filling it up) */
                prekeys[i] = RotateRight(prekeys[i - 8] ^ prekeys[i - 5] ^ prekeys[i - 3] ^ prekeys[i - 1] ^ GoldenRatio ^ i - 8, -11);
                int num = (int)prekeys[i];
            }

            /* apply the initial permutation and the round keys are done */
            Word[] tmp = new Word[4];
            for (int j = 0; j < 33; j++)
            {
                Array.Copy(prekeys, 8 + j * 4, tmp, 0, 4);
                Substitution(tmp, 35 - j, SBox);
                Array.Copy(tmp, 0, prekeys, 8 + j * 4, 4);
            }
            roundKeys = new Word[132];
            Array.Copy(prekeys, 8, roundKeys, 0, 132);

            /* Encryption*/

            Word[] cipher = new Word[] { input[0], input[1], input[2], input[3] };
            /* 32 rounds, in which 31 are the same */
            for (int i = 0; i < 31; i++)
            {
                XORRoundKey(cipher, i);
                Substitution(cipher, i, SBox);
                EncryptOperation(cipher);
            }

            /* 32th round: no transformation applied, just XOR-ing with the 33th round key */
            XORRoundKey(cipher, 31);
            Substitution(cipher, 31, SBox);
            XORRoundKey(cipher, 32);

            return cipher;
        }

        // Entschlüsselung
        public Word[] Decrypt(Word[] input, Word[] key)
        {
            /* Keyscheduling */

            Word[] Words;
            /* if keysize is smaller than 256 bits, then its going to be filled up */
            if (key.Length < 8)
            {
                /* to do so, we add a one and the rest is going to be filled with zeros */
                Words = new Word[8];
                Array.Copy(key, Words, key.Length);
                Words[key.Length] = 1;
                key = Words;
            }
            else
            {
                Words = new Word[8];
                Array.Copy(key, Words, 8);
                key = Words;
            }

            /* expand the eight 32-Bit Words to 132 32-bit prekeys */
            Word[] prekeys = new Word[140];
            Array.Copy(key, prekeys, 8);
            for (Word i = 8; i < prekeys.Length; i++)
            {
                /* with this formula we evenly distribute the key even though it had  a lot of zeros in it (because of filling it up) */
                prekeys[i] = RotateRight(prekeys[i - 8] ^ prekeys[i - 5] ^ prekeys[i - 3] ^ prekeys[i - 1] ^ GoldenRatio ^ i - 8, -11);
                int num = (int)prekeys[i];
            }

            /* apply the initial permutation and the round keys are done */
            Word[] tmp = new Word[4];
            for (int j = 0; j < 33; j++)
            {
                Array.Copy(prekeys, 8 + j * 4, tmp, 0, 4);
                Substitution(tmp, 35 - j, SBox);
                Array.Copy(tmp, 0, prekeys, 8 + j * 4, 4);
            }
            roundKeys = new Word[132];
            Array.Copy(prekeys, 8, roundKeys, 0, 132);

            /* Decryption */

            Word[] plain = new Word[] { input[0], input[1], input[2], input[3] };
            /* the 32 rounds are now performed backwards, beginning with round 32 */
            XORRoundKey(plain, 32);
            Substitution(plain, 31, InvSBox);
            XORRoundKey(plain, 31);

            for (int i = 30; i > -1; i--)
            {
                DecryptOperation(plain);
                Substitution(plain, i, InvSBox);
                XORRoundKey(plain, i);
            }
            return plain;
        }


        #region Haupt Operationen
       
        // Verschlüsselungs Operation
        private void EncryptOperation(Word[] input)
        {
            input[0] = RotateLeft(input[0], 13);
            input[2] = RotateLeft(input[2], 3);
            input[1] = input[1] ^ input[0] ^ input[2];
            input[3] = input[3] ^ input[2] ^ input[0] << 3;
            input[1] = RotateLeft(input[1], 1);
            input[3] = RotateLeft(input[3], 7);
            input[0] = input[0] ^ input[1] ^ input[3];
            input[2] = input[2] ^ input[3] ^ input[1] << 7;
            input[0] = RotateLeft(input[0], 5);
            input[2] = RotateLeft(input[2], 22);

        }

        // Entschlüsselungs Operation
        private void DecryptOperation(Word[] input){
            input[2] = RotateRight(input[2], 22);
            input[0] = RotateRight(input[0], 5);
            input[2] = input[2] ^ input[3] ^ input[1] << 7;
            input[0] = input[0] ^ input[1] ^ input[3];
            input[3] = RotateRight(input[3], 7);
            input[1] = RotateRight(input[1], 1);
            input[3] = input[3] ^ input[2] ^ input[0] << 3;
            input[1] = input[1] ^ input[0] ^ input[2];
            input[2] = RotateRight(input[2], 3);
            input[0] = RotateRight(input[0], 13);
            
        }

        #endregion


        #region Zusätzliche Operationen
        //Rotation
        public Word RotateLeft(Word value, int positions ) {
            return Convert.ToUInt32(((value << positions) | (value >> (32 - positions))) & 0xffffffff);
        }
        public Word RotateRight(Word value, int positions)
        {
            return Convert.ToUInt32(((value >> positions) | (value << (32 - positions))) & 0xffffffff);
        }

        //Substitution
        private void Substitution(Word[] input, int round, byte[][] substitution) {

            //S-Box wählen
            byte[] tmp = substitution[round % 8];


            Word n0 = input[0];
            Word n1 = input[1];
            Word n2 = input[2];
            Word n3 = input[3];
            Word n4 = 0;
            Word n5 = 0;
            Word n6 = 0;
            Word n7 = 0;
            Word n8 = 0;

            //Substituieren
            for (int i = 0; i < 32; i++) {
                n8 = tmp[n0 >> (i & 31) & 1 | (n1 >> (i & 31) & 1) << 1 | (n2 >> (i & 31) & 1) << 2 | (n3 >> (i & 31) & 1) << 3];
                
                n4 = n4 | (n8 & 1) << (i & 31);
				n5 = n5 | (n8 >> 1 & 1) << (i & 31);
				n6 = n6 | (n8 >> 2 & 1) << (i & 31);
				n7 = n7 | (n8 >> 3 & 1) << (i & 31);
			}

			input[0] = n4;
			input[1] = n5;
			input[2] = n6;
			input[3] = n7;

        }

        //XOR - Block mit Rundenschlüssel
        private void XORRoundKey(Word[] input, int round) {
            for (int i = 0; i < 4; i++)
                input[i] = input[i] ^ roundKeys[round * 4 + i];

        }
            #endregion

        #endregion

    }
}
