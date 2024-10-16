using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Enumeration;
using System.Security.Cryptography.X509Certificates;

namespace AES
{
    internal class AES
    {
        private string password;
        private byte[] data;
        private byte[] ciphertext;
        //this is needed for substitution step
        private readonly byte[] sBox = new byte[256];
        private readonly byte[] inverseSBox = new byte[256];

        private readonly byte[] Gmul2 = new byte[256];
        private readonly byte[] Gmul3 = new byte[256];
        private readonly byte[] Gmul9 = new byte[256];
        private readonly byte[] GmulB = new byte[256];
        private readonly byte[] GmulD = new byte[256];
        private readonly byte[] GmulE = new byte[256];
        private readonly Dictionary<string, int> tableIndexDictionary = new Dictionary<string, int>();

        public AES(byte[] data)
        {
            this.data = data;
        }



        public void InitialiseLookupTables()
        {
            Dictionary<String, String> filepathDictionary = new Dictionary<String, String>();
            string currentDirectory = AppDomain.CurrentDomain.BaseDirectory;

            string[] filenames = new string[8]
            {
                "sBox.txt",
                "inverseSbox.txt",
                "Gmul2.txt",
                "Gmul3.txt",
                "Gmul9.txt",
                "GmulB.txt",
                "GmulD.txt",
                "GmulE.txt"
            };



            //int i = 0;
            foreach (string filename in filenames)
            {
                //filepaths[i] = System.IO.Path.Combine(currentDirectory, filename);
                filepathDictionary.Add(filename, Path.Combine(currentDirectory, filename));
            }

            foreach (string filename in filenames)
            {
                ReadFile(filepathDictionary[filename], filename);
            }

        }

        public void ReadFile(string filepath, string filename)
        {

            if (!tableIndexDictionary.ContainsKey(filename))
                tableIndexDictionary.Add(filename, 0);

            using (StreamReader reader = new StreamReader(filepath))
            {
                while (!reader.EndOfStream)
                {

                    string line = reader.ReadLine();
                    string[] hexValues = line.Split(new[] { ", ", "," }, StringSplitOptions.RemoveEmptyEntries);

                    for (int i = 0; i < hexValues.Length; i++)
                    {
                        //filepathDictionary[filename].Append(Convert.ToByte(hexValue.Replace("0x", ""), 16));
                        string hexValue = hexValues[i].Replace("0x", "");
                        hexValue = hexValue.Replace(" ", "");

                        switch (filename)
                        {
                            case "sBox.txt":
                                sBox[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                            case "inverseSbox.txt":
                                inverseSBox[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                            case "Gmul2.txt":
                                Gmul2[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                            case "Gmul3.txt":
                                Gmul3[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                            case "Gmul9.txt":
                                Gmul9[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                            case "GmulB.txt":
                                GmulB[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                            case "GmulD.txt":
                                GmulD[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                            case "GmulE.txt":
                                GmulE[tableIndexDictionary[filename]] = Convert.ToByte(hexValue, 16);
                                break;
                        }
                        tableIndexDictionary[filename]++;
                    }
                }
            }
        }


        public byte[] Encrypt(string password)
        {
            //byte[] plainText;
            byte[] cipherText;
            byte[][,] keyArray = GenerateKeys(password);

            (byte[][,], int) returnedItems = DivideIntoBlocks(this.data);
            byte[][,] blocks = returnedItems.Item1;
            int remainder = returnedItems.Item2;

            cipherText = new byte[(blocks.Length * 16) + 10];

            byte[][,] encodedBlocks = new byte[blocks.Length][,];

            int blockCount = 0;
            foreach (byte[,] block in blocks/*int i = 0; i<cipherText.Length-16; i += 16*/)
            {
                byte[,] stateMatrix = block;
                stateMatrix = EncodeBlock(stateMatrix, keyArray);

                encodedBlocks[blockCount] = stateMatrix;
                blockCount++;

            }

            AddRemainder(cipherText, remainder);
            int cipherTextIndex = 10;
            foreach (byte[,] block in encodedBlocks)
            {
                byte[] hexValues =
                {
                    block[0,0], block[1,0], block[2,0], block[3,0],
                    block[0,1], block[1,1], block[2,1], block[3,1],
                    block[0,2], block[1,2], block[2,2], block[3,2],
                    block[0,3], block[1,3], block[2,3], block[3,3]
                };

                foreach (byte b in hexValues)
                {
                    cipherText[cipherTextIndex] = b;
                    cipherTextIndex++;
                }
            }
            return cipherText;
        }

        public (byte[][,], int) DivideIntoBlocks(byte[] bytes)
        {
            byte[][,] blocks = new byte[((bytes.Length - 1) / 16) + 1][,];
            int remainder = 0;

            int blockcount = 0;
            for (int i = 0; i < bytes.Length; i += 16)
            {
                byte[,] block = new byte[4, 4];
                //{
                //    {plaintext[i], plaintext[i+4], plaintext[i+8], plaintext[i+12] },
                //    {plaintext[i + 1], plaintext[i+5], plaintext[i+9], plaintext[i+13] },
                //    {plaintext[i + 2], plaintext[i+6], plaintext[i+10], plaintext[i+14] },
                //    {plaintext[i + 3],plaintext[i+7], plaintext[i+11], plaintext[i+15] }
                //};
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < bytes.Length)
                        block[j % 4, j / 4] = bytes[i + j];
                    else
                    {
                        block[j % 4, j / 4] = 0;
                        remainder++;
                    }
                }

                blocks[blockcount] = block;
                blockcount++;
            }

            return (blocks, remainder);
        }

        public void AddRemainder(byte[] cipherText, int remainder)
        {
            string remainderTag = "remainder";

            int index = 0;
            foreach (char c in remainderTag)
            {
                //cipherText.Append(Convert.ToByte(c.ToString(),16));
                cipherText[index] = (byte)c;
                index++;
            }
            cipherText[index] = (byte)remainder;
        }
        public byte[,] EncodeBlock(byte[,] stateMatrix, byte[][,] keyArray)
        {
            Console.WriteLine("\n\n\n");
            Console.WriteLine("Initial");
            DisplayByteArray(stateMatrix);

            stateMatrix = AddRoundKey(stateMatrix, keyArray[0]);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After AddRoundKey");
            DisplayByteArray(stateMatrix);
            for (int round = 1; round <= 9; round++)
            {
                stateMatrix = SubBytes(stateMatrix);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After SubBytes round: " + round.ToString());
                DisplayByteArray(stateMatrix);
                stateMatrix = ShiftRows(stateMatrix);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After ShiftRows round: " + round.ToString());
                DisplayByteArray(stateMatrix);
                stateMatrix = MixColumns(stateMatrix);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After MixColumns round: " + round.ToString());
                DisplayByteArray(stateMatrix);
                stateMatrix = AddRoundKey(stateMatrix, keyArray[round]);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After AddRoundKey round: " + round.ToString());
                DisplayByteArray(stateMatrix);
            }

            stateMatrix = SubBytes(stateMatrix);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After final SubBytes");
            DisplayByteArray(stateMatrix);
            stateMatrix = ShiftRows(stateMatrix);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After final ShiftRows");
            DisplayByteArray(stateMatrix);
            stateMatrix = AddRoundKey(stateMatrix, keyArray[10]);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After final AddRoundKey");
            DisplayByteArray(stateMatrix);

            return stateMatrix;
        }
        public void DisplayByteArray(byte[,] stateMatrix)
        {
            byte[] hexValues = new byte[16]
            {
                    stateMatrix[0,0], stateMatrix[1,0], stateMatrix[2,0], stateMatrix[3,0],
                    stateMatrix[0,1], stateMatrix[1,1], stateMatrix[2,1], stateMatrix[3,1],
                    stateMatrix[0,2], stateMatrix[1,2], stateMatrix[2,2], stateMatrix[3,2],
                    stateMatrix[0,3], stateMatrix[1,3], stateMatrix[2,3], stateMatrix[3,3]
            };

            int count = 0;
            foreach (byte b in hexValues)
            {
                if (count % 4 == 1 && count > 4)
                {
                    Console.Write(b.ToString("X2") + "\n");
                }
                else
                {
                    Console.Write(b.ToString("X2") + ", ");
                }
            }
        }


        public byte[] Decrypt(string password)
        {
            int remainder = Convert.ToInt32(data[9]);

            byte[] bytes = RemoveRemainderTag();
            byte[] plainText = new byte[bytes.Length - remainder];

            byte[][,] keyArray = GenerateKeys(password);
            byte[][,] blocks = DivideIntoBlocks(bytes).Item1;
            byte[][,] decodedBlocks = new byte[blocks.Length][,];


            int blockIndex = 0;
            foreach (byte[,] block in blocks/*int i=0; i<bytes.Count; i+=16*/)
            {
                byte[,] stateMatrix = block;
                byte[,] decodedBlock = DecodeBlock(stateMatrix, keyArray);

                decodedBlocks[blockIndex] = decodedBlock;
                blockIndex++;
            }

            int plainTextIndex = 0;
            foreach (byte[,] block in decodedBlocks)
            {
                byte[] hexValues =
               {
                    block[0,0], block[1,0], block[2,0], block[3,0],
                    block[0,1], block[1,1], block[2,1], block[3,1],
                    block[0,2], block[1,2], block[2,2], block[3,2],
                    block[0,3], block[1,3], block[2,3], block[3,3]
                };

                foreach (byte b in hexValues)
                {
                    if (plainTextIndex < plainText.Length)
                        plainText[plainTextIndex] = b;
                    else
                        break;
                    plainTextIndex++;
                }
            }



            return plainText;

        }

        public byte[] RemoveRemainderTag()
        {
            byte[] bytes = new byte[data.Length - 10];
            for (int i = 10; i < data.Length; i++)
            {
                bytes[i - 10] = data[i];
            }

            return bytes;
        }
        public byte[,] DecodeBlock(byte[,] stateMatrix, byte[][,] keyArray)
        {
            /*byte[,] stateMatrix = new byte[4, 4]
                {
                    /*{bytes[0], bytes[4], bytes[8], bytes[12]  },
                    {bytes[1], bytes[5], bytes[9], bytes[13] },
                    {bytes[2], bytes[6], bytes[10], bytes[14] },
                    {bytes[3], bytes[7], bytes[11], bytes[15] }
                    {0x39, 0x02, 0xdc, 0x19  },
                    {0x25, 0xdc, 0x11, 0x6a  },
                    {0x84, 0x09, 0x85, 0x0b },
                    {0x1d, 0xfb, 0x97, 0x32 }
                };*/
            Console.WriteLine("\n\n\n");
            Console.WriteLine("initial state");
            DisplayByteArray(stateMatrix);



            stateMatrix = AddRoundKey(stateMatrix, keyArray[10]);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After AddRoundKey");
            DisplayByteArray(stateMatrix);

            for (int round = 9; round >= 1; round--)
            {
                stateMatrix = InvShiftRows(stateMatrix);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After InvShiftRows round: " + round.ToString());
                DisplayByteArray(stateMatrix);
                stateMatrix = InvSubBytes(stateMatrix);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After InvSubBytes round: " + round.ToString());
                DisplayByteArray(stateMatrix);
                stateMatrix = AddRoundKey(stateMatrix, keyArray[round]);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After AddRoundKey round: " + round.ToString());
                DisplayByteArray(stateMatrix);
                stateMatrix = InvMixColumns(stateMatrix);
                Console.WriteLine("\n\n\n");
                Console.WriteLine("After InvMixColumns round: " + round.ToString());
                DisplayByteArray(stateMatrix);
            }

            stateMatrix = InvShiftRows(stateMatrix);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After InvShiftRows");
            DisplayByteArray(stateMatrix);
            stateMatrix = InvSubBytes(stateMatrix);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After InvSubBytes");
            DisplayByteArray(stateMatrix);
            stateMatrix = AddRoundKey(stateMatrix, keyArray[0]);
            Console.WriteLine("\n\n\n");
            Console.WriteLine("After AddRoundKey");
            DisplayByteArray(stateMatrix);

            //string s = "";
            //for (int c = 0; c <= 3; c++)
            //{
            //    for (int r = 0; r <= 3; r++)
            //    {
            //        if (index < decoded.Length)
            //        {
            //            decoded.Append(stateMatrix[r, c]);
            //        }
            //    }
            //}

            return stateMatrix;
        }

        public static byte[,] GetMatrix(byte[] plaintext)
        {
            byte[,] messageMatrix = new byte[4, 4];
            int i = 0;
            //while (plaintext.Length < 16)
            //{
            //    text = text + " "; //blank space represented by 32 in ascii
            //}

            for (int c = 0; c <= 3; c++)
            {
                for (int r = 0; r <= 3; r++)
                {
                    if (i < plaintext.Length)
                    {
                        messageMatrix[r, c] = plaintext[i];
                    }
                    else
                    {
                        messageMatrix[r, c] = 0x00;
                    }

                    i++;
                }
            }

            return messageMatrix;
        }

        public byte[][,] GenerateKeys(string password)
        {

            byte[][,] keyArray = new byte[11][,];
            byte[,] wordArray = GetWordArrayMatrix(password);
            //{
            //    {0x2b, 0x28, 0xab, 0x09 },
            //    {0x7e, 0xae, 0xf7, 0xcf },
            //    {0x15, 0xd2, 0x15, 0x4f },
            //    {0x16, 0xa6, 0x88, 0x3c }
            //};

            keyArray[0] = wordArray;

            byte[] word1 = new byte[4];
            byte[] word2 = new byte[4];
            byte[] word3 = new byte[4];
            byte[] word4 = new byte[4];


            for (int x = 0; x <= 3; x++)
            {
                word1[x] = wordArray[x, 0];
                word2[x] = wordArray[x, 1];
                word3[x] = wordArray[x, 2];
                word4[x] = wordArray[x, 3];

            }

            byte[] temp = new byte[4];
            keyArray[0] = wordArray;
            for (int i = 1; i <= 10; i++)
            {
                temp = RotWords(word4);
                temp = SubWords(temp);
                temp = Rcon(temp, i - 1);
                word1 = XOR(temp, word1); //temp ^ word4;
                word2 = XOR(word1, word2); //temp ^ word1;
                word3 = XOR(word2, word3); //temp ^ word2;
                word4 = XOR(word3, word4); //temp ^ word3;

                byte[,] key = new byte[4, 4]
                {
                    {word1[0], word2[0], word3[0], word4[0] },
                    {word1[1], word2[1], word3[1], word4[1]  },
                    {word1[2], word2[2], word3[2], word4[2]  },
                    {word1[3], word2[3], word3[3], word4[3]  }
                };
                keyArray[i] = key;
            }

            return keyArray;

        }

        public byte[,] GetWordArrayMatrix(string password)
        {
            byte[] wordArrayMatrix = new byte[password.Length];

            int i = 0;
            foreach (char c in password)
            {
                byte b = (byte)c;

                wordArrayMatrix[i] = b;
                i++;
            }
            return GetMatrix(wordArrayMatrix);
        }

        public byte[] XOR(byte[] tempWord, byte[] word)
        {
            byte[] newTemp = new byte[4]
            {
                (byte)(tempWord[0]^word[0]), (byte)(tempWord[1]^word[1]), (byte)(tempWord[2]^word[2]), (byte)(tempWord[3]^word[3])
            };

            return newTemp;
        }

        public byte[] RotWords(byte[] InitialWord)
        {
            //shift the columns of the matrix
            byte[] newWord = new byte[4]
            {
                InitialWord[1], InitialWord[2], InitialWord[3], InitialWord[0]
            };

            return newWord;
        }

        public byte[] SubWords(byte[] InitialWord)
        {
            byte[] newWord = new byte[4]
            {
                sBox[Convert.ToInt32(InitialWord[0])], sBox[Convert.ToInt32(InitialWord[1])] , sBox[Convert.ToInt32(InitialWord[2])] , sBox[Convert.ToInt32(InitialWord[3])]
            };

            return newWord;
        }

        public byte[] Rcon(byte[] InitialWord, int round)
        {
            byte[,] RoundConstants = new byte[10, 4]
            {
                {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00}, {0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00},
                {0x10, 0x00, 0x00, 0x00 },  {0x20, 0x00, 0x00, 0x00},  {0x40, 0x00, 0x00, 0x00},  {0x80, 0x00, 0x00, 0x00},
                {0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00 }
            };

            byte[] newWord = new byte[4]
            {
                (byte)(InitialWord[0]^RoundConstants[round,0]), (byte)(InitialWord[1]^RoundConstants[round,1]), (byte)(InitialWord[2]^RoundConstants[round,2]), (byte)(InitialWord[3]^RoundConstants[round,3])
            };

            return newWord;
        }

        public byte[,] AddRoundKey(byte[,] initialState, byte[,] key)
        {
            byte[,] newState = new byte[4, 4];

            for (int row = 0; row <= 3; row++)
            {
                for (int column = 0; column <= 3; column++)
                {
                    newState[row, column] = (byte)(initialState[row, column] ^ key[row, column]);
                }
            }

            return newState;
        }

        public byte[,] SubBytes(byte[,] InitialState)
        {
            byte[,] newState = new byte[4, 4];

            for (int row = 0; row <= 3; row++)
            {
                for (int column = 0; column <= 3; column++)
                {
                    byte b = InitialState[row, column];
                    int sBoxIndex = Convert.ToInt32(b);
                    newState[row, column] = sBox[sBoxIndex];
                }
            }

            return newState;
        }

        public byte[,] ShiftRows(byte[,] InitialState)
        {
            //shift second row InitialState[1,c] one place to the left
            //shift third row InitialState[2,c] two places to the left
            //shift fourth row InitialState[3,c] three places to the left
            byte[,] NewState = new byte[4, 4] {
                { InitialState[0,0], InitialState[0,1], InitialState[0,2], InitialState[0,3] },
                { InitialState[1,1], InitialState[1,2], InitialState[1,3], InitialState[1,0]},
                { InitialState[2,2], InitialState[2,3], InitialState[2,0], InitialState[2,1]},
                { InitialState[3,3], InitialState[3,0], InitialState[3,1], InitialState[3,2]} };

            return NewState;
        }

        public byte[,] MixColumns(byte[,] InitialState)
        {
            /*mulitply the initialState matrix by a constant matrix:
             * 
             *    02    03    01    01
             *    01    02    03    01
             *    01    01    02    03 
             *    03    01    01    02 
             */
            /* follows the rules of matrix multiplication but addition 
             * is an XOR operation and multiplication is Galois multiplication*/

            byte[,] newState = new byte[4, 4];

            //this is essentially just matrix multiplication but instead of addition it is an XOR operation
            //and instead of multiplication it is galois multiplication
            for (int column = 0; column <= 3; column++)
            {
                newState[0, column] = (byte)((Gmul2[Convert.ToInt32(InitialState[0, column])]) ^
                                           (Gmul3[Convert.ToInt32(InitialState[1, column])]) ^
                                           InitialState[2, column] ^ InitialState[3, column]);
                newState[1, column] = (byte)((InitialState[0, column]) ^ (Gmul2[Convert.ToInt32(InitialState[1, column])]) ^
                                           (Gmul3[Convert.ToInt32(InitialState[2, column])]) ^ (InitialState[3, column]));
                newState[2, column] = (byte)((InitialState[0, column]) ^ (InitialState[1, column]) ^
                                           (Gmul2[Convert.ToInt32(InitialState[2, column])]) ^
                                           (Gmul3[Convert.ToInt32(InitialState[3, column])]));
                newState[3, column] = (byte)((Gmul3[Convert.ToInt32(InitialState[0, column])]) ^
                                            (InitialState[1, column]) ^ (InitialState[2, column]) ^
                                            (Gmul2[Convert.ToInt32(InitialState[3, column])]));

            }

            return newState;

        }

        public byte[,] InvShiftRows(byte[,] InitialMatrix)
        {
            //same as shift rows except shifiting the matrix rows to the right instead of left
            byte[,] newMatrix = new byte[4, 4]
            {
                {InitialMatrix[0,0], InitialMatrix[0,1], InitialMatrix[0,2], InitialMatrix[0,3] },
                {InitialMatrix[1,3], InitialMatrix[1,0], InitialMatrix[1,1], InitialMatrix[1,2] },
                {InitialMatrix[2,2], InitialMatrix[2,3], InitialMatrix[2,0], InitialMatrix[2,1] },
                {InitialMatrix[3,1], InitialMatrix[3,2], InitialMatrix[3,3], InitialMatrix[3,0] }
            };

            return newMatrix;
        }

        public byte[,] InvSubBytes(byte[,] InitialMatrix)
        {
            byte[,] newState = new byte[4, 4];

            for (int row = 0; row <= 3; row++)
            {
                for (int column = 0; column <= 3; column++)
                {
                    byte b = InitialMatrix[row, column];
                    int sBoxIndex = Convert.ToInt32(b);
                    newState[row, column] = inverseSBox[sBoxIndex];
                }
            }

            return newState;
        }
        public byte[,] InvMixColumns(byte[,] InitialMatrix)
        {
            //once again this is very similar to the Mixcolumns method but the constant matrix is inversed
            byte[,] newState = new byte[4, 4];


            for (int column = 0; column <= 3; column++)
            {
                newState[0, column] = (byte)((GmulE[Convert.ToInt32(InitialMatrix[0, column])]) ^
                                           (GmulB[Convert.ToInt32(InitialMatrix[1, column])]) ^
                                           (GmulD[Convert.ToInt32(InitialMatrix[2, column])]) ^
                                           (Gmul9[Convert.ToInt32(InitialMatrix[3, column])]));
                newState[1, column] = (byte)((Gmul9[Convert.ToInt32(InitialMatrix[0, column])]) ^
                                            (GmulE[Convert.ToInt32(InitialMatrix[1, column])]) ^
                                           (GmulB[Convert.ToInt32(InitialMatrix[2, column])]) ^
                                           (GmulD[Convert.ToInt32(InitialMatrix[3, column])]));
                newState[2, column] = (byte)((GmulD[Convert.ToInt32(InitialMatrix[0, column])]) ^
                                            (Gmul9[Convert.ToInt32(InitialMatrix[1, column])]) ^
                                           (GmulE[Convert.ToInt32(InitialMatrix[2, column])]) ^
                                           (GmulB[Convert.ToInt32(InitialMatrix[3, column])]));
                newState[3, column] = (byte)((GmulB[Convert.ToInt32(InitialMatrix[0, column])]) ^
                                            (GmulD[Convert.ToInt32(InitialMatrix[1, column])]) ^
                                            (Gmul9[Convert.ToInt32(InitialMatrix[2, column])]) ^
                                            (GmulE[Convert.ToInt32(InitialMatrix[3, column])]));

            }

            return newState;
        }

    }
}
