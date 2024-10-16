// See https://aka.ms/new-console-template for more information
using System;

namespace AES
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] fileBytes;
            //Console.WriteLine("would you like to encrypt (E) or decrypt (D)?");
            string answer = "";
            Console.WriteLine("Enter the filepath");
            string filepath = Console.ReadLine();
            try
            {
                fileBytes = File.ReadAllBytes(filepath);
                AES aes = new AES(fileBytes);
                aes.InitialiseLookupTables();

                do
                {
                    Console.WriteLine("would you like to encrypt (E) or decrypt (D) the file?");
                    answer = Console.ReadLine();

                    Console.WriteLine("enter the password");
                    string password = Console.ReadLine();
                    if (answer == "E")
                    {
                        byte[] encryptedData = aes.Encrypt(password);
                        File.WriteAllBytes(filepath, encryptedData);
                        Console.WriteLine("file encrypted");
                    }
                    else if (answer == "D")
                    {
                        //if yout think this is inefficient it would be more efficient to not think about it
                        byte[] decryptedData = aes.Decrypt(password);
                        File.WriteAllBytes(filepath, decryptedData);
                        Console.WriteLine("file decrypted");
                    }


                } while (answer != "E" || answer != "D");
            }
            catch (FileLoadException ex)
            {
                Console.WriteLine(ex.Message);
            }


            //Console.WriteLine("Enter the path of the file to encrypt");

            //string filepath = Console.ReadLine();
            //fileBytes = File.ReadAllBytes(filepath);

            //AES aes = new AES(fileBytes);

            Console.ReadLine();
        }
    }
}
