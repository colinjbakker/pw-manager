#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/eax.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/modes.h>
// #include "password.h"
#include <iostream>
#include <fstream>

using namespace CryptoPP;
using std::cout, std::cin, std::endl, std::string;

void printInfo(SHA3_256 hashArg)
{
    cout << "Name: " << hashArg.AlgorithmName() << endl;
    cout << "Digest size: " << hashArg.DigestSize() << endl;
    cout << "Block size: " << hashArg.BlockSize() << endl;
}

string hashPassword(SHA3_256 hash, string msg)
{
    byte digest[SHA3_256::DIGESTSIZE];

    hash.CalculateDigest(digest, (byte *)msg.c_str(), msg.length());

    HexEncoder encoder;
    string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;
}

string verifyMasterPassword(SHA3_256 hash, string masterDigest)
{
    string attempt;
    cout << "Enter password: " << endl;
    cin >> attempt;
    string attemptDigest = hashPassword(hash, attempt);
    if (attemptDigest != masterDigest)
    {
        cout << "Incorrect password..." << endl;
        return verifyMasterPassword(hash, masterDigest);
    }
    else
    {
        return attempt;
    }
}

// void addPasswords()
// {
//     std::string input;
//     std::cout << "Enter App/Website Name, Username, and Password separated by a single space, or exit to exit: " << std::endl;
//     std::cin >> input;
//     while (input != "exit")
//     {
//         Password newPw;
//         newPw.readFromString(input);
//         std::cout << "Enter App/Website Name, Username, and Password separated by a single space, or exit to exit: " << std::endl;
//         cin >> input;
//     }
// }
void addPasswords(string masterPW)
{
    unsigned int iterations = 15000;
    char purpose = 0;
    SecByteBlock derived(32);
    PKCS5_PBKDF2_HMAC<SHA3_256> kdf;

    EAX<AES>::Encryption encryptor;

    std::ofstream oFS;
    string appName;
    string un;
    string pw;
    string pwEncoded;
    string cont = "x";
    HexEncoder encoder;
    string pwPretty;
    AuthenticatedEncryptionFilter ef(encryptor, new StringSink(pwEncoded));
    oFS.open("passwords.txt", std::ios::app);
    while (cont == "x")
    {
        kdf.DeriveKey(derived.data(), derived.size(), purpose, (byte *)masterPW.data(), masterPW.size(), NULL, 0, iterations);
        encryptor.SetKeyWithIV(derived.data(), 16, derived.data() + 16, 16);
        pwPretty = "";
        pwEncoded = "";
        cout << "Website/Application: " << endl;
        cin >> appName;
        cout << "Username: " << endl;
        cin >> un;
        cout << "Password: " << endl;
        cin >> pw;
        ef.Put((byte *)pw.data(), pw.size());
        ef.MessageEnd();
        encoder.Detach(new StringSink(pwPretty));
        encoder.Put((byte *)pwEncoded.data(), pwEncoded.size());
        encoder.MessageEnd();

        oFS << appName << " " << un << " " << pwPretty << "\n";

        cout << "Enter 'x' to continue: " << endl;
        cin >> cont;
    }

    oFS.close();
}

int main()
{
    SHA3_256 hash;
    printInfo(hash);
    std::ifstream inFS;
    std::ofstream oFS;
    string master;
    string masterDigest;

    inFS.open("master.txt", std::ios::app);
    if (!inFS.is_open())
    {
        cout << "Failed to open file" << endl;
        return 1;
    }

    int c = inFS.peek();
    if (c == EOF)
    {
        oFS.open("master.txt", std::ios::app);
        cout << "Set master password: " << endl;
        cin >> master;
        masterDigest = hashPassword(hash, master);
        oFS << masterDigest;
        oFS.close();
    }

    inFS >> masterDigest;
    cout << masterDigest << endl;

    string masterPw = verifyMasterPassword(hash, masterDigest);
    inFS.close();
    cout << "Success!" << endl;

    addPasswords(masterPw);
    // unsigned int iterations = 15000;
    // char purpose = 0;

    // SecByteBlock derived(32);

    // PKCS5_PBKDF2_HMAC<SHA3_256> kdf;
    // kdf.DeriveKey(derived.data(), derived.size(), purpose, (byte *)masterPw.data(), masterPw.size(), NULL, 0, iterations);

    // string plaintext = "Attack at dawn";
    // string ciphertext;
    // string recovered;

    // // Key the cipher
    // EAX<AES>::Encryption encryptor;
    // encryptor.SetKeyWithIV(derived.data(), 16, derived.data() + 16, 16);

    // AuthenticatedEncryptionFilter ef(encryptor, new StringSink(ciphertext));
    // ef.Put((byte *)plaintext.data(), plaintext.size());
    // ef.MessageEnd();

    // // Key the cipher
    // EAX<AES>::Decryption decryptor;
    // decryptor.SetKeyWithIV(derived.data(), 16, derived.data() + 16, 16);

    // AuthenticatedDecryptionFilter df(decryptor, new StringSink(recovered));
    // df.Put((byte *)ciphertext.data(), ciphertext.size());
    // df.MessageEnd();

    // // Done with encryption and decryption

    // // Encode various parameters
    // HexEncoder encoder;
    // string key, iv, cipher;

    // encoder.Detach(new StringSink(key));
    // encoder.Put(derived.data(), 16);
    // encoder.MessageEnd();

    // encoder.Detach(new StringSink(iv));
    // encoder.Put(derived.data() + 16, 16);
    // encoder.MessageEnd();

    // encoder.Detach(new StringSink(cipher));
    // encoder.Put((byte *)ciphertext.data(), ciphertext.size());
    // encoder.MessageEnd();

    // // Print stuff
    // cout << "plaintext: " << plaintext << endl;
    // cout << "key: " << key << endl;
    // cout << "iv: " << iv << endl;
    // cout << "ciphertext: " << cipher << endl;
    // cout << "recovered: " << recovered << endl;

    // std::cout << "1. See passwords\n2. Add passwords\n3. Exit" << std::endl;
    // std::string selection;
    // cin >> selection;
    // if (selection == "3")
    // {
    //     return 0;
    // }

    // if (selection == "2")
    // {
    //     addPasswords();
    // }

    return 0;
}