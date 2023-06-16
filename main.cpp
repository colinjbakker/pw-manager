#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/eax.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/modes.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>

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
std::vector<string> splitString(string input)
{
    std::vector<string> output;
    std::stringstream ss(input);
    string temp;
    while (std::getline(ss, temp, ' '))
    {
        output.push_back(temp);
    }
    return output;
}
void displayPasswords(string masterPW)
{
    unsigned int iterations = 15000;
    char purpose = 0;
    SecByteBlock derived(32);
    PKCS5_PBKDF2_HMAC<SHA3_256> kdf;
    kdf.DeriveKey(derived.data(), derived.size(), purpose, (byte *)masterPW.data(), masterPW.size(), NULL, 0, iterations);
    EAX<AES>::Decryption decryptor;
    HexDecoder decoder;
    std::ifstream inFS;
    string recovered;
    string decoded;
    string line;
    std::vector<string> infoLine;
    inFS.open("passwords.txt");
    if (!inFS.is_open())
    {
        cout << "Error didnt open" << endl;
    }
    while (std::getline(inFS, line))
    {
        string recovered = "";
        string decoded = "";
        infoLine = splitString(line);
        decoder.Attach(new StringSink(decoded));
        decoder.Put((byte *)infoLine.at(2).data(), infoLine.at(2).size());
        decoder.MessageEnd();

        decryptor.SetKeyWithIV(derived.data(), 16, derived.data() + 16, 16);
        AuthenticatedDecryptionFilter df(decryptor, new StringSink(recovered));
        df.Put((byte *)decoded.data(), decoded.size());
        df.MessageEnd();

        cout << infoLine.at(0) << " " << infoLine.at(1) << " " << recovered << endl;
    }
    inFS.close();
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

    string selection;
    cout << "1. Add Passwords\n2. See Passwords\n(else) Exit" << endl;
    cin >> selection;
    if (selection == "1")
    {
        addPasswords(masterPw);
    }
    else if (selection == "2")
    {
        displayPasswords(masterPw);
    }
    return 0;
}