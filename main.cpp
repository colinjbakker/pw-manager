#include <cryptopp/cryptlib.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
#include <fstream>

using namespace CryptoPP;

void printInfo(SHA3_256 hashArg)
{
    std::cout << "Name: " << hashArg.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hashArg.DigestSize() << std::endl;
    std::cout << "Block size: " << hashArg.BlockSize() << std::endl;
}

std::string hashPassword(SHA3_256 hash, std::string msg)
{
    byte digest[SHA3_256::DIGESTSIZE];

    hash.CalculateDigest(digest, (byte *)msg.c_str(), msg.length());

    HexEncoder encoder;
    std::string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;
}

int verifyMasterPassword(SHA3_256 hash, std::string masterDigest)
{
    std::string attempt;
    std::cout << "Enter password: " << std::endl;
    std::cin >> attempt;
    std::string attemptDigest = hashPassword(hash, attempt);
    if (attemptDigest != masterDigest)
    {
        std::cout << "Incorrect password..." << std::endl;
        return verifyMasterPassword(hash, masterDigest);
    }
    else
    {
        return 0;
    }
}

int main()
{
    SHA3_256 hash;
    printInfo(hash);
    std::ifstream inFS;
    std::ofstream oFS;
    std::string master;
    std::string masterDigest;

    inFS.open("master.txt", std::ios::app);
    if (!inFS.is_open())
    {
        std::cout << "Failed to open file" << std::endl;
        return 1;
    }

    int c = inFS.peek();
    if (c == EOF)
    {
        oFS.open("master.txt", std::ios::app);
        // create master pw
        std::cout << "Set master password: " << std::endl;
        std::cin >> master;
        masterDigest = hashPassword(hash, master);
        oFS << masterDigest;
        oFS.close();
    }

    inFS >> masterDigest;
    std::cout << masterDigest << std::endl;
    if (verifyMasterPassword(hash, masterDigest))
    {
        inFS.close();
        return 1;
    }

    std::cout << "Success!" << std::endl;

    inFS.close();

    return 0;
}