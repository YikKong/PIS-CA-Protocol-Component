#include <iostream>

#include <NTL/ZZ.h>

int main()
{
    NTL::ZZ a;
    NTL::ZZ b;
    NTL::ZZ modulus;

    NTL::RandomBits(a, 128);
    NTL::RandomBits(b, 128);
    NTL::GenPrime(modulus, 256);

    const NTL::ZZ sum = NTL::AddMod(a, b, modulus);
    const NTL::ZZ product = NTL::MulMod(a, b, modulus);
    const NTL::ZZ power = NTL::PowerMod(a, 17, modulus);

    std::cout << "NTL smoke test" << std::endl;
    std::cout << "a = " << a << std::endl;
    std::cout << "b = " << b << std::endl;
    std::cout << "modulus = " << modulus << std::endl;
    std::cout << "(a + b) mod modulus = " << sum << std::endl;
    std::cout << "(a * b) mod modulus = " << product << std::endl;
    std::cout << "a^17 mod modulus = " << power << std::endl;

    if (modulus <= 0 || sum < 0 || product < 0 || power < 0)
    {
        std::cerr << "NTL smoke test failed" << std::endl;
        return 1;
    }

    std::cout << "NTL smoke test passed" << std::endl;
    return 0;
}

// .\build\ntl_smoke_test.exe