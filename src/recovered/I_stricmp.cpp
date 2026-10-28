// Comparison is ASCII-only. Bytes above 127 remain unsigned and unchanged.
// The limit and zero-extended 32-bit result follow the native instructions.
extern "C" int I_stricmp(const unsigned char* left, const unsigned char* right)
{
    unsigned long long remaining = 0x7fffffff;
    for (;;)
    {
        unsigned int a = *left++;
        unsigned int b = *right++;
        if (remaining-- == 0)
            return 0;
        if (a != b)
        {
            if (a >= 'A' && a <= 'Z')
                a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z')
                b += 'a' - 'A';
            if (a != b)
                return a < b ? -1 : 1;
        }
        if (a == 0)
            return 0;
    }
}
