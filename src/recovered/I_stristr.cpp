// Preserve Replay's native locale-aware conversion, including signed-char
// promotion. An empty haystack returns null even when the needle is empty.
extern "C" int tolower(int character);

extern "C" const char* I_stristr(const char* haystack, const char* needle)
{
    for (const char* start = haystack; *start; ++start)
    {
        const char* match = start;
        const char* pattern = needle;
        for (;;)
        {
            if (*pattern == 0)
                return start;
            const int a = tolower(static_cast<signed char>(*match));
            const int b = tolower(static_cast<signed char>(*pattern));
            if (a != b)
                break;
            ++match;
            ++pattern;
        }
    }
    return nullptr;
}
