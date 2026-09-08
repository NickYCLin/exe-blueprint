/* Built only for static Ghidra acceptance; the fixture is never executed. */
#define EXPORTED __declspec(dllexport) __declspec(noinline)

EXPORTED int target(int value)
{
    return value + 7;
}

EXPORTED int tail(int value)
{
    return target(value);
}

EXPORTED int ordinary(int value)
{
    return target(value) + 3;
}

EXPORTED int loop(int count)
{
    volatile int sum = 0;
    while (count > 0)
    {
        sum += count--;
    }
    return sum;
}

EXPORTED int indirect(int (*handler)(int), int value)
{
    return handler(value);
}
