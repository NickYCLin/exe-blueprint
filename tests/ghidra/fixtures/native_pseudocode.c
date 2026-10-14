#define EXPORTED __declspec(dllexport) __declspec(noinline)

EXPORTED int branch(int value)
{
    if (value < 0) return -value;
    return value + 5;
}

EXPORTED int loop(int count)
{
    volatile int total = 0;
    while (count > 0) total += count--;
    return total;
}

EXPORTED int choice(int value)
{
    switch (value) {
        case 0: return branch(value);
        case 1: return loop(value);
        case 2: return value * 19;
        case 3: return value - 17;
        case 4: return value + 23;
        default: return value;
    }
}

EXPORTED int caller(int value)
{
    return branch(value) + loop(value) + choice(value);
}
