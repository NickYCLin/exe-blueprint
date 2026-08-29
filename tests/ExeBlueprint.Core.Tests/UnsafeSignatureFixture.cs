namespace ExeBlueprint.Core.Tests;

internal sealed unsafe class UnsafeMemberFixture
{
    internal int* PointerField = null;

    internal byte* PointerProperty { get; set; } = null;

    internal delegate* managed<void> Callback { get; set; } = null;

    internal UnsafeMemberFixture(int* pointer)
    {
        PointerField = pointer;
    }

    internal int* Echo(int* value) => value;

    internal byte* this[delegate* managed<void> callback] => null;
}

internal unsafe interface IUnsafeSignatureFixture
{
    delegate* unmanaged<void> Callback { get; }

    byte* Transform(byte* value);
}

internal unsafe delegate int* UnsafeSignatureDelegateFixture(
    byte* value,
    delegate* managed<void> callback);

internal static unsafe class UnsafePointerSourceFixture
{
    internal static int* GetPointer() => null;
}

internal static unsafe class UnsafeBodyOnlyFixture
{
    internal static void DiscardPointer()
    {
        UnsafePointerSourceFixture.GetPointer();
    }
}

internal static class SafeUnsafeNestedOwnerFixture
{
    internal unsafe struct Child
    {
        internal byte* Value;

        internal Child(byte* value)
        {
            Value = value;
        }
    }
}
