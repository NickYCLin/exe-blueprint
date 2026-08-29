namespace ExeBlueprint.Core.Tests;

internal static unsafe class FunctionPointerFixture
{
    public static delegate* managed<int, ref string, bool> EchoManaged(
        delegate* managed<int, ref string, bool> value) => value;

    public static delegate* unmanaged[Cdecl]<nint, void> EchoNative(
        delegate* unmanaged[Cdecl]<nint, void> value) => value;

    public static delegate* unmanaged[SuppressGCTransition, Cdecl]<nint, void> EchoDecoratedNative(
        delegate* unmanaged[SuppressGCTransition, Cdecl]<nint, void> value) => value;
}
