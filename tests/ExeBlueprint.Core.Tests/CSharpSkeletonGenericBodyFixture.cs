namespace ExeBlueprint.Core.Tests;

internal static class CSharpSkeletonGenericBodyFixture<T>
{
    public static EqualityComparer<T> TypeComparer() => EqualityComparer<T>.Default;

    public static EqualityComparer<TMethod> MethodComparer<TMethod>() => EqualityComparer<TMethod>.Default;

    public static T[] EmptyTypeArray() => Array.Empty<T>();

    public static TMethod[] EmptyMethodArray<TMethod>() => Array.Empty<TMethod>();

    public static bool IsKnownState() => Enum.IsDefined(GenericCallState.Ready);

    public static string MetadataLikeLiteral() => "!0 !!0";

    public static string EscapedMetadataLikeLiteral() => "\"!0\" \\\\ !!0";
}

internal enum GenericCallState
{
    Ready
}
