namespace ExeBlueprint.Core.Tests;

internal static class CSharpSkeletonGenericBodyFixture<T>
{
    public static EqualityComparer<T> TypeComparer() => EqualityComparer<T>.Default;

    public static EqualityComparer<TMethod> MethodComparer<TMethod>() => EqualityComparer<TMethod>.Default;

    public static string MetadataLikeLiteral() => "!0 !!0";

    public static string EscapedMetadataLikeLiteral() => "\"!0\" \\\\ !!0";
}
