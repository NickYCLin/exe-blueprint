namespace ExeBlueprint.Core.Tests;

internal interface ICSharpSkeletonExplicitInterfaceFixture
{
    string Name { get; }

    void Execute();
}

internal sealed class CSharpSkeletonExplicitInterfaceFixture : ICSharpSkeletonExplicitInterfaceFixture
{
    string ICSharpSkeletonExplicitInterfaceFixture.Name => "explicit";

    void ICSharpSkeletonExplicitInterfaceFixture.Execute()
    {
    }
}
