namespace ExeBlueprint.Core.Tests;

internal interface ICSharpSkeletonExplicitInterfaceFixture
{
    string Name { get; }

    string this[int index] { get; set; }

    void Execute();
}

internal sealed class CSharpSkeletonExplicitInterfaceFixture : ICSharpSkeletonExplicitInterfaceFixture
{
    string ICSharpSkeletonExplicitInterfaceFixture.Name => "explicit";

    public string this[string key]
    {
        get => key;
        set { }
    }

    string ICSharpSkeletonExplicitInterfaceFixture.this[int index]
    {
        get => index.ToString();
        set { }
    }

    void ICSharpSkeletonExplicitInterfaceFixture.Execute()
    {
    }
}
