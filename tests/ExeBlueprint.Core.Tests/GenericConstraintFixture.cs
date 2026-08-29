namespace ExeBlueprint.Core.Tests;

internal interface IGenericVarianceFixture<out TOut, in TIn>
{
    TOut Convert(TIn value);
}

internal delegate TResult GenericVarianceDelegateFixture<out TResult, in TArgument>(TArgument value);

internal class GenericConstraintBaseFixture
{
}

internal interface IGenericConstraintInterfaceFixture
{
}

internal class GenericConstraintFixture<
    TClass,
    TNullableClass,
    TStruct,
    TUnmanaged,
    TNotNull,
    TConstructed>
    where TClass : class
    where TNullableClass : class?
    where TStruct : struct
    where TUnmanaged : unmanaged
    where TNotNull : notnull
    where TConstructed : GenericConstraintBaseFixture, IGenericConstraintInterfaceFixture, new()
{
    internal class Nested<TNested>
        where TNested : TNotNull
    {
    }

    public static void Method<TMethodClass, TMethodNullable, TMethodNew, TMethodLink>()
        where TMethodClass : class
        where TMethodNullable : class?
        where TMethodNew : IGenericConstraintInterfaceFixture, new()
        where TMethodLink : TNotNull
    {
    }
}

internal class NullableTypeConstraintFixture<TBase, TInterface, TConstructed>
    where TBase : GenericConstraintBaseFixture?
    where TInterface : IGenericConstraintInterfaceFixture?
    where TConstructed : IEnumerable<string?>
{
}

internal interface IAllowsRefStructFixture<T>
    where T : allows ref struct
{
}

[AttributeUsage(AttributeTargets.GenericParameter)]
internal sealed class GenericMarkerAttribute<T> : Attribute
{
}

internal sealed class GenericAttributeTarget<[GenericMarker<int>] T>
{
}
