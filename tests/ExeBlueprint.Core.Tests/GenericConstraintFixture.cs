namespace ExeBlueprint.Core.Tests;

internal interface IGenericVarianceFixture<out TOut, in TIn>
{
    TOut Convert(TIn value);
}

internal delegate TResult GenericVarianceDelegateFixture<out TResult, in TArgument>(TArgument value)
    where TResult : class?
    where TArgument : notnull;

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

internal abstract class GenericConstraintOverrideBaseFixture
{
    public abstract T Echo<T>(T value)
        where T : class;
}

internal sealed class GenericConstraintOverrideFixture : GenericConstraintOverrideBaseFixture
{
    public override T Echo<T>(T value) => value;
}

internal interface IGenericConstraintMethodFixture
{
    T Echo<T>(T value)
        where T : class;
}

internal sealed class ExplicitGenericConstraintMethodFixture : IGenericConstraintMethodFixture
{
    T IGenericConstraintMethodFixture.Echo<T>(T value) => value;
}

internal sealed class OrderedConstraintFixture<TFirst, TSecond, TValue>
    where TFirst : GenericConstraintBaseFixture
    where TSecond : GenericConstraintBaseFixture
    where TValue : notnull, GenericConstraintBaseFixture, TFirst, TSecond, IGenericConstraintInterfaceFixture
{
}

internal sealed class NullableLocalConstraintFixture<TLocalBase, TLocalInterface, TParameter, TLinked>
    where TLocalBase : GenericConstraintBaseFixture?
    where TLocalInterface : IGenericConstraintInterfaceFixture?
    where TParameter : class?
    where TLinked : TParameter?
{
    public static void Method<TMethod>()
        where TMethod : TParameter?
    {
    }

    internal sealed class Nested<TNested>
        where TNested : TParameter?
    {
    }
}

internal sealed class KeywordGenericConstraintFixture<
    @class,
    @required,
    @record,
    @file,
    @scoped,
    @closed,
    @__arglist>
    where @class : IGenericConstraintInterfaceFixture
    where @required : IGenericConstraintInterfaceFixture
    where @record : IGenericConstraintInterfaceFixture
    where @file : IGenericConstraintInterfaceFixture
    where @scoped : IGenericConstraintInterfaceFixture
    where @closed : IGenericConstraintInterfaceFixture
    where @__arglist : IGenericConstraintInterfaceFixture
{
    public static @class Echo<@struct>(@class value, @struct other)
        where @struct : @class => value;
}
