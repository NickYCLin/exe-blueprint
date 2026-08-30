namespace ExeBlueprint.Core.Tests;

internal enum ConstructorModeFixture
{
    Disabled,
    Enabled
}

internal class ConstructorBaseFixture
{
    protected ConstructorBaseFixture(ConstructorModeFixture mode, bool enabled)
    {
    }
}

internal sealed class ConstructorDerivedFixture : ConstructorBaseFixture
{
    private readonly int _value;
    private readonly ConstructorModeFixture _mode;
    private readonly bool _enabled;

    public ConstructorDerivedFixture(int value)
        : base(ConstructorModeFixture.Enabled, true)
    {
        _value = value;
        _mode = ConstructorModeFixture.Enabled;
        _enabled = true;
    }

    public ConstructorDerivedFixture(int value, ConstructorModeFixture mode)
        : this(value, mode, false)
    {
    }

    private ConstructorDerivedFixture(int value, ConstructorModeFixture mode, bool enabled)
        : base(mode, enabled)
    {
        _value = value;
        _mode = mode;
        _enabled = enabled;
    }
}
