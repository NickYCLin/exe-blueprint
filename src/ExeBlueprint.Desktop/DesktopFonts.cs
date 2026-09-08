using Avalonia;
using Avalonia.Media;

namespace ExeBlueprint.Desktop;

internal static class DesktopFonts
{
    internal const string ChineseFontFamily = "avares://ExeBlueprint/Assets/Fonts#Noto Sans TC";

    public static AppBuilder WithDesktopFonts(this AppBuilder builder) =>
        builder.WithInterFont().With(new FontManagerOptions
        {
            FontFallbacks =
            [
                new FontFallback { FontFamily = new FontFamily(ChineseFontFamily) }
            ]
        });
}
