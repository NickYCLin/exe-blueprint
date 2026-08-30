namespace ExeBlueprint.Core.Tests;

internal static class MultiDimensionalArrayBodyFixture<T>
{
    public static T GetTypeMatrix(T[,] values, int row, int column) =>
        values[row, column];

    public static void SetTypeMatrix(T[,] values, int row, int column, T value) =>
        values[row, column] = value;

    public static T[,] CreateTypeMatrix(int rows, int columns) =>
        new T[rows, columns];

    public static T GetTypeMatrixAfterIdentity(
        T[,] values,
        int row,
        int column) =>
        Identity(values)[row, column];

    public static void SetTypeMatrixAfterIdentity(
        T[,] values,
        int row,
        int column,
        T value) =>
        Identity(values)[row, column] = value;

    public static ref T AddressTypeMatrix(T[,] values, int row, int column) =>
        ref values[row, column];

    public static TMethod GetMethodMatrix<TMethod>(
        TMethod[,] values,
        int row,
        int column) =>
        values[row, column];

    public static void SetMethodMatrix<TMethod>(
        TMethod[,] values,
        int row,
        int column,
        TMethod value) =>
        values[row, column] = value;

    public static TMethod[,] CreateMethodMatrix<TMethod>(int rows, int columns) =>
        new TMethod[rows, columns];

    public static TMethod GetMethodMatrixAfterIdentity<TMethod>(
        TMethod[,] values,
        int row,
        int column) =>
        Identity(values)[row, column];

    public static void SetMethodMatrixAfterIdentity<TMethod>(
        TMethod[,] values,
        int row,
        int column,
        TMethod value) =>
        Identity(values)[row, column] = value;

    public static ref TMethod AddressMethodMatrix<TMethod>(
        TMethod[,] values,
        int row,
        int column) =>
        ref values[row, column];

    private static TValue Identity<TValue>(TValue value) => value;
}
