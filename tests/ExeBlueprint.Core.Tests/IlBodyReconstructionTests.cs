using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

// 用手工組出的 IL bytes 驗證控制流程還原，不依賴自我組件剛好有對應形狀。
// 多數 IL 只用區域變數、參數、算式與分支；typed field target 另使用本測試 assembly 的真實 token。
public sealed class IlBodyReconstructionTests
{
    [Fact]
    public void ReconstructsWhileLoop()
    {
        // static int M(int n) { int i = 0; while (i < n) { i = i + 1; } return i; }
        byte[] il =
        [
            0x16,             // ldc.i4.0
            0x0A,             // stloc.0
            0x2B, 0x04,       // br.s COND (+4 -> IL_0008)
            0x06,             // IL_0004 BODY: ldloc.0
            0x17,             // ldc.i4.1
            0x58,             // add
            0x0A,             // stloc.0
            0x06,             // IL_0008 COND: ldloc.0
            0x02,             // ldarg.0
            0x32, 0xF8,       // blt.s BODY (-8 -> IL_0004)
            0x06,             // ldloc.0
            0x2A              // ret
        ];

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            parameterTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            ["int v0 = 0;", "while (v0 < arg0)", "{", "    v0 = (v0 + 1);", "}", "return v0;"],
            body);
    }

    [Fact]
    public void ReconstructsDoWhileLoop()
    {
        // static int M(int n) { int i = 0; do { i = i + 1; } while (i < n); return i; }
        byte[] il =
        [
            0x16,       // ldc.i4.0
            0x0A,       // stloc.0
            0x06,       // IL_0002 BODY: ldloc.0
            0x17,       // ldc.i4.1
            0x58,       // add
            0x0A,       // stloc.0
            0x06,       // ldloc.0
            0x02,       // ldarg.0
            0x32, 0xF8, // blt.s BODY (-8 -> IL_0002)
            0x06,       // ldloc.0
            0x2A        // ret
        ];

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            parameterTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            ["int v0 = 0;", "do", "{", "    v0 = (v0 + 1);", "} while (v0 < arg0);", "return v0;"],
            body);
    }

    [Fact]
    public void IgnoresBranchToImmediatelyFollowingInstruction()
    {
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x0A,       // IL_0001 stloc.0
            0x2B, 0x00, // IL_0002 br.s IL_0004
            0x06,       // IL_0004 ldloc.0
            0x2A        // IL_0005 ret
        ];

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            parameterTypes: ["int"]);

        Assert.Equal(["int v0 = arg0;", "return v0;"], body);
    }

    [Fact]
    public void ReconstructsIf()
    {
        // static int M(int n) { if (n == 5) { return 1; } return 2; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x1B,       // IL_0001 ldc.i4.5
            0x33, 0x02, // IL_0002 bne.un.s IL_0006 (+2)
            0x17,       // IL_0004 ldc.i4.1
            0x2A,       // IL_0005 ret
            0x18,       // IL_0006 ldc.i4.2
            0x2A        // IL_0007 ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            ["if (arg0 == 5)", "{", "    return 1;", "}", "return 2;"],
            body);
    }

    [Theory]
    [InlineData("int", "uint", 0x34, 0x41, ">=", "<")]
    [InlineData("int", "uint", 0x35, 0x42, ">", "<=")]
    [InlineData("int", "uint", 0x36, 0x43, "<=", ">")]
    [InlineData("int", "uint", 0x37, 0x44, "<", ">=")]
    [InlineData("long", "ulong", 0x34, 0x41, ">=", "<")]
    [InlineData("long", "ulong", 0x35, 0x42, ">", "<=")]
    [InlineData("long", "ulong", 0x36, 0x43, "<=", ">")]
    [InlineData("long", "ulong", 0x37, 0x44, "<", ">=")]
    [InlineData("nint", "nuint", 0x34, 0x41, ">=", "<")]
    [InlineData("nint", "nuint", 0x35, 0x42, ">", "<=")]
    [InlineData("nint", "nuint", 0x36, 0x43, "<=", ">")]
    [InlineData("nint", "nuint", 0x37, 0x44, "<", ">=")]
    public void LowersUnsignedRelationalBranchesAcrossIfAndLoopPaths(
        string signedType,
        string unsignedType,
        int shortOpcode,
        int longOpcode,
        string takenOperator,
        string fallThroughOperator)
    {
        var ifBody = new[]
        {
            $"if (unchecked(({unsignedType})arg0) {fallThroughOperator} unchecked(({unsignedType})arg1))",
            "{",
            "    return true;",
            "}",
            "return false;"
        };
        Assert.Equal(
            ifBody,
            Reconstruct(
                BuildUnsignedRelationalIf((byte)shortOpcode, shortForm: true),
                isInstance: false,
                returnType: "bool",
                parameterTypes: [signedType, unsignedType]));
        Assert.Equal(
            ifBody,
            Reconstruct(
                BuildUnsignedRelationalIf((byte)longOpcode, shortForm: false),
                isInstance: false,
                returnType: "bool",
                parameterTypes: [signedType, unsignedType]));

        var takenCondition =
            $"unchecked(({unsignedType})arg0) {takenOperator} unchecked(({unsignedType})arg1)";
        Assert.Equal(
            [
                "arg2 = 0;",
                $"while ({takenCondition})",
                "{",
                "    arg2 = (arg2 + 1);",
                "}",
                "return arg2;"
            ],
            Reconstruct(
                BuildUnsignedRelationalWhile((byte)shortOpcode),
                isInstance: false,
                returnType: "int",
                parameterTypes: [signedType, unsignedType, "int"]));
        Assert.Equal(
            [
                "do",
                "{",
                "    arg2 = (arg2 + 1);",
                $"}} while ({takenCondition});",
                "return arg2;"
            ],
            Reconstruct(
                BuildUnsignedRelationalDoWhile((byte)longOpcode),
                isInstance: false,
                returnType: "int",
                parameterTypes: [signedType, unsignedType, "int"]));
    }

    [Fact]
    public void RejectsUnsignedRelationalBranchesForUnknownCrossFamilyAndFloatingTypes()
    {
        IReadOnlyList<string>[] unsafeOperandTypes =
        [
            [],
            ["int", "ulong"],
            ["float", "float"],
            ["double", "double"]
        ];

        foreach (var operandTypes in unsafeOperandTypes)
        {
            var loopTypes = operandTypes.Count == 0
                ? null
                : new[] { operandTypes[0], operandTypes[1], "int" };
            Assert.Null(Reconstruct(
                BuildUnsignedRelationalIf(0x34, shortForm: true),
                isInstance: false,
                returnType: "bool",
                parameterTypes: operandTypes));
            Assert.Null(Reconstruct(
                BuildUnsignedRelationalWhile(0x34),
                isInstance: false,
                returnType: "int",
                parameterTypes: loopTypes));
            Assert.Null(Reconstruct(
                BuildUnsignedRelationalDoWhile(0x41),
                isInstance: false,
                returnType: "int",
                parameterTypes: loopTypes));
        }
    }

    [Fact]
    public void ReconstructsTypedTruthinessConditions()
    {
        // static bool M(T value) { if (value) return true; return false; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x2C, 0x02, // IL_0001 brfalse.s IL_0005
            0x17,       // IL_0003 ldc.i4.1
            0x2A,       // IL_0004 ret
            0x16,       // IL_0005 ldc.i4.0
            0x2A        // IL_0006 ret
        ];

        var booleanBody = Reconstruct(
            il,
            isInstance: false,
            returnType: "bool",
            parameterTypes: ["bool"]);
        Assert.Equal(["if (arg0)", "{", "    return true;", "}", "return false;"], booleanBody);

        var integerBody = Reconstruct(
            il,
            isInstance: false,
            returnType: "bool",
            parameterTypes: ["int"]);
        Assert.Equal(
            [
                "if (!(System.Collections.Generic.EqualityComparer<int>.Default.Equals(arg0, default)))",
                "{",
                "    return true;",
                "}",
                "return false;"
            ],
            integerBody);
    }

    [Fact]
    public void NormalizesIlBooleanEqualityWithoutChangingUnorderedComparisonSemantics()
    {
        byte[] equalsFalse = [0x02, 0x16, 0xFE, 0x01, 0x2A];
        byte[] equalsTrue = [0x02, 0x17, 0xFE, 0x01, 0x2A];
        byte[] invertedLessThanZero =
        [
            0x02,
            0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFE, 0x04,
            0x16,
            0xFE, 0x01,
            0x2A
        ];

        Assert.Equal(
            ["return !(arg0);"],
            Reconstruct(equalsFalse, isInstance: false, returnType: "bool", parameterTypes: ["bool"]));
        Assert.Equal(
            ["return arg0;"],
            Reconstruct(equalsTrue, isInstance: false, returnType: "bool", parameterTypes: ["bool"]));
        var inverted = Assert.Single(
            Reconstruct(
                invertedLessThanZero,
                isInstance: false,
                returnType: "bool",
                parameterTypes: ["double"])!);
        Assert.Equal("return !((arg0 < 0.0));", inverted);
        Assert.DoesNotContain(">=", inverted, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsIntegerExpressionsReturnedAsUnverifiedEnums()
    {
        byte[] il = [0x19, 0x2A]; // ldc.i4.3; ret
        byte[] converted = [0x17, 0x6A, 0x2A]; // ldc.i4.1; conv.i8; ret
        byte[] argument = [0x02, 0x2A]; // ldarg.0; ret

        Assert.Null(Reconstruct(
            il,
            isInstance: false,
            returnType: "System.Reflection.FieldAttributes"));
        Assert.Null(Reconstruct(
            converted,
            isInstance: false,
            returnType: "Example.LongEnum"));
        Assert.Null(Reconstruct(
            argument,
            isInstance: false,
            returnType: "System.Reflection.FieldAttributes",
            parameterTypes: ["int"]));
        Assert.Equal(
            ["return arg0;"],
            Reconstruct(
                argument,
                isInstance: false,
                returnType: "System.Reflection.FieldAttributes",
                parameterTypes: ["System.Reflection.FieldAttributes"]));
        Assert.Equal(
            ["return 3;"],
            Reconstruct(il, isInstance: false, returnType: "int"));
    }

    [Fact]
    public void NormalizesUnsignedReferenceNullComparison()
    {
        byte[] il = [0x02, 0x14, 0xFE, 0x03, 0x2A];
        byte[] reversed = [0x14, 0x02, 0xFE, 0x03, 0x2A];
        byte[] twoReferences = [0x02, 0x03, 0xFE, 0x03, 0x2A];
        byte[] lessThanNull = [0x02, 0x14, 0xFE, 0x05, 0x2A];

        Assert.Equal(
            ["return (arg0 is not null);"],
            Reconstruct(il, isInstance: false, returnType: "bool", parameterTypes: ["object"]));
        Assert.Null(Reconstruct(reversed, isInstance: false, returnType: "bool", parameterTypes: ["object"]));
        Assert.Null(
            Reconstruct(
                twoReferences,
                isInstance: false,
                returnType: "bool",
                parameterTypes: ["object", "object"]));
        Assert.Null(
            Reconstruct(
                lessThanNull,
                isInstance: false,
                returnType: "bool",
                parameterTypes: ["object"]));
    }

    [Theory]
    [InlineData("int", "uint")]
    [InlineData("long", "ulong")]
    [InlineData("nint", "nuint")]
    public void LowersUnsignedComparisonsForKnownStackFamilies(
        string signedType,
        string unsignedType)
    {
        byte[] greaterThan = [0x02, 0x03, 0xFE, 0x03, 0x2A];
        byte[] lessThan = [0x02, 0x03, 0xFE, 0x05, 0x2A];

        Assert.Equal(
            [$"return (unchecked(({unsignedType})arg0) > unchecked(({unsignedType})arg1));"],
            Reconstruct(
                greaterThan,
                isInstance: false,
                returnType: "bool",
                parameterTypes: [signedType, unsignedType]));
        Assert.Equal(
            [$"return (unchecked(({unsignedType})arg0) < unchecked(({unsignedType})arg1));"],
            Reconstruct(
                lessThan,
                isInstance: false,
                returnType: "bool",
                parameterTypes: [signedType, unsignedType]));
    }

    [Fact]
    public void RejectsUnsignedComparisonsForUnknownCrossFamilyAndFloatingTypes()
    {
        byte[][] operations =
        [
            [0x02, 0x03, 0xFE, 0x03, 0x2A],
            [0x02, 0x03, 0xFE, 0x05, 0x2A]
        ];

        foreach (var il in operations)
        {
            Assert.Null(Reconstruct(il, isInstance: false, returnType: "bool"));
            Assert.Null(Reconstruct(
                il,
                isInstance: false,
                returnType: "bool",
                parameterTypes: ["int", "ulong"]));
            Assert.Null(Reconstruct(
                il,
                isInstance: false,
                returnType: "bool",
                parameterTypes: ["float", "float"]));
            Assert.Null(Reconstruct(
                il,
                isInstance: false,
                returnType: "bool",
                parameterTypes: ["double", "double"]));
        }
    }

    [Theory]
    [InlineData("int", "uint")]
    [InlineData("long", "ulong")]
    [InlineData("nint", "nuint")]
    public void LowersUnsignedDivisionAndRemainderForKnownStackFamilies(
        string signedType,
        string unsignedType)
    {
        byte[] unsignedDivision = [0x02, 0x03, 0x5C, 0x2A];
        byte[] unsignedRemainder = [0x02, 0x03, 0x5E, 0x2A];

        Assert.Equal(
            [$"return (unchecked(({unsignedType})arg0) / unchecked(({unsignedType})arg1));"],
            Reconstruct(
                unsignedDivision,
                isInstance: false,
                returnType: unsignedType,
                parameterTypes: [signedType, unsignedType]));
        Assert.Equal(
            [$"return (unchecked(({unsignedType})arg0) % unchecked(({unsignedType})arg1));"],
            Reconstruct(
                unsignedRemainder,
                isInstance: false,
                returnType: unsignedType,
                parameterTypes: [signedType, unsignedType]));
    }

    [Theory]
    [InlineData("int", "uint")]
    [InlineData("long", "ulong")]
    [InlineData("nint", "nuint")]
    public void CastsUnsignedResultsBackToSignedReturnAndLocalTypes(
        string signedType,
        string unsignedType)
    {
        byte[] directReturn = [0x02, 0x03, 0x5C, 0x2A];
        byte[] localRoundTrip = [0x02, 0x03, 0x5E, 0x0A, 0x06, 0x2A];
        byte[] argumentRoundTrip = [0x02, 0x03, 0x5C, 0x10, 0x00, 0x02, 0x2A];
        var division = $"(unchecked(({unsignedType})arg0) / unchecked(({unsignedType})arg1))";
        var remainder = $"(unchecked(({unsignedType})arg0) % unchecked(({unsignedType})arg1))";

        Assert.Equal(
            [$"return unchecked(({signedType}){division});"],
            Reconstruct(
                directReturn,
                isInstance: false,
                returnType: signedType,
                parameterTypes: [signedType, unsignedType]));
        Assert.Equal(
            [
                $"{signedType} v0 = unchecked(({signedType}){remainder});",
                "return v0;"
            ],
            Reconstruct(
                localRoundTrip,
                isInstance: false,
                returnType: signedType,
                localTypes: [signedType],
                parameterTypes: [signedType, unsignedType]));
        Assert.Equal(
            [
                $"arg0 = unchecked(({signedType}){division});",
                "return arg0;"
            ],
            Reconstruct(
                argumentRoundTrip,
                isInstance: false,
                returnType: signedType,
                parameterTypes: [signedType, unsignedType]));
    }

    [Fact]
    public void DoesNotApplyUnsignedOperationBoundaryRulesToOrdinaryUnsignedExpressions()
    {
        byte[] localRoundTrip = [0x02, 0x0A, 0x06, 0x2A];

        Assert.Equal(
            ["uint v0 = arg0;", "return v0;"],
            Reconstruct(
                localRoundTrip,
                isInstance: false,
                returnType: "uint",
                localTypes: ["uint"],
                parameterTypes: ["uint"]));
    }

    [Fact]
    public void RejectsUnsignedDivisionAndRemainderForUnknownOrUnsafeTypes()
    {
        byte[] unknownLocal = [0x02, 0x03, 0x5C, 0x0A, 0x06, 0x2A];
        byte[][] operations =
        [
            [0x02, 0x03, 0x5C, 0x2A],
            [0x02, 0x03, 0x5E, 0x2A]
        ];

        foreach (var il in operations)
        {
            Assert.Null(Reconstruct(il, isInstance: false, returnType: "uint"));
            Assert.Null(Reconstruct(
                il,
                isInstance: false,
                returnType: "ulong",
                parameterTypes: ["int", "ulong"]));
            Assert.Null(Reconstruct(
                il,
                isInstance: false,
                returnType: "float",
                parameterTypes: ["float", "float"]));
            Assert.Null(Reconstruct(
                il,
                isInstance: false,
                returnType: "double",
                parameterTypes: ["double", "double"]));
        }

        Assert.Null(Reconstruct(
            unknownLocal,
            isInstance: false,
            returnType: "uint",
            parameterTypes: ["int", "uint"]));
        Assert.Null(Reconstruct(
            operations[0],
            isInstance: false,
            returnType: "long",
            parameterTypes: ["int", "uint"]));

        byte[] signedDivision = [0x02, 0x03, 0x5B, 0x2A];
        Assert.Equal(
            ["return (arg0 / arg1);"],
            Reconstruct(
                signedDivision,
                isInstance: false,
                returnType: "long",
                parameterTypes: ["long", "long"]));
    }

    [Fact]
    public void PreservesSignedAndUnsignedRightShiftSemantics()
    {
        byte[] signedShift = [0x02, 0x17, 0x63, 0x2A];
        byte[] unsignedShift = [0x02, 0x17, 0x64, 0x2A];

        Assert.Equal(
            ["return (arg0 >> 1);"],
            Reconstruct(
                signedShift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int"]));
        Assert.Equal(
            ["return (arg0 >>> 1);"],
            Reconstruct(
                unsignedShift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int"]));
        Assert.Equal(
            ["return (arg0 >>> 1);"],
            Reconstruct(
                unsignedShift,
                isInstance: false,
                returnType: "long",
                parameterTypes: ["long"]));
    }

    [Fact]
    public void NormalizesCliShiftOperandsAndEnumResults()
    {
        byte[] shiftLeft = [0x02, 0x17, 0x62, 0x2A];
        byte[] shiftRight = [0x02, 0x17, 0x63, 0x2A];
        byte[] shiftRightUnsigned = [0x02, 0x17, 0x64, 0x2A];
        byte[] variableShift = [0x02, 0x03, 0x62, 0x2A];
        var intEnum = typeof(Int32StackCoercionEnum).FullName!;
        var byteEnum = typeof(ByteStackCoercionEnum).FullName!;
        var longEnum = typeof(Int64StackCoercionEnum).FullName!;
        var ulongEnum = typeof(UInt64StackCoercionEnum).FullName!;

        Assert.Equal(
            ["return (unchecked((int)arg0) << 1);"],
            Reconstruct(
                shiftLeft,
                isInstance: false,
                returnType: "int",
                parameterTypes: [intEnum]));
        Assert.Equal(
            ["return (unchecked((int)arg0) >> 1);"],
            Reconstruct(
                shiftRight,
                isInstance: false,
                returnType: "int",
                parameterTypes: [byteEnum]));
        Assert.Equal(
            ["return (unchecked((long)arg0) >> 1);"],
            Reconstruct(
                shiftRight,
                isInstance: false,
                returnType: "long",
                parameterTypes: [longEnum]));
        Assert.Equal(
            ["return (unchecked((long)arg0) >>> 1);"],
            Reconstruct(
                shiftRightUnsigned,
                isInstance: false,
                returnType: "long",
                parameterTypes: [ulongEnum]));
        Assert.Equal(
            [$"return unchecked(({byteEnum})(unchecked((int)arg0) << 1));"],
            Reconstruct(
                shiftLeft,
                isInstance: false,
                returnType: byteEnum,
                parameterTypes: [byteEnum]));

        Assert.Equal(
            ["return unchecked((uint)(unchecked((int)arg0) >> 1));"],
            Reconstruct(
                shiftRight,
                isInstance: false,
                returnType: "uint",
                parameterTypes: ["uint"]));
        Assert.Equal(
            ["return unchecked((uint)(unchecked((int)arg0) >>> 1));"],
            Reconstruct(
                shiftRightUnsigned,
                isInstance: false,
                returnType: "uint",
                parameterTypes: ["uint"]));
        Assert.Equal(
            ["return unchecked((ulong)(unchecked((long)arg0) >> 1));"],
            Reconstruct(
                shiftRight,
                isInstance: false,
                returnType: "ulong",
                parameterTypes: ["ulong"]));
        Assert.Equal(
            ["return unchecked((ulong)(unchecked((long)arg0) >>> 1));"],
            Reconstruct(
                shiftRightUnsigned,
                isInstance: false,
                returnType: "ulong",
                parameterTypes: ["ulong"]));
        Assert.Equal(
            ["return unchecked((nuint)(unchecked((nint)arg0) >> 1));"],
            Reconstruct(
                shiftRight,
                isInstance: false,
                returnType: "nuint",
                parameterTypes: ["nuint"]));
        Assert.Equal(
            ["return unchecked((nuint)(unchecked((nint)arg0) >>> 1));"],
            Reconstruct(
                shiftRightUnsigned,
                isInstance: false,
                returnType: "nuint",
                parameterTypes: ["nuint"]));

        Assert.Equal(
            ["return (arg0 << unchecked((int)arg1));"],
            Reconstruct(
                variableShift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int", "uint"]));
        Assert.Equal(
            ["return (arg0 << unchecked((int)arg1));"],
            Reconstruct(
                variableShift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int", "byte"]));
        Assert.Equal(
            ["return (arg0 << unchecked((int)arg1));"],
            Reconstruct(
                variableShift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int", "nint"]));
        Assert.Equal(
            ["return (arg0 << unchecked((int)arg1));"],
            Reconstruct(
                variableShift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int", "nuint"]));
        Assert.Equal(
            ["return (arg0 << unchecked((int)arg1));"],
            Reconstruct(
                variableShift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int", intEnum]));
    }

    [Fact]
    public void RejectsUnsafeCliShiftOperandsAndCounts()
    {
        byte[] shift = [0x02, 0x03, 0x62, 0x2A];
        var intEnum = typeof(Int32StackCoercionEnum).FullName!;
        var longEnum = typeof(Int64StackCoercionEnum).FullName!;

        Assert.Null(Reconstruct(
            shift,
            isInstance: false,
            returnType: "int",
            parameterTypes: ["int"]));
        Assert.Null(Reconstruct(
            [0x02, 0x17, 0x62, 0x2A],
            isInstance: false,
            returnType: "int"));
        Assert.Null(Reconstruct(
            shift,
            isInstance: false,
            returnType: "int",
            parameterTypes: ["System.DayOfWeek", "int"]));
        Assert.Null(Reconstruct(
            shift,
            isInstance: false,
            returnType: "int",
            parameterTypes: ["float", "int"]));
        Assert.Null(Reconstruct(
            shift,
            isInstance: false,
            returnType: "int",
            parameterTypes: ["bool", "int"]));
        Assert.Null(Reconstruct(
            shift,
            isInstance: false,
            returnType: "int",
            parameterTypes: [typeof(StackCoercionClass).FullName!, "int"]));
        Assert.Null(Reconstruct(
            [0x02, 0x17, 0x62, 0x2A],
            isInstance: false,
            returnType: "int",
            parameterTypes: ["long"]));

        foreach (var countType in new[]
                 {
                     "long",
                     "ulong",
                     "float",
                     "bool",
                     "object",
                     "System.DayOfWeek",
                     longEnum
                 })
        {
            Assert.Null(Reconstruct(
                shift,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int", countType]));
        }

        Assert.NotNull(Reconstruct(
            shift,
            isInstance: false,
            returnType: "int",
            parameterTypes: [intEnum, "int"]));
    }

    [Fact]
    public void NormalizesCliBooleanAndEnumAssignmentsAtTypedTargets()
    {
        byte[] storeLocalAndReturn = [0x02, 0x0A, 0x06, 0x2A];
        byte[] assignArgumentAndReturn = [0x17, 0x10, 0x00, 0x02, 0x2A];
        byte[] assignEnumArgumentAndReturn = [0x17, 0xFE, 0x0B, 0x00, 0x00, 0x02, 0x2A];
        byte[] storeEnumInIntArgumentAndReturn = [0x03, 0x10, 0x00, 0x02, 0x2A];
        byte[] invalidBoolean = [0x18, 0x0A, 0x2A];
        var intEnum = typeof(Int32StackCoercionEnum).FullName!;
        var longEnum = typeof(Int64StackCoercionEnum).FullName!;
        var nonEnum = typeof(StackCoercionClass).FullName!;

        Assert.Equal(
            ["bool v0 = false;", "return v0;"],
            Reconstruct(
                [0x16, 0x0A, 0x06, 0x2A],
                isInstance: false,
                returnType: "bool",
                localTypes: ["bool"]));
        Assert.Equal(
            ["arg0 = true;", "return arg0;"],
            Reconstruct(
                assignArgumentAndReturn,
                isInstance: false,
                returnType: "bool",
                parameterTypes: ["bool"]));
        Assert.Null(Reconstruct(
            invalidBoolean,
            isInstance: false,
            returnType: "void",
            localTypes: ["bool"]));
        Assert.Null(Reconstruct(
            [0x02, 0x2A],
            isInstance: false,
            returnType: "bool",
            parameterTypes: ["int"]));
        Assert.Null(Reconstruct(
            storeLocalAndReturn,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            parameterTypes: ["bool"]));

        Assert.Equal(
            ["int v0 = unchecked((int)arg0);", "return v0;"],
            Reconstruct(
                storeLocalAndReturn,
                isInstance: false,
                returnType: "int",
                localTypes: ["int"],
                parameterTypes: [intEnum]));
        Assert.Equal(
            [$"{intEnum} v0 = unchecked(({intEnum})arg0);", "return v0;"],
            Reconstruct(
                storeLocalAndReturn,
                isInstance: false,
                returnType: intEnum,
                localTypes: [intEnum],
                parameterTypes: ["int"]));
        Assert.Equal(
            ["long v0 = unchecked((long)arg0);", "return v0;"],
            Reconstruct(
                storeLocalAndReturn,
                isInstance: false,
                returnType: "long",
                localTypes: ["long"],
                parameterTypes: [longEnum]));
        Assert.Equal(
            ["arg0 = unchecked((int)arg1);", "return arg0;"],
            Reconstruct(
                storeEnumInIntArgumentAndReturn,
                isInstance: false,
                returnType: "int",
                parameterTypes: ["int", intEnum]));
        Assert.Equal(
            [$"arg0 = unchecked(({intEnum})1);", "return arg0;"],
            Reconstruct(
                assignEnumArgumentAndReturn,
                isInstance: false,
                returnType: intEnum,
                parameterTypes: [intEnum]));
        Assert.Null(Reconstruct(
            storeLocalAndReturn,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            parameterTypes: [longEnum]));
        Assert.Null(Reconstruct(
            [0x02, 0x2A],
            isInstance: false,
            returnType: "int",
            parameterTypes: [longEnum]));
        Assert.Null(Reconstruct(
            storeEnumInIntArgumentAndReturn,
            isInstance: false,
            returnType: "int",
            parameterTypes: ["int", longEnum]));
        Assert.Null(Reconstruct(
            storeLocalAndReturn,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            parameterTypes: [nonEnum]));
        Assert.Null(Reconstruct(
            [0x16, 0x2A],
            isInstance: false,
            returnType: nonEnum));

        var instanceEnumToken = typeof(CliStackCoercionFixture)
            .GetField("_instanceEnum", BindingFlags.Instance | BindingFlags.NonPublic)!
            .MetadataToken;
        var staticIntToken = typeof(CliStackCoercionFixture)
            .GetField("s_staticInt", BindingFlags.Static | BindingFlags.NonPublic)!
            .MetadataToken;
        var staticFlagToken = typeof(CliStackCoercionFixture)
            .GetField("s_staticFlag", BindingFlags.Static | BindingFlags.NonPublic)!
            .MetadataToken;
        Assert.Equal(
            [$"this._instanceEnum = unchecked(({intEnum})1);"],
            Reconstruct(
                BuildFieldStoreIl([0x02, 0x17], 0x7D, instanceEnumToken),
                isInstance: true,
                returnType: "void"));
        Assert.Equal(
            ["ExeBlueprint.Core.Tests.CliStackCoercionFixture.s_staticInt = unchecked((int)arg0);"],
            Reconstruct(
                BuildFieldStoreIl([0x02], 0x80, staticIntToken),
                isInstance: false,
                returnType: "void",
                parameterTypes: [intEnum]));
        Assert.Null(Reconstruct(
            BuildFieldStoreIl([0x18], 0x80, staticFlagToken),
            isInstance: false,
            returnType: "void"));
    }

    private static byte[] BuildFieldStoreIl(byte[] prefix, byte opcode, int token)
    {
        var il = new byte[prefix.Length + 6];
        prefix.CopyTo(il, 0);
        il[prefix.Length] = opcode;
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(prefix.Length + 1, 4), token);
        il[^1] = 0x2A;
        return il;
    }

    [Fact]
    public void ReconstructsTerminalSwitchCases()
    {
        // static int M(int n) => n switch { 0 => 10, 1 => 20, 2 => 30, _ => 99 };
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x45, 0x03, 0x00, 0x00, 0x00, // IL_0001 switch (3 targets)
            0x02, 0x00, 0x00, 0x00,       // case 0 -> IL_0014
            0x05, 0x00, 0x00, 0x00,       // case 1 -> IL_0017
            0x08, 0x00, 0x00, 0x00,       // case 2 -> IL_001A
            0x2B, 0x09,                   // IL_0012 br.s default (IL_001D)
            0x1F, 0x0A, 0x2A,             // IL_0014 ldc.i4.s 10; ret
            0x1F, 0x14, 0x2A,             // IL_0017 ldc.i4.s 20; ret
            0x1F, 0x1E, 0x2A,             // IL_001A ldc.i4.s 30; ret
            0x1F, 0x63, 0x2A              // IL_001D ldc.i4.s 99; ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            [
                "switch (arg0)",
                "{",
                "    case 0:",
                "        return 10;",
                "    case 1:",
                "        return 20;",
                "    case 2:",
                "        return 30;",
                "    default:",
                "        return 99;",
                "}"
            ],
            body);
    }

    [Fact]
    public void ReconstructsEnumMaskAndSwitchCases()
    {
        // static int M(Int32StackCoercionEnum value) => (value & (Int32StackCoercionEnum)7) - 1 switch { ... };
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x1D,                         // IL_0001 ldc.i4.7
            0x5F,                         // IL_0002 and
            0x17,                         // IL_0003 ldc.i4.1
            0x59,                         // IL_0004 sub
            0x45, 0x02, 0x00, 0x00, 0x00, // IL_0005 switch (2 targets)
            0x02, 0x00, 0x00, 0x00,       // case 0 -> IL_0014
            0x05, 0x00, 0x00, 0x00,       // case 1 -> IL_0017
            0x2B, 0x06,                   // IL_0012 br.s default (IL_001A)
            0x1F, 0x0A, 0x2A,             // IL_0014 ldc.i4.s 10; ret
            0x1F, 0x14, 0x2A,             // IL_0017 ldc.i4.s 20; ret
            0x1F, 0x63, 0x2A              // IL_001A ldc.i4.s 99; ret
        ];

        var enumType = typeof(Int32StackCoercionEnum).FullName!;
        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            parameterTypes: [enumType]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                $"switch (((arg0 & unchecked(({enumType})7)) - 1))",
                "{",
                $"    case unchecked(({enumType})0):",
                "        return 10;",
                $"    case unchecked(({enumType})1):",
                "        return 20;",
                "    default:",
                "        return 99;",
                "}"
            ],
            body);
    }

    [Fact]
    public void ReconstructsGroupedCasesAndFallThroughDefault()
    {
        // case 0 與 case 1 共用同一個 target；default 直接接在 switch 後面，沒有額外 br。
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x45, 0x02, 0x00, 0x00, 0x00, // IL_0001 switch (2 targets)
            0x03, 0x00, 0x00, 0x00,       // case 0 -> IL_0011
            0x03, 0x00, 0x00, 0x00,       // case 1 -> IL_0011
            0x1F, 0x63, 0x2A,             // IL_000E default: ldc.i4.s 99; ret
            0x1F, 0x0A, 0x2A              // IL_0011 cases: ldc.i4.s 10; ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            [
                "switch (arg0)",
                "{",
                "    default:",
                "        return 99;",
                "    case 0:",
                "    case 1:",
                "        return 10;",
                "}"
            ],
            body);
    }

    [Fact]
    public void ReconstructsSwitchWithSharedJoin()
    {
        // 每個 case 指派 result 後跳到共同 return；default 直接落到 join。
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x45, 0x03, 0x00, 0x00, 0x00, // IL_0001 switch (3 targets)
            0x02, 0x00, 0x00, 0x00,       // case 0 -> IL_0014
            0x07, 0x00, 0x00, 0x00,       // case 1 -> IL_0019
            0x0C, 0x00, 0x00, 0x00,       // case 2 -> IL_001E
            0x2B, 0x0F,                   // IL_0012 br.s default (IL_0023)
            0x1F, 0x0A, 0x0A, 0x2B, 0x0D, // IL_0014 result = 10; br.s join
            0x1F, 0x14, 0x0A, 0x2B, 0x08, // IL_0019 result = 20; br.s join
            0x1F, 0x1E, 0x0A, 0x2B, 0x03, // IL_001E result = 30; br.s join
            0x1F, 0x63, 0x0A,             // IL_0023 default: result = 99
            0x06, 0x2A                    // IL_0026 join: return result
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int", localTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "switch (arg0)",
                "{",
                "    case 0:",
                "        v0 = 10;",
                "        break;",
                "    case 1:",
                "        v0 = 20;",
                "        break;",
                "    case 2:",
                "        v0 = 30;",
                "        break;",
                "    default:",
                "        v0 = 99;",
                "        break;",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsTryFinallyFromExceptionRegion()
    {
        // static int M(int n) { try { result = n + 1; } finally { result += 10; } return result; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x06, // IL_0004 leave.s IL_000C
            0x06,       // IL_0006 ldloc.0
            0x1F, 0x0A, // IL_0007 ldc.i4.s 10
            0x58,       // IL_0009 add
            0x0A,       // IL_000A stloc.0
            0xDC,       // IL_000B endfinally
            0x06,       // IL_000C ldloc.0
            0x2A        // IL_000D ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Finally,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions,
            parameterTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    v0 = (arg0 + 1);",
                "}",
                "finally",
                "{",
                "    v0 = (v0 + 10);",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsFaultAsCatchAndRethrow()
    {
        // CLR fault 只在例外路徑執行；C# 沒有 fault，等價輸出為 catch { cleanup; throw; }。
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x06, // IL_0004 leave.s IL_000C
            0x06,       // IL_0006 ldloc.0
            0x1F, 0x0A, // IL_0007 ldc.i4.s 10
            0x58,       // IL_0009 add
            0x0A,       // IL_000A stloc.0
            0xDC,       // IL_000B endfinally
            0x06,       // IL_000C ldloc.0
            0x2A        // IL_000D ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Fault,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions,
            parameterTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    v0 = (arg0 + 1);",
                "}",
                "catch",
                "{",
                "    v0 = (v0 + 10);",
                "    throw;",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsTerminalTryWithFault()
    {
        byte[] il =
        [
            0x14,       // IL_0000 ldnull
            0x7A,       // IL_0001 throw
            0x02,       // IL_0002 ldarg.0
            0x17,       // IL_0003 ldc.i4.1
            0x58,       // IL_0004 add
            0x10, 0x00, // IL_0005 starg.s 0
            0xDC        // IL_0007 endfinally
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Fault,
                TryOffset: 0,
                TryLength: 2,
                HandlerOffset: 2,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "void",
            exceptionRegions: regions,
            parameterTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "try",
                "{",
                "    throw null;",
                "}",
                "catch",
                "{",
                "    arg0 = (arg0 + 1);",
                "    throw;",
                "}"
            ],
            body);
    }

    [Fact]
    public void BailsOnFaultWithoutEndFinally()
    {
        byte[] il =
        [
            0x00,       // IL_0000 nop
            0xDE, 0x01, // IL_0001 leave.s IL_0004
            0x2A,       // IL_0003 ret（fault handler 不可用 ret 收尾）
            0x2A        // IL_0004 ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Fault,
                TryOffset: 0,
                TryLength: 3,
                HandlerOffset: 3,
                HandlerLength: 1)
        };

        Assert.Null(Reconstruct(
            il,
            isInstance: false,
            returnType: "void",
            exceptionRegions: regions));
    }

    [Fact]
    public void ReconstructsCatchFromExceptionRegion()
    {
        // static int M(int n) { try { return n + 1; } catch (InvalidOperationException) { return -1; } }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x05, // IL_0004 leave.s IL_000B
            0x26,       // IL_0006 pop
            0x15,       // IL_0007 ldc.i4.m1
            0x0A,       // IL_0008 stloc.0
            0xDE, 0x00, // IL_0009 leave.s IL_000B
            0x06,       // IL_000B ldloc.0
            0x2A        // IL_000C ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Catch,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 5,
                CatchType: "System.InvalidOperationException")
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions,
            parameterTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    v0 = (arg0 + 1);",
                "}",
                "catch (System.InvalidOperationException)",
                "{",
                "    v0 = -1;",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsCombinedCatchAndFinallyFromNestedExceptionRegions()
    {
        // static int M(int n) { try { result = n + 1; } catch (Exception) { result = -1; }
        // finally { result += 10; } return result; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x05, // IL_0004 leave.s IL_000B
            0x26,       // IL_0006 pop
            0x15,       // IL_0007 ldc.i4.m1
            0x0A,       // IL_0008 stloc.0
            0xDE, 0x00, // IL_0009 leave.s IL_000B
            0xDE, 0x06, // IL_000B leave.s IL_0013
            0x06,       // IL_000D ldloc.0
            0x1F, 0x0A, // IL_000E ldc.i4.s 10
            0x58,       // IL_0010 add
            0x0A,       // IL_0011 stloc.0
            0xDC,       // IL_0012 endfinally
            0x06,       // IL_0013 ldloc.0
            0x2A        // IL_0014 ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Catch,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 5,
                CatchType: "System.Exception"),
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Finally,
                TryOffset: 0,
                TryLength: 13,
                HandlerOffset: 13,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions,
            parameterTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    try",
                "    {",
                "        v0 = (arg0 + 1);",
                "    }",
                "    catch (System.Exception)",
                "    {",
                "        v0 = -1;",
                "    }",
                "}",
                "finally",
                "{",
                "    v0 = (v0 + 10);",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void BailsOnMalformedFilterRegion()
    {
        byte[] il =
        [
            0x00,       // IL_0000 nop
            0xDE, 0x03, // IL_0001 leave.s IL_0006
            0x26,       // IL_0003 pop
            0xDE, 0x00, // IL_0004 leave.s IL_0006
            0x2A        // IL_0006 ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Filter,
                TryOffset: 0,
                TryLength: 3,
                HandlerOffset: 3,
                HandlerLength: 3,
                FilterOffset: 3)
        };

        Assert.Null(Reconstruct(
            il,
            isInstance: false,
            returnType: "void",
            exceptionRegions: regions));
    }

    [Fact]
    public void BailsOnBackwardInfiniteLoop()
    {
        // BODY: nop; br.s BODY  -> while(true), 目前不支援，應放棄。
        byte[] il =
        [
            0x00,             // IL_0000 nop
            0x2B, 0xFD        // br.s -3 -> IL_0000
        ];

        Assert.Null(Reconstruct(il, isInstance: false, returnType: "void"));
    }

    private static IReadOnlyList<string>? Reconstruct(
        byte[] il,
        bool isInstance,
        string returnType,
        IReadOnlyList<string>? localTypes = null,
        IReadOnlyList<ManagedSymbolReader.ExceptionRegionInfo>? exceptionRegions = null,
        IReadOnlyList<string>? parameterTypes = null)
    {
        // 使用測試組件 metadata，讓手工 IL 也能精確驗證本地 enum 的 underlying type。
        var assemblyPath = typeof(IlBodyReconstructionTests).Assembly.Location;
        using var peReader = new PEReader(File.OpenRead(assemblyPath));
        var metadata = peReader.GetMetadataReader();
        return ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            il,
            isInstance,
            returnType,
            localTypes,
            exceptionRegions,
            parameterTypes);
    }

    private static byte[] BuildUnsignedRelationalIf(byte opcode, bool shortForm) => shortForm
        ?
        [
            0x02, 0x03,       // ldarg.0; ldarg.1
            opcode, 0x02,     // branch to false return
            0x17, 0x2A,       // ldc.i4.1; ret
            0x16, 0x2A        // ldc.i4.0; ret
        ]
        :
        [
            0x02, 0x03,                   // ldarg.0; ldarg.1
            opcode, 0x02, 0x00, 0x00, 0x00, // branch to false return
            0x17, 0x2A,                   // ldc.i4.1; ret
            0x16, 0x2A                    // ldc.i4.0; ret
        ];

    private static byte[] BuildUnsignedRelationalWhile(byte opcode) =>
    [
        0x16, 0x10, 0x02, // arg2 = 0
        0x2B, 0x05,       // br.s condition
        0x04, 0x17, 0x58, 0x10, 0x02, // body: arg2 = arg2 + 1
        0x02, 0x03,       // condition: ldarg.0; ldarg.1
        opcode, 0xF7,     // branch back to body
        0x04, 0x2A        // return arg2
    ];

    private static byte[] BuildUnsignedRelationalDoWhile(byte opcode) =>
    [
        0x04, 0x17, 0x58, 0x10, 0x02, // body: arg2 = arg2 + 1
        0x02, 0x03,                   // condition: ldarg.0; ldarg.1
        opcode, 0xF4, 0xFF, 0xFF, 0xFF, // branch back to body
        0x04, 0x2A                    // return arg2
    ];
}

internal enum Int32StackCoercionEnum
{
    Zero
}

internal enum ByteStackCoercionEnum : byte
{
    Zero
}

internal enum Int64StackCoercionEnum : long
{
    Zero
}

internal enum UInt64StackCoercionEnum : ulong
{
    Zero
}

internal sealed class StackCoercionClass
{
}

internal sealed class CliStackCoercionFixture
{
    private bool _instanceFlag = true;
    private Int32StackCoercionEnum _instanceEnum;
    private static bool s_staticFlag = true;
    private static int s_staticInt;

    public bool ReadInstanceFlag() => _instanceFlag;

    public static bool ReadStaticFlag() => s_staticFlag;

    public void ClearInstanceFlag() => _instanceFlag = false;

    public static void ClearStaticFlag() => s_staticFlag = false;

    public static void SetStaticFlag() => s_staticFlag = true;

    public Int32StackCoercionEnum ReadInstanceEnum() => _instanceEnum;

    public void SetInstanceEnumFromInt(int value) => _instanceEnum = (Int32StackCoercionEnum)value;

    public static int ReadStaticInt() => s_staticInt;

    public static void SetStaticIntFromEnum(Int32StackCoercionEnum value) => s_staticInt = (int)value;

    public static int ToInt32(Int32StackCoercionEnum value) => (int)value;

    public static Int32StackCoercionEnum FromInt32(int value) => (Int32StackCoercionEnum)value;

    public static int ShiftLeft(Int32StackCoercionEnum value, int count) => (int)value << count;
}

internal static class SwitchFixture
{
    public static int TerminalCases(int value)
    {
        switch (value)
        {
            case 0:
                return 10;
            case 1:
                return 20;
            case 2:
                return 30;
            default:
                return 99;
        }
    }

    public static int JoinedCases(int value)
    {
        int result;
        switch (value)
        {
            case 0:
                result = 10;
                break;
            case 1:
                result = 20;
                break;
            case 2:
                result = 30;
                break;
            default:
                result = 99;
                break;
        }

        return result;
    }
}
