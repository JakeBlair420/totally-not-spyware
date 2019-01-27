#pragma once

#include <cstdint>

// Entries in the NodeType enum (below) are composed of an id, a result type (possibly none)
// and some additional informative flags (must generate, is constant, etc).
#define NodeResultMask                   0x0007
#define NodeResultJS                     0x0001
#define NodeResultNumber                 0x0002
#define NodeResultDouble                 0x0003
#define NodeResultInt32                  0x0004
#define NodeResultInt52                  0x0005
#define NodeResultBoolean                0x0006
#define NodeResultStorage                0x0007

#define NodeMustGenerate                 0x0008 // set on nodes that have side effects, and may not trivially be removed by DCE.
#define NodeHasVarArgs                   0x0010

#define NodeBehaviorMask                 0x07e0
#define NodeMayHaveDoubleResult          0x0020
#define NodeMayOverflowInt52             0x0040
#define NodeMayOverflowInt32InBaseline   0x0080
#define NodeMayOverflowInt32InDFG        0x0100
#define NodeMayNegZeroInBaseline         0x0200
#define NodeMayNegZeroInDFG              0x0400
#define NodeMayHaveNonNumberResult       0x0800
#define NodeMayHaveNonIntResult          (NodeMayHaveDoubleResult | NodeMayHaveNonNumberResult)

#define NodeBytecodeBackPropMask        0x1f000
#define NodeBytecodeUseBottom           0x00000
#define NodeBytecodeUsesAsNumber        0x01000 // The result of this computation may be used in a context that observes fractional, or bigger-than-int32, results.
#define NodeBytecodeNeedsNegZero        0x02000 // The result of this computation may be used in a context that observes -0.
#define NodeBytecodeUsesAsOther         0x04000 // The result of this computation may be used in a context that distinguishes between NaN and other things (like undefined).
#define NodeBytecodeUsesAsValue         (NodeBytecodeUsesAsNumber | NodeBytecodeNeedsNegZero | NodeBytecodeUsesAsOther)
#define NodeBytecodeUsesAsInt           0x08000 // The result of this computation is known to be used in a context that prefers, but does not require, integer values.
#define NodeBytecodeUsesAsArrayIndex    0x10000 // The result of this computation is known to be used in a context that strongly prefers integer values, to the point that we should avoid using doubles if at all possible.

#define NodeArithFlagsMask               (NodeBehaviorMask | NodeBytecodeBackPropMask)

#define NodeIsFlushed                   0x20000 // Computed by CPSRethreadingPhase, will tell you which local nodes are backwards-reachable from a Flush.

#define NodeMiscFlag1                   0x40000
#define NodeMiscFlag2                   0x80000

typedef uint32_t NodeFlags;
