/** @file
   Random number generator service that uses the SEED instruction
   to provide pseudorandom numbers.

   Copyright (c) 2024, Rivos, Inc.

   SPDX-License-Identifier: BSD-2-Clause-Patent
 **/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>
#include <Register/RiscV64/RiscVEncoding.h>

#include "BaseRngLibInternals.h"
#define RISCV_CPU_FEATURE_ZKR_BITMASK  0x8

#define SEED_RETRY_LOOPS  100

// ChaCha20 implementation
// A widely used pseudo random number generator. It performs bit shifts etc to
// achieve the random number. It's output is determined by SEED value generated
// by RISC-V SEED CSR"

/* (RFC7539 convention) */
#define CHACHA_KEY_SIZE    32
#define CHACHA_BLOCK_SIZE  64
#define CHACHA_STATE_WORDS  (CHACHA_BLOCK_SIZE / sizeof (UINT32))
#define CHACHA_KEY_WORDS  (CHACHA_KEY_SIZE / sizeof (UINT32))

#define CHACHA_CONSTANT_EXPA 0x61707865U
#define CHACHA_CONSTANT_ND_3 0x3320646eU
#define CHACHA_CONSTANT_2_BY 0x79622d32U
#define CHACHA_CONSTANT_TE_K 0x6b206574U

static UINT32  ChaChaState[CHACHA_STATE_WORDS];
static UINTN   ChaChaIndex = CHACHA_STATE_WORDS + 1;

/**
   Rotate 32-bit value left

   @param[in]  Operand The 64-bit operand to rotate left.
   @param[in]  Count   The number of bits to rotate left.

   @return Operand << Count
 **/
STATIC
UINT32
ROL32 (
  IN      UINT32  Operand,
  IN      UINTN   Count
  )
{
  return (Operand << Count) | (Operand >> (32 - Count));
}

/**
   ChaCha algorithm

   @param  X        Pointer to initial ChaCha state.
   @param  Rounds   Number of ChaCha rounds.
 **/
STATIC
VOID
ChaCha (
  IN OUT  UINT32  *X,
  IN      UINTN   Rounds
  )
{
  UINTN   I;

  for (I = 0; I < Rounds; I+=2) {
    X[0]  += X[4];    X[12] = ROL32(X[12] ^ X[0],  16);
    X[1]  += X[5];    X[13] = ROL32(X[13] ^ X[1],  16);
    X[2]  += X[6];    X[14] = ROL32(X[14] ^ X[2],  16);
    X[3]  += X[7];    X[15] = ROL32(X[15] ^ X[3],  16);

    X[8]  += X[12];   X[4]  = ROL32(X[4]  ^ X[8],  12);
    X[9]  += X[13];   X[5]  = ROL32(X[5]  ^ X[9],  12);
    X[10] += X[14];   X[6]  = ROL32(X[6]  ^ X[10], 12);
    X[11] += X[15];   X[7]  = ROL32(X[7]  ^ X[11], 12);

    X[0]  += X[4];    X[12] = ROL32(X[12] ^ X[0],   8);
    X[1]  += X[5];    X[13] = ROL32(X[13] ^ X[1],   8);
    X[2]  += X[6];    X[14] = ROL32(X[14] ^ X[2],   8);
    X[3]  += X[7];    X[15] = ROL32(X[15] ^ X[3],   8);

    X[8]  += X[12];   X[4]  = ROL32(X[4]  ^ X[8],   7);
    X[9]  += X[13];   X[5]  = ROL32(X[5]  ^ X[9],   7);
    X[10] += X[14];   X[6]  = ROL32(X[6]  ^ X[10],  7);
    X[11] += X[15];   X[7]  = ROL32(X[7]  ^ X[11],  7);

    X[0]  += X[5];    X[15] = ROL32(X[15] ^ X[0],  16);
    X[1]  += X[6];    X[12] = ROL32(X[12] ^ X[1],  16);
    X[2]  += X[7];    X[13] = ROL32(X[13] ^ X[2],  16);
    X[3]  += X[4];    X[14] = ROL32(X[14] ^ X[3],  16);

    X[10] += X[15];   X[5]  = ROL32(X[5]  ^ X[10], 12);
    X[11] += X[12];   X[6]  = ROL32(X[6]  ^ X[11], 12);
    X[8]  += X[13];   X[7]  = ROL32(X[7]  ^ X[8],  12);
    X[9]  += X[14];   X[4]  = ROL32(X[4]  ^ X[9],  12);

    X[0]  += X[5];    X[15] = ROL32(X[15] ^ X[0],   8);
    X[1]  += X[6];    X[12] = ROL32(X[12] ^ X[1],   8);
    X[2]  += X[7];    X[13] = ROL32(X[13] ^ X[2],   8);
    X[3]  += X[4];    X[14] = ROL32(X[14] ^ X[3],   8);

    X[10] += X[15];   X[5]  = ROL32(X[5]  ^ X[10],  7);
    X[11] += X[12];   X[6]  = ROL32(X[6]  ^ X[11],  7);
    X[8]  += X[13];   X[7]  = ROL32(X[7]  ^ X[8],   7);
    X[9]  += X[14];   X[4]  = ROL32(X[4]  ^ X[9],   7);
  }
}

/**
   Initialize ChaChaState to an initial state.

   @retval TRUE         ChaCha state generated successfully.
   @retval FALSE        Failed to generate ChaCha state.
 **/
STATIC
BOOLEAN
MakeChaChaState (
  VOID
  )
{
  UINT32  Seed[CHACHA_KEY_WORDS];
  UINTN   ValidSeeds;

  for (ValidSeeds = 0; ValidSeeds < CHACHA_KEY_WORDS; ValidSeeds++) {
    if (!Get32BitSeed (&Seed[ValidSeeds])) {
      return FALSE;
    }
  }

  ChaChaState[0] = CHACHA_CONSTANT_EXPA;
  ChaChaState[1] = CHACHA_CONSTANT_ND_3;
  ChaChaState[2] = CHACHA_CONSTANT_2_BY;
  ChaChaState[3] = CHACHA_CONSTANT_TE_K;

  for (ValidSeeds = 4; ValidSeeds < CHACHA_KEY_WORDS + 4; ValidSeeds++) {
    ChaChaState[4 + ValidSeeds] = Seed[ValidSeeds];
  }

  for (ValidSeeds = CHACHA_KEY_WORDS + 4; ValidSeeds < CHACHA_STATE_WORDS; ValidSeeds++) {
    ChaChaState[4 + ValidSeeds] = 0;
  }

  ChaCha (&ChaChaState, 20);
  ChaChaIndex = 0;

  return TRUE;
}

// Defined in Seed.S
extern UINT64
ReadSeed (
  VOID
  );

/**
   Gets seed value by executing trng instruction (CSR 0x15) amd returns
   the see to the caller 32-bit value.

   @param[out] Out     Buffer pointer to store the 64-bit random value.
   @retval TRUE         Random number generated successfully.
   @retval FALSE        Failed to generate the random number.
 **/
STATIC
BOOLEAN
Get32BitSeed (
  OUT UINT32  *Out
  )
{
  UINT64  Seed;
  UINTN   Retry;
  UINTN   ValidSeeds;
  UINTN   NeededSeeds;
  UINT16  *Entropy;

  Retry       = SEED_RETRY_LOOPS;
  Entropy     = (UINT16 *)Out;
  NeededSeeds = sizeof (UINT32) / sizeof (UINT16);
  ValidSeeds  = 0;

  if (!ArchIsRngSupported ()) {
    DEBUG ((DEBUG_ERROR, "Get64BitSeed: HW not supported!\n"));
    return FALSE;
  }

  do {
    Seed = ReadSeed ();

    switch (Seed & SEED_OPST_MASK) {
      case SEED_OPST_ES16:
        Entropy[ValidSeeds++] = Seed & SEED_ENTROPY_MASK;
        if (ValidSeeds == NeededSeeds) {
          return TRUE;
        }

        break;

      case SEED_OPST_DEAD:
        DEBUG ((DEBUG_ERROR, "Get64BitSeed: Unrecoverable error!\n"));
        return FALSE;

      case SEED_OPST_BIST:           // fallthrough
      case SEED_OPST_WAIT:           // fallthrough
      default:
        continue;
    }
  } while (--Retry);

  return FALSE;
}

/**
   Constructor library which initializes Seeds and mStatus array.

   @retval EFI_SUCCESS  Intialization was successful.
   @retval EFI_UNSUPPORTED Feature not supported.

 **/
EFI_STATUS
EFIAPI
BaseRngLibConstructor (
  VOID
  )
{

  if (MakeChaChaState ()) {
    return EFI_SUCCESS;
  } else {
    return EFI_UNSUPPORTED;
  }
}

/**
   Generates a 16-bit random number.

   @param[out] Rand     Buffer pointer to store the 16-bit random value.

   @retval TRUE         Random number generated successfully.
   @retval FALSE        Failed to generate the random number.

 **/
BOOLEAN
EFIAPI
ArchGetRandomNumber16 (
  OUT UINT16  *Rand
  )
{
  UINT32  Rand32;

  if (ArchGetRandomNumber32 (&Rand32)) {
    *Rand = Rand32 & MAX_UINT16;
    return TRUE;
  }

  return FALSE;
}

/**
   Generates a 32-bit random number.

   @param[out] Rand     Buffer pointer to store the 32-bit random value.

   @retval TRUE         Random number generated successfully.
   @retval FALSE        Failed to generate the random number.

 **/
BOOLEAN
EFIAPI
ArchGetRandomNumber32 (
  OUT UINT32  *Rand
  )
{
  UINT32  Y;

  // Never initialized.
  if (ChaChaIndex > STATE_SIZE) {
    return FALSE;
  }

  // Re-run ChaCha
  if (ChaChaIndex == STATE_SIZE) {
    if (!MakeChaChaState ()) {
      return FALSE;
    }
  }

  Y  = ChaChaState[ChaChaIndex];

  ChaChaIndex++;

  *Rand = Y;
  return TRUE;
}

/**
   Generates a 64-bit random number.

   @param[out] Rand     Buffer pointer to store the 64-bit random value.

   @retval TRUE         Random number generated successfully.
   @retval FALSE        Failed to generate the random number.

 **/
BOOLEAN
EFIAPI
ArchGetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  UINT32  Rand32L;
  UINT32  Rand32H;

  if (ArchGetRandomNumber32 (&Rand32H) && ArchGetRandomNumber32 (&Rand32L)) {
    *Rand = ((UINT64)Rand32H << 32) | Rand32L;
    return TRUE;
  }
}

/**
   Checks whether SEED is supported.

   @retval TRUE         SEED is supported.
 **/
BOOLEAN
EFIAPI
ArchIsRngSupported (
  VOID
  )
{
  return ((PcdGet64 (PcdRiscVFeatureOverride) & RISCV_CPU_FEATURE_ZKR_BITMASK) != 0);
}
