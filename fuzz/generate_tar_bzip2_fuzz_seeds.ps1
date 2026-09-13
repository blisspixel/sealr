[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$fuzzRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$expectedCorpus = [IO.Path]::Combine(
    $fuzzRoot,
    'corpus',
    'tar_bzip2_ustar_portable_v1'
)
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $corpus = $expectedCorpus
} else {
    $corpus = [IO.Path]::GetFullPath($OutputDirectory)
    $leaf = [IO.Path]::GetFileName($corpus)
    if ([IO.Path]::GetDirectoryName($corpus) -cne $temporaryBase -or
        $leaf -notmatch '^sealr-tar-bzip2-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR/bzip2 seeds outside an exact temporary corpus: $corpus"
    }
}
[IO.Directory]::CreateDirectory($corpus) | Out-Null

function ConvertFrom-Hex {
    param([Parameter(Mandatory)][string]$Hex)

    if ($Hex.Length % 2 -ne 0 -or $Hex -notmatch '^[0-9a-f]+$') {
        throw "invalid pinned hex literal: $Hex"
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring(2 * $index, 2), 16)
    }
    return ,$bytes
}

function Join-Bytes {
    param([Parameter(Mandatory)][object[]]$Parts)

    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($part in $Parts) {
        $bytes.AddRange([byte[]]$part)
    }
    return ,$bytes.ToArray()
}

function Copy-WithByteXor {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][byte]$Mask
    )

    $mutated = [byte[]]$Bytes.Clone()
    $mutated[$Offset] = $mutated[$Offset] -bxor $Mask
    return ,$mutated
}

function Write-Seed {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    if ($Name -notmatch '^[a-z0-9-]+$') {
        throw "invalid seed name: $Name"
    }
    [IO.File]::WriteAllBytes((Join-Path $corpus $Name), $Bytes)
}

# Pinned deterministic CPython 3.12.10 `bz2.compress` streams (bundled
# libbz2 1.0.8; byte-identical to `bzip2 -9` / `bzip2 -1`) over the standard
# conformance TAR archives. bzip2 has no uncompressed mode, so every hostile
# seed is a deterministic mutation of these committed bytes.
$cliLevel9SingleBlock = ConvertFrom-Hex -Hex (
    '425a68393141592653597b1dc2a70000447b91ca0000404005ff0040006f27dfe00400' +
    '00400008200074226a64f51a64d0340640c4d064a0d341a680034d001e6587e2308c00' +
    '5913503e46a2880842162fc4d83544cc801bd752180f90d0c026e224716664838d467b' +
    '58fbfac1cf118147687b09c160a4ad2080f498e75a99561f215194f509f0637e2ee48a' +
    '70a120f63b854e'
)
$cliLevel1SingleBlock = ConvertFrom-Hex -Hex (
    '425a68313141592653597b1dc2a70000447b91ca0000404005ff0040006f27dfe00400' +
    '00400008200074226a64f51a64d0340640c4d064a0d341a680034d001e6587e2308c00' +
    '5913503e46a2880842162fc4d83544cc801bd752180f90d0c026e224716664838d467b' +
    '58fbfac1cf118147687b09c160a4ad2080f498e75a99561f215194f509f0637e2ee48a' +
    '70a120f63b854e'
)
$cliMultiblockThreeBlocks = ConvertFrom-Hex -Hex (
    '425a6831314159265359957b66fa007a18fd90681000404005ff8800087fe79fa00400' +
    '400238d00018c9a640c9a1906469811832534d00d0006800009aaa1354dea9ed23d536' +
    'a068f53d4c9ea7a9e486326990326864191a60467f6e5ae7ba9e38b6e99b360bc64896' +
    '2e4489779225b1225cc912c8912d4912c0912dc4897dc912ea48962489042882082410' +
    '9cd518019338016b0d68548982dad2d8516b57e6c31d3c3d36244b2b0244bd3d4912d9' +
    '244bf84897992259922581225d4912dc489748912f81225d0912d24896048975244b22' +
    '44b2ebd9244b7781225a1225a922586f244bc2244bb9225ec4896448972d3cbdb79225' +
    '8ebbe88977244b81225d8912e04897c8912d0912db3c4912f2b4bb922591225a6a4897' +
    '3e78c912c8912e3c4912e3aedad97ac912edc2244b7e04896648977f7f7922599225c0' +
    '912cc912f34912ec48961c648972ff98a0ac9329ace1ea564d802e1c2cc00008200280' +
    '041ff1cfd02000ec000283468d0640685068d1a0c80d04d5529fa4c4d4da9a69a3ca14' +
    '1a346832034c2225dd112e9112ec8897cd112c5112f1444b2444b3a225b2225ee8897c' +
    '22258288971444b79112f28897a444b3444b2a225f8889668897a5112d1112f48897ea' +
    '22592225ee88961112e5112db2a225ad112da8896e88967444b65112e9112e5112c511' +
    '2d288968889748896b444b9a225ad112f088968a225d222595112f32225da88977a225' +
    'f688967152aadd112e9112d2889708896288970a225fc8896e8897f98a0ac9329acf6a' +
    '878ea80128aece06008200280041ff1cfd0100000042000deeaa5145346803400014d1' +
    'a00d000026aa91a3468000d014aaa79194c8f51868326f30c11c62a2fc1516d151662a' +
    '2d1429ad429cd429854298a8533151788a8b0151628545ff150e2a853b5429e2a14c6a' +
    '14c2a12dfc0a8b88a8b5854598a8b514a7c50a6150a7b50a6ba85345429b5429928538' +
    '54299a85372aa8b71516c2a2c62a2ca2a2c80a7ea853250a68a14c9429c6a14daa853f' +
    '542982853aaa14d8a14dea14eca14c549159d429b0a8b28a8b415163151688a87ba853' +
    '350a693f8bb9229c28481f8a198400'
)
$emptyStream = ConvertFrom-Hex -Hex '425a683917724538509000000000'

Write-Seed 'valid-cli-level9-single-block' $cliLevel9SingleBlock
Write-Seed 'valid-cli-level1-single-block' $cliLevel1SingleBlock
# The pinned three-block stream decodes to 261,120 bytes: beyond the
# campaign's 131,072-byte derived cap, so it exercises the Denied path.
Write-Seed 'resource-derived-over-cap' $cliMultiblockThreeBlocks
Write-Seed 'unsupported-empty-stream' $emptyStream
Write-Seed 'unsupported-bzip1-version' (Copy-WithByteXor `
    -Bytes $cliLevel9SingleBlock -Offset 2 -Mask ([byte]([byte][char]'h' -bxor [byte][char]'0')))
Write-Seed 'unsupported-level-zero' (Copy-WithByteXor `
    -Bytes $cliLevel9SingleBlock -Offset 3 -Mask ([byte]([byte][char]'9' -bxor [byte][char]'0')))
Write-Seed 'unsupported-randomized-block' (Copy-WithByteXor `
    -Bytes $cliLevel9SingleBlock -Offset 14 -Mask 0x80)
Write-Seed 'unsupported-concatenated-streams' (Join-Bytes @(
    $cliLevel9SingleBlock,
    $cliLevel9SingleBlock
))
Write-Seed 'invalid-magic' (Copy-WithByteXor `
    -Bytes $cliLevel9SingleBlock -Offset 0 -Mask 0xbc)
$truncated = [byte[]]::new([int]($cliLevel9SingleBlock.Length / 2))
[Array]::Copy($cliLevel9SingleBlock, $truncated, $truncated.Length)
Write-Seed 'invalid-truncated' $truncated
Write-Seed 'invalid-payload-corruption' (Copy-WithByteXor `
    -Bytes $cliLevel9SingleBlock -Offset ([int]($cliLevel9SingleBlock.Length / 2)) -Mask 0x40)
Write-Seed 'invalid-trailing-byte' (Join-Bytes @(
    $cliLevel9SingleBlock,
    [byte[]]@(0x7f)
))
Write-Seed 'invalid-block-crc' (Copy-WithByteXor `
    -Bytes $cliLevel9SingleBlock -Offset 11 -Mask 0x01)
Write-Seed 'invalid-footer-corruption' (Copy-WithByteXor `
    -Bytes $cliLevel9SingleBlock -Offset ($cliLevel9SingleBlock.Length - 3) -Mask 0x01)

Write-Host 'Generated deterministic public TAR/bzip2 fuzz seeds.'
