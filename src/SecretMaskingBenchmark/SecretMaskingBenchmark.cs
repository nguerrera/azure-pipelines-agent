using BenchmarkDotNet.Attributes;
using Microsoft.VisualStudio.Services.Agent;
using System.IO;

namespace SecretMaskingBenchmark;

public class SecretMaskingBenchmark
{
    private static readonly string[] _lines = File.ReadAllLines(@"d:\temp\biglog.txt");

    private void Bench(bool useNewSecretMasker, bool useAdditionalMaskingRegexes)
    {
        using var masker = HostContext.CreateSecretMasker(useNewSecretMasker, useAdditionalMaskingRegexes);
        foreach (var line in _lines)
        {
            masker.MaskSecrets(line);
        }
    }

    [Benchmark]
    public void VsoMasker_NoAdditionalRegexes() => Bench(useNewSecretMasker: false, useAdditionalMaskingRegexes: false);

    [Benchmark]
    public void OssMasker_NoAdditionalRegexes() => Bench(useNewSecretMasker: true, useAdditionalMaskingRegexes: false);

    [Benchmark]
    public void VsoMasker_AdditionalRegexes() => Bench(useNewSecretMasker: false, useAdditionalMaskingRegexes: true);

    [Benchmark]
    public void OssMasker_AdditionalRegexes() => Bench(useNewSecretMasker: true, useAdditionalMaskingRegexes: true);
}


