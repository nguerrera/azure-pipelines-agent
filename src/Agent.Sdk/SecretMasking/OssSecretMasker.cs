// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.Security.Utilities;

using ISecretMasker = Microsoft.TeamFoundation.DistributedTask.Logging.ISecretMasker;
using ValueEncoder = Microsoft.TeamFoundation.DistributedTask.Logging.ValueEncoder;

namespace Agent.Sdk.SecretMasking;

public sealed class OssSecretMasker : ISecretMasker, IDisposable
{
    private SecretMasker _secretMasker;
    private readonly ConcurrentDictionary<string, string> _detectionsForTelemetry;
    private readonly Action<Detection> _detectionAction;
    private const int _maxDetectionsForTelemetry = 5;

    public OssSecretMasker() : this(Array.Empty<RegexPattern>())
    {
    }

    public OssSecretMasker(IEnumerable<RegexPattern> patterns)
    {
        _secretMasker = new SecretMasker(patterns, generateCorrelatingIds: true);
        _secretMasker.DefaultRegexRedactionToken = "***";
        _detectionAction = this.ProcessDetection;
    }

    private OssSecretMasker(OssSecretMasker copy)
    {
        _secretMasker = copy._secretMasker.Clone();
        _detectionAction = this.ProcessDetection;
        _detectionsForTelemetry = new ConcurrentDictionary<string, string>(copy._detectionsForTelemetry);
    }

    /// <summary>
    /// This property allows to set the minimum length of a secret for masking
    /// </summary>
    public int MinSecretLength
    {
        get => _secretMasker.MinimumSecretLength;
        set => _secretMasker.MinimumSecretLength = value;
    }

    public bool HasTelemetry => _detectionsForTelemetry.Count > 0;

    /// <summary>
    /// This implementation assumes no more than one thread is adding regexes, values, or encoders at any given time.
    /// </summary>
    public void AddRegex(string pattern)
    {
        // NOTE: This code path is used for regexes sent to the agent via
        // `AgentJobRequestMessage.MaskHints`. The regexes are effectively
        // arbitrary from our perspective at this layer and therefore we cannot
        // use regex options like 'NonBacktracking' that may not be compatible
        // with them. 
        var regexPattern = new RegexPattern(
            id: string.Empty,
            name: string.Empty,
            label: string.Empty,
            pattern: pattern,
            patternMetadata: DetectionMetadata.None,
            regexOptions: RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture);

        _secretMasker.AddRegex(regexPattern);
    }

    /// <summary>
    /// This implementation assumes no more than one thread is adding regexes, values, or encoders at any given time.
    /// </summary>
    public void AddValue(string test)
    {
        _secretMasker.AddValue(test);
    }

    /// <summary>
    /// This implementation assumes no more than one thread is adding regexes, values, or encoders at any given time.
    /// </summary>
    public void AddValueEncoder(ValueEncoder encoder)
    {
       _secretMasker.AddLiteralEncoder(x => encoder(x));
    }

    public OssSecretMasker Clone() => new OssSecretMasker(this);

    public void Dispose()
    {
        _secretMasker?.Dispose();
        _secretMasker = null;
    }

    public string MaskSecrets(string input)
    {
        return _secretMasker.MaskSecrets(input, _detectionAction);
    }

    private void ProcessDetection(Detection detection)
    {
        if (_detectionsForTelemetry.Count < _maxDetectionsForTelemetry &&
            !string.IsNullOrEmpty(detection.CrossCompanyCorrelatingId) &&
            !string.IsNullOrEmpty(detection.Moniker))
        {
            _detectionsForTelemetry.TryAdd(detection.Moniker, detection.CrossCompanyCorrelatingId);
        }
    }

    public void AddTelemetryDataTo(Dictionary<string, string> telemetryData)
    {
        int count = 0;
        foreach ((string key, string value) in _detectionsForTelemetry)
        {
            if (count >= _maxDetectionsForTelemetry)
            {
                // Corner case: dictionary can exceed this size if multiple
                // threads added to it at the same time.
                break;
            }
            telemetryData.Add(key, value);
            count++;
        }
    }

    /// <summary>
    /// Removes secrets from the dictionary shorter than the MinSecretLength property.
    /// This implementation assumes no more than one thread is adding regexes, values, or encoders at any given time.
    /// </summary>
    public void RemoveShortSecretsFromDictionary()
    {
        var filteredValueSecrets = new HashSet<SecretLiteral>();
        var filteredRegexSecrets = new HashSet<RegexPattern>();

        try
        {
            _secretMasker.SyncObject.EnterReadLock();

            foreach (var secret in _secretMasker.EncodedSecretLiterals)
            {
                if (secret.Value.Length < MinSecretLength)
                {
                    filteredValueSecrets.Add(secret);
                }
            }

            foreach (var secret in _secretMasker.RegexPatterns)
            {
                if (secret.Pattern.Length < MinSecretLength)
                {
                    filteredRegexSecrets.Add(secret);
                }
            }
        }
        finally
        {
            if (_secretMasker.SyncObject.IsReadLockHeld)
            {
                _secretMasker.SyncObject.ExitReadLock();
            }
        }

        try
        {
            _secretMasker.SyncObject.EnterWriteLock();

            foreach (var secret in filteredValueSecrets)
            {
                _secretMasker.EncodedSecretLiterals.Remove(secret);
            }

            foreach (var secret in filteredRegexSecrets)
            {
                _secretMasker.RegexPatterns.Remove(secret);
            }

            foreach (var secret in filteredValueSecrets)
            {
                _secretMasker.ExplicitlyAddedSecretLiterals.Remove(secret);
            }
        }
        finally
        {
            if (_secretMasker.SyncObject.IsWriteLockHeld)
            {
                _secretMasker.SyncObject.ExitWriteLock();
            }
        }
    }

    ISecretMasker ISecretMasker.Clone() => this.Clone();
}