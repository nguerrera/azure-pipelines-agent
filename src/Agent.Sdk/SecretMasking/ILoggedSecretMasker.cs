// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//using Microsoft.TeamFoundation.DistributedTask.Logging;
using ValueEncoder = Microsoft.TeamFoundation.DistributedTask.Logging.ValueEncoder;
using ISecretMaskerVSO = Microsoft.TeamFoundation.DistributedTask.Logging.ISecretMasker;

using System;

namespace Agent.Sdk.SecretMasking
{
    /// <summary>
    /// Extended ISecretMasker interface that adds support for logging the origin of
    /// regexes, encoders and literal secret values.
    /// </summary>
    public interface ILoggedSecretMasker : ISecretMaskerVSO, IDisposable
    {
        static int MinSecretLengthLimit { get; }

        void AddRegex(String pattern, string origin);
        void AddValue(String value, string origin);
        void AddValueEncoder(ValueEncoder encoder, string origin);
        void SetTrace(ITraceWriter trace);
    }
}
